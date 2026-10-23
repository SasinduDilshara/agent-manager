// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// The traffic-log feed: the gateway's traffic logging (WSO2 API Platform
// gateway, policy-engine/internal/analytics/publishers/traffic_log_event.go)
// writes one JSON line per request, and its "http" sink POSTs them here in
// NDJSON batches. It is a second gateway feed beside the OTel one, kept apart
// so the two can be compared and either removed.

// trafficPropAuthSubject is the traffic_logging.properties key the gateway
// extension chart binds to "$ctx:auth.subject" — the token subject, which
// names an agent on AgentID-authenticated routes. The line carries no auth
// fields of its own.
const (
	trafficPropAuthSubject = "authSubject"
	trafficPropAuthType    = "authType"
)

// Reasons a delivered line is not relayed.
const (
	rejectMalformedLine    = "malformed-line"
	rejectTrafficTimestamp = "bad-timestamp"
)

// trafficEventNamespace keys the deterministic event ids of relayed lines. It
// differs from the OTel feed's, so the two feeds never share an id.
var trafficEventNamespace = uuid.MustParse("7d4b1c9e-2a63-4f80-b5e1-0c9a8f3d6e21")

// GatewayTrafficAuditIngestService relays the agent activity in an AI
// gateway's traffic log into the audit trail: one record per line.
type GatewayTrafficAuditIngestService interface {
	// Ingest parses an NDJSON batch of traffic-log lines and writes one audit
	// record per accepted line before returning. It returns
	// utils.ErrMalformedAuditBatch when no line of a non-empty batch is a
	// traffic-log line, and utils.ErrAuditIngestUnavailable when the batch
	// could not be written or its agents could not be looked up — the gateway
	// retries that.
	Ingest(ctx context.Context, caller GatewayAuditCaller, body []byte) (*GatewayAuditIngestResult, error)
}

type gatewayTrafficAuditIngestService struct {
	sink     audit.Sink
	resolver *gatewayAgentResolver
	// excerptBytes keeps that much of each captured body in the record; 0 keeps none.
	excerptBytes int
	logger       *slog.Logger
}

// NewGatewayTrafficAuditIngestService returns the traffic-log ingest service.
// sink is the OpenChoreo audit sink, as for the OTel feed.
func NewGatewayTrafficAuditIngestService(
	sink audit.Sink,
	apps repositories.AIApplicationRepository,
	identities repositories.AgentThunderClientRepository,
	cacheTTL time.Duration,
	excerptBytes int,
	logger *slog.Logger,
) GatewayTrafficAuditIngestService {
	if logger == nil {
		logger = slog.Default()
	}
	return &gatewayTrafficAuditIngestService{
		sink:         sink,
		resolver:     newGatewayAgentResolver(apps, identities, cacheTTL),
		excerptBytes: excerptBytes,
		logger:       logger,
	}
}

// trafficLogLine is the subset of a traffic-log line this feed reads. Headers
// (requestHeaders, responseHeaders) are deliberately not declared, so they are
// never decoded; bodies are read only for the fields bodyFields extracts.
type trafficLogLine struct {
	Timestamp     string `json:"timestamp"`
	CorrelationID string `json:"correlationId"`
	Status        int    `json:"status"`
	API           *struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Context   string `json:"context"`
		Kind      string `json:"kind"`
		ProjectID string `json:"projectId"`
	} `json:"api"`
	Operation *struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	} `json:"operation"`
	Target *struct {
		StatusCode  int    `json:"statusCode"`
		Destination string `json:"destination"`
	} `json:"target"`
	Application *struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		KeyType string `json:"keyType"`
	} `json:"application"`
	Client *struct {
		IP        string `json:"ip"`
		UserAgent string `json:"userAgent"`
	} `json:"client"`
	Latencies *struct {
		DurationUs                 int64 `json:"durationUs"`
		RequestMediationLatencyUs  int64 `json:"requestMediationLatencyUs"`
		ResponseMediationLatencyUs int64 `json:"responseMediationLatencyUs"`
		BackendLatencyUs           int64 `json:"backendLatencyUs"`
	} `json:"latencies"`
	RequestBody  string         `json:"requestBody"`
	ResponseBody string         `json:"responseBody"`
	Properties   map[string]any `json:"properties"`
}

func (l *trafficLogLine) property(key string) string {
	v, _ := l.Properties[key].(string)
	return v
}

func (s *gatewayTrafficAuditIngestService) Ingest(
	ctx context.Context, caller GatewayAuditCaller, body []byte,
) (*GatewayAuditIngestResult, error) {
	if caller.GatewayID == "" || caller.OUID == "" {
		return nil, fmt.Errorf("traffic audit ingest: caller has no gateway or organization")
	}
	result := &GatewayAuditIngestResult{RejectReasons: map[string]int{}}
	reject := func(reason string) {
		result.Rejected++
		result.RejectReasons[reason]++
	}

	events := make([]audit.Event, 0)
	lines := 0
	for _, raw := range bytes.Split(body, []byte("\n")) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		lines++
		var line trafficLogLine
		if err := json.Unmarshal(raw, &line); err != nil {
			reject(rejectMalformedLine)
			continue
		}
		occurred, err := time.Parse(time.RFC3339Nano, line.Timestamp)
		if err != nil {
			reject(rejectTrafficTimestamp)
			continue
		}
		applicationID := ""
		if line.Application != nil {
			applicationID = line.Application.ID
		}
		agent, err := s.resolver.resolve(ctx, caller.OUID, applicationID, line.property(trafficPropAuthSubject))
		if err != nil {
			// As for the OTel feed: a record written without its agent would
			// lose the attribution for good, so the batch is retried instead.
			return nil, fmt.Errorf("%w: resolve agent: %w", utils.ErrAuditIngestUnavailable, err)
		}
		id := uuid.NewSHA1(trafficEventNamespace, append([]byte(caller.GatewayID+"\n"), raw...))
		events = append(events, buildTrafficLogEvent(caller, id, occurred.UTC(), &line, agent, s.excerptBytes))
	}
	if lines > 0 && result.Rejected == lines {
		return nil, fmt.Errorf("%w: no line of the batch is a traffic-log line", utils.ErrMalformedAuditBatch)
	}

	if err := audit.WriteSync(ctx, s.sink, events); err != nil {
		return nil, fmt.Errorf("%w: %w", utils.ErrAuditIngestUnavailable, err)
	}
	result.Accepted = len(events)

	if result.Rejected > 0 {
		s.logger.Warn("gateway traffic-log batch had lines that were not relayed",
			"gatewayId", caller.GatewayID, "rejected", result.Rejected, "reasons", result.RejectReasons)
		audit.RecordAncillary(ctx, audit.ActionAuditIngestRejected,
			audit.Org(caller.OUID),
			audit.Resource(audit.ResourceGateway, caller.GatewayID),
			audit.SurfaceOpt(audit.SurfaceInternal),
			audit.OutcomeOpt(audit.OutcomeFailure),
			audit.Detail("gatewayId", caller.GatewayID),
			audit.Detail("reason", rejectReasonSummary(result.RejectReasons)),
			audit.Detail("rejectedCount", result.Rejected),
		)
	}
	return result, nil
}

// buildTrafficLogEvent maps one traffic-log line onto an audit event, with the
// same actions, resources and agent attribution as the OTel feed so the two
// can be compared field for field.
func buildTrafficLogEvent(
	caller GatewayAuditCaller, id uuid.UUID, occurred time.Time, line *trafficLogLine, agent resolvedAgent,
	excerptBytes int,
) audit.Event {
	apiKind, apiID, apiName := "", "", ""
	if line.API != nil {
		apiKind, apiID, apiName = line.API.Kind, line.API.ID, line.API.Name
	}
	fromBody := extractTrafficBodyFields(apiKind, line.RequestBody, line.ResponseBody)
	action, resourceType := classifyGatewayRequest(apiKind, fromBody.mcpMethod)

	opts := []audit.Option{
		audit.EventID(id),
		audit.OccurredAt(occurred),
		audit.Org(caller.OUID),
		audit.SurfaceOpt(audit.SurfaceGateway),
		audit.ProducedBy(audit.OpenChoreoProducerGatewayTrafficLog),
		audit.Correlation(line.CorrelationID),
		audit.ResourceNamed(resourceType, apiID, apiName),
		audit.Detail("gatewayId", caller.GatewayID),
		audit.Detail("provenance", provenanceObserved),
		audit.Detail("resolution", agent.resolution),
	}
	if line.Client != nil {
		opts = append(opts, audit.Origin(line.Client.IP, line.Client.UserAgent))
	}
	if line.Operation != nil {
		// The traffic log carries the API's route template, not the requested path.
		opts = append(opts, audit.Request(line.Operation.Method, line.Operation.Path))
	}

	if agent.agentName != "" {
		opts = append(opts,
			audit.Actor(audit.ActorAgent, agent.agentName, ""),
			audit.Agent(agent.agentName),
			audit.Project(agent.projectName),
			audit.Environment(agent.environmentName),
		)
	} else {
		opts = append(opts, audit.Actor(audit.ActorAnonymous, "", ""))
	}

	if line.Status == 0 {
		// No response status: the outcome is not known to have been a success.
		opts = append(opts, audit.OutcomeOpt(audit.OutcomeFailure))
	} else {
		opts = append(opts, audit.Status(line.Status))
	}
	if line.Status == 401 || line.Status == 403 || fromBody.mcpError {
		opts = append(opts, audit.SeverityOpt(audit.SeverityWarning))
	}
	if l := line.Latencies; l != nil {
		opts = append(opts, audit.Duration(l.DurationUs/1000))
		opts = append(opts,
			audit.Detail("backendLatencyMs", l.BackendLatencyUs/1000),
			audit.Detail("requestMediationMs", l.RequestMediationLatencyUs/1000),
			audit.Detail("responseMediationMs", l.ResponseMediationLatencyUs/1000),
		)
	}

	detail := func(key, value string) {
		if value != "" {
			opts = append(opts, audit.Detail(key, value))
		}
	}
	if line.API != nil {
		detail("apiId", line.API.ID)
		detail("apiKind", line.API.Kind)
		detail("apiName", line.API.Name)
		detail("apiVersion", line.API.Version)
		detail("apiContext", line.API.Context)
	}
	if line.Application != nil {
		detail("applicationId", line.Application.ID)
		detail("applicationName", line.Application.Name)
		detail("applicationKeyType", line.Application.KeyType)
	}
	detail("authSubject", line.property(trafficPropAuthSubject))
	detail("authType", line.property(trafficPropAuthType))
	if line.Target != nil {
		detail("upstreamHost", line.Target.Destination)
		if line.Target.StatusCode != 0 {
			opts = append(opts, audit.Detail("upstreamStatus", int64(line.Target.StatusCode)))
		}
	}
	opts = append(opts, fromBody.options()...)
	opts = append(opts, bodyExcerptOptions(line.RequestBody, line.ResponseBody, excerptBytes)...)

	return audit.BuildObservedEvent(action, opts...)
}
