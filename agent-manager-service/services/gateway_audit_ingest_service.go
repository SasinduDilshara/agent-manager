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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// The gateway's OTel analytics publisher (WSO2 API Platform gateway,
// policy-engine/internal/analytics/publishers/otel.go) sends one OTLP log record
// per request it handled, in this scope and with this event name.
const (
	gatewayAnalyticsScope = "wso2.analytics"
	gatewayAnalyticsEvent = "wso2.api.transaction"
)

// Reasons a reported record is not relayed.
const (
	rejectUnexpectedScope = "unexpected-scope"
	rejectUnexpectedEvent = "unexpected-event"
	rejectBadTimestamp    = "bad-timestamp"
)

// observedEventNamespace keys the deterministic event ids of relayed records.
var observedEventNamespace = uuid.MustParse("2c8a5e3d-6f1b-4d7e-9a0c-5b3f1e8d2a74")

// GatewayAuditIngestService relays the agent activity an AI gateway observed
// into the audit trail: one record per request the gateway handled.
type GatewayAuditIngestService interface {
	// Ingest parses an OTLP/HTTP JSON logs export request and writes one audit
	// record per accepted log record before returning. It returns
	// utils.ErrMalformedAuditBatch when the body is not an export request at
	// all, and utils.ErrAuditIngestUnavailable when the batch could not be
	// written or its agents could not be looked up — the gateway retries that.
	Ingest(ctx context.Context, caller GatewayAuditCaller, body []byte) (*GatewayAuditIngestResult, error)
}

type gatewayAuditIngestService struct {
	sink     audit.Sink
	resolver *gatewayAgentResolver
	// excerptBytes keeps that much of each captured body in the record; 0 keeps none.
	excerptBytes int
	logger       *slog.Logger
}

// NewGatewayAuditIngestService returns the ingest service. sink is where relayed
// records are written: the OpenChoreo audit sink, which the audit store reads.
func NewGatewayAuditIngestService(
	sink audit.Sink,
	apps repositories.AIApplicationRepository,
	identities repositories.AgentThunderClientRepository,
	cacheTTL time.Duration,
	excerptBytes int,
	logger *slog.Logger,
) GatewayAuditIngestService {
	if logger == nil {
		logger = slog.Default()
	}
	return &gatewayAuditIngestService{
		sink:         sink,
		resolver:     newGatewayAgentResolver(apps, identities, cacheTTL),
		excerptBytes: excerptBytes,
		logger:       logger,
	}
}

func (s *gatewayAuditIngestService) Ingest(ctx context.Context, caller GatewayAuditCaller, body []byte) (*GatewayAuditIngestResult, error) {
	if caller.GatewayID == "" || caller.OUID == "" {
		return nil, fmt.Errorf("audit ingest: caller has no gateway or organization")
	}
	var req otlpExportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("%w: %w", utils.ErrMalformedAuditBatch, err)
	}

	result := &GatewayAuditIngestResult{RejectReasons: map[string]int{}}
	reject := func(reason string) {
		result.Rejected++
		result.RejectReasons[reason]++
	}

	events := make([]audit.Event, 0)
	for _, rl := range req.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			if sl.Scope.Name != gatewayAnalyticsScope {
				for range sl.LogRecords {
					reject(rejectUnexpectedScope)
				}
				continue
			}
			for _, raw := range sl.LogRecords {
				var rec otlpLogRecord
				if err := json.Unmarshal(raw, &rec); err != nil {
					reject(rejectUnexpectedEvent)
					continue
				}
				attrs := newOTLPAttributes(rec.Attributes)
				eventName := rec.EventName
				if eventName == "" {
					eventName = attrs.str("event.name")
				}
				if eventName != gatewayAnalyticsEvent {
					reject(rejectUnexpectedEvent)
					continue
				}
				occurred, ok := parseUnixNano(rec.TimeUnixNano)
				if !ok {
					reject(rejectBadTimestamp)
					continue
				}
				agent, err := s.resolver.resolve(ctx, caller.OUID,
					attrs.str("wso2.application.id"), attrs.str("user.id"))
				if err != nil {
					// Writing the record without its agent would lose the
					// attribution for good; failing the batch lets the gateway
					// deliver it again once the lookup works.
					return nil, fmt.Errorf("%w: resolve agent: %w", utils.ErrAuditIngestUnavailable, err)
				}
				id := uuid.NewSHA1(observedEventNamespace, []byte(caller.GatewayID+"\n"+string(raw)))
				events = append(events, buildObservedGatewayEvent(caller, id, occurred, attrs, agent, s.excerptBytes))
			}
		}
	}

	if err := audit.WriteSync(ctx, s.sink, events); err != nil {
		return nil, fmt.Errorf("%w: %w", utils.ErrAuditIngestUnavailable, err)
	}
	result.Accepted = len(events)

	if result.Rejected > 0 {
		s.logger.Warn("gateway audit batch had records that were not relayed",
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

// rejectReasonSummary names the most frequent reject reason.
func rejectReasonSummary(reasons map[string]int) string {
	best, bestN := "", 0
	for r, n := range reasons {
		if n > bestN || (n == bestN && r < best) {
			best, bestN = r, n
		}
	}
	return best
}

// buildObservedGatewayEvent maps one gateway analytics record onto an audit
// event. Only the attributes named here are read: header attributes
// (http.request.header.*, http.response.header.*) and payloads
// (wso2.request.body, wso2.response.body) are read only for the opt-in
// excerpts (excerptBytes > 0), so credentials cannot reach the trail and
// prompt content reaches it only when an operator asks for it.
func buildObservedGatewayEvent(
	caller GatewayAuditCaller, id uuid.UUID, occurred time.Time, a otlpAttributes, agent resolvedAgent,
	excerptBytes int,
) audit.Event {
	apiKind := a.str("wso2.api.type")
	mcpMethod := a.str("mcp.method.name")
	action, resourceType := classifyGatewayRequest(apiKind, mcpMethod)

	opts := []audit.Option{
		audit.EventID(id),
		audit.OccurredAt(occurred),
		audit.Org(caller.OUID),
		audit.SurfaceOpt(audit.SurfaceGateway),
		audit.ProducedBy(audit.OpenChoreoProducerGatewayOTel),
		audit.Correlation(a.str("wso2.correlation.id")),
		audit.Origin(a.str("client.address"), a.str("user_agent.original")),
		audit.Request(a.str("http.request.method"), a.str("url.path")),
		audit.ResourceNamed(resourceType, a.str("wso2.api.id"), a.str("wso2.api.name")),
		audit.Detail("gatewayId", caller.GatewayID),
		audit.Detail("provenance", provenanceObserved),
		audit.Detail("resolution", agent.resolution),
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

	status, hasStatus := a.int("http.response.status_code")
	guardrailHit, _ := a.bool("wso2.guardrail.hit")
	switch {
	case !hasStatus:
		// The gateway recorded no response status, so the outcome is not
		// known to have been a success.
		opts = append(opts, audit.OutcomeOpt(audit.OutcomeFailure))
	default:
		opts = append(opts, audit.Status(int(status)))
	}
	if guardrailHit {
		opts = append(opts, audit.OutcomeOpt(audit.OutcomeDeny))
	}
	if (hasStatus && (status == 401 || status == 403)) || guardrailHit {
		opts = append(opts, audit.SeverityOpt(audit.SeverityWarning))
	}
	if d, ok := a.int("wso2.latency.duration_ms"); ok {
		opts = append(opts, audit.Duration(d))
	}

	detailStr := func(key, attr string) {
		if v := a.str(attr); v != "" {
			opts = append(opts, audit.Detail(key, v))
		}
	}
	detailInt := func(key, attr string) {
		if v, ok := a.int(attr); ok {
			opts = append(opts, audit.Detail(key, v))
		}
	}
	detailStr("applicationId", "wso2.application.id")
	detailStr("authSubject", "user.id")
	detailStr("apiId", "wso2.api.id")
	if apiKind != "" {
		opts = append(opts, audit.Detail("apiKind", apiKind))
	}
	detailStr("apiContext", "wso2.api.context")
	detailStr("route", "http.route")
	detailStr("upstreamHost", "server.address")
	detailInt("upstreamStatus", "wso2.upstream.response.status_code")
	detailStr("faultType", "error.type")
	detailStr("provider", "gen_ai.provider.name")
	detailStr("operation", "gen_ai.operation.name")
	detailStr("requestModel", "gen_ai.request.model")
	detailStr("responseModel", "gen_ai.response.model")
	detailInt("inputTokens", "gen_ai.usage.input_tokens")
	detailInt("outputTokens", "gen_ai.usage.output_tokens")
	detailInt("totalTokens", "wso2.gen_ai.usage.total_tokens")
	if cost, ok := a.float("wso2.gen_ai.cost.total"); ok {
		opts = append(opts, audit.Detail("costUsd", cost))
	}
	if mcpMethod != "" {
		opts = append(opts, audit.Detail("mcpMethod", mcpMethod))
	}
	detailStr("mcpSessionId", "mcp.session.id")
	detailStr("toolName", "gen_ai.tool.name")
	detailStr("promptName", "gen_ai.prompt.name")
	detailStr("resourceUri", "mcp.resource.uri")
	if hit, ok := a.bool("wso2.guardrail.hit"); ok {
		opts = append(opts, audit.Detail("guardrailHit", hit))
	}
	detailStr("guardrailName", "wso2.guardrail.name")
	detailInt("backendLatencyMs", "wso2.latency.backend_ms")
	// Opt-in excerpts of the bodies the publisher sends when the gateway's
	// collector captures them. Nothing else of a body is ever read.
	opts = append(opts, bodyExcerptOptions(a.str("wso2.request.body"), a.str("wso2.response.body"), excerptBytes)...)

	return audit.BuildObservedEvent(action, opts...)
}

func parseUnixNano(s string) (time.Time, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(0, n).UTC(), true
}

// --- OTLP/HTTP JSON ------------------------------------------------------------

// otlpExportRequest is the OTLP ExportLogsServiceRequest in its proto3 JSON
// mapping. Log records are kept raw so a record's exact bytes can key its id.
type otlpExportRequest struct {
	ResourceLogs []struct {
		ScopeLogs []struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
			LogRecords []json.RawMessage `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type otlpLogRecord struct {
	TimeUnixNano string         `json:"timeUnixNano"`
	EventName    string         `json:"eventName"`
	Attributes   []otlpKeyValue `json:"attributes"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

// otlpAnyValue is the OTLP AnyValue union. 64-bit integers are JSON strings in
// the proto3 mapping; some senders emit bare numbers, so both are accepted.
type otlpAnyValue struct {
	StringValue *string      `json:"stringValue,omitempty"`
	IntValue    *json.Number `json:"intValue,omitempty"`
	DoubleValue *float64     `json:"doubleValue,omitempty"`
	BoolValue   *bool        `json:"boolValue,omitempty"`
}

// otlpAttributes is a record's attributes by key.
type otlpAttributes map[string]otlpAnyValue

func newOTLPAttributes(kvs []otlpKeyValue) otlpAttributes {
	out := make(otlpAttributes, len(kvs))
	for _, kv := range kvs {
		out[kv.Key] = kv.Value
	}
	return out
}

func (a otlpAttributes) str(key string) string {
	if v, ok := a[key]; ok && v.StringValue != nil {
		return *v.StringValue
	}
	return ""
}

func (a otlpAttributes) int(key string) (int64, bool) {
	v, ok := a[key]
	if !ok {
		return 0, false
	}
	switch {
	case v.IntValue != nil:
		n, err := v.IntValue.Int64()
		return n, err == nil
	case v.StringValue != nil:
		n, err := strconv.ParseInt(*v.StringValue, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func (a otlpAttributes) float(key string) (float64, bool) {
	v, ok := a[key]
	if !ok {
		return 0, false
	}
	switch {
	case v.DoubleValue != nil:
		return *v.DoubleValue, true
	case v.IntValue != nil:
		f, err := v.IntValue.Float64()
		return f, err == nil
	case v.StringValue != nil:
		f, err := strconv.ParseFloat(*v.StringValue, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func (a otlpAttributes) bool(key string) (bool, bool) {
	if v, ok := a[key]; ok && v.BoolValue != nil {
		return *v.BoolValue, true
	}
	return false, false
}
