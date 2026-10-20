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
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// The gateway's OTel analytics publisher (WSO2 API Platform gateway,
// policy-engine/internal/analytics/publishers/otel.go) sends one OTLP log record
// per request it handled, in this scope and with this event name.
const (
	gatewayAnalyticsScope = "wso2.analytics"
	gatewayAnalyticsEvent = "wso2.api.transaction"

	// provenanceObserved marks a record as relayed from a gateway's
	// best-effort analytics feed, as opposed to one this service produced.
	provenanceObserved = "observed-best-effort"
)

// How the acting agent of an observed request was identified.
const (
	resolutionApplication   = "application"    // the gateway's application id (API-key routes)
	resolutionAgentIdentity = "agent-identity" // the AgentID token subject (JWT routes)
	resolutionUnresolved    = "unresolved"     // neither named a known agent of the gateway's org
)

// Reasons a reported record is not relayed.
const (
	rejectUnexpectedScope = "unexpected-scope"
	rejectUnexpectedEvent = "unexpected-event"
	rejectBadTimestamp    = "bad-timestamp"
)

// observedEventNamespace keys the deterministic event ids of relayed records.
var observedEventNamespace = uuid.MustParse("2c8a5e3d-6f1b-4d7e-9a0c-5b3f1e8d2a74")

// GatewayAuditCaller is the authenticated gateway delivering a batch. Its
// organization comes from its credential, never from the batch.
type GatewayAuditCaller struct {
	GatewayID string
	OUID      string
}

// GatewayAuditIngestResult reports what became of a delivered batch.
type GatewayAuditIngestResult struct {
	Accepted int
	Rejected int
	// RejectReasons counts rejected records by reason.
	RejectReasons map[string]int
}

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
	logger   *slog.Logger
}

// NewGatewayAuditIngestService returns the ingest service. sink is where relayed
// records are written: the OpenChoreo audit sink, which the audit store reads.
func NewGatewayAuditIngestService(
	sink audit.Sink,
	apps repositories.AIApplicationRepository,
	identities repositories.AgentThunderClientRepository,
	cacheTTL time.Duration,
	logger *slog.Logger,
) GatewayAuditIngestService {
	if logger == nil {
		logger = slog.Default()
	}
	return &gatewayAuditIngestService{
		sink:     sink,
		resolver: newGatewayAgentResolver(apps, identities, cacheTTL),
		logger:   logger,
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
				events = append(events, buildObservedGatewayEvent(caller, id, occurred, attrs, agent))
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
// (wso2.request.body, wso2.response.body) are never touched, so credentials and
// prompt content the gateway may have captured cannot reach the trail.
func buildObservedGatewayEvent(
	caller GatewayAuditCaller, id uuid.UUID, occurred time.Time, a otlpAttributes, agent resolvedAgent,
) audit.Event {
	apiKind := a.str("wso2.api.type")
	mcpMethod := a.str("mcp.method.name")
	action, resourceType := classifyGatewayRequest(apiKind, mcpMethod)

	opts := []audit.Option{
		audit.EventID(id),
		audit.OccurredAt(occurred),
		audit.Org(caller.OUID),
		audit.SurfaceOpt(audit.SurfaceGateway),
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

	return audit.BuildObservedEvent(action, opts...)
}

// classifyGatewayRequest names the action and resource type of a request from
// the kind of API it reached (the gateway's artifact kinds: LlmProxy,
// LlmProvider, Mcp, Agent, RestApi, ...). Unknown kinds are recorded as a plain
// API call rather than dropped.
func classifyGatewayRequest(apiKind, mcpMethod string) (audit.Action, string) {
	switch strings.ToLower(apiKind) {
	case "llmproxy":
		return audit.ActionLLMCall, audit.ResourceLLMProxy
	case "llmprovider":
		return audit.ActionLLMCall, audit.ResourceLLMProvider
	case "mcp":
		if mcpMethod == "tools/call" {
			return audit.ActionMCPToolCall, audit.ResourceMCPProxy
		}
		return audit.ActionMCPCall, audit.ResourceMCPProxy
	case "agent":
		return audit.ActionAgentInvoke, audit.ResourceAgent
	default:
		return audit.ActionAPICall, audit.ResourceAPI
	}
}

func parseUnixNano(s string) (time.Time, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(0, n).UTC(), true
}

// --- Agent resolution --------------------------------------------------------

type resolvedAgent struct {
	agentName       string
	projectName     string
	environmentName string
	resolution      string
}

// gatewayAgentResolver names the agent behind an observed request. Every
// lookup is confined to the delivering gateway's organization, so a request
// naming another organization's application or identity resolves to nothing.
type gatewayAgentResolver struct {
	apps       repositories.AIApplicationRepository
	identities repositories.AgentThunderClientRepository
	ttl        time.Duration

	mu    sync.Mutex
	cache map[string]cachedAgent
}

type cachedAgent struct {
	agent   resolvedAgent
	expires time.Time
}

// resolverCacheMax bounds the cache; past it the cache is cleared rather than
// growing with every distinct id a gateway reports.
const resolverCacheMax = 10000

func newGatewayAgentResolver(
	apps repositories.AIApplicationRepository, identities repositories.AgentThunderClientRepository, ttl time.Duration,
) *gatewayAgentResolver {
	return &gatewayAgentResolver{apps: apps, identities: identities, ttl: ttl, cache: map[string]cachedAgent{}}
}

// resolve tries the application id first (API-key routes), then the token
// subject (AgentID-authenticated routes). A lookup that fails for any reason
// other than "not found" is returned as an error.
func (r *gatewayAgentResolver) resolve(ctx context.Context, ouID, applicationID, subject string) (resolvedAgent, error) {
	if applicationID != "" {
		agent, found, err := r.cached("app|"+ouID+"|"+applicationID, func() (resolvedAgent, bool, error) {
			app, err := r.apps.GetByHandle(ctx, ouID, applicationID)
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return resolvedAgent{}, false, nil
			}
			if err != nil {
				return resolvedAgent{}, false, err
			}
			return agentFromApplication(app), true, nil
		})
		if err != nil || found {
			return agent, err
		}
	}
	if subject != "" {
		agent, found, err := r.cached("sub|"+ouID+"|"+subject, func() (resolvedAgent, bool, error) {
			c, err := r.identities.FindByThunderIdentity(ctx, ouID, subject)
			if errors.Is(err, repositories.ErrAgentThunderClientNotFound) {
				return resolvedAgent{}, false, nil
			}
			if err != nil {
				return resolvedAgent{}, false, err
			}
			return agentFromIdentity(c), true, nil
		})
		if err != nil || found {
			return agent, err
		}
	}
	return resolvedAgent{resolution: resolutionUnresolved}, nil
}

// cached memoises lookups, including misses, for the TTL. Errors are not cached.
func (r *gatewayAgentResolver) cached(key string, lookup func() (resolvedAgent, bool, error)) (resolvedAgent, bool, error) {
	now := time.Now()
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && now.Before(e.expires) {
		r.mu.Unlock()
		return e.agent, e.agent.agentName != "", nil
	}
	r.mu.Unlock()

	// Looked up without the lock held: never hold a lock across I/O.
	agent, found, err := lookup()
	if err != nil {
		return resolvedAgent{}, false, err
	}
	if r.ttl > 0 {
		r.mu.Lock()
		if len(r.cache) >= resolverCacheMax {
			r.cache = map[string]cachedAgent{}
		}
		r.cache[key] = cachedAgent{agent: agent, expires: now.Add(r.ttl)}
		r.mu.Unlock()
	}
	return agent, found, nil
}

func agentFromApplication(app *models.AIApplication) resolvedAgent {
	return resolvedAgent{
		agentName:       app.AgentID,
		projectName:     app.ProjectName,
		environmentName: app.EnvironmentName,
		resolution:      resolutionApplication,
	}
}

func agentFromIdentity(c *models.AgentThunderClient) resolvedAgent {
	return resolvedAgent{
		agentName:       c.AgentName,
		projectName:     c.ProjectName,
		environmentName: c.EnvironmentName,
		resolution:      resolutionAgentIdentity,
	}
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
