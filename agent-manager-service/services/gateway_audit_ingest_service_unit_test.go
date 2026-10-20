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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	"github.com/wso2/agent-manager/agent-manager-service/repositories/repomocks"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// captureSink records what a sink was asked to write.
type captureSink struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (s *captureSink) Name() string { return "capture" }

func (s *captureSink) Write(_ context.Context, events []audit.Event) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	return nil
}

func (s *captureSink) written() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

// otlpAttr renders one OTLP attribute in the publisher's proto3-JSON shape.
func otlpAttr(key string, value any) string {
	switch v := value.(type) {
	case string:
		return fmt.Sprintf(`{"key":%q,"value":{"stringValue":%q}}`, key, v)
	case int:
		return fmt.Sprintf(`{"key":%q,"value":{"intValue":"%d"}}`, key, v)
	case float64:
		return fmt.Sprintf(`{"key":%q,"value":{"doubleValue":%v}}`, key, v)
	case bool:
		return fmt.Sprintf(`{"key":%q,"value":{"boolValue":%v}}`, key, v)
	case []string:
		vals := make([]string, 0, len(v))
		for _, s := range v {
			vals = append(vals, fmt.Sprintf(`{"stringValue":%q}`, s))
		}
		return fmt.Sprintf(`{"key":%q,"value":{"arrayValue":{"values":[%s]}}}`, key, strings.Join(vals, ","))
	default:
		panic(fmt.Sprintf("unsupported attribute type %T", value))
	}
}

// otlpRecord renders one wso2.api.transaction log record.
func otlpRecord(timeNanos int64, attrs ...string) string {
	all := append([]string{otlpAttr("event.name", gatewayAnalyticsEvent)}, attrs...)
	return fmt.Sprintf(`{"timeUnixNano":"%d","observedTimeUnixNano":"%d","severityNumber":9,`+
		`"severityText":"INFO","eventName":%q,"body":{"stringValue":"POST /chat/completions"},"attributes":[%s]}`,
		timeNanos, timeNanos+1000, gatewayAnalyticsEvent, strings.Join(all, ","))
}

// otlpBatch wraps records in an export request under the given scope.
func otlpBatch(scope string, records ...string) []byte {
	return []byte(fmt.Sprintf(`{"resourceLogs":[{"resource":{"attributes":[%s]},`+
		`"scopeLogs":[{"scope":{"name":%q},"logRecords":[%s]}]}]}`,
		otlpAttr("service.name", "wso2-api-platform-gateway"), scope, strings.Join(records, ",")))
}

var testRequestTime = time.Date(2026, 10, 20, 9, 15, 2, 481000000, time.UTC)

func llmCallRecord(extra ...string) string {
	attrs := []string{
		otlpAttr("http.request.method", "POST"),
		otlpAttr("url.path", "/support-cfg-3fa9c1d2-proxy/chat/completions"),
		otlpAttr("http.route", "/chat/completions"),
		otlpAttr("http.response.status_code", 200),
		otlpAttr("client.address", "10.42.3.17"),
		otlpAttr("user_agent.original", "python-httpx/0.27.0"),
		otlpAttr("wso2.api.id", "0b7d4c1e-api"),
		otlpAttr("wso2.api.name", "support-cfg-3fa9c1d2-proxy"),
		otlpAttr("wso2.api.type", "LlmProxy"),
		otlpAttr("wso2.application.id", "support-agent-9c41e0ab"),
		otlpAttr("wso2.correlation.id", "6f1c2a9e-corr"),
		otlpAttr("gen_ai.provider.name", "openai"),
		otlpAttr("gen_ai.request.model", "gpt-4o"),
		otlpAttr("gen_ai.response.model", "gpt-4o-2024-08-06"),
		otlpAttr("gen_ai.usage.input_tokens", 1840),
		otlpAttr("gen_ai.usage.output_tokens", 212),
		otlpAttr("wso2.gen_ai.cost.total", 0.0067),
		otlpAttr("wso2.latency.duration_ms", 1834),
		otlpAttr("server.address", "api.openai.com"),
		// Captured content and credentials the ingest must never read.
		otlpAttr("http.request.header.api-key", []string{"sk-live-very-secret"}),
		otlpAttr("http.request.header.authorization", []string{"Bearer eyJhbGciOi"}),
		otlpAttr("wso2.request.body", `{"messages":[{"role":"user","content":"my card is 4111"}]}`),
		otlpAttr("wso2.response.body", `{"choices":[]}`),
	}
	return otlpRecord(testRequestTime.UnixNano(), append(attrs, extra...)...)
}

func supportAgentApps(t *testing.T) *repomocks.AIApplicationRepositoryMock {
	t.Helper()
	return &repomocks.AIApplicationRepositoryMock{
		GetByHandleFunc: func(_ context.Context, ouID, handle string) (*models.AIApplication, error) {
			if ouID == "ou-acme" && handle == "support-agent-9c41e0ab" {
				return &models.AIApplication{
					Handle: handle, AgentID: "support-agent", ProjectName: "customer-care",
					EnvironmentName: "default", OUID: ouID,
				}, nil
			}
			return nil, gorm.ErrRecordNotFound
		},
	}
}

func noIdentities() *repomocks.AgentThunderClientRepositoryMock {
	return &repomocks.AgentThunderClientRepositoryMock{
		FindByThunderIdentityFunc: func(_ context.Context, _, _ string) (*models.AgentThunderClient, error) {
			return nil, repositories.ErrAgentThunderClientNotFound
		},
	}
}

var acmeGateway = GatewayAuditCaller{GatewayID: "gw-1", OUID: "ou-acme"}

func TestGatewayAuditIngest_LLMCallIsRelayedWithAttribution(t *testing.T) {
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, discardLogger())

	res, err := svc.Ingest(context.Background(), acmeGateway, otlpBatch(gatewayAnalyticsScope, llmCallRecord()))
	require.NoError(t, err)
	assert.Equal(t, 1, res.Accepted)
	assert.Zero(t, res.Rejected)

	got := sink.written()
	require.Len(t, got, 1)
	e := got[0]
	assert.Equal(t, audit.ActionLLMCall, e.Action)
	assert.Equal(t, audit.ClassActivity, e.ActionClass)
	assert.Equal(t, audit.SurfaceGateway, e.Surface)
	assert.Equal(t, audit.OutcomeSuccess, e.Outcome)
	assert.Equal(t, testRequestTime, e.OccurredAt, "the time the gateway received the request")
	// Tenant from the gateway's credential, agent from the org-scoped lookup.
	assert.Equal(t, "ou-acme", e.OUID)
	assert.Equal(t, audit.ActorAgent, e.ActorType)
	assert.Equal(t, "support-agent", e.ActorID)
	assert.Equal(t, "support-agent", e.AgentName)
	assert.Equal(t, "customer-care", e.ProjectName)
	assert.Equal(t, "default", e.Environment)
	assert.Equal(t, audit.ResourceLLMProxy, e.ResourceType)
	assert.Equal(t, "support-cfg-3fa9c1d2-proxy", e.ResourceName)
	assert.Equal(t, "6f1c2a9e-corr", e.CorrelationID)
	assert.Equal(t, "10.42.3.17", e.SourceIP)
	assert.Equal(t, 200, e.StatusCode)
	assert.Equal(t, int64(1834), e.DurationMs)

	d := e.Details
	assert.Equal(t, "gw-1", d["gatewayId"])
	assert.Equal(t, provenanceObserved, d["provenance"])
	assert.Equal(t, resolutionApplication, d["resolution"])
	assert.Equal(t, "openai", d["provider"])
	assert.Equal(t, "gpt-4o", d["requestModel"])
	assert.Equal(t, "gpt-4o-2024-08-06", d["responseModel"])
	assert.Equal(t, int64(1840), d["inputTokens"])
	assert.Equal(t, int64(212), d["outputTokens"])
	assert.InDelta(t, 0.0067, d["costUsd"], 1e-9)
	assert.Equal(t, "api.openai.com", d["upstreamHost"])
	assert.NotContains(t, d, "_droppedKeys", "every detail the ingest writes is declared")
}

// TestGatewayAuditIngest_NeverRecordsHeadersOrBodies is the reason the
// attribute mapping is an allowlist: the gateway may have captured credential
// headers and prompts, and none of it may reach the trail in any field.
func TestGatewayAuditIngest_NeverRecordsHeadersOrBodies(t *testing.T) {
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, discardLogger())
	_, err := svc.Ingest(context.Background(), acmeGateway, otlpBatch(gatewayAnalyticsScope, llmCallRecord()))
	require.NoError(t, err)

	raw, err := json.Marshal(sink.written())
	require.NoError(t, err)
	for _, leaked := range []string{"sk-live-very-secret", "eyJhbGciOi", "4111", "messages", "choices"} {
		assert.NotContains(t, string(raw), leaked)
	}
}

func TestGatewayAuditIngest_MCPToolCallResolvedByAgentIdentity(t *testing.T) {
	identities := &repomocks.AgentThunderClientRepositoryMock{
		FindByThunderIdentityFunc: func(_ context.Context, ouID, subject string) (*models.AgentThunderClient, error) {
			if ouID == "ou-acme" && subject == "agent-client-77" {
				return &models.AgentThunderClient{
					OUID: ouID, ProjectName: "customer-care", AgentName: "refund-agent", EnvironmentName: "default",
				}, nil
			}
			return nil, repositories.ErrAgentThunderClientNotFound
		},
	}
	// AgentID-authenticated routes carry no application id.
	apps := &repomocks.AIApplicationRepositoryMock{}
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, apps, identities, time.Minute, discardLogger())

	rec := otlpRecord(testRequestTime.UnixNano(),
		otlpAttr("http.response.status_code", 200),
		otlpAttr("wso2.api.name", "billing-mcp"),
		otlpAttr("wso2.api.type", "Mcp"),
		otlpAttr("user.id", "agent-client-77"),
		otlpAttr("mcp.method.name", "tools/call"),
		otlpAttr("mcp.session.id", "c0a8-sess"),
		otlpAttr("gen_ai.tool.name", "issue_refund"),
	)
	_, err := svc.Ingest(context.Background(), acmeGateway, otlpBatch(gatewayAnalyticsScope, rec))
	require.NoError(t, err)

	got := sink.written()
	require.Len(t, got, 1)
	e := got[0]
	assert.Equal(t, audit.ActionMCPToolCall, e.Action)
	assert.Equal(t, audit.ResourceMCPProxy, e.ResourceType)
	assert.Equal(t, "refund-agent", e.ActorID)
	assert.Equal(t, resolutionAgentIdentity, e.Details["resolution"])
	assert.Equal(t, "issue_refund", e.Details["toolName"])
	assert.Equal(t, "tools/call", e.Details["mcpMethod"])
	assert.Equal(t, "agent-client-77", e.Details["authSubject"])
	assert.Empty(t, apps.GetByHandleCalls(), "no application id, so no application lookup")
}

// TestGatewayAuditIngest_ForeignApplicationDoesNotResolve: lookups are scoped
// to the delivering gateway's organization, so a request naming another
// organization's application is recorded unresolved, under the gateway's org.
func TestGatewayAuditIngest_ForeignApplicationDoesNotResolve(t *testing.T) {
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, discardLogger())
	other := GatewayAuditCaller{GatewayID: "gw-2", OUID: "ou-globex"}

	_, err := svc.Ingest(context.Background(), other, otlpBatch(gatewayAnalyticsScope, llmCallRecord()))
	require.NoError(t, err)
	got := sink.written()
	require.Len(t, got, 1)
	assert.Equal(t, "ou-globex", got[0].OUID)
	assert.Equal(t, audit.ActorAnonymous, got[0].ActorType)
	assert.Empty(t, got[0].ActorID)
	assert.Empty(t, got[0].AgentName)
	assert.Equal(t, resolutionUnresolved, got[0].Details["resolution"])
	assert.Equal(t, "support-agent-9c41e0ab", got[0].Details["applicationId"], "the raw id is kept for investigation")
}

func TestGatewayAuditIngest_DeniedAndGuardrailOutcomes(t *testing.T) {
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, discardLogger())

	denied := otlpRecord(testRequestTime.UnixNano(), otlpAttr("http.response.status_code", 403), otlpAttr("wso2.api.type", "Mcp"))
	blocked := otlpRecord(testRequestTime.UnixNano()+1, otlpAttr("http.response.status_code", 422),
		otlpAttr("wso2.api.type", "LlmProxy"), otlpAttr("wso2.guardrail.hit", true),
		otlpAttr("wso2.guardrail.name", "pii-masking"))
	noStatus := otlpRecord(testRequestTime.UnixNano()+2, otlpAttr("wso2.api.type", "LlmProxy"))
	failed := otlpRecord(testRequestTime.UnixNano()+3, otlpAttr("http.response.status_code", 502), otlpAttr("wso2.api.type", "Agent"))

	_, err := svc.Ingest(context.Background(), acmeGateway, otlpBatch(gatewayAnalyticsScope, denied, blocked, noStatus, failed))
	require.NoError(t, err)
	got := sink.written()
	require.Len(t, got, 4)

	assert.Equal(t, audit.OutcomeDeny, got[0].Outcome)
	assert.Equal(t, audit.SeverityWarning, got[0].Severity)
	assert.Equal(t, audit.ActionMCPCall, got[0].Action, "not tools/call")

	assert.Equal(t, audit.OutcomeDeny, got[1].Outcome, "a guardrail block is a refusal")
	assert.Equal(t, true, got[1].Details["guardrailHit"])
	assert.Equal(t, "pii-masking", got[1].Details["guardrailName"])

	assert.Equal(t, audit.OutcomeFailure, got[2].Outcome, "no recorded status is not a success")

	assert.Equal(t, audit.OutcomeFailure, got[3].Outcome)
	assert.Equal(t, audit.ActionAgentInvoke, got[3].Action)
}

// TestGatewayAuditIngest_RedeliveryYieldsTheSameEventID: the gateway resends a
// batch it was not acknowledged for; the copy must be recognisable as one.
func TestGatewayAuditIngest_RedeliveryYieldsTheSameEventID(t *testing.T) {
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, discardLogger())
	batch := otlpBatch(gatewayAnalyticsScope, llmCallRecord())

	_, err := svc.Ingest(context.Background(), acmeGateway, batch)
	require.NoError(t, err)
	_, err = svc.Ingest(context.Background(), acmeGateway, batch)
	require.NoError(t, err)

	got := sink.written()
	require.Len(t, got, 2)
	assert.Equal(t, got[0].EventID, got[1].EventID)

	// A different gateway reporting identical bytes is a different event.
	_, err = svc.Ingest(context.Background(), GatewayAuditCaller{GatewayID: "gw-9", OUID: "ou-acme"}, batch)
	require.NoError(t, err)
	assert.NotEqual(t, got[0].EventID, sink.written()[2].EventID)
}

func TestGatewayAuditIngest_RejectsRecordsItCannotAccept(t *testing.T) {
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, discardLogger())

	otherEvent := strings.ReplaceAll(llmCallRecord(), gatewayAnalyticsEvent, "some.other.event")
	badTime := strings.Replace(llmCallRecord(), fmt.Sprintf(`"timeUnixNano":"%d"`, testRequestTime.UnixNano()),
		`"timeUnixNano":"not-a-number"`, 1)
	batch := []byte(fmt.Sprintf(`{"resourceLogs":[{"scopeLogs":[`+
		`{"scope":{"name":"some.other.scope"},"logRecords":[%s]},`+
		`{"scope":{"name":%q},"logRecords":[%s,%s,%s]}]}]}`,
		llmCallRecord(), gatewayAnalyticsScope, llmCallRecord(), otherEvent, badTime))

	res, err := svc.Ingest(auditableCtx(t), acmeGateway, batch)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Accepted)
	assert.Equal(t, 3, res.Rejected)
	assert.Equal(t, map[string]int{
		rejectUnexpectedScope: 1, rejectUnexpectedEvent: 1, rejectBadTimestamp: 1,
	}, res.RejectReasons)
	assert.Len(t, sink.written(), 1)
}

func TestGatewayAuditIngest_MalformedBatch(t *testing.T) {
	svc := NewGatewayAuditIngestService(&captureSink{}, supportAgentApps(t), noIdentities(), time.Minute, discardLogger())
	_, err := svc.Ingest(context.Background(), acmeGateway, []byte("not json"))
	require.ErrorIs(t, err, utils.ErrMalformedAuditBatch)
}

// TestGatewayAuditIngest_LookupFailureAsksForRedelivery: writing the batch
// without its agents would lose attribution for good, so the whole batch is
// refused as unavailable — which the gateway resends — and nothing is written.
func TestGatewayAuditIngest_LookupFailureAsksForRedelivery(t *testing.T) {
	apps := &repomocks.AIApplicationRepositoryMock{
		GetByHandleFunc: func(_ context.Context, _, _ string) (*models.AIApplication, error) {
			return nil, errors.New("connection refused")
		},
	}
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, apps, noIdentities(), time.Minute, discardLogger())

	_, err := svc.Ingest(context.Background(), acmeGateway, otlpBatch(gatewayAnalyticsScope, llmCallRecord()))
	require.ErrorIs(t, err, utils.ErrAuditIngestUnavailable)
	assert.NotErrorIs(t, err, utils.ErrMalformedAuditBatch)
	assert.Empty(t, sink.written())
}

func TestGatewayAuditIngest_SinkFailureAsksForRedelivery(t *testing.T) {
	sink := &captureSink{err: errors.New("stdout closed")}
	svc := NewGatewayAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, discardLogger())
	_, err := svc.Ingest(context.Background(), acmeGateway, otlpBatch(gatewayAnalyticsScope, llmCallRecord()))
	require.ErrorIs(t, err, utils.ErrAuditIngestUnavailable)
}

func TestGatewayAuditIngest_ResolverCachesHitsAndMisses(t *testing.T) {
	apps := supportAgentApps(t)
	svc := NewGatewayAuditIngestService(&captureSink{}, apps, noIdentities(), time.Minute, discardLogger())
	unknown := strings.Replace(llmCallRecord(), "support-agent-9c41e0ab", "ghost-app", 1)
	batch := otlpBatch(gatewayAnalyticsScope, llmCallRecord(), llmCallRecord(), unknown, unknown)

	_, err := svc.Ingest(context.Background(), acmeGateway, batch)
	require.NoError(t, err)
	assert.Len(t, apps.GetByHandleCalls(), 2, "one lookup per distinct application, miss included")
}

func TestClassifyGatewayRequest(t *testing.T) {
	cases := []struct {
		kind, method string
		action       audit.Action
		resource     string
	}{
		{"LlmProxy", "", audit.ActionLLMCall, audit.ResourceLLMProxy},
		{"LlmProvider", "", audit.ActionLLMCall, audit.ResourceLLMProvider},
		{"Mcp", "tools/call", audit.ActionMCPToolCall, audit.ResourceMCPProxy},
		{"Mcp", "tools/list", audit.ActionMCPCall, audit.ResourceMCPProxy},
		{"Agent", "", audit.ActionAgentInvoke, audit.ResourceAgent},
		{"RestApi", "", audit.ActionAPICall, audit.ResourceAPI},
		{"", "", audit.ActionAPICall, audit.ResourceAPI},
	}
	for _, c := range cases {
		action, resource := classifyGatewayRequest(c.kind, c.method)
		assert.Equal(t, c.action, action, "%s %s", c.kind, c.method)
		assert.Equal(t, c.resource, resource, "%s %s", c.kind, c.method)
	}
}
