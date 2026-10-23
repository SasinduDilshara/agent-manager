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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories/repomocks"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// trafficLine renders one traffic-log line in the gateway's shape
// (publishers/traffic_log_event.go), with the given fields overriding a
// default LLM-proxy request.
func trafficLine(t *testing.T, override map[string]any) string {
	t.Helper()
	line := map[string]any{
		"component":     "pol",
		"timestamp":     "2026-10-20T09:15:02.481Z",
		"correlationId": "6f1c2a9e-corr",
		"status":        200,
		"api": map[string]any{
			"id": "0b7d4c1e-api", "name": "support-cfg-3fa9c1d2-proxy", "version": "v1.0",
			"context": "/support-cfg-3fa9c1d2-proxy", "kind": "LlmProxy",
		},
		"operation":   map[string]any{"method": "POST", "path": "/chat/completions"},
		"target":      map[string]any{"statusCode": 200, "destination": "api.openai.com"},
		"application": map[string]any{"id": "support-agent-9c41e0ab", "name": "support-agent", "keyType": "PRODUCTION"},
		"client":      map[string]any{"ip": "10.42.3.17", "userAgent": "python-httpx/0.27.0"},
		"latencies": map[string]any{
			"durationUs": 1834000, "requestMediationLatencyUs": 2100,
			"responseMediationLatencyUs": 900, "backendLatencyUs": 1820000,
		},
		// Headers are in the line when the gateway captures them; the feed must never read them.
		"requestHeaders": map[string]any{"authorization": "****", "x-raw": "Bearer sk-live-very-secret"},
		"requestBody":    `{"model":"gpt-4o","messages":[{"role":"user","content":"Where is my order 1182?"}]}`,
		"responseBody": `{"id":"chatcmpl-1","model":"gpt-4o-2024-08-06","choices":[{"message":{"content":"It ships today."}}],` +
			`"usage":{"prompt_tokens":1840,"completion_tokens":212,"total_tokens":2052}}`,
		"properties": map[string]any{"authType": "api-key"},
	}
	for k, v := range override {
		if v == nil {
			delete(line, k)
		} else {
			line[k] = v
		}
	}
	b, err := json.Marshal(line)
	require.NoError(t, err)
	return string(b)
}

func ndjson(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func newTrafficIngest(t *testing.T, sink audit.Sink, excerptBytes int) GatewayTrafficAuditIngestService {
	t.Helper()
	return NewGatewayTrafficAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, excerptBytes, discardLogger())
}

func TestTrafficAuditIngest_LLMCallIsRelayedWithAttribution(t *testing.T) {
	sink := &captureSink{}
	res, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway, ndjson(trafficLine(t, nil)))
	require.NoError(t, err)
	assert.Equal(t, 1, res.Accepted)

	got := sink.written()
	require.Len(t, got, 1)
	e := got[0]
	assert.Equal(t, audit.ActionLLMCall, e.Action)
	assert.Equal(t, audit.OpenChoreoProducerGatewayTrafficLog, e.Producer)
	assert.Equal(t, "ou-acme", e.OUID)
	assert.Equal(t, audit.ActorAgent, e.ActorType)
	assert.Equal(t, "support-agent", e.ActorID)
	assert.Equal(t, "support-agent", e.AgentName)
	assert.Equal(t, "customer-care", e.ProjectName)
	assert.Equal(t, audit.ResourceLLMProxy, e.ResourceType)
	assert.Equal(t, "support-cfg-3fa9c1d2-proxy", e.ResourceName)
	assert.Equal(t, "6f1c2a9e-corr", e.CorrelationID)
	assert.Equal(t, "/chat/completions", e.RequestPath, "the route template, which is all the traffic log has")
	assert.Equal(t, 200, e.StatusCode)
	assert.Equal(t, audit.OutcomeSuccess, e.Outcome)
	assert.Equal(t, int64(1834), e.DurationMs)
	assert.Equal(t, time.Date(2026, 10, 20, 9, 15, 2, 481000000, time.UTC), e.OccurredAt)

	d := e.Details
	assert.Equal(t, "gpt-4o", d["requestModel"])
	assert.Equal(t, "gpt-4o-2024-08-06", d["responseModel"])
	assert.Equal(t, int64(1840), d["inputTokens"])
	assert.Equal(t, int64(212), d["outputTokens"])
	assert.Equal(t, int64(2052), d["totalTokens"])
	assert.Equal(t, true, d["derivedFromBody"])
	assert.Equal(t, "PRODUCTION", d["applicationKeyType"])
	assert.Equal(t, "api-key", d["authType"])
	assert.Equal(t, int64(1820), d["backendLatencyMs"])
	assert.Equal(t, provenanceObserved, d["provenance"])
	assert.Equal(t, resolutionApplication, d["resolution"])
	assert.NotContains(t, d, "_droppedKeys", "every key is declared")

	// Neither a header nor any body text reaches the record without excerpts.
	raw, _ := json.Marshal(e)
	for _, leaked := range []string{"sk-live-very-secret", "Where is my order", "It ships today"} {
		assert.NotContains(t, string(raw), leaked)
	}
}

func TestTrafficAuditIngest_StreamedCompletionUsage(t *testing.T) {
	stream := "data: {\"model\":\"gpt-4o-2024-08-06\",\"choices\":[{\"delta\":{\"content\":\"It\"}}]}\n\n" +
		"data: {\"model\":\"gpt-4o-2024-08-06\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":7,\"total_tokens\":57}}\n\n" +
		"data: [DONE]\n\n"
	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway,
		ndjson(trafficLine(t, map[string]any{"responseBody": stream})))
	require.NoError(t, err)
	d := sink.written()[0].Details
	assert.Equal(t, int64(50), d["inputTokens"])
	assert.Equal(t, int64(7), d["outputTokens"])
	assert.Equal(t, "gpt-4o-2024-08-06", d["responseModel"])
}

func TestTrafficAuditIngest_AnthropicUsage(t *testing.T) {
	body := `{"model":"claude-sonnet-4","usage":{"input_tokens":120,"output_tokens":30}}`
	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway,
		ndjson(trafficLine(t, map[string]any{"responseBody": body})))
	require.NoError(t, err)
	d := sink.written()[0].Details
	assert.Equal(t, int64(120), d["inputTokens"])
	assert.Equal(t, int64(30), d["outputTokens"])
	assert.Equal(t, int64(150), d["totalTokens"], "summed when the provider reports no total")
}

func mcpLine(t *testing.T, requestBody, responseBody string) string {
	return trafficLine(t, map[string]any{
		"api": map[string]any{
			"id": "mcp-1", "name": "github-mcp", "version": "v1", "context": "/github-mcp", "kind": "Mcp",
		},
		"operation":    map[string]any{"method": "POST", "path": "/mcp"},
		"requestBody":  requestBody,
		"responseBody": responseBody,
	})
}

func TestTrafficAuditIngest_MCPToolCall(t *testing.T) {
	req := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_issue","arguments":{"title":"x"}}}`
	resp := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[],\"isError\":true}}\n\n"
	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway, ndjson(mcpLine(t, req, resp)))
	require.NoError(t, err)
	e := sink.written()[0]
	assert.Equal(t, audit.ActionMCPToolCall, e.Action)
	assert.Equal(t, audit.ResourceMCPProxy, e.ResourceType)
	assert.Equal(t, "tools/call", e.Details["mcpMethod"])
	assert.Equal(t, "create_issue", e.Details["toolName"])
	assert.Equal(t, true, e.Details["mcpError"], "a failed tool call answered with HTTP 200")
	assert.Equal(t, audit.SeverityWarning, e.Severity)
}

func TestTrafficAuditIngest_MCPOtherMethods(t *testing.T) {
	cases := []struct {
		request string
		action  audit.Action
		key     string
		value   string
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, audit.ActionMCPCall, "mcpMethod", "tools/list"},
		{`{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"triage"}}`, audit.ActionMCPCall, "promptName", "triage"},
		{
			`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"repo://wso2/issues"}}`,
			audit.ActionMCPCall, "resourceUri", "repo://wso2/issues",
		},
		{`[{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search"}}]`, audit.ActionMCPToolCall, "toolName", "search"},
	}
	for _, c := range cases {
		sink := &captureSink{}
		_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway,
			ndjson(mcpLine(t, c.request, `{"jsonrpc":"2.0","result":{}}`)))
		require.NoError(t, err)
		e := sink.written()[0]
		assert.Equal(t, c.action, e.Action, c.request)
		assert.Equal(t, c.value, e.Details[c.key], c.request)
		assert.NotContains(t, e.Details, "mcpError", c.request)
	}

	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway,
		ndjson(mcpLine(t, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"x"}}`,
			`{"jsonrpc":"2.0","id":9,"error":{"code":-32602,"message":"bad"}}`)))
	require.NoError(t, err)
	assert.Equal(t, true, sink.written()[0].Details["mcpError"], "a JSON-RPC error")
}

// TestTrafficAuditIngest_WithoutBodiesTheFeedHasNoLLMFields: what the traffic
// log gives when the gateway captures no bodies — the comparison with OTel.
func TestTrafficAuditIngest_WithoutBodiesTheFeedHasNoLLMFields(t *testing.T) {
	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway,
		ndjson(trafficLine(t, map[string]any{"requestBody": nil, "responseBody": nil})))
	require.NoError(t, err)
	e := sink.written()[0]
	assert.Equal(t, audit.ActionLLMCall, e.Action, "the API kind still names the call")
	for _, key := range []string{"requestModel", "responseModel", "inputTokens", "derivedFromBody"} {
		assert.NotContains(t, e.Details, key)
	}
	assert.Equal(t, "support-agent", e.AgentName, "attribution does not need bodies")
}

// TestTrafficAuditIngest_TruncatedBodyIsIgnored: max_payload_size can cut a
// body mid-JSON; the record is kept without the fields.
func TestTrafficAuditIngest_TruncatedBodyIsIgnored(t *testing.T) {
	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway,
		ndjson(trafficLine(t, map[string]any{"requestBody": `{"model":"gpt-4o","messa`, "responseBody": `{"usage":{"prompt_tok`})))
	require.NoError(t, err)
	got := sink.written()
	require.Len(t, got, 1)
	assert.NotContains(t, got[0].Details, "requestModel")
	assert.NotContains(t, got[0].Details, "inputTokens")
}

func TestTrafficAuditIngest_BodyExcerptsAreOptIn(t *testing.T) {
	line := trafficLine(t, map[string]any{
		"requestBody": `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("é", 40) +
			` key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"}]}`,
	})

	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway, ndjson(line))
	require.NoError(t, err)
	assert.NotContains(t, sink.written()[0].Details, "requestBodyExcerpt", "off unless configured")

	sink = &captureSink{}
	_, err = newTrafficIngest(t, sink, 4096).Ingest(auditableCtx(t), acmeGateway, ndjson(line))
	require.NoError(t, err)
	d := sink.written()[0].Details
	req, _ := d["requestBodyExcerpt"].(string)
	assert.Contains(t, req, `"model":"gpt-4o"`)
	assert.NotContains(t, req, "abcdefghijklmnopqrstuvwxyz0123456789", "credential-shaped text is masked")
	assert.Contains(t, d["responseBodyExcerpt"], "It ships today.")
	assert.NotContains(t, d, "bodyExcerptTruncated")

	sink = &captureSink{}
	_, err = newTrafficIngest(t, sink, 41).Ingest(auditableCtx(t), acmeGateway, ndjson(line))
	require.NoError(t, err)
	d = sink.written()[0].Details
	cut, _ := d["requestBodyExcerpt"].(string)
	assert.LessOrEqual(t, len(cut), 41)
	assert.True(t, strings.HasPrefix(cut, `{"model":"gpt-4o","messages"`))
	assert.Equal(t, true, d["bodyExcerptTruncated"])
	assert.True(t, json.Valid([]byte(`"`+strings.ReplaceAll(cut, `"`, `\"`)+`"`)), "cut on a UTF-8 boundary")
}

// TestTrafficAuditIngest_SubjectNamesTheAgent: on AgentID-authenticated routes
// the agent comes from the token subject, which the chart puts in properties.
func TestTrafficAuditIngest_SubjectNamesTheAgent(t *testing.T) {
	identities := &repomocks.AgentThunderClientRepositoryMock{
		FindByThunderIdentityFunc: func(_ context.Context, ouID, subject string) (*models.AgentThunderClient, error) {
			require.Equal(t, "ou-acme", ouID)
			require.Equal(t, "agent-sub-1", subject)
			return &models.AgentThunderClient{AgentName: "billing-agent", ProjectName: "finance", EnvironmentName: "default"}, nil
		},
	}
	sink := &captureSink{}
	svc := NewGatewayTrafficAuditIngestService(sink, supportAgentApps(t), identities, time.Minute, 0, discardLogger())
	_, err := svc.Ingest(auditableCtx(t), acmeGateway, ndjson(trafficLine(t, map[string]any{
		"application": nil,
		"properties":  map[string]any{"authSubject": "agent-sub-1", "authType": "jwt"},
	})))
	require.NoError(t, err)
	e := sink.written()[0]
	assert.Equal(t, "billing-agent", e.AgentName)
	assert.Equal(t, resolutionAgentIdentity, e.Details["resolution"])
	assert.Equal(t, "agent-sub-1", e.Details["authSubject"])
}

func TestTrafficAuditIngest_UnresolvedCallerIsAnonymous(t *testing.T) {
	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway, ndjson(trafficLine(t, map[string]any{
		"application": nil, "properties": nil, "status": 401,
	})))
	require.NoError(t, err)
	e := sink.written()[0]
	assert.Equal(t, audit.ActorAnonymous, e.ActorType)
	assert.Equal(t, resolutionUnresolved, e.Details["resolution"])
	assert.Equal(t, audit.SeverityWarning, e.Severity)
	assert.Equal(t, audit.OutcomeDeny, e.Outcome)
}

func TestTrafficAuditIngest_BadLinesAreCountedNotFatal(t *testing.T) {
	sink := &captureSink{}
	res, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway, ndjson(
		trafficLine(t, nil),
		`{"timestamp":"yesterday"}`,
		`not json`,
		"",
	))
	require.NoError(t, err)
	assert.Equal(t, 1, res.Accepted)
	assert.Equal(t, 2, res.Rejected)
	assert.Equal(t, map[string]int{rejectTrafficTimestamp: 1, rejectMalformedLine: 1}, res.RejectReasons)
	assert.Len(t, sink.written(), 1)
}

func TestTrafficAuditIngest_AWholeBatchOfGarbageIsMalformed(t *testing.T) {
	_, err := newTrafficIngest(t, &captureSink{}, 0).Ingest(auditableCtx(t), acmeGateway, ndjson("nope", "[1,2]"))
	require.ErrorIs(t, err, utils.ErrMalformedAuditBatch)

	res, err := newTrafficIngest(t, &captureSink{}, 0).Ingest(auditableCtx(t), acmeGateway, []byte("\n\n"))
	require.NoError(t, err, "an empty batch is not an error")
	assert.Zero(t, res.Accepted)
}

func TestTrafficAuditIngest_UnwritableBatchIsRetried(t *testing.T) {
	_, err := newTrafficIngest(t, &captureSink{err: errors.New("disk full")}, 0).
		Ingest(auditableCtx(t), acmeGateway, ndjson(trafficLine(t, nil)))
	require.ErrorIs(t, err, utils.ErrAuditIngestUnavailable)
}

// TestTrafficAuditIngest_IdsAreDeterministicAndFeedSpecific: a resent line
// keeps its id, and the two feeds never share one.
func TestTrafficAuditIngest_IdsAreDeterministicAndFeedSpecific(t *testing.T) {
	line := trafficLine(t, nil)
	sink := &captureSink{}
	svc := newTrafficIngest(t, sink, 0)
	_, err := svc.Ingest(auditableCtx(t), acmeGateway, ndjson(line))
	require.NoError(t, err)
	_, err = svc.Ingest(auditableCtx(t), acmeGateway, ndjson(line))
	require.NoError(t, err)
	got := sink.written()
	require.Len(t, got, 2)
	assert.Equal(t, got[0].EventID, got[1].EventID)

	other := GatewayAuditCaller{GatewayID: "gw-2", OUID: "ou-acme"}
	_, err = svc.Ingest(auditableCtx(t), other, ndjson(line))
	require.NoError(t, err)
	assert.NotEqual(t, got[0].EventID, sink.written()[2].EventID, "another gateway's identical line is another record")
	assert.NotEqual(t, trafficEventNamespace, observedEventNamespace)
}

func TestTrafficAuditIngest_RequiresACaller(t *testing.T) {
	_, err := newTrafficIngest(t, &captureSink{}, 0).Ingest(auditableCtx(t), GatewayAuditCaller{}, ndjson(trafficLine(t, nil)))
	require.Error(t, err)
}

// TestOTelAuditIngest_BodyExcerptsAreOptIn: the OTel feed keeps the bodies the
// publisher sends only when configured, like the traffic-log feed.
func TestOTelAuditIngest_BodyExcerptsAreOptIn(t *testing.T) {
	sink := &captureSink{}
	svc := NewGatewayAuditIngestService(sink, supportAgentApps(t), noIdentities(), time.Minute, 4096, discardLogger())
	_, err := svc.Ingest(auditableCtx(t), acmeGateway, otlpBatch(gatewayAnalyticsScope, llmCallRecord()))
	require.NoError(t, err)
	d := sink.written()[0].Details
	assert.Contains(t, d["requestBodyExcerpt"], "my card is 4111")
	assert.Equal(t, `{"choices":[]}`, d["responseBodyExcerpt"])
	assert.Equal(t, audit.OpenChoreoProducerGatewayOTel, sink.written()[0].Producer)
	raw, _ := json.Marshal(sink.written()[0])
	assert.NotContains(t, string(raw), "sk-live-very-secret", "headers are never read")
}

func llmUsageOf(t *testing.T, responseBody string) map[string]any {
	t.Helper()
	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway,
		ndjson(trafficLine(t, map[string]any{"responseBody": responseBody})))
	require.NoError(t, err)
	return sink.written()[0].Details
}

// TestTrafficAuditIngest_AnthropicStream: input tokens and the model arrive in
// message_start, output tokens in a later message_delta.
func TestTrafficAuditIngest_AnthropicStream(t *testing.T) {
	stream := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4","usage":{"input_tokens":412,"output_tokens":1}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":58}}` + "\n\n" +
		"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"
	d := llmUsageOf(t, stream)
	assert.Equal(t, "claude-sonnet-4", d["responseModel"])
	assert.Equal(t, int64(412), d["inputTokens"], "kept from message_start")
	assert.Equal(t, int64(58), d["outputTokens"], "replaced by message_delta")
	assert.Equal(t, int64(470), d["totalTokens"])
}

// TestTrafficAuditIngest_ResponsesAPIStream: the OpenAI Responses API reports
// usage under response in its response.completed event.
func TestTrafficAuditIngest_ResponsesAPIStream(t *testing.T) {
	stream := `data: {"type":"response.output_text.delta","delta":"Hi"}` + "\n\n" +
		`data: {"type":"response.completed","response":{"model":"gpt-4.1","usage":{"input_tokens":30,"output_tokens":9,"total_tokens":39}}}` + "\n\n"
	d := llmUsageOf(t, stream)
	assert.Equal(t, "gpt-4.1", d["responseModel"])
	assert.Equal(t, int64(30), d["inputTokens"])
	assert.Equal(t, int64(39), d["totalTokens"])
}

// TestTrafficAuditIngest_MultiLineSSEData: an event's data may span several
// data: lines, joined by newlines.
func TestTrafficAuditIngest_MultiLineSSEData(t *testing.T) {
	stream := "data: {\"model\":\"gpt-4o\",\n" + "data: \"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n\n"
	d := llmUsageOf(t, stream)
	assert.Equal(t, "gpt-4o", d["responseModel"])
	assert.Equal(t, int64(5), d["inputTokens"])
}

// TestTrafficAuditIngest_MCPBatchReplyError: an error inside a JSON-RPC batch
// reply is still flagged.
func TestTrafficAuditIngest_MCPBatchReplyError(t *testing.T) {
	sink := &captureSink{}
	_, err := newTrafficIngest(t, sink, 0).Ingest(auditableCtx(t), acmeGateway, ndjson(mcpLine(t,
		`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}]`,
		`[{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"down"}}]`)))
	require.NoError(t, err)
	assert.Equal(t, true, sink.written()[0].Details["mcpError"])
}
