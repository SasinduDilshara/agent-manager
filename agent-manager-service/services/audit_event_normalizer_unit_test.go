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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type wantGatewayEvent struct {
	ua        string // client.userAgent tail, identifies the fixture case
	category  string
	action    string
	outcome   string
	agent     string // "project/name", "" for none
	actorType string
	actorID   string
	obo       bool
}

const (
	ext = "default/ext-audit-agent"
	in  = "default/int-audit-agent"
	a2a = "default/a2a-notes-agent"
)

// gatewayFixtureExpectations lists, in file order, what each live gateway line
// in testdata/audit/gateway_traffic.ndjson must normalise to.
var gatewayFixtureExpectations = []wantGatewayEvent{
	{"E01-llm-chat-ok", "LLM", "llm:chat", "SUCCESS", ext, "ANONYMOUS", "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89", false},
	{"E02-llm-stream-ok", "LLM", "llm:chat", "SUCCESS", ext, "ANONYMOUS", "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89", false},
	{"E03-llm-wrong-key", "LLM", "llm:chat", "DENIED", ext, "ANONYMOUS", "", false},
	{"E04-llm-no-key", "LLM", "llm:chat", "DENIED", ext, "ANONYMOUS", "", false},
	{"E05-llm-request-guardrail", "LLM", "llm:chat", "DENIED", ext, "ANONYMOUS", "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89", false},
	{"E06-llm-upstream-404", "LLM", "llm:chat", "FAILED", ext, "ANONYMOUS", "hmac-sha256:530040166dd782088ff3066f7c32eaa3a1871c319d6406888553e2e5517e6a89", false},
	// A response guardrail fires after the upstream answered 200: still denied.
	{"E07-llm-response-guardrail", "LLM", "llm:chat", "DENIED", ext, "ANONYMOUS", "hmac-sha256:d05ed0f137247237e03600f01fd9f68d23f0cd1a4a0baf43cfd1cc60cf786aec", false},
	{"E08-mcp-initialize", "MCP", "mcp:initialize", "SUCCESS", ext, "AGENT", auditTestExtAgentID, false},
	{"E09-mcp-initialized-notification", "MCP", "mcp:notifications/initialized", "SUCCESS", ext, "AGENT", auditTestExtAgentID, false},
	{"E10-mcp-tools-list", "MCP", "mcp:tools/list", "SUCCESS", ext, "AGENT", auditTestExtAgentID, false},
	{"E11-mcp-tools-call-echo-ok", "MCP", "mcp:tools/call", "SUCCESS", ext, "AGENT", auditTestExtAgentID, false},
	{"E12-mcp-tools-call-denied-scope", "MCP", "mcp:tools/call", "DENIED", ext, "AGENT", auditTestExtAgentID, false},
	{"E13-mcp-no-token", "MCP", "mcp:tools/call", "DENIED", "", "ANONYMOUS", "", false},
	{"E14-mcp-obo-initialize", "MCP", "mcp:initialize", "SUCCESS", ext, "AGENT", auditTestExtAgentID, true},
	{"E15-mcp-obo-tools-call-echo-ok", "MCP", "mcp:tools/call", "SUCCESS", ext, "AGENT", auditTestExtAgentID, true},
	{"E16-mcp-obo-tools-call-denied", "MCP", "mcp:tools/call", "DENIED", ext, "AGENT", auditTestExtAgentID, true},
	{"E17-otel-ok", "OTHER", "telemetry:export", "SUCCESS", ext, "AGENT", "ext-audit-agent", false},
	{"E18-otel-bad-token", "OTHER", "telemetry:export", "DENIED", "", "ANONYMOUS", "", false},
	// Ingress to an agent: the agent is the one being called.
	{"I01-agent-endpoint-ok", "OTHER", "agent:invoke", "SUCCESS", in, "ANONYMOUS", "hmac-sha256:dc59deec57cec11e2e3c4466e2f7b396f1b56f68c9be51ac579a5cc52abd9da3", false},
	{"I02-agent-endpoint-no-key", "OTHER", "agent:invoke", "DENIED", in, "ANONYMOUS", "", false},
	{"I03-internal-llm-chat-ok", "LLM", "llm:chat", "SUCCESS", in, "ANONYMOUS", "hmac-sha256:75d34b2dd06f37023f4d98d6fb9a1b850a99ed92b7eb8f6dfe59d5ad0d96f412", false},
	{"I04-internal-mcp-agentid-echo-ok-init", "MCP", "mcp:initialize", "SUCCESS", in, "AGENT", auditTestIntAgentID, false},
	{"I04-internal-mcp-agentid-echo-ok", "MCP", "mcp:tools/call", "SUCCESS", in, "AGENT", auditTestIntAgentID, false},
	{"I05-internal-otel-ok", "OTHER", "telemetry:export", "SUCCESS", in, "AGENT", "int-audit-agent", false},
	{"A01-a2a-agent-card", "A2A", "a2a:agentCard", "SUCCESS", a2a, "ANONYMOUS", "", false},
	{"A02-a2a-sendmessage-ok", "A2A", "a2a:SendMessage", "SUCCESS", a2a, "ANONYMOUS", "hmac-sha256:a16ffa5d2298826af22e9e77d220201aa5be31e9010295913fe836c377d03094", false},
	{"A03-a2a-no-key", "A2A", "a2a:SendMessage", "DENIED", a2a, "ANONYMOUS", "", false},
}

func TestNormalizeAuditDocument_LiveGatewayLines(t *testing.T) {
	idx := auditTestIndex(t)
	docs := loadGatewayFixture(t)
	require.Len(t, docs, len(gatewayFixtureExpectations))

	for i, doc := range docs {
		want := gatewayFixtureExpectations[i]
		t.Run(want.ua, func(t *testing.T) {
			ua := docString(doc, "client", "userAgent")
			require.Equal(t, "audit-lab/after/"+want.ua, ua, "fixture order changed")

			e := normalizeAuditDocument("doc-id", doc, idx)
			assert.Equal(t, docString(doc, "eventId"), e.Id)
			assert.Equal(t, "GATEWAY", e.Source)
			assert.Equal(t, want.category, string(e.Category))
			assert.Equal(t, want.action, e.Action)
			assert.Equal(t, want.outcome, string(e.Outcome))
			assert.Equal(t, want.actorType, e.Actor.Type)
			assert.Equal(t, want.actorID, e.Actor.Id)
			assert.NotEmpty(t, e.Summary)
			assert.Equal(t, docString(doc, "correlationId"), e.CorrelationId)
			assert.Equal(t, "default", e.Environment)
			require.NotNil(t, e.Gateway.Get())
			assert.Equal(t, "default", e.Gateway.Get().Organization)
			assert.Equal(t, doc, e.Raw)

			ts, err := time.Parse(time.RFC3339Nano, docString(doc, "timestamp"))
			require.NoError(t, err)
			assert.True(t, ts.Equal(e.Timestamp))

			status, _ := docInt(doc, "status")
			require.NotNil(t, e.StatusCode.Get())
			assert.Equal(t, int32(status), *e.StatusCode.Get())

			if want.agent == "" {
				assert.Nil(t, e.Agent.Get())
			} else {
				require.NotNil(t, e.Agent.Get())
				assert.Equal(t, want.agent, e.Agent.Get().Project+"/"+e.Agent.Get().Name)
				assert.Equal(t, e.Agent.Get().Project, e.Project)
			}

			if want.obo {
				obo := e.OnBehalfOf.Get()
				require.NotNil(t, obo)
				// subject is the token sub (the end user); chain[0] the actor.
				assert.Equal(t, auditTestUserID, obo.Subject)
				assert.Equal(t, []string{auditTestExtAgentID}, obo.Chain)
			} else {
				assert.Nil(t, e.OnBehalfOf.Get())
			}

			// Blocks are present exactly when the line carries them.
			assert.Equal(t, docMap(doc, "ai") != nil, e.Llm.Get() != nil, "llm")
			assert.Equal(t, docMap(doc, "mcp") != nil, e.Mcp.Get() != nil, "mcp")
			assert.Equal(t, docMap(doc, "a2a") != nil, e.A2a.Get() != nil, "a2a")
			assert.Equal(t, docMap(doc, "decision") != nil, e.Decision.Get() != nil, "decision")
			assert.Equal(t, docMap(doc, "guardrail") != nil, e.Guardrail.Get() != nil, "guardrail")
			assert.Equal(t, docString(doc, "errorType") != "", e.Error.Get() != nil, "error")
			if want.actorType == "ANONYMOUS" && want.actorID != "" {
				assert.Equal(t, "apikey", e.Actor.AuthMethod)
				assert.Equal(t, want.actorID, e.Actor.TokenId)
			}

			// The Go category rule and the OpenSearch query agree.
			assert.True(t, evalOS(t, auditCategoryQuery(want.category), doc), "category query")
			assert.True(t, evalOS(t, auditOutcomeQuery(want.outcome), doc), "outcome query")
		})
	}
}

func TestNormalizeAuditDocument_GatewayBlocks(t *testing.T) {
	idx := auditTestIndex(t)
	docs := loadGatewayFixture(t)

	llm := normalizeAuditDocument("", docs[0], idx).Llm.Get()
	require.NotNil(t, llm)
	assert.Equal(t, "openai", llm.Provider)
	assert.Equal(t, "gpt-4o-mini", llm.RequestModel)
	assert.Equal(t, "gpt-4o-mini-2024-07-18", llm.Model)
	assert.Equal(t, []int64{8, 9, 17}, []int64{llm.PromptTokens, llm.CompletionTokens, llm.TotalTokens})
	assert.Nil(t, llm.Cost.Get())

	denied := normalizeAuditDocument("", docs[11], idx)
	require.NotNil(t, denied.Decision.Get())
	db := denied.Decision.Get().DeniedBy.Get()
	require.NotNil(t, db)
	assert.Equal(t, "policy_denied", denied.Decision.Get().TerminalReason)
	assert.Equal(t, []string{"mcp-authz", "v1", "request_headers"}, []string{db.Policy, db.Version, db.Phase})
	mcp := denied.Mcp.Get()
	require.NotNil(t, mcp)
	assert.Equal(t, "everything-primary-ca1514968f6242deb7dfd72ae7c4eaab", mcp.Server)
	assert.Equal(t, "orderPizza", mcp.Tool)
	assert.Equal(t, "4", mcp.JsonRpcId)
	require.NotNil(t, denied.Error.Get())
	assert.Equal(t, "AUTH", denied.Error.Get().Type)
	assert.Equal(t, int32(403), denied.Error.Get().Code)
	assert.Equal(t, "AUTHORIZATION_FAILURE", denied.Error.Get().Message)

	guard := normalizeAuditDocument("", docs[4], idx).Guardrail.Get()
	require.NotNil(t, guard)
	assert.True(t, guard.Hit)
	assert.Equal(t, "content-length-guardrail", guard.Name)

	a2aEvt := normalizeAuditDocument("", docs[25], idx)
	require.NotNil(t, a2aEvt.A2a.Get())
	assert.Equal(t, "SendMessage", a2aEvt.A2a.Get().AdditionalProperties["operation"])

	// The UUID learnt from the agent's API artifact reaches every record
	// attributed to the agent, however it was attributed.
	viaLLM := normalizeAuditDocument("", docs[20], idx).Agent.Get()
	require.NotNil(t, viaLLM)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", viaLLM.Uuid)
}

func TestNormalizeAuditDocument_LiveControlPlaneRecords(t *testing.T) {
	idx := auditTestIndex(t)
	docs := loadControlPlaneFixture(t)
	require.Len(t, docs, 52)

	for _, doc := range docs {
		e := normalizeAuditDocument("doc-id", doc, idx)
		ev := docMap(doc, "event")
		assert.Equal(t, docString(ev, "eventId"), e.Id)
		assert.Equal(t, "CONTROL_PLANE", e.Source)
		assert.Equal(t, "OPERATIONAL", string(e.Category))
		assert.Equal(t, docString(ev, "action"), e.Action)
		assert.Equal(t, docString(ev, "actorId"), e.Actor.Id)
		assert.Equal(t, docString(ev, "actorTokenId"), e.Actor.TokenId)
		assert.Nil(t, e.Gateway.Get())
		assert.Nil(t, e.Llm.Get())
		assert.True(t, evalOS(t, auditCategoryQuery("OPERATIONAL"), doc))
		assert.True(t, evalOS(t, auditOutcomeQuery(string(e.Outcome)), doc), "outcome query for %s", docString(ev, "outcome"))

		switch docString(ev, "outcome") {
		case "success":
			assert.Equal(t, "SUCCESS", string(e.Outcome))
		case "unknown":
			assert.Equal(t, "STARTED", string(e.Outcome))
			assert.True(t, strings.HasSuffix(e.Summary, " (started)"), e.Summary)
			assert.False(t, evalOS(t, auditOutcomeQuery("SUCCESS"), doc), "an intent record is not a success")
		case "failure":
			assert.Equal(t, "FAILED", string(e.Outcome))
		case "deny":
			assert.Equal(t, "DENIED", string(e.Outcome))
		}
		if sc, ok := docInt(ev, "statusCode"); ok {
			require.NotNil(t, e.StatusCode.Get())
			assert.Equal(t, int32(sc), *e.StatusCode.Get())
		} else {
			assert.Nil(t, e.StatusCode.Get())
		}
	}

	byID := map[string]map[string]any{}
	for _, d := range docs {
		byID[docString(d, "event", "eventId")] = d
	}

	// An envelope record: the route was called, with the status it answered.
	create := normalizeAuditDocument("", byID["b4ca1e08-1615-4840-9df3-21fa91de44b9"], idx)
	assert.Equal(t, "agent:create", create.Action)
	assert.Equal(t, "USER", create.Actor.Type)
	require.NotNil(t, create.StatusCode.Get())
	assert.Equal(t, int32(202), *create.StatusCode.Get())

	startup := normalizeAuditDocument("", byID["d535ccd0-4a5f-4e91-9a69-25f2ac667c00"], idx)
	assert.Equal(t, "SYSTEM", startup.Actor.Type)

	sync := normalizeAuditDocument("", byID["0fe9e381-a07b-44bc-9b4c-300e06b90278"], idx)
	assert.Equal(t, "GATEWAY", sync.Actor.Type)
	assert.Equal(t, "10.42.0.87", sync.Network.ClientIp)
}

// An intent record and the failure that resolves it must not read as a success
// next to a failure: the intent is STARTED, and only the outcome record is
// FAILED.
func TestNormalizeAuditDocument_IntentRecordIsStarted(t *testing.T) {
	docs := loadControlPlaneFixture(t)
	byID := map[string]map[string]any{}
	for _, d := range docs {
		byID[docString(d, "event", "eventId")] = d
	}
	pairs := 0
	for _, outcomeDoc := range docs {
		attemptID := docString(outcomeDoc, "event", "details", "attemptEventId")
		intent, ok := byID[attemptID]
		if attemptID == "" || !ok {
			continue
		}
		pairs++
		require.Equal(t, "unknown", docString(intent, "event", "outcome"))

		in := normalizeAuditDocument("", intent, nil)
		out := normalizeAuditDocument("", outcomeDoc, nil)
		assert.Equal(t, "STARTED", string(in.Outcome))
		assert.NotEqual(t, "STARTED", string(out.Outcome), "the outcome record carries the result")
		assert.True(t, evalOS(t, auditOutcomeQuery("STARTED"), intent))
		assert.False(t, evalOS(t, auditOutcomeQuery("STARTED"), outcomeDoc))
		for _, o := range []string{"SUCCESS", "DENIED", "FAILED"} {
			assert.False(t, evalOS(t, auditOutcomeQuery(o), intent), "intent record matched outcome=%s", o)
		}
	}
	assert.Positive(t, pairs, "fixture has no intent/outcome pair; the test proves nothing")

	// A failed privileged operation is one FAILED and one STARTED record.
	failed := map[string]any{
		"audit_source": auditSourceControlPlane,
		"event":        map[string]any{"action": "git-secret:create", "outcome": "failure", "details": map[string]any{"attemptEventId": "a-1"}},
	}
	attempt := map[string]any{
		"audit_source": auditSourceControlPlane,
		"event":        map[string]any{"eventId": "a-1", "action": "git-secret:create", "outcome": "unknown"},
	}
	assert.Equal(t, "FAILED", string(normalizeAuditDocument("", failed, nil).Outcome))
	assert.Equal(t, "STARTED", string(normalizeAuditDocument("", attempt, nil).Outcome))
	assert.False(t, evalOS(t, auditOutcomeQuery("SUCCESS"), attempt))
	assert.False(t, evalOS(t, auditOutcomeQuery("SUCCESS"), failed))
}

// Gateway records have no intent phase, so STARTED never matches them.
func TestAuditOutcomeQuery_StartedExcludesGateway(t *testing.T) {
	for _, doc := range loadGatewayFixture(t) {
		assert.False(t, evalOS(t, auditOutcomeQuery("STARTED"), doc))
		assert.NotEqual(t, "STARTED", string(normalizeAuditDocument("", doc, nil).Outcome))
	}
}

func TestNormalizeAuditDocument_ControlPlaneAgentAttribution(t *testing.T) {
	idx := auditTestIndex(t)
	for _, doc := range loadControlPlaneFixture(t) {
		ev := docMap(doc, "event")
		if docString(ev, "details", "agentName") == "" {
			continue
		}
		e := normalizeAuditDocument("", doc, idx)
		require.NotNil(t, e.Agent.Get(), docString(ev, "action"))
		assert.Equal(t, "ext-audit-agent", e.Agent.Get().Name)
		assert.Equal(t, "default", e.Agent.Get().Project)
		assert.Equal(t, "default", e.Project)
	}
}

func TestNormalizeAuditDocument_ActChainOutermostFirst(t *testing.T) {
	doc := map[string]any{
		"audit_source": auditSourceGateway,
		"status":       json.Number("200"),
		"api":          map[string]any{"kind": "Mcp", "name": "srv"},
		"auth": map[string]any{
			"subject": "user-1", "authenticated": true, "type": "mcp/oauth",
			"claims": map[string]any{"act": map[string]any{
				"sub": auditTestIntAgentID,
				"act": map[string]any{"sub": "orchestrator-agent"},
			}},
		},
	}
	e := normalizeAuditDocument("id-1", doc, auditTestIndex(t))
	obo := e.OnBehalfOf.Get()
	require.NotNil(t, obo)
	assert.Equal(t, "user-1", obo.Subject)
	assert.Equal(t, []string{auditTestIntAgentID, "orchestrator-agent"}, obo.Chain)
	assert.Equal(t, "AGENT", e.Actor.Type)
	assert.Equal(t, auditTestIntAgentID, e.Actor.Id)
	require.NotNil(t, e.Agent.Get())
	assert.Equal(t, "int-audit-agent", e.Agent.Get().Name)
	assert.Equal(t, "id-1", e.Id, "falls back to the store id without an eventId")
}

func TestNormalizeAuditDocument_MCPToolErrorIsFailure(t *testing.T) {
	doc := map[string]any{
		"audit_source": auditSourceGateway,
		"status":       json.Number("200"),
		"api":          map[string]any{"kind": "Mcp"},
		"mcp":          map[string]any{"method": "tools/call", "isError": true},
	}
	e := normalizeAuditDocument("", doc, nil)
	assert.Equal(t, "FAILED", string(e.Outcome))
	assert.True(t, evalOS(t, auditOutcomeQuery("FAILED"), doc))
	assert.False(t, evalOS(t, auditOutcomeQuery("SUCCESS"), doc))
}

func TestNormalizeAuditDocument_GarbageDoesNotPanic(t *testing.T) {
	for _, doc := range []map[string]any{
		nil,
		{},
		{"audit_source": auditSourceControlPlane, "event": "not-an-object"},
		{"audit_source": auditSourceGateway, "status": "abc", "auth": []any{1}, "api": 7},
	} {
		e := normalizeAuditDocument("fallback", doc, nil)
		assert.Equal(t, "fallback", e.Id)
		_, err := json.Marshal(e)
		require.NoError(t, err)
	}
}

func TestAuditEvent_JSONShape(t *testing.T) {
	e := normalizeAuditDocument("", loadControlPlaneFixture(t)[0], auditTestIndex(t))
	b, err := json.Marshal(e)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	// Every key of the contract is present, with null where there is no value.
	for _, k := range []string{
		"id", "timestamp", "source", "category", "action", "outcome", "statusCode", "summary", "actor",
		"onBehalfOf", "agent", "project", "environment", "resource", "decision", "llm", "mcp", "a2a",
		"guardrail", "error", "network", "correlationId", "gateway", "raw",
	} {
		assert.Contains(t, m, k)
	}
	for _, k := range []string{"onBehalfOf", "agent", "decision", "llm", "mcp", "a2a", "guardrail", "error", "gateway", "statusCode"} {
		assert.Nil(t, m[k], k)
	}
	actor := m["actor"].(map[string]any)
	for _, k := range []string{"type", "id", "display", "authMethod", "clientId", "tokenId"} {
		assert.Contains(t, actor, k)
	}
}
