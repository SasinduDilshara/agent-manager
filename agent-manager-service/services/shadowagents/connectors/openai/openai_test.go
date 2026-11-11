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

package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

var (
	day1 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	day2 = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
)

func TestProvider(t *testing.T) {
	assert.Equal(t, models.ShadowProviderOpenAI, New(nil, nil).Provider())
}

func TestScanRequestBuilding(t *testing.T) {
	_, m, _ := runScan(t, true)
	w := testWindow()
	start := strconv.FormatInt(w.Start.Unix(), 10)
	end := strconv.FormatInt(w.End.Unix(), 10)

	admin := func(t *testing.T, r *http.Request) {
		t.Helper()
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "Bearer "+adminKey, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("OpenAI-Beta"))
	}

	t.Run("projects", func(t *testing.T) {
		rs := m.requestsTo("/v1/organization/projects")
		require.Len(t, rs, 2)
		for _, r := range rs {
			admin(t, r)
			assert.Equal(t, "true", r.URL.Query().Get("include_archived"))
			assert.Equal(t, "100", r.URL.Query().Get("limit"))
		}
		assert.Empty(t, rs[0].URL.Query().Get("after"))
		assert.Equal(t, "proj_beta", rs[1].URL.Query().Get("after"))
	})
	t.Run("api keys", func(t *testing.T) {
		rs := m.requestsTo("/v1/organization/projects/proj_alpha/api_keys")
		require.Len(t, rs, 2)
		for _, r := range rs {
			admin(t, r)
			assert.Equal(t, "any", r.URL.Query().Get("owner_project_access"))
			assert.Equal(t, "100", r.URL.Query().Get("limit"))
		}
		assert.Equal(t, "key_alpha1", rs[1].URL.Query().Get("after"))
		assert.Len(t, m.requestsTo("/v1/organization/projects/proj_beta/api_keys"), 1)
		assert.Len(t, m.requestsTo("/v1/organization/projects/proj_old/api_keys"), 1)
	})
	t.Run("audit logs", func(t *testing.T) {
		rs := m.requestsTo("/v1/organization/audit_logs")
		require.Len(t, rs, 2)
		for _, r := range rs {
			admin(t, r)
			assert.Contains(t, r.URL.RawQuery, "event_types[]=api_key.created")
		}
		assert.Equal(t, "audit_log-yyy__20240101", rs[1].URL.Query().Get("after"))
	})
	usage := []struct {
		path    string
		groupBy string
		limit   string
		page2   string
	}{
		{"/v1/organization/usage/completions", "group_by[]=project_id&group_by[]=api_key_id&group_by[]=model&group_by[]=api_source", "31", "page_AAAAAGdGxdEiJdKOAAAAAGcqsYA="},
		{"/v1/organization/costs", "group_by[]=project_id&group_by[]=api_key_id&group_by[]=api_source", "180", "page_COSTS2"},
		{"/v1/organization/usage/web_search_calls", "group_by[]=api_key_id&group_by[]=project_id&group_by[]=api_source", "31", "page_WEB2"},
		{"/v1/organization/usage/file_search_calls", "group_by[]=api_key_id&group_by[]=project_id&", "31", "page_FILE2"},
		{"/v1/organization/usage/code_interpreter_sessions", "group_by[]=project_id&", "31", "page_CI2"},
	}
	for _, u := range usage {
		t.Run(u.path, func(t *testing.T) {
			rs := m.requestsTo(u.path)
			require.Len(t, rs, 2)
			for _, r := range rs {
				admin(t, r)
				q := r.URL.Query()
				assert.Equal(t, start, q.Get("start_time"))
				assert.Equal(t, end, q.Get("end_time"))
				assert.Equal(t, "1d", q.Get("bucket_width"))
				assert.Equal(t, u.limit, q.Get("limit"))
				assert.Contains(t, r.URL.RawQuery, u.groupBy)
				assert.NotContains(t, r.URL.RawQuery, "%5B")
			}
			assert.Empty(t, rs[0].URL.Query().Get("page"))
			assert.Equal(t, u.page2, rs[1].URL.Query().Get("page"))
		})
	}
	t.Run("file search has no api_source or model group", func(t *testing.T) {
		for _, r := range m.requestsTo("/v1/organization/usage/file_search_calls") {
			assert.NotContains(t, r.URL.RawQuery, "api_source")
			assert.NotContains(t, r.URL.RawQuery, "group_by[]=model")
		}
	})
	t.Run("agents use the project key and the beta header", func(t *testing.T) {
		rs := m.requestsTo("/v1/agents")
		require.Len(t, rs, 3) // alpha: 1 page; beta: 2 pages
		for _, r := range rs {
			assert.Equal(t, "agents=v1", r.Header.Get("OpenAI-Beta"))
			assert.Contains(t, []string{"Bearer " + alphaKey, "Bearer " + betaKey}, r.Header.Get("Authorization"))
			assert.Equal(t, "desc", r.URL.Query().Get("order"))
			assert.Equal(t, "100", r.URL.Query().Get("limit"))
		}
		assert.Equal(t, "agent_b1", rs[2].URL.Query().Get("after"))
		ss := m.requestsTo("/v1/agents/sessions")
		require.Len(t, ss, 3)
		for _, r := range ss {
			assert.Equal(t, "agents=v1", r.Header.Get("OpenAI-Beta"))
			assert.Equal(t, "50", r.URL.Query().Get("limit"))
		}
	})
	t.Run("content endpoints use the project key", func(t *testing.T) {
		cs := m.requestsTo("/v1/chat/completions")
		require.Len(t, cs, 3)
		assert.Equal(t, "Bearer "+alphaKey, cs[0].Header.Get("Authorization"))
		assert.Equal(t, "desc", cs[0].URL.Query().Get("order"))
		assert.Equal(t, "chatcmpl-A", cs[1].URL.Query().Get("after"))
		assert.Empty(t, cs[0].Header.Get("OpenAI-Beta"))
		bs := m.requestsTo("/v1/batches")
		require.Len(t, bs, 3)
		assert.Equal(t, "batch_1", bs[1].URL.Query().Get("after"))
		for _, p := range []string{"file-out1", "file-in1", "file-out2", "file-in2", "file-outb", "file-inb"} {
			assert.Len(t, m.requestsTo("/v1/files/"+p+"/content"), 1, p)
		}
		// Embeddings batches and batches before the window are not read.
		for _, p := range []string{"file-out3", "file-in3", "file-outold", "file-inold"} {
			assert.Empty(t, m.requestsTo("/v1/files/"+p+"/content"), p)
		}
	})
	t.Run("admin key never goes to project endpoints and vice versa", func(t *testing.T) {
		for _, r := range m.requests() {
			admin := strings.HasPrefix(r.URL.Path, "/v1/organization/")
			isAdminKey := r.Header.Get("Authorization") == "Bearer "+adminKey
			assert.Equal(t, admin, isAdminKey, r.URL.Path)
		}
	})
}

func TestScanCallResults(t *testing.T) {
	res, _, _ := runScan(t, true)
	want := map[string]struct {
		outcome string
		items   int
	}{
		callProjects:                      {models.ShadowCallOK, 3},
		callAPIKeys:                       {models.ShadowCallOK, 3},
		callAPIKeysArchived:               {models.ShadowCallSkipped, 0},
		callAuditLogs:                     {models.ShadowCallOK, 4},
		callUsage:                         {models.ShadowCallOK, 8},
		callCosts:                         {models.ShadowCallOK, 5},
		callWebSearch:                     {models.ShadowCallOK, 3},
		callFileSearch:                    {models.ShadowCallOK, 2},
		callCodeInterpreter:               {models.ShadowCallOK, 3},
		callAgents:                        {models.ShadowCallOK, 3},
		callSessions:                      {models.ShadowCallOK, 3},
		callChatCompletions:               {models.ShadowCallOK, 4},
		callBatches:                       {models.ShadowCallOK, 5},
		callFileContent:                   {models.ShadowCallOK, 8},
		callFileContent + suffixOnProject: {models.ShadowCallSkipped, 0},
	}
	for call, w := range want {
		r := callResult(t, res, call)
		assert.Equal(t, w.outcome, r.Outcome, call)
		assert.Equal(t, w.items, r.Items, call)
	}
	assert.Contains(t, callResult(t, res, callAPIKeysArchived).Message, "1 archived project")
	assert.Contains(t, callResult(t, res, callFileContent+suffixOnProject).Message, "proj_beta: 2 keys with usage")
	// The archived project's keys cannot be listed, so the listing is not
	// complete; the active projects' keys were listed in full.
	assert.False(t, res.KeysListed, "the archived project's keys are unknown")
	assert.ElementsMatch(t, []string{"proj_alpha", "proj_beta"}, res.KeyScopesListed)
	for _, r := range res.Calls {
		assert.NotContains(t, r.Call, callChatCompletions+suffixNotAttributed)
		assert.NotContains(t, r.Call, suffixPageLimit)
	}
}

func TestScanKeysAndOwnerHints(t *testing.T) {
	res, _, _ := runScan(t, false)
	require.Len(t, res.Keys, 3)
	keys := map[string]sa.Key{}
	for _, k := range res.Keys {
		keys[k.KeyID] = k
	}

	a1 := keys["key_alpha1"]
	assert.Equal(t, "Alpha backend", a1.Name)
	assert.Equal(t, "sk-abc...def", a1.RedactedHint)
	assert.Equal(t, "proj_alpha", a1.Scope)
	assert.Equal(t, stateActive, a1.Status)
	assert.Equal(t, time.Unix(1735689600, 0).UTC(), *a1.CreatedAt)
	assert.Equal(t, time.Unix(1793633400, 0).UTC(), *a1.LastUsedAt)
	// The listing owner wins over the audit actor (dave); the audit event
	// gives the creation time.
	assert.Equal(t, "alice@example.com", a1.OwnerHint.Email)
	assert.Equal(t, "Alice Example", a1.OwnerHint.Name)
	assert.Equal(t, "user_alice", a1.OwnerHint.Username)
	assert.Equal(t, ownerTypeUser, a1.OwnerHint.Type)
	assert.Equal(t, callAPIKeys, a1.OwnerHint.Source)
	require.NotNil(t, a1.OwnerHint.CreatedAt)
	assert.Equal(t, time.Unix(1735689602, 0).UTC(), *a1.OwnerHint.CreatedAt)

	// Service account key: the session user who created it fills the email.
	a2 := keys["key_alpha2"]
	assert.Nil(t, a2.LastUsedAt)
	assert.Equal(t, ownerTypeServiceAcct, a2.OwnerHint.Type)
	assert.Equal(t, "svc-bot", a2.OwnerHint.Name)
	assert.Equal(t, "svc_acct_1", a2.OwnerHint.Username)
	assert.Equal(t, "carol@example.com", a2.OwnerHint.Email)
	assert.Equal(t, callAPIKeys+"; "+callAuditLogs, a2.OwnerHint.Source)

	// Expired key; a null audit actor adds only the creation time.
	b1 := keys["key_beta1"]
	assert.Equal(t, stateExpired, b1.Status)
	assert.Equal(t, "bob@example.com", b1.OwnerHint.Email)
	assert.Equal(t, callAPIKeys, b1.OwnerHint.Source)
	assert.Equal(t, time.Unix(1735689601, 0).UTC(), *b1.OwnerHint.CreatedAt)

	// Every listed key is a finding with the same owner hint.
	f := finding(t, res, models.ShadowKindAPIKey, "key_alpha2")
	assert.Equal(t, a2.OwnerHint, f.OwnerHint)
	assert.Equal(t, "Alpha bot", f.DisplayName)
	assert.Equal(t, "proj_alpha", f.Scope)
	assert.Equal(t, []string{"key_alpha2"}, f.KeyIDs)
	assert.Equal(t, "Alpha", f.Attributes["project"])
	assert.Empty(t, f.Signals, "no usage, no search: no signal")
	assert.Empty(t, f.Usage)
}

func TestScanAgentObject(t *testing.T) {
	res, _, _ := runScan(t, false)
	f := finding(t, res, models.ShadowKindPlatformAgent, "agent_alpha")
	assert.Equal(t, "Support agent", f.DisplayName)
	assert.Equal(t, "proj_alpha", f.Scope)
	assert.Equal(t, stateActive, f.State)
	assert.Equal(t, "gpt-x", f.Attributes["model"])
	assert.Equal(t, int64(4), f.Attributes["toolCount"])
	assert.Equal(t, []sa.ToolRef{
		{Type: "function", Name: "lookup_order"},
		{Type: "mcp", Name: "github"},
		{Type: "mcp", Name: "docs"},
		{Type: "web_search"},
	}, f.Attributes["tools"])
	assert.Equal(t, []sa.MCPServerRef{
		{Label: "github", Origin: "https://mcp.example.com"},
		{Label: "docs", Origin: "https://tools.example.org"},
	}, f.Attributes["mcpServers"])
	assert.Equal(t, int64(1), f.Attributes["sessionCount"], "one session active in the window; one older")
	assert.Equal(t, "2026-11-02T15:30:00Z", f.Attributes["lastSessionAt"])
	assert.Equal(t, time.Unix(1793404800, 0).UTC(), *f.ProviderCreatedAt)
	sig, ok := signal(f, sa.SigOpenAIAgentObject, callAgents)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"toolCount": int64(4), "mcpServerCount": int64(2)}, sig.Observed)
	_, has := f.Attributes["instructions"]
	assert.False(t, has)

	b2 := finding(t, res, models.ShadowKindPlatformAgent, "agent_b2")
	assert.Equal(t, "agent_b2", b2.DisplayName, "unnamed agent shows its ID")
	_, ok = signal(b2, sa.SigOpenAIAgentObject, "")
	assert.True(t, ok)
	_, has = b2.Attributes["sessionCount"]
	assert.False(t, has)
}

func TestScanNoAgentsMeansNoAgentFinding(t *testing.T) {
	m, srv := newMock(t)
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/agents" {
			writeStatus(w, http.StatusOK, `{"data":[],"first_id":null,"has_more":false,"last_id":null,"object":"list"}`)
			return true
		}
		return false
	}
	c, _ := newTestConnector(srv)
	res := c.Scan(context.Background(), testConn(srv.URL, false), testWindow())
	for _, f := range res.Findings {
		assert.NotEqual(t, models.ShadowKindPlatformAgent, f.Kind)
	}
	assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, callSessions).Outcome)
	// With no agent, Agents API usage stays on the key.
	k := finding(t, res, models.ShadowKindAPIKey, "key_alpha1")
	sig, ok := signal(k, sa.SigOpenAIAgentsAPIUsage, callUsage)
	require.True(t, ok)
	assert.Equal(t, int64(5), sig.Observed["numModelRequests"])
}

func TestScanUsageAggregation(t *testing.T) {
	res, _, _ := runScan(t, false)
	ag := finding(t, res, models.ShadowKindPlatformAgent, "agent_alpha")
	a1 := finding(t, res, models.ShadowKindAPIKey, "key_alpha1")
	b1 := finding(t, res, models.ShadowKindAPIKey, "key_beta1")
	gone := finding(t, res, models.ShadowKindAPIKey, "key_gone")

	usd := func(v float64) *float64 { return &v }
	// Agents API rows of the project's only agent go to the agent.
	assert.ElementsMatch(t, []sa.UsageDay{
		{Day: day1, KeyID: "key_alpha1", Model: "gpt-x", Requests: 5, InputTokens: 300, OutputTokens: 100},
		{Day: day1, KeyID: "key_alpha1", CostAmount: usd(0.2), Currency: "usd"},
	}, ag.Usage)
	assert.Equal(t, []string{"key_alpha1"}, ag.KeyIDs)
	// The rest stays on the key, summed per day/key/model, never both.
	assert.ElementsMatch(t, []sa.UsageDay{
		{Day: day1, KeyID: "key_alpha1", Model: "gpt-x", Requests: 10, InputTokens: 1000, OutputTokens: 500},
		{Day: day2, KeyID: "key_alpha1", Model: "gpt-x", Requests: 2, InputTokens: 200, OutputTokens: 100},
		{Day: day1, KeyID: "key_alpha1", CostAmount: usd(0.5), Currency: "usd"},
	}, a1.Usage)
	require.Len(t, a1.Related, 1)
	assert.Equal(t, sa.Relation{
		ExternalID: "agent_alpha", Kind: models.ShadowKindPlatformAgent, Relation: relationUsedByAgent,
		Reason: a1.Related[0].Reason,
	}, a1.Related[0])
	// Two agents in proj_beta: its Agents API usage stays on the key.
	assert.ElementsMatch(t, []sa.UsageDay{
		{Day: day1, KeyID: "key_beta1", Model: "gpt-y", Requests: 3, InputTokens: 60, OutputTokens: 30},
		{Day: day2, KeyID: "key_beta1", CostAmount: usd(0.1), Currency: "usd"},
	}, b1.Usage)
	assert.Empty(t, b1.Related)
	// A key that is not listed but has usage is still a workload.
	assert.Equal(t, "proj_beta", gone.Scope)
	assert.Equal(t, "Beta", gone.Attributes["project"])
	assert.Equal(t, []sa.UsageDay{{Day: day2, KeyID: "key_gone", Model: "gpt-y", Requests: 4, InputTokens: 40, OutputTokens: 20}}, gone.Usage)

	// No double counting: the attributable rows sum to 24 requests and
	// 0.8 USD (the null-key rows are not attributed).
	var reqs int64
	var cost float64
	for _, f := range res.Findings {
		for _, u := range f.Usage {
			reqs += u.Requests
			if u.CostAmount != nil {
				cost += *u.CostAmount
			}
		}
	}
	assert.Equal(t, int64(24), reqs)
	assert.InDelta(t, 0.8, cost, 1e-9)

	// First/last use: usage days and the key's last_used_at.
	assert.Equal(t, day1, *a1.FirstUsedAt)
	assert.Equal(t, time.Unix(1793633400, 0).UTC(), *a1.LastUsedAt)
	assert.Equal(t, day1, *ag.FirstUsedAt)
	assert.Equal(t, time.Unix(1793633400, 0).UTC(), *ag.LastUsedAt, "last session activity")

	assert.Equal(t, []string{"gpt-x"}, a1.Attributes["models"])
	assert.Equal(t, []string{"unlabeled"}, a1.Attributes["apiSources"])
	assert.Equal(t, []string{"agents_api"}, ag.Attributes["apiSources"])
}

func TestScanSignals(t *testing.T) {
	res, _, _ := runScan(t, true)
	ag := finding(t, res, models.ShadowKindPlatformAgent, "agent_alpha")
	a1 := finding(t, res, models.ShadowKindAPIKey, "key_alpha1")
	a2 := finding(t, res, models.ShadowKindAPIKey, "key_alpha2")
	b1 := finding(t, res, models.ShadowKindAPIKey, "key_beta1")
	gone := finding(t, res, models.ShadowKindAPIKey, "key_gone")

	type want struct {
		f        *sa.Finding
		code     string
		source   string
		observed map[string]any
	}
	positives := []want{
		{a1, sa.SigOpenAIPlainUsage, callUsage, map[string]any{"numModelRequests": int64(12), "days": int64(2)}},
		{b1, sa.SigOpenAIPlainUsage, callUsage, map[string]any{"numModelRequests": int64(3), "days": int64(1)}},
		{gone, sa.SigOpenAIPlainUsage, callUsage, map[string]any{"numModelRequests": int64(4), "days": int64(1)}},
		{ag, sa.SigOpenAIAgentsAPIUsage, callUsage, map[string]any{"numModelRequests": int64(5), "days": int64(1)}},
		{ag, sa.SigOpenAIAgentsAPIUsage, callCosts, map[string]any{"days": int64(1)}},
		{b1, sa.SigOpenAIAgentsAPIUsage, callUsage, map[string]any{"numModelRequests": int64(3), "days": int64(1)}},
		{a1, sa.SigOpenAIHostedSearch, callWebSearch, map[string]any{"numRequests": int64(4), "days": int64(1)}},
		{ag, sa.SigOpenAIHostedSearch, callWebSearch, map[string]any{"numRequests": int64(2), "days": int64(1)}},
		{b1, sa.SigOpenAIHostedSearch, callFileSearch, map[string]any{"numRequests": int64(3), "days": int64(1)}},
		{a1, sa.SigOpenAICodeInterpreter, callCodeInterpreter, map[string]any{"numSessions": int64(2), "keysWithUsage": int64(1)}},
		{b1, sa.SigOpenAICodeInterpreterPrj, callCodeInterpreter, map[string]any{"numSessions": int64(1), "keysWithUsage": int64(2)}},
		{gone, sa.SigOpenAICodeInterpreterPrj, callCodeInterpreter, map[string]any{"numSessions": int64(1), "keysWithUsage": int64(2)}},
		{ag, sa.SigOpenAIAgentObject, callAgents, map[string]any{"toolCount": int64(4), "mcpServerCount": int64(2)}},
		{a1, sa.SigOpenAIToolCallCompletion, callChatCompletions, map[string]any{"completionsWithToolCalls": int64(2), "completionsInspected": int64(3)}},
		{a1, sa.SigOpenAIToolCallBatch, callFileContent, map[string]any{"batches": int64(1), "linesWithToolCalls": int64(1)}},
		{a1, sa.SigOpenAIToolResultBatch, callFileContent, map[string]any{"batches": int64(1), "linesWithToolResults": int64(1)}},
	}
	for _, p := range positives {
		sig, ok := signal(p.f, p.code, p.source)
		if assert.True(t, ok, "%s should have %s from %s", p.f.ExternalID, p.code, p.source) {
			assert.Equal(t, p.observed, sig.Observed, "%s %s", p.f.ExternalID, p.code)
		}
	}
	negatives := []want{
		// num_model_requests == 0 only.
		{a2, sa.SigOpenAIPlainUsage, "", nil},
		// Agents API usage of the sole agent is not also on the key.
		{a1, sa.SigOpenAIAgentsAPIUsage, "", nil},
		// costs agents_api row with amount.value == 0.
		{b1, sa.SigOpenAIAgentsAPIUsage, callCosts, nil},
		// web search num_requests == 0; file search num_requests == 0.
		{b1, sa.SigOpenAIHostedSearch, callWebSearch, nil},
		{a2, sa.SigOpenAIHostedSearch, "", nil},
		// Several keys with usage: only the project-level info signal.
		{b1, sa.SigOpenAICodeInterpreter, "", nil},
		{a1, sa.SigOpenAICodeInterpreterPrj, "", nil},
		// Deep signals of proj_beta (two keys with usage) go on the project
		// finding, not on a key.
		{b1, sa.SigOpenAIToolCallBatch, "", nil},
		{b1, sa.SigOpenAIToolResultBatch, "", nil},
		{b1, sa.SigOpenAIToolCallCompletion, "", nil},
		{a1, sa.SigOpenAIAgentObject, "", nil},
	}
	for _, n := range negatives {
		_, ok := signal(n.f, n.code, n.source)
		assert.False(t, ok, "%s must not have %s from %q", n.f.ExternalID, n.code, n.source)
	}

	score, verdict := sa.Score(ag.Kind, codes(ag))
	assert.Equal(t, 100, score)
	assert.Equal(t, models.ShadowVerdictAgent, verdict)
	_, verdict = sa.Score(a2.Kind, codes(a2))
	assert.Equal(t, models.ShadowVerdictLLMConsumer, verdict)
	for _, f := range res.Findings {
		for _, s := range f.Signals {
			_, known := sa.Def(s.Code)
			assert.True(t, known, s.Code)
		}
	}
}

func codes(f *sa.Finding) []string {
	out := []string{}
	for _, s := range f.Signals {
		out = append(out, s.Code)
	}
	return out
}

func TestCodeInterpreterWithoutKeyUsage(t *testing.T) {
	// No key of proj_alpha has usage: the info signal goes to its listed keys.
	m, srv := newMock(t)
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/organization/usage/completions" {
			writeStatus(w, http.StatusOK, `{"object":"page","data":[],"has_more":false,"next_page":null}`)
			return true
		}
		return false
	}
	c, _ := newTestConnector(srv)
	res := c.Scan(context.Background(), testConn(srv.URL, false), testWindow())
	for _, id := range []string{"key_alpha1", "key_alpha2"} {
		sig, ok := signal(finding(t, res, models.ShadowKindAPIKey, id), sa.SigOpenAICodeInterpreterPrj, "")
		require.True(t, ok, id)
		assert.Equal(t, int64(0), sig.Observed["keysWithUsage"])
	}
	_, ok := signal(finding(t, res, models.ShadowKindAPIKey, "key_alpha1"), sa.SigOpenAICodeInterpreter, "")
	assert.False(t, ok)
}

func TestToolCallConditions(t *testing.T) {
	chat := func(s string) []chatChoice {
		var c storedCompletion
		require.NoError(t, json.Unmarshal([]byte(s), &c))
		return c.Choices
	}
	assert.True(t, completionHasToolCall(chat(`{"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[{"type":"function"}]}}]}`)))
	assert.True(t, completionHasToolCall(chat(`{"choices":[{"finish_reason":"stop","message":{"tool_calls":[{"type":"custom"}]}}]}`)))
	assert.True(t, completionHasToolCall(chat(`{"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":null}}]}`)))
	assert.True(t, completionHasToolCall(chat(`{"choices":[{"finish_reason":"stop","message":{"function_call":{"name":"f","arguments":"{}"}}}]}`)))
	assert.True(t, completionHasToolCall(chat(`{"choices":[{"finish_reason":"function_call","message":{}}]}`)))
	assert.False(t, completionHasToolCall(chat(`{"choices":[{"finish_reason":"stop","message":{"tool_calls":null,"function_call":null}}]}`)))
	assert.False(t, completionHasToolCall(chat(`{"choices":[{"finish_reason":"stop","message":{"tool_calls":[]}}]}`)))
	assert.False(t, completionHasToolCall(nil))

	out := func(body string) []byte {
		return []byte(`{"id":"batch_req_1","custom_id":"r","response":{"status_code":200,"request_id":"q","body":` + body + `},"error":null}`)
	}
	for _, typ := range []string{"function_call", "web_search_call", "file_search_call", "computer_call", "mcp_call", "code_interpreter_call", "custom_tool_call"} {
		assert.True(t, outputLineHasToolCall(out(`{"output":[{"type":"message"},{"type":"`+typ+`"}]}`)), typ)
	}
	assert.False(t, outputLineHasToolCall(out(`{"output":[{"type":"message"},{"type":"reasoning"}]}`)))
	assert.True(t, outputLineHasToolCall(out(`{"choices":[{"finish_reason":"tool_calls","message":{}}]}`)))
	assert.False(t, outputLineHasToolCall(out(`{"choices":[{"finish_reason":"stop","message":{}}]}`)))
	assert.False(t, outputLineHasToolCall([]byte(`{"id":"x","custom_id":"r","response":null,"error":{"code":"batch_expired","message":"m"}}`)))
	assert.False(t, outputLineHasToolCall([]byte(`not json`)))

	assert.True(t, inputLineHasToolResult([]byte(`{"url":"/v1/responses","body":{"input":[{"type":"function_call_output","call_id":"c","output":"x"}]}}`)))
	assert.False(t, inputLineHasToolResult([]byte(`{"url":"/v1/responses","body":{"input":[{"role":"user","content":"x"}]}}`)))
	assert.False(t, inputLineHasToolResult([]byte(`{"url":"/v1/responses","body":{"input":"just text"}}`)))
	assert.True(t, inputLineHasToolResult([]byte(`{"url":"/v1/chat/completions","body":{"messages":[{"role":"tool","content":"x"}]}}`)))
	assert.True(t, inputLineHasToolResult([]byte(`{"url":"/v1/chat/completions","body":{"messages":[{"role":"function","content":"x"}]}}`)))
	assert.False(t, inputLineHasToolResult([]byte(`{"url":"/v1/chat/completions","body":{"messages":[{"role":"user","content":"x"}]}}`)))
}

func TestMCPOrigin(t *testing.T) {
	assert.Equal(t, "https://a.example", mcpOrigin(agentTool{ServerURL: "https://u:p@a.example/x?k=v"}))
	assert.Equal(t, "https://b.example", mcpOrigin(agentTool{Transport: json.RawMessage(`{"url":"https://b.example/sse?t=1"}`)}))
	assert.Equal(t, "https://c.example", mcpOrigin(agentTool{Transport: json.RawMessage(`{"server_url":"https://c.example/p"}`)}))
	assert.Equal(t, "https://d.example", mcpOrigin(agentTool{ConnectionOrigin: json.RawMessage(`"https://d.example/x"`)}))
	assert.Empty(t, mcpOrigin(agentTool{Transport: json.RawMessage(`"streamable_http"`), ConnectionOrigin: json.RawMessage(`"customer"`)}))
}

func TestRedactedHint(t *testing.T) {
	assert.Equal(t, "sk-abc...def", redactedHint("sk-abc...def"))
	assert.Equal(t, "sk-a…CRET", redactedHint("sk-abcdefghijklmnopSECRET"), "an unredacted value is reduced to a hint")
}

func TestRetention(t *testing.T) {
	res, _, logs := runScan(t, true)
	b, err := json.Marshal(res)
	require.NoError(t, err)
	m, srv := newMock(t)
	_ = m
	c, testLogs := newTestConnector(srv)
	info := c.Test(context.Background(), testConn(srv.URL, true))
	ib, err := json.Marshal(info)
	require.NoError(t, err)
	for name, text := range map[string]string{
		"result": string(b), "scan logs": logs.String(), "test info": string(ib), "test logs": testLogs.String(),
	} {
		for _, bad := range []string{markerPrompt, markerKey, "203.0.113.9", "Mozilla", "token=", "api_key=", "user:pw", "/sse", "cred_"} {
			assert.NotContains(t, text, bad, "%s leaks %q", name, bad)
		}
	}
	assert.Contains(t, logs.String(), "Shadow agent discovery provider call", "debug logs were captured")
}

func TestErrorMessagesAreScrubbed(t *testing.T) {
	m, srv := newMock(t)
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/organization/costs" {
			m.serveStatus(w, http.StatusForbidden, "error_permission_plain.json")
			return true
		}
		return false
	}
	c, logs := newTestConnector(srv)
	res := c.Scan(context.Background(), testConn(srv.URL, false), testWindow())
	r := callResult(t, res, callCosts)
	assert.Equal(t, models.ShadowCallPermissionDenied, r.Outcome)
	assert.Contains(t, r.Message, "insufficient permissions")
	b, _ := json.Marshal(res)
	assert.NotContains(t, string(b), markerKey)
	assert.NotContains(t, logs.String(), markerKey)
	// The other calls still ran.
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callUsage).Outcome)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callWebSearch).Outcome)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callAgents).Outcome)
}

func TestDeepInspectionOff(t *testing.T) {
	m, srv := newMock(t)
	m.forbidContent = true
	c, _ := newTestConnector(srv)
	conn := testConn(srv.URL, false)
	delete(conn.Secret.ScopedKeys, "proj_beta")
	res := c.Scan(context.Background(), conn, testWindow())
	for _, call := range []string{callChatCompletions, callBatches, callFileContent} {
		r := callResult(t, res, call)
		assert.Equal(t, models.ShadowCallSkipped, r.Outcome, call)
		assert.Equal(t, reasonDeepOff, r.Message, call)
	}
	assert.Empty(t, m.requestsTo("/v1/chat/completions"))
	assert.Empty(t, m.requestsTo("/v1/batches"))
	r := callResult(t, res, callProjectKeysMiss)
	assert.Equal(t, models.ShadowCallSkipped, r.Outcome)
	assert.Contains(t, r.Message, "1 of 2 active projects")
	for _, f := range res.Findings {
		_, ok := f.Attributes["deepInspection"]
		assert.False(t, ok)
	}
}

func TestNoProjectKeys(t *testing.T) {
	m, srv := newMock(t)
	m.forbidContent = true
	c, _ := newTestConnector(srv)
	conn := testConn(srv.URL, true)
	conn.Secret.ScopedKeys = nil
	res := c.Scan(context.Background(), conn, testWindow())
	for _, call := range []string{callAgents, callSessions, callChatCompletions, callBatches, callFileContent} {
		assert.Equal(t, reasonNoProjectKey, callResult(t, res, call).Message, call)
	}
	assert.Empty(t, m.requestsTo("/v1/agents"))
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callUsage).Outcome)
}

func TestAuthFailureStopsEarly(t *testing.T) {
	m, srv := newMock(t)
	c, _ := newTestConnector(srv)
	conn := testConn(srv.URL, true)
	conn.Secret.APIKey = "sk-test-SECRETSECRETSECRET-WRONG"
	res := c.Scan(context.Background(), conn, testWindow())
	require.Len(t, res.Calls, 1)
	assert.Equal(t, callProjects, res.Calls[0].Call)
	assert.Equal(t, models.ShadowCallAuthFailed, res.Calls[0].Outcome)
	assert.Len(t, m.requests(), 1, "nothing else is called after the Admin key is rejected")
	assert.Empty(t, res.Findings)
	assert.False(t, res.KeysListed)
	b, _ := json.Marshal(res)
	assert.NotContains(t, string(b), markerKey)
}

// TestProjectFinding: with the Admin key, proj_beta's batch evidence (two
// keys of the project had usage) goes on the project's finding, linked to
// the project's agents and to the keys that may have made the calls.
// Expected values come from testdata: batch_b (file-outb.jsonl has one line
// with finish_reason tool_calls; file-inb.jsonl one message with role tool);
// proj_beta's one stored completion ends with "stop".
func TestProjectFinding(t *testing.T) {
	res, _, _ := runScan(t, true)
	pf := finding(t, res, models.ShadowKindProject, "proj_beta")
	assert.Equal(t, "Project Beta", pf.DisplayName)
	assert.Equal(t, "proj_beta", pf.Scope)
	assert.Equal(t, stateActive, pf.State)
	assert.Equal(t, "Beta", pf.Attributes["project"])
	callSig, ok := signal(pf, sa.SigOpenAIToolCallBatch, callFileContent)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"batches": int64(1), "linesWithToolCalls": int64(1)}, callSig.Observed)
	resultSig, ok := signal(pf, sa.SigOpenAIToolResultBatch, callFileContent)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"batches": int64(1), "linesWithToolResults": int64(1)}, resultSig.Observed)
	_, ok = signal(pf, sa.SigOpenAIToolCallCompletion, "")
	assert.False(t, ok, "proj_beta's stored completion has no tool call")
	score, verdict := sa.Score(pf.Kind, codes(pf))
	assert.Equal(t, 70, score)
	assert.Equal(t, models.ShadowVerdictAgent, verdict)
	assert.ElementsMatch(t, []sa.Relation{
		{ExternalID: "agent_b1", Kind: models.ShadowKindPlatformAgent, Relation: "agent_in_project", Reason: "agent in this project"},
		{ExternalID: "agent_b2", Kind: models.ShadowKindPlatformAgent, Relation: "agent_in_project", Reason: "agent in this project"},
		{ExternalID: "key_beta1", Kind: models.ShadowKindAPIKey, Relation: "candidate_key", Reason: "had usage in this project in the window"},
		{ExternalID: "key_gone", Kind: models.ShadowKindAPIKey, Relation: "candidate_key", Reason: "had usage in this project in the window"},
	}, pf.Related)
	// proj_alpha's evidence has one key with usage: it stays on that key.
	for _, f := range res.Findings {
		assert.False(t, f.Kind == models.ShadowKindProject && f.ExternalID == "proj_alpha", "proj_alpha has no project finding")
	}
}

// TestProjectKeysOnly: without an Admin key the organization routes are
// skipped (never called), the projects with a project key are scanned, and
// their deep evidence goes on project findings with no candidate keys.
func TestProjectKeysOnly(t *testing.T) {
	m, srv := newMock(t)
	c, _ := newTestConnector(srv)
	conn := testConn(srv.URL, true)
	conn.Secret.APIKey = " "
	res := c.Scan(context.Background(), conn, testWindow())

	for _, call := range []string{callProjects, callAPIKeys, callAuditLogs, callUsage, callCosts, callWebSearch, callFileSearch, callCodeInterpreter} {
		r := callResult(t, res, call)
		assert.Equal(t, models.ShadowCallSkipped, r.Outcome, call)
		assert.Equal(t, reasonNeedsAdminKey, r.Message, call)
	}
	for _, r := range m.requests() {
		assert.NotContains(t, r.URL.Path, "/organization/", "no organization route without an Admin key")
		assert.NotEqual(t, "Bearer "+adminKey, r.Header.Get("Authorization"))
	}
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callAgents).Outcome)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callSessions).Outcome)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callChatCompletions).Outcome)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callBatches).Outcome)
	assert.False(t, res.KeysListed, "keys are not listed without the Admin key")
	assert.Empty(t, res.Keys)
	assert.Empty(t, res.KeyScopesListed)

	kinds := map[string]int{}
	for _, f := range res.Findings {
		kinds[f.Kind]++
		assert.Empty(t, f.Usage, "%s: no usage without the Admin key", f.ExternalID)
	}
	assert.Equal(t, map[string]int{models.ShadowKindPlatformAgent: 3, models.ShadowKindProject: 2}, kinds)

	ag := finding(t, res, models.ShadowKindPlatformAgent, "agent_alpha")
	_, ok := signal(ag, sa.SigOpenAIAgentObject, callAgents)
	assert.True(t, ok)
	assert.Equal(t, "proj_alpha", ag.Attributes["project"], "the project name needs the Admin key; the ID is shown")

	// proj_alpha: completions and batch evidence, no key to tie it to.
	pa := finding(t, res, models.ShadowKindProject, "proj_alpha")
	assert.Equal(t, "Project proj_alpha", pa.DisplayName)
	cs, ok := signal(pa, sa.SigOpenAIToolCallCompletion, callChatCompletions)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"completionsWithToolCalls": int64(2), "completionsInspected": int64(3)}, cs.Observed)
	_, ok = signal(pa, sa.SigOpenAIToolCallBatch, callFileContent)
	assert.True(t, ok)
	_, ok = signal(pa, sa.SigOpenAIToolResultBatch, callFileContent)
	assert.True(t, ok)
	for _, r := range pa.Related {
		assert.NotEqual(t, "candidate_key", r.Relation, "no candidate keys without the Admin key")
	}
	assert.Contains(t, pa.Related, sa.Relation{
		ExternalID: "agent_alpha", Kind: models.ShadowKindPlatformAgent, Relation: "agent_in_project", Reason: "agent in this project",
	})
	note := callResult(t, res, callChatCompletions+suffixOnProject)
	assert.Contains(t, note.Message, "no Admin API key")
	assert.Contains(t, note.Message, "proj_alpha: project keys only")
}

// TestNoCredentialAtAll: with neither an Admin key nor project keys (the
// service refuses to store such a connection) the scan reads nothing.
func TestNoCredentialAtAll(t *testing.T) {
	m, srv := newMock(t)
	c, _ := newTestConnector(srv)
	conn := testConn(srv.URL, true)
	conn.Secret.APIKey = ""
	conn.Secret.ScopedKeys = nil
	res := c.Scan(context.Background(), conn, testWindow())
	assert.Empty(t, m.requests())
	assert.Empty(t, res.Findings)
	assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, callAgents).Outcome)
}

func TestRateLimitRetry(t *testing.T) {
	m, srv := newMock(t)
	hits := 0
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/organization/usage/completions" && r.URL.Query().Get("page") == "" {
			hits++
			if hits == 1 {
				w.Header().Set("Retry-After", "0")
				writeStatus(w, http.StatusTooManyRequests, `{"error":{"message":"Too many management requests.","type":"rate_limit_error","param":null,"code":null}}`)
				return true
			}
		}
		return false
	}
	c, _ := newTestConnector(srv)
	res := c.Scan(context.Background(), testConn(srv.URL, false), testWindow())
	r := callResult(t, res, callUsage)
	assert.Equal(t, models.ShadowCallOK, r.Outcome)
	assert.Equal(t, 8, r.Items)
	assert.Len(t, m.requestsTo("/v1/organization/usage/completions"), 3)
}

func TestMalformedJSON(t *testing.T) {
	m, srv := newMock(t)
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/organization/audit_logs" {
			writeStatus(w, http.StatusOK, `{"object":"list","data":[{"id":`)
			return true
		}
		if r.URL.Path == "/v1/organization/usage/web_search_calls" {
			writeStatus(w, http.StatusOK, `{"object":"page","results":[]}`)
			return true
		}
		return false
	}
	c, _ := newTestConnector(srv)
	res := c.Scan(context.Background(), testConn(srv.URL, false), testWindow())
	assert.Equal(t, models.ShadowCallUnsupported, callResult(t, res, callAuditLogs).Outcome)
	assert.Equal(t, models.ShadowCallUnsupported, callResult(t, res, callWebSearch).Outcome, "no data list is a shape change")
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callUsage).Outcome)
	// Without audit logs the owner hints come from the listing alone.
	f := finding(t, res, models.ShadowKindAPIKey, "key_alpha1")
	assert.Nil(t, f.OwnerHint.CreatedAt)
}

func TestAgentsBetaRemovedContinues(t *testing.T) {
	m, srv := newMock(t)
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/agents" && r.Header.Get("Authorization") == "Bearer "+betaKey {
			m.serveStatus(w, http.StatusBadRequest, "error_agents_beta.json")
			return true
		}
		return false
	}
	c, _ := newTestConnector(srv)
	res := c.Scan(context.Background(), testConn(srv.URL, false), testWindow())
	r := callResult(t, res, callAgents)
	assert.Equal(t, models.ShadowCallFailed, r.Outcome)
	assert.Contains(t, r.Message, "invalid_beta")
	assert.Contains(t, r.Message, "1 of 2 scopes failed")
	assert.Equal(t, 1, r.Items)
	finding(t, res, models.ShadowKindPlatformAgent, "agent_alpha")
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callUsage).Outcome)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callCodeInterpreter).Outcome)
}

func TestKeyListingFailureClearsKeysListed(t *testing.T) {
	m, srv := newMock(t)
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/organization/projects/proj_beta/api_keys" {
			writeStatus(w, http.StatusForbidden, `{"error":"forbidden"}`)
			return true
		}
		return false
	}
	c, _ := newTestConnector(srv)
	res := c.Scan(context.Background(), testConn(srv.URL, false), testWindow())
	assert.False(t, res.KeysListed)
	assert.Equal(t, models.ShadowCallPermissionDenied, callResult(t, res, callAPIKeys).Outcome)
	assert.Len(t, res.Keys, 2)
}

func TestConnectionTest(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		m, srv := newMock(t)
		c, _ := newTestConnector(srv)
		info := c.Test(context.Background(), testConn(srv.URL, true))
		assert.True(t, info.OK)
		names := map[string]models.ShadowConnectionCheck{}
		for _, ch := range info.Checks {
			names[ch.Name] = ch
			assert.Equal(t, models.ShadowCallOK, ch.Outcome, ch.Name)
		}
		for _, n := range []string{
			checkProjects, checkAPIKeys, checkUsage, checkCosts, checkSearch, checkCodeInterpreter, checkAuditLogs,
			"Agents (project proj_alpha)", "Agents (project proj_beta)", "Stored chat completions (project proj_alpha)", "Batches (project proj_beta)",
		} {
			assert.Contains(t, names, n)
		}
		assert.Equal(t, []string{sa.SigOpenAIAgentObject}, names["Agents (project proj_alpha)"].Unlocks)
		assert.Equal(t, []string{sa.SigOpenAIPlainUsage, sa.SigOpenAIAgentsAPIUsage}, names[checkUsage].Unlocks)
		for _, r := range m.requests() {
			assert.Equal(t, "1", r.URL.Query().Get("limit"), r.URL.Path)
		}
		ag := m.requestsTo("/v1/agents")
		require.NotEmpty(t, ag)
		assert.Equal(t, "agents=v1", ag[0].Header.Get("OpenAI-Beta"))
		assert.Len(t, m.requestsTo("/v1/organization/projects/proj_alpha/api_keys"), 1)
	})
	t.Run("project keys only", func(t *testing.T) {
		m, srv := newMock(t)
		c, _ := newTestConnector(srv)
		conn := testConn(srv.URL, true)
		conn.Secret.APIKey = ""
		info := c.Test(context.Background(), conn)
		assert.True(t, info.OK, "every project key can list its agents")
		for _, n := range []string{checkProjects, checkAPIKeys, checkUsage, checkCosts, checkSearch, checkCodeInterpreter, checkAuditLogs} {
			found := false
			for _, ch := range info.Checks {
				if ch.Name == n {
					found = true
					assert.Equal(t, models.ShadowCallSkipped, ch.Outcome, n)
					assert.Equal(t, reasonNeedsAdminKey, ch.Message, n)
				}
			}
			assert.True(t, found, n)
		}
		for _, r := range m.requests() {
			assert.NotContains(t, r.URL.Path, "/organization/")
		}
		assert.Len(t, m.requestsTo("/v1/agents"), 2)
	})
	t.Run("project keys only, one rejected", func(t *testing.T) {
		m, srv := newMock(t)
		m.override = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/v1/agents" && r.Header.Get("Authorization") == "Bearer "+betaKey {
				writeStatus(w, http.StatusUnauthorized, `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}`)
				return true
			}
			return false
		}
		c, _ := newTestConnector(srv)
		conn := testConn(srv.URL, false)
		conn.Secret.APIKey = ""
		info := c.Test(context.Background(), conn)
		assert.False(t, info.OK, "a rejected project key fails the test")
	})
	t.Run("admin key rejected", func(t *testing.T) {
		m, srv := newMock(t)
		c, _ := newTestConnector(srv)
		conn := testConn(srv.URL, false)
		conn.Secret.APIKey = "sk-wrong-key-0000000000"
		info := c.Test(context.Background(), conn)
		assert.False(t, info.OK)
		require.NotEmpty(t, info.Checks)
		assert.Equal(t, models.ShadowCallAuthFailed, info.Checks[0].Outcome)
		for _, ch := range info.Checks[1:7] {
			assert.Equal(t, models.ShadowCallSkipped, ch.Outcome, ch.Name)
		}
		assert.Len(t, m.requestsTo("/v1/organization/projects"), 1)
		assert.Len(t, m.requestsTo("/v1/agents"), 2, "project keys are still checked")
		b, _ := json.Marshal(info)
		assert.NotContains(t, string(b), "sk-wrong-key")
	})
	t.Run("one capability denied", func(t *testing.T) {
		m, srv := newMock(t)
		m.override = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/v1/agents" && r.Header.Get("Authorization") == "Bearer "+alphaKey {
				writeStatus(w, http.StatusForbidden, `{"error":{"type":"permission_error","code":"missing_scope","message":"The API key lacks the required permission","param":null}}`)
				return true
			}
			return false
		}
		c, _ := newTestConnector(srv)
		info := c.Test(context.Background(), testConn(srv.URL, false))
		assert.True(t, info.OK, "agents are optional")
		for _, ch := range info.Checks {
			if ch.Name == "Agents (project proj_alpha)" {
				assert.Equal(t, models.ShadowCallPermissionDenied, ch.Outcome)
				assert.Contains(t, ch.Message, "lacks the required permission")
			}
		}
	})
	t.Run("usage denied fails the test", func(t *testing.T) {
		m, srv := newMock(t)
		m.override = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/v1/organization/usage/completions" {
				writeStatus(w, http.StatusForbidden, `{"error":"insufficient permissions"}`)
				return true
			}
			return false
		}
		c, _ := newTestConnector(srv)
		info := c.Test(context.Background(), testConn(srv.URL, false))
		assert.False(t, info.OK)
	})
}
