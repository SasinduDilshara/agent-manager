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

package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

var testNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// harness is a connector wired to a mock server, with captured logs and
// recorded sleeps.
type harness struct {
	m      *mockServer
	c      *Connector
	logs   *bytes.Buffer
	mu     sync.Mutex
	sleeps []time.Duration
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{m: newMock(t), logs: &bytes.Buffer{}}
	logger := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.c = New(h.m.srv.Client(), logger).(*Connector)
	h.c.now = func() time.Time { return testNow }
	h.c.sleep = func(_ context.Context, d time.Duration) error {
		h.mu.Lock()
		h.sleeps = append(h.sleeps, d)
		h.mu.Unlock()
		return nil
	}
	return h
}

func (h *harness) conn() sa.Connection {
	return sa.Connection{
		Provider: models.ShadowProviderAnthropic,
		Config: models.ShadowConnectionConfig{
			Endpoints:      map[string]string{sa.EPAnthropicAPI: h.m.srv.URL},
			DeepInspection: true,
		},
		Secret: models.ShadowConnectionSecret{APIKey: adminKey, ScopedKeys: map[string]string{wsA: wsKey}},
	}
}

func (h *harness) scan(conn sa.Connection) *sa.Result {
	return h.c.Scan(context.Background(), conn, sa.NewWindow(testNow, 30))
}

func findingOf(t *testing.T, res *sa.Result, kind, id string) *sa.Finding {
	t.Helper()
	for _, f := range res.Findings {
		if f.Kind == kind && f.ExternalID == id {
			return f
		}
	}
	t.Fatalf("no %s finding %s", kind, id)
	return nil
}

func hasFinding(res *sa.Result, kind, id string) bool {
	for _, f := range res.Findings {
		if f.Kind == kind && f.ExternalID == id {
			return true
		}
	}
	return false
}

func signalOf(f *sa.Finding, code string) (sa.Signal, bool) {
	for _, s := range f.Signals {
		if s.Code == code {
			return s, true
		}
	}
	return sa.Signal{}, false
}

func callOf(t *testing.T, res *sa.Result, call string) models.ShadowScanCallResult {
	t.Helper()
	for _, c := range res.Calls {
		if c.Call == call {
			return c
		}
	}
	t.Fatalf("call %q not recorded; calls: %+v", call, res.Calls)
	return models.ShadowScanCallResult{}
}

func day(s string) time.Time {
	t, _ := time.Parse(time.DateOnly, s)
	return t
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestScanFirstPartyCalls(t *testing.T) {
	h := newHarness(t)
	res := h.scan(h.conn())
	want := map[string]int{
		callWorkspaces: 2, callUsers: 2, callAPIKeys: 3, callUsage: 6, callCost: 4,
		callAgents: 2, callSessions: 2, callEvents: 8, callBatches: 4, callBatchResults: 5,
	}
	for call, items := range want {
		c := callOf(t, res, call)
		if c.Outcome != models.ShadowCallOK || c.Items != items {
			t.Errorf("%s: outcome %s items %d (%s), want ok %d", call, c.Outcome, c.Items, c.Message, items)
		}
	}
	if !res.KeysListed {
		t.Error("KeysListed should be true when the key listing succeeded")
	}
	if c := callOf(t, res, callAgents+" (workspaces without a key)"); c.Outcome != models.ShadowCallSkipped ||
		c.Message != "no workspace key for 1 of 2 workspaces ("+wsB+"); their Managed Agents, sessions and batches are not read" {
		t.Errorf("workspaces without a key = %+v", c)
	}
	if len(res.Findings) != 5 {
		var ids []string
		for _, f := range res.Findings {
			ids = append(ids, f.Kind+":"+f.ExternalID)
		}
		t.Errorf("findings = %v, want keys A, B, C and the two agents", ids)
	}
}

func TestRequestBuilding(t *testing.T) {
	h := newHarness(t)
	h.scan(h.conn())
	m := h.m

	ws := m.requestsTo("fp /v1/organizations/workspaces")
	if len(ws) != 2 {
		t.Fatalf("workspaces pages = %d, want 2", len(ws))
	}
	q := queryOf(t, ws[0].RawQuery)
	if q.Get("include_default") != "true" || q.Get("limit") != "1000" || q.Get("after_id") != "" {
		t.Errorf("workspaces page 1 query = %s", ws[0].RawQuery)
	}
	if queryOf(t, ws[1].RawQuery).Get("after_id") != wsA {
		t.Errorf("workspaces page 2 query = %s, want after_id=last_id", ws[1].RawQuery)
	}
	for _, route := range []string{"fp /v1/organizations/users", "fp /v1/organizations/api_keys"} {
		reqs := m.requestsTo(route)
		if len(reqs) != 2 || queryOf(t, reqs[1].RawQuery).Get("after_id") == "" {
			t.Errorf("%s: want 2 pages with after_id, got %d", route, len(reqs))
		}
		if q := queryOf(t, reqs[0].RawQuery); q.Get("limit") != "1000" || q.Has("status") {
			t.Errorf("%s: query %s (all statuses are listed, no status filter)", route, reqs[0].RawQuery)
		}
	}

	usage := m.requestsTo("fp /v1/organizations/analytics/usage")
	if len(usage) != 2 {
		t.Fatalf("usage pages = %d, want 2", len(usage))
	}
	wantUsage := "ending_at=2026-11-10T00%3A00%3A00Z&group_by[]=api_key_id&group_by[]=model&group_by[]=product&group_by[]=agent_id" +
		"&limit=1000&starting_at=2026-10-11T00%3A00%3A00Z&time_bucket_width=1d"
	if usage[0].RawQuery != wantUsage {
		t.Errorf("usage query =\n%s\nwant\n%s", usage[0].RawQuery, wantUsage)
	}
	if queryOf(t, usage[1].RawQuery).Get("page") != "page_2" {
		t.Errorf("usage page 2 query = %s", usage[1].RawQuery)
	}
	cost := m.requestsTo("fp /v1/organizations/analytics/cost")
	if len(cost) != 2 || !strings.Contains(cost[0].RawQuery, "group_by[]=agent_id&group_by[]=cost_type") {
		t.Errorf("cost requests %d, query %s", len(cost), cost[0].RawQuery)
	}
	// One analytics request a second: 4 requests, 3 waits of 1s.
	if len(h.sleeps) != 3 || h.sleeps[0] != time.Second {
		t.Errorf("analytics pacing sleeps = %v, want 3 x 1s", h.sleeps)
	}

	agents := m.requestsTo("fp /v1/agents")
	if len(agents) != 2 {
		t.Fatalf("agents pages = %d", len(agents))
	}
	if q := queryOf(t, agents[0].RawQuery); q.Get("include_archived") != "true" || q.Get("limit") != "100" {
		t.Errorf("agents query = %s", agents[0].RawQuery)
	}
	if queryOf(t, agents[1].RawQuery).Get("page") != "page_2" {
		t.Errorf("agents page 2 query = %s", agents[1].RawQuery)
	}
	sessions := m.requestsTo("fp /v1/sessions")
	var agent1Pages int
	for _, r := range sessions {
		q := queryOf(t, r.RawQuery)
		if q.Get("include_archived") != "true" || q.Get("order") != "desc" {
			t.Errorf("sessions query = %s", r.RawQuery)
		}
		if q.Get("agent_id") == agent1 {
			agent1Pages++
		}
	}
	if agent1Pages != 2 || len(sessions) != 3 {
		t.Errorf("sessions requests = %d (agent 1 pages %d), want 3 (2)", len(sessions), agent1Pages)
	}
	events := m.requestsTo("fp /v1/sessions/{id}/events")
	if len(events) != 4 {
		t.Fatalf("events requests = %d, want 2 sessions x 2 pages", len(events))
	}
	if !strings.HasPrefix(events[0].RawQuery, "types[]=agent.tool_use&types[]=agent.custom_tool_use&types[]=agent.mcp_tool_use") {
		t.Errorf("events query = %s", events[0].RawQuery)
	}
	if !strings.HasPrefix(events[0].Path, "/v1/sessions/sesn_011CZkZAtmR3yMPDzynEDxu7/events") {
		t.Errorf("events path = %s", events[0].Path)
	}
	batches := m.requestsTo("fp /v1/messages/batches")
	if len(batches) != 2 || queryOf(t, batches[1].RawQuery).Get("after_id") != "msgbatch_02InProgressXXXXXXXXXX" {
		t.Errorf("batches requests = %d", len(batches))
	}
	results := m.requestsTo("fp /v1/messages/batches/{id}/results")
	if len(results) != 2 {
		t.Fatalf("results requests = %d, want 2 (ended, succeeded, within 29 days)", len(results))
	}
	if results[0].Path != "/v1/messages/batches/msgbatch_01ToolUseXXXXXXXXXXXX/results" ||
		results[1].Path != "/v1/messages/batches/msgbatch_04PlainXXXXXXXXXXXXXX/results" {
		t.Errorf("results paths = %s, %s", results[0].Path, results[1].Path)
	}
	if !strings.Contains(strings.Join(results[0].Header.Values("Accept"), ","), "application/x-jsonl") {
		t.Errorf("results Accept = %v", results[0].Header.Values("Accept"))
	}
}

func TestKeysAndOwnerHints(t *testing.T) {
	h := newHarness(t)
	res := h.scan(h.conn())
	if len(res.Keys) != 3 {
		t.Fatalf("keys = %d", len(res.Keys))
	}
	byID := map[string]sa.Key{}
	for _, k := range res.Keys {
		byID[k.KeyID] = k
	}
	a := byID[keyA]
	if a.Name != "Developer Key" || a.RedactedHint != "sk-ant-api03-R2D...igAA" || a.Status != "active" || a.Scope != "workspace:"+wsA {
		t.Errorf("key A = %+v", a)
	}
	if a.OwnerHint.Email != "user@emaildomain.com" || a.OwnerHint.Name != "Jane Doe" || a.OwnerHint.Type != "user" ||
		a.OwnerHint.Source != "GET /v1/organizations/api_keys (created_by) + GET /v1/organizations/users" {
		t.Errorf("key A owner = %+v", a.OwnerHint)
	}
	if a.CreatedAt == nil || a.OwnerHint.CreatedAt == nil {
		t.Error("key A created time missing")
	}
	if a.LastUsedAt == nil || !a.LastUsedAt.Equal(day("2026-10-25")) {
		t.Errorf("key A last used = %v, want the last usage bucket 2026-10-25", a.LastUsedAt)
	}
	b := byID[keyB]
	if b.Status != "inactive" || b.OwnerHint.Username != "svac_01ServiceAccountXXXXX" || b.OwnerHint.Type != "service_account" || b.OwnerHint.Email != "" {
		t.Errorf("key B = %+v", b)
	}
	if b.LastUsedAt != nil {
		t.Errorf("key B had no requests, last used = %v", b.LastUsedAt)
	}
	c := byID[keyC]
	if c.Scope != "organization" || c.OwnerHint.Name != "Sam Second" || c.OwnerHint.Source != "GET /v1/organizations/api_keys (principal) + GET /v1/organizations/users" {
		t.Errorf("key C = %+v", c)
	}

	fa := findingOf(t, res, models.ShadowKindAPIKey, keyA)
	if fa.DisplayName != "Developer Key" || fa.State != "active" || fa.Scope != "workspace:"+wsA || fa.OwnerHint.Email != "user@emaildomain.com" {
		t.Errorf("key A finding = %+v", fa)
	}
	if fa.Attributes["workspace"] != wsA || len(fa.KeyIDs) != 1 || fa.KeyIDs[0] != keyA {
		t.Errorf("key A attributes %v keyIDs %v", fa.Attributes, fa.KeyIDs)
	}
	if models, _ := fa.Attributes["models"].([]string); len(models) != 1 || models[0] != "claude-opus-5-5" {
		t.Errorf("key A models = %v", fa.Attributes["models"])
	}
	if fb := findingOf(t, res, models.ShadowKindAPIKey, keyB); fb.State != "inactive" || len(fb.Signals) != 0 || len(fb.Usage) != 0 {
		t.Errorf("key B finding = %+v", fb)
	}
}

func TestSignals(t *testing.T) {
	h := newHarness(t)
	res := h.scan(h.conn())
	fa := findingOf(t, res, models.ShadowKindAPIKey, keyA)
	fb := findingOf(t, res, models.ShadowKindAPIKey, keyB)
	fc := findingOf(t, res, models.ShadowKindAPIKey, keyC)
	ag := findingOf(t, res, models.ShadowKindPlatformAgent, agent1)
	old := findingOf(t, res, models.ShadowKindPlatformAgent, agentArchived)

	type expect struct {
		name string
		f    *sa.Finding
		code string
		want bool
		obs  map[string]any
	}
	cases := []expect{
		// Plain usage: requests > 0 on rows without agent_id, per key.
		{"plain usage key A", fa, sa.SigAnthropicPlainUsage, true, map[string]any{"requests": int64(133)}},
		{"plain usage key B (requests 0)", fb, sa.SigAnthropicPlainUsage, false, nil},
		{"no plain usage on the agent", ag, sa.SigAnthropicPlainUsage, false, nil},
		// Managed Agent usage: agent_id != null and requests > 0.
		{"agent usage", ag, sa.SigAnthropicManagedAgentUsage, true, map[string]any{"requests": int64(40)}},
		{"no agent usage on the key", fa, sa.SigAnthropicManagedAgentUsage, false, nil},
		// Server web search: web_search_requests > 0.
		{"web search key A", fa, sa.SigAnthropicServerWebSearch, true, map[string]any{"webSearchRequests": int64(10)}},
		{"web search key B", fb, sa.SigAnthropicServerWebSearch, false, nil},
		{"web search agent (0)", ag, sa.SigAnthropicServerWebSearch, false, nil},
		// Server code execution: cost_type == code_execution (amount > 0).
		{"code execution key A", fa, sa.SigAnthropicServerCodeExec, true, map[string]any{"costRows": 1}},
		{"code execution key B (amount 0)", fb, sa.SigAnthropicServerCodeExec, false, nil},
		// Managed Agent object: any listed agent.
		{"agent object", ag, sa.SigAnthropicManagedAgent, true, map[string]any{"archived": false}},
		{"archived agent object", old, sa.SigAnthropicManagedAgent, true, map[string]any{"archived": true}},
		// Session tool use: 2 tool events in each of 2 sessions (agent.message and
		// user.message are not tool use).
		{"session tool use", ag, sa.SigAnthropicSessionToolUse, true, map[string]any{"toolUseEvents": int64(4), "sessions": int64(2)}},
		{"no sessions, no tool use", old, sa.SigAnthropicSessionToolUse, false, nil},
		// Batch tool call: the only key that can act in workspace A with usage.
		{"batch tool call key A", fa, sa.SigAnthropicToolCallBatch, true, map[string]any{"batchesWithToolUse": int64(1), "toolUseResults": int64(2)}},
		{"batch tool call key C (no usage)", fc, sa.SigAnthropicToolCallBatch, false, nil},
	}
	for _, c := range cases {
		s, ok := signalOf(c.f, c.code)
		if ok != c.want {
			t.Errorf("%s: signal %s present = %v, want %v", c.name, c.code, ok, c.want)
			continue
		}
		if !ok {
			continue
		}
		for k, v := range c.obs {
			if s.Observed[k] != v {
				t.Errorf("%s: observed[%s] = %v (%T), want %v", c.name, k, s.Observed[k], s.Observed[k], v)
			}
		}
		if _, known := sa.Def(s.Code); !known || s.Source == "" {
			t.Errorf("%s: signal %+v", c.name, s)
		}
	}
	if hasFinding(res, models.ShadowKindPlatformAgent, "agent_02UnlistedAgentXXXXXXX") {
		t.Error("an agent row with zero requests and tokens must not create a finding")
	}
	score, verdict := sa.Score(ag.Kind, codes(ag))
	if verdict != models.ShadowVerdictAgent || score < sa.AgentThreshold {
		t.Errorf("agent score %d verdict %s", score, verdict)
	}
}

func codes(f *sa.Finding) []string {
	var out []string
	for _, s := range f.Signals {
		out = append(out, s.Code)
	}
	return out
}

func TestUsageAggregation(t *testing.T) {
	h := newHarness(t)
	res := h.scan(h.conn())
	fa := findingOf(t, res, models.ShadowKindAPIKey, keyA)
	ag := findingOf(t, res, models.ShadowKindPlatformAgent, agent1)

	type row struct {
		day, key, model string
		req, in, out    int64
		cost            float64 // -1: none
	}
	check := func(name string, got []sa.UsageDay, want []row) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s usage = %+v, want %d rows", name, got, len(want))
		}
		for i, w := range want {
			g := got[i]
			if !g.Day.Equal(day(w.day)) || g.KeyID != w.key || g.Model != w.model || g.Requests != w.req ||
				g.InputTokens != w.in || g.OutputTokens != w.out {
				t.Errorf("%s usage[%d] = %+v, want %+v", name, i, g, w)
			}
			switch {
			case w.cost < 0 && g.CostAmount != nil:
				t.Errorf("%s usage[%d] cost = %v, want none", name, i, *g.CostAmount)
			case w.cost >= 0 && (g.CostAmount == nil || !approx(*g.CostAmount, w.cost) || g.Currency != "USD"):
				t.Errorf("%s usage[%d] cost = %v %s, want %v USD", name, i, g.CostAmount, g.Currency, w.cost)
			}
		}
	}
	// Key A: its own rows only; the agent's 2026-10-21 row is not counted
	// here. Input = uncached + cache creation + cache read. Cost "41280.000000"
	// cents = 412.80 USD; code execution "150.000000" = 1.50 (model null).
	check("key A", fa.Usage, []row{
		{"2026-10-20", keyA, "", 0, 0, 0, 1.5},
		{"2026-10-20", keyA, "claude-opus-5-5", 128, 1060, 500, 412.80},
		{"2026-10-25", keyA, "claude-opus-5-5", 5, 50, 25, -1},
	})
	check("agent", ag.Usage, []row{{"2026-10-21", keyA, "claude-opus-5-5", 40, 400, 200, 5}})

	if fa.FirstUsedAt == nil || !fa.FirstUsedAt.Equal(day("2026-10-20")) || !fa.LastUsedAt.Equal(day("2026-10-25")) {
		t.Errorf("key A used %v .. %v", fa.FirstUsedAt, fa.LastUsedAt)
	}
	// Agent: analytics day, sessions and session events within the window.
	if !ag.FirstUsedAt.Equal(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)) || !ag.LastUsedAt.Equal(time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC)) {
		t.Errorf("agent used %v .. %v", ag.FirstUsedAt, ag.LastUsedAt)
	}
	// The key used by the agent is linked both ways.
	if len(ag.KeyIDs) != 1 || ag.KeyIDs[0] != keyA {
		t.Errorf("agent keys = %v", ag.KeyIDs)
	}
	if len(fa.Related) != 1 || fa.Related[0].ExternalID != agent1 || fa.Related[0].Relation != "used_by_agent" ||
		fa.Related[0].Kind != models.ShadowKindPlatformAgent {
		t.Errorf("key A related = %+v", fa.Related)
	}
}

func TestAgentAttributes(t *testing.T) {
	h := newHarness(t)
	res := h.scan(h.conn())
	ag := findingOf(t, res, models.ShadowKindPlatformAgent, agent1)
	if ag.DisplayName != "My First Agent" || ag.State != "active" || ag.Scope != "workspace:"+wsA ||
		ag.ProviderCreatedAt == nil || !ag.ProviderCreatedAt.Equal(time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("agent = %+v", ag)
	}
	a := ag.Attributes
	if a["model"] != "claude-opus-5-5" || a["workspace"] != wsA || a["agentVersion"] != int64(3) || a["archived"] != false ||
		a["description"] != "A general-purpose starter agent." || a["toolCount"] != 3 {
		t.Errorf("agent attributes = %v", a)
	}
	tools, _ := a["tools"].([]sa.ToolRef)
	wantTools := []sa.ToolRef{{Type: "agent_toolset_20260401", Name: "bash"}, {Type: "mcp_toolset", Name: "example-mcp"}, {Type: "custom", Name: "lookup_order"}}
	if len(tools) != len(wantTools) {
		t.Fatalf("tools = %v", tools)
	}
	for i := range wantTools {
		if tools[i] != wantTools[i] {
			t.Errorf("tools[%d] = %v, want %v", i, tools[i], wantTools[i])
		}
	}
	mcp, _ := a["mcpServers"].([]sa.MCPServerRef)
	if len(mcp) != 1 || mcp[0] != (sa.MCPServerRef{Label: "example-mcp", Origin: "https://example-server.modelcontextprotocol.io"}) {
		t.Errorf("mcpServers = %v", mcp)
	}
	if skills, _ := a["skills"].([]string); len(skills) != 2 || skills[0] != "xlsx" {
		t.Errorf("skills = %v", a["skills"])
	}
	if a["repositoryUrl"] != "https://github.com/example-org/example-repo" || a["sessionCount"] != 2 || a["lastSessionAt"] != "2026-11-02T09:30:00Z" {
		t.Errorf("session attributes = %v %v %v", a["repositoryUrl"], a["sessionCount"], a["lastSessionAt"])
	}
	old := findingOf(t, res, models.ShadowKindPlatformAgent, agentArchived)
	if old.State != "archived" || old.Attributes["archived"] != true || old.Attributes["roleArn"] != "arn:aws:iam::123456789012:role/agent-exec" {
		t.Errorf("archived agent = %+v", old)
	}
}

func TestRetention(t *testing.T) {
	h := newHarness(t)
	conn := h.conn()
	res := h.scan(conn)
	info := h.c.Test(context.Background(), conn)
	out, err := json.Marshal(struct {
		R *sa.Result
		I models.ShadowConnectionTestInfo
	}{res, info})
	if err != nil {
		t.Fatal(err)
	}
	markers := []string{
		secretMarker, "SECRET-PROMPT-MARKER", "SECRET-INPUT-MARKER", "SECRET-SCHEMA-MARKER", "SECRET-METADATA-MARKER",
		"You are a general-purpose agent", "Where is my order", "Hello again", "token=", "user:",
	}
	for _, mk := range markers {
		if bytes.Contains(out, []byte(mk)) {
			t.Errorf("result contains %q", mk)
		}
		if strings.Contains(h.logs.String(), mk) {
			t.Errorf("logs contain %q", mk)
		}
	}
	if !strings.Contains(h.logs.String(), "Shadow agent discovery provider call") {
		t.Error("expected debug call logs to be captured")
	}
	// A query string is never logged.
	if strings.Contains(h.logs.String(), "group_by") || strings.Contains(h.logs.String(), "agent_id=") {
		t.Error("logs contain a query string")
	}
}

func TestDeepInspectionOff(t *testing.T) {
	h := newHarness(t)
	for _, r := range []string{"fp /v1/sessions/{id}/events", "fp /v1/messages/batches", "fp /v1/messages/batches/{id}/results"} {
		h.m.forbid[r] = true
	}
	conn := h.conn()
	conn.Config.DeepInspection = false
	res := h.scan(conn)
	for _, call := range []string{callEvents, callBatches, callBatchResults} {
		c := callOf(t, res, call)
		if c.Outcome != models.ShadowCallSkipped || c.Message != "deep inspection is off" {
			t.Errorf("%s = %+v", call, c)
		}
	}
	ag := findingOf(t, res, models.ShadowKindPlatformAgent, agent1)
	if _, ok := signalOf(ag, sa.SigAnthropicSessionToolUse); ok {
		t.Error("session tool use without deep inspection")
	}
	// Agents and sessions (metadata) are still read.
	if callOf(t, res, callAgents).Outcome != models.ShadowCallOK || callOf(t, res, callSessions).Items != 2 {
		t.Error("agents and sessions should still be listed")
	}
}

func TestNoWorkspaceKeys(t *testing.T) {
	h := newHarness(t)
	for _, r := range []string{"fp /v1/agents", "fp /v1/sessions", "fp /v1/messages/batches"} {
		h.m.forbid[r] = true
	}
	conn := h.conn()
	conn.Secret.ScopedKeys = nil
	res := h.scan(conn)
	if c := callOf(t, res, callAgents); c.Outcome != models.ShadowCallSkipped || c.Message != "no workspace keys" {
		t.Errorf("agents = %+v", c)
	}
	// Agent usage from analytics still makes the agent a finding.
	ag := findingOf(t, res, models.ShadowKindPlatformAgent, agent1)
	if ag.DisplayName != agent1 || ag.Scope != "organization" {
		t.Errorf("unlisted agent = %+v", ag)
	}
	if _, ok := signalOf(ag, sa.SigAnthropicManagedAgentUsage); !ok {
		t.Error("agent usage signal missing")
	}
}

func TestBatchAttributionSeveralKeys(t *testing.T) {
	h := newHarness(t)
	// The org-scoped key C also had usage: two keys can act in workspace A,
	// so the batch tool use cannot be tied to one.
	h.m.override["fp /v1/organizations/analytics/usage"] = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("page") != "" {
			return false
		}
		writeJSON(w, `{"data":[
		 {"starting_at":"2026-10-20T00:00:00Z","ending_at":"2026-10-21T00:00:00Z","group":{"api_key_id":"`+keyA+`","agent_id":null,"model":"claude-opus-5-5","product":"messages_api"},"usage":{"uncached_input_tokens":1,"cache_creation":{"ephemeral_1h_input_tokens":0,"ephemeral_5m_input_tokens":0},"cache_read_input_tokens":0,"output_tokens":1,"total_tokens":2,"server_tool_use":{"web_search_requests":0},"requests":1}},
		 {"starting_at":"2026-10-20T00:00:00Z","ending_at":"2026-10-21T00:00:00Z","group":{"api_key_id":"`+keyC+`","agent_id":null,"model":"claude-opus-5-5","product":"messages_api"},"usage":{"uncached_input_tokens":1,"cache_creation":{"ephemeral_1h_input_tokens":0,"ephemeral_5m_input_tokens":0},"cache_read_input_tokens":0,"output_tokens":1,"total_tokens":2,"server_tool_use":{"web_search_requests":0},"requests":1}}
		],"has_more":false,"next_page":null,"data_refreshed_at":null}`)
		return true
	}
	res := h.scan(h.conn())
	for _, k := range []string{keyA, keyC} {
		if _, ok := signalOf(findingOf(t, res, models.ShadowKindAPIKey, k), sa.SigAnthropicToolCallBatch); ok {
			t.Errorf("key %s got the workspace-level batch signal", k)
		}
	}
	c := callOf(t, res, "tool calls in batch results of workspace "+wsA+" (on the workspace finding)")
	if c.Outcome != models.ShadowCallSkipped || !strings.Contains(c.Message, "2 batch results with tool use in 1 batches") ||
		!strings.Contains(c.Message, "2 keys") {
		t.Errorf("attribution note = %+v", c)
	}
	// The evidence is on the workspace's finding, linked to both keys and to
	// the workspace's Managed Agents.
	wf := findingOf(t, res, models.ShadowKindProject, "workspace:"+wsA)
	sig, ok := signalOf(wf, sa.SigAnthropicToolCallBatch)
	if !ok || sig.Observed["batchesWithToolUse"] != int64(1) || sig.Observed["toolUseResults"] != int64(2) {
		t.Errorf("workspace finding signal = %+v (ok=%v)", sig, ok)
	}
	if wf.DisplayName != "Workspace "+wsA || wf.Scope != "workspace:"+wsA || wf.Attributes["workspace"] != wsA {
		t.Errorf("workspace finding = %+v", wf)
	}
	keys, agents := map[string]bool{}, map[string]bool{}
	for _, r := range wf.Related {
		switch r.Relation {
		case "candidate_key":
			keys[r.ExternalID] = r.Kind == models.ShadowKindAPIKey
		case "agent_in_project":
			agents[r.ExternalID] = r.Kind == models.ShadowKindPlatformAgent
		}
	}
	if len(keys) != 2 || !keys[keyA] || !keys[keyC] {
		t.Errorf("candidate keys = %v", keys)
	}
	wantAgents := map[string]bool{}
	for _, f := range res.Findings {
		if f.Kind == models.ShadowKindPlatformAgent && f.Scope == "workspace:"+wsA {
			wantAgents[f.ExternalID] = true
		}
	}
	if len(wantAgents) == 0 || len(agents) != len(wantAgents) {
		t.Errorf("agents linked = %v, want %v", agents, wantAgents)
	}
	for id := range wantAgents {
		if !agents[id] {
			t.Errorf("agent %s not linked", id)
		}
	}
}

// TestWorkspaceKeysOnly: without an Admin key the organization routes are
// never called, the workspace with a key is scanned, and batch tool use goes
// on the workspace finding with no candidate keys.
func TestWorkspaceKeysOnly(t *testing.T) {
	h := newHarness(t)
	conn := h.conn()
	conn.Secret.APIKey = ""
	res := h.scan(conn)
	for _, call := range []string{callWorkspaces, callUsers, callAPIKeys, callUsage, callCost} {
		c := callOf(t, res, call)
		if c.Outcome != models.ShadowCallSkipped || c.Message != reasonNeedsAdminKey {
			t.Errorf("%s = %+v", call, c)
		}
	}
	h.m.mu.Lock()
	recs := append([]recorded{}, h.m.requests...)
	h.m.mu.Unlock()
	for _, r := range recs {
		if strings.Contains(r.Path, "/v1/organizations/") {
			t.Errorf("organization route called without an Admin key: %s", r.Path)
		}
		if r.Header.Get("x-api-key") == adminKey {
			t.Errorf("the Admin key was sent")
		}
	}
	if res.KeysListed || len(res.Keys) != 0 {
		t.Errorf("keys listed without an Admin key: %v %v", res.KeysListed, res.Keys)
	}
	agents := 0
	for _, f := range res.Findings {
		switch f.Kind {
		case models.ShadowKindPlatformAgent:
			agents++
		case models.ShadowKindProject:
		default:
			t.Errorf("unexpected %s finding %s without an Admin key", f.Kind, f.ExternalID)
		}
	}
	if agents == 0 {
		t.Errorf("no Managed Agents found with the workspace key")
	}
	wf := findingOf(t, res, models.ShadowKindProject, "workspace:"+wsA)
	if _, ok := signalOf(wf, sa.SigAnthropicToolCallBatch); !ok {
		t.Errorf("batch tool use is not on the workspace finding: %+v", wf.Signals)
	}
	for _, r := range wf.Related {
		if r.Relation == "candidate_key" {
			t.Errorf("candidate key without an Admin key: %+v", r)
		}
	}
	c := callOf(t, res, "tool calls in batch results of workspace "+wsA+" (on the workspace finding)")
	if !strings.Contains(c.Message, "no Admin API key") {
		t.Errorf("note = %+v", c)
	}
}

func TestBatchLineHasToolUse(t *testing.T) {
	cases := map[string]bool{
		`{"result":{"type":"succeeded","message":{"stop_reason":"tool_use","content":[{"type":"text"}]}}}`:            true,
		`{"result":{"type":"succeeded","message":{"stop_reason":"end_turn","content":[{"type":"tool_use"}]}}}`:        true,
		`{"result":{"type":"succeeded","message":{"stop_reason":"end_turn","content":[{"type":"text"}]}}}`:            false,
		`{"result":{"type":"succeeded","message":{"stop_reason":"end_turn","content":[{"type":"server_tool_use"}]}}}`: false,
		`{"result":{"type":"errored","error":{"type":"error","error":{"type":"api_error","message":"x"}}}}`:           false,
		`{"result":{"type":"canceled"}}`: false,
	}
	for line, want := range cases {
		var r batchResultLine
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if got := batchLineHasToolUse(&r); got != want {
			t.Errorf("%s: %v, want %v", line, got, want)
		}
	}
}

func TestAnalyticsSpans(t *testing.T) {
	now := testNow
	spans, _, clamped := analyticsSpans(sa.NewWindow(now, 90), now)
	if clamped || len(spans) != 3 {
		t.Fatalf("90 days: %d spans, clamped %v", len(spans), clamped)
	}
	if !spans[0].start.Equal(day("2026-08-12")) || !spans[0].end.Equal(day("2026-09-12")) ||
		!spans[2].end.Equal(day("2026-11-10")) {
		t.Errorf("spans = %+v", spans)
	}
	for _, sp := range spans {
		if sp.end.Sub(sp.start) > 31*24*time.Hour {
			t.Errorf("span longer than 31 days: %+v", sp)
		}
	}
	// A window before 2026-01-01 is clamped.
	early := time.Date(2026, 2, 10, 8, 0, 0, 0, time.UTC)
	spans, floor, clamped := analyticsSpans(sa.NewWindow(early, 90), early)
	if !clamped || !floor.Equal(analyticsEpoch) || !spans[0].start.Equal(analyticsEpoch) {
		t.Errorf("clamp: %+v floor %v clamped %v", spans, floor, clamped)
	}
	// No complete day: nothing to ask.
	if spans, _, _ := analyticsSpans(sa.NewWindow(now, 0), now); len(spans) != 0 {
		t.Errorf("0-day window spans = %+v", spans)
	}
}

func TestAnalyticsWindowClampRecorded(t *testing.T) {
	h := newHarness(t)
	h.c.now = func() time.Time { return time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC) }
	conn := h.conn()
	conn.Secret.ScopedKeys = nil
	res := h.c.Scan(context.Background(), conn, sa.NewWindow(time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC), 30))
	c := callOf(t, res, "analytics before 2026-01-01")
	if c.Outcome != models.ShadowCallSkipped || !strings.Contains(c.Message, "2026-01-01T00:00:00Z") {
		t.Errorf("clamp record = %+v", c)
	}
	q := queryOf(t, h.m.requestsTo("fp /v1/organizations/analytics/usage")[0].RawQuery)
	if q.Get("starting_at") != "2026-01-01T00:00:00Z" || q.Get("ending_at") != "2026-01-20T00:00:00Z" {
		t.Errorf("clamped query = %v", q)
	}
}

func TestAuthFailureStopsEarly(t *testing.T) {
	h := newHarness(t)
	h.m.override["fp /v1/organizations/workspaces"] = func(w http.ResponseWriter, _ *http.Request) bool {
		anthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid x-api-key")
		return true
	}
	for _, r := range []string{"fp /v1/organizations/users", "fp /v1/organizations/api_keys", "fp /v1/organizations/analytics/usage", "fp /v1/organizations/analytics/cost"} {
		h.m.forbid[r] = true
	}
	res := h.scan(h.conn())
	if c := callOf(t, res, callWorkspaces); c.Outcome != models.ShadowCallAuthFailed || !strings.Contains(c.Message, "authentication_error") {
		t.Errorf("workspaces = %+v", c)
	}
	for _, call := range []string{callUsers, callAPIKeys, callUsage, callCost} {
		if c := callOf(t, res, call); c.Outcome != models.ShadowCallSkipped {
			t.Errorf("%s = %+v, want skipped", call, c)
		}
	}
	if res.KeysListed {
		t.Error("KeysListed must be false when the key listing did not run")
	}
	// The workspace key is a separate credential: its calls still run.
	if callOf(t, res, callAgents).Outcome != models.ShadowCallOK {
		t.Error("workspace calls should still run")
	}
}

func TestWorkspaceKeyRejected(t *testing.T) {
	h := newHarness(t)
	h.m.override["fp /v1/agents"] = func(w http.ResponseWriter, _ *http.Request) bool {
		anthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid key")
		return true
	}
	for _, r := range []string{"fp /v1/sessions", "fp /v1/messages/batches"} {
		h.m.forbid[r] = true
	}
	res := h.scan(h.conn())
	for _, call := range []string{callAgents, callSessions, callBatches} {
		if c := callOf(t, res, call); c.Outcome != models.ShadowCallAuthFailed {
			t.Errorf("%s = %+v", call, c)
		}
	}
}

func TestPermissionDeniedOnOneCall(t *testing.T) {
	h := newHarness(t)
	h.m.override["fp /v1/organizations/users"] = func(w http.ResponseWriter, _ *http.Request) bool {
		anthropicError(w, http.StatusForbidden, "permission_error", "not allowed")
		return true
	}
	res := h.scan(h.conn())
	if c := callOf(t, res, callUsers); c.Outcome != models.ShadowCallPermissionDenied {
		t.Errorf("users = %+v", c)
	}
	for _, call := range []string{callAPIKeys, callUsage, callCost, callAgents} {
		if c := callOf(t, res, call); c.Outcome != models.ShadowCallOK {
			t.Errorf("%s = %+v", call, c)
		}
	}
	// Without the users list the creator is kept by ID only.
	k := findingOf(t, res, models.ShadowKindAPIKey, keyA)
	if k.OwnerHint.Username != "user_01WxYzAbCdEfGhJkMnPqRsTu" || k.OwnerHint.Email != "" {
		t.Errorf("owner = %+v", k.OwnerHint)
	}
}

func TestRateLimitedThenOK(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	first := true
	h.m.override["fp /v1/organizations/api_keys"] = func(w http.ResponseWriter, _ *http.Request) bool {
		mu.Lock()
		defer mu.Unlock()
		if first {
			first = false
			w.Header().Set("Retry-After", "0")
			anthropicError(w, http.StatusTooManyRequests, "rate_limit_error", "slow down")
			return true
		}
		return false
	}
	res := h.scan(h.conn())
	if c := callOf(t, res, callAPIKeys); c.Outcome != models.ShadowCallOK || c.Items != 3 {
		t.Errorf("api_keys = %+v", c)
	}
	if !res.KeysListed {
		t.Error("KeysListed after a retried 429")
	}
}

func TestMalformedJSON(t *testing.T) {
	h := newHarness(t)
	h.m.override["fp /v1/agents"] = func(w http.ResponseWriter, _ *http.Request) bool {
		writeJSON(w, `{"data":[{"id":`)
		return true
	}
	h.m.override["fp /v1/organizations/workspaces"] = func(w http.ResponseWriter, _ *http.Request) bool {
		writeJSON(w, `{"object":"list"}`)
		return true
	}
	res := h.scan(h.conn())
	for _, call := range []string{callAgents, callWorkspaces} {
		if c := callOf(t, res, call); c.Outcome != models.ShadowCallUnsupported {
			t.Errorf("%s = %+v, want unsupported_response", call, c)
		}
	}
	if callOf(t, res, callAPIKeys).Outcome != models.ShadowCallOK {
		t.Error("other calls should still run")
	}
}

func TestConnectionTestWorkspaceKeysOnly(t *testing.T) {
	h := newHarness(t)
	conn := h.conn()
	conn.Secret.APIKey = ""
	info := h.c.Test(context.Background(), conn)
	if !info.OK {
		t.Errorf("test = %+v", info)
	}
	skipped := 0
	for _, ch := range info.Checks {
		if ch.Outcome == models.ShadowCallSkipped && ch.Message == reasonNeedsAdminKey {
			skipped++
		}
		if ch.Outcome == models.ShadowCallAuthFailed {
			t.Errorf("check %s failed: %+v", ch.Name, ch)
		}
	}
	if skipped != 3 {
		t.Errorf("admin checks skipped = %d, want 3: %+v", skipped, info.Checks)
	}
	h.m.mu.Lock()
	recs := append([]recorded{}, h.m.requests...)
	h.m.mu.Unlock()
	for _, r := range recs {
		if strings.Contains(r.Path, "/v1/organizations/") {
			t.Errorf("organization route called: %s", r.Path)
		}
	}
}

func TestConnectionTest(t *testing.T) {
	h := newHarness(t)
	info := h.c.Test(context.Background(), h.conn())
	if !info.OK {
		t.Errorf("test = %+v", info)
	}
	want := []string{
		"Admin API key: list API keys", "Usage analytics", "Cost analytics",
		"Workspace " + wsA + ": Managed Agents", "Workspace " + wsA + ": Message batches",
	}
	if len(info.Checks) != len(want) {
		t.Fatalf("checks = %+v", info.Checks)
	}
	for i, c := range info.Checks {
		if c.Name != want[i] || c.Outcome != models.ShadowCallOK {
			t.Errorf("check %d = %+v, want %s ok", i, c, want[i])
		}
	}
	if u := info.Checks[1].Unlocks; len(u) != 3 || u[0] != "Plain usage" {
		t.Errorf("usage unlocks = %v", u)
	}
	if q := queryOf(t, h.m.requestsTo("fp /v1/organizations/api_keys")[0].RawQuery); q.Get("limit") != "1" {
		t.Errorf("test api_keys query = %v", q)
	}

	// The Admin key is rejected: not OK, and the analytics checks are not made.
	h2 := newHarness(t)
	h2.m.override["fp /v1/organizations/api_keys"] = func(w http.ResponseWriter, _ *http.Request) bool {
		anthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid x-api-key")
		return true
	}
	h2.m.forbid["fp /v1/organizations/analytics/usage"] = true
	conn := h2.conn()
	conn.Config.DeepInspection = false
	info = h2.c.Test(context.Background(), conn)
	if info.OK || info.Checks[0].Outcome != models.ShadowCallAuthFailed {
		t.Errorf("failing test = %+v", info)
	}
	last := info.Checks[len(info.Checks)-1]
	if last.Name != "Workspace "+wsA+": Message batches" || last.Outcome != models.ShadowCallSkipped || last.Message != "deep inspection is off" {
		t.Errorf("batches check = %+v", last)
	}
}
