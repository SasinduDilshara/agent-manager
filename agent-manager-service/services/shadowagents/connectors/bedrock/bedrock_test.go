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

package bedrock

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go/encoding/cbor"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

const (
	acct       = "123456789012"
	rtSupport  = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/support_agent-AbCdEf1234"
	rtOrders   = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/orders_mcp-GhIjKl5678"
	rtBroken   = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/broken_agent-ZyXwVu9876"
	claude     = "anthropic.claude-sonnet-4-20250514-v1:0"
	nova       = "amazon.nova-pro-v1:0"
	alice      = "arn:aws:iam::123456789012:user/dev-alice"
	sharedRole = "arn:aws:iam::123456789012:role/SharedRuntimeRole"
	agentRole  = "arn:aws:iam::123456789012:role/AmazonBedrockExecutionRoleForAgents_billing"
)

var testNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

type harness struct {
	fake *fakeAWS
	c    *Connector
	logs *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fake := newFakeAWS(t)
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, ok := New(sa.NewHTTPClient(fake.srv.Client().Transport), logger).(*Connector)
	require.True(t, ok)
	c.trailInterval = 0
	// The SDK's standard retry policy, without the backoff wait.
	c.retryer = func() aws.Retryer {
		return retry.NewStandard(func(o *retry.StandardOptions) {
			o.MaxAttempts = 4
			o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			o.RateLimiter = ratelimit.None
		})
	}
	return &harness{fake: fake, c: c, logs: logs}
}

func (h *harness) conn(deep bool, regions ...string) sa.Connection {
	if len(regions) == 0 {
		regions = []string{"us-east-1"}
	}
	eps := map[string]string{}
	for _, k := range []string{
		sa.EPBedrockSTS, sa.EPBedrockAgentCore, sa.EPBedrockRegistry, sa.EPBedrockAgent, sa.EPBedrock,
		sa.EPBedrockCloudWatch, sa.EPBedrockLogs, sa.EPBedrockCloudTrail,
	} {
		eps[k] = h.fake.srv.URL
	}
	return sa.Connection{
		ID: uuid.New(), OUID: "ou", Name: "aws", Provider: models.ShadowProviderBedrock,
		Config: models.ShadowConnectionConfig{Endpoints: eps, Regions: regions, AccessKeyID: testKeyID, DeepInspection: deep},
		Secret: models.ShadowConnectionSecret{SecretAccessKey: testSecret},
	}
}

func (h *harness) scan(t *testing.T, conn sa.Connection) *sa.Result {
	t.Helper()
	return h.c.Scan(context.Background(), conn, sa.NewWindow(testNow, 30))
}

func find(t *testing.T, res *sa.Result, kind, id string) *sa.Finding {
	t.Helper()
	for _, f := range res.Findings {
		if f.Kind == kind && f.ExternalID == id {
			return f
		}
	}
	t.Fatalf("no %s finding %q; have %v", kind, id, findingIDs(res))
	return nil
}

func findingIDs(res *sa.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Kind+" "+f.ExternalID)
	}
	return out
}

func hasFinding(res *sa.Result, kind, id string) bool {
	for _, f := range res.Findings {
		if f.Kind == kind && f.ExternalID == id {
			return true
		}
	}
	return false
}

func signal(f *sa.Finding, code string) (sa.Signal, bool) {
	for _, s := range f.Signals {
		if s.Code == code {
			return s, true
		}
	}
	return sa.Signal{}, false
}

func codes(f *sa.Finding) []string {
	var out []string
	for _, s := range f.Signals {
		out = append(out, s.Code)
	}
	sort.Strings(out)
	return out
}

func call(res *sa.Result, name string) models.ShadowScanCallResult {
	for _, c := range res.Calls {
		if c.Call == name {
			return c
		}
	}
	return models.ShadowScanCallResult{Call: name, Outcome: "missing"}
}

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// ---- the full scan ------------------------------------------------------------

func TestScanFindingsAndSignals(t *testing.T) {
	h := newHarness(t)
	res := h.scan(t, h.conn(true))

	// Every call succeeded.
	for _, c := range res.Calls {
		assert.Equal(t, models.ShadowCallOK, c.Outcome, "%s: %s", c.Call, c.Message)
	}
	assert.False(t, res.KeysListed)
	assert.Empty(t, res.Keys)

	// AgentCore runtime READY: definitive signal, attributes from GetAgentRuntime.
	sup := find(t, res, models.ShadowKindRuntime, rtSupport)
	assert.Equal(t, "support_agent", sup.DisplayName)
	assert.Equal(t, "us-east-1", sup.Scope)
	assert.Equal(t, "READY", sup.State)
	assert.Equal(t, "HTTP", sup.Attributes["serverProtocol"])
	assert.Equal(t, "123456789012.dkr.ecr.us-east-1.amazonaws.com/support-agent:latest", sup.Attributes["image"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/AgentCoreRuntimeRole", sup.Attributes["roleArn"])
	assert.Equal(t, "us-east-1", sup.Attributes["region"])
	assert.Equal(t, rtSupport, sup.Attributes["resourceId"])
	assert.Equal(t, "container", sup.Attributes["agentKind"])
	assert.Equal(t, true, sup.Attributes["invocationLogging"])
	require.NotNil(t, sup.ProviderCreatedAt)
	assert.Equal(t, time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC), *sup.ProviderCreatedAt)
	assert.Equal(t, models.ShadowOwnerHint{}, sup.OwnerHint)
	_, ok := signal(sup, sa.SigBedrockAgentCoreRuntime)
	assert.True(t, ok)
	_, ok = signal(sup, sa.SigBedrockRuntimeNotReady)
	assert.False(t, ok, "a READY runtime is not 'not ready'")

	// Not READY runtime: only the info signal.
	broken := find(t, res, models.ShadowKindRuntime, rtBroken)
	assert.Equal(t, "CREATE_FAILED", broken.State)
	assert.Equal(t, []string{sa.SigBedrockRuntimeNotReady}, codes(broken))

	// Code-deployed MCP runtime: an MCP server, so tool infrastructure, not
	// an agent; its registry MCP record is merged into it.
	orders := find(t, res, models.ShadowKindToolInfra, rtOrders)
	assert.Equal(t, "MCP", orders.Attributes["serverProtocol"])
	assert.Equal(t, "code", orders.Attributes["agentKind"])
	assert.Nil(t, orders.Attributes["image"])
	assert.Equal(t, "MCP", orders.Attributes["recordType"])
	assert.ElementsMatch(t, []string{sa.SigBedrockRuntimeMCPServer, sa.SigBedrockRegistryTool}, codes(orders))

	// Registry AGENT record with runtime provenance merged into the runtime.
	_, ok = signal(sup, sa.SigBedrockRegistryAgent)
	assert.True(t, ok, "AGENT record merged into the runtime")
	assert.False(t, hasFinding(res, models.ShadowKindPlatformAgent, "arn:aws:agent-registry:us-east-1:123456789012:registry/AbCdEf123456/record/Rec000000001"))
	assert.False(t, hasFinding(res, models.ShadowKindToolInfra, "arn:aws:agent-registry:us-east-1:123456789012:registry/AbCdEf123456/record/Rec123456789"))

	// Standalone AGENT record: platform agent.
	travel := find(t, res, models.ShadowKindPlatformAgent, "arn:aws:agent-registry:us-east-1:123456789012:registry/AbCdEf123456/record/Rec000000003")
	assert.Equal(t, "Travel planner", travel.DisplayName)
	assert.Equal(t, "AGENT", travel.Attributes["recordType"])
	assert.Equal(t, "APPROVED", travel.State)
	assert.Equal(t, []string{sa.SigBedrockRegistryAgent}, codes(travel))
	// MCP and SKILL records without provenance: tool infrastructure.
	wiki := find(t, res, models.ShadowKindToolInfra, "arn:aws:agent-registry:us-east-1:123456789012:registry/GhIjKl789012/record/Rec000000005")
	assert.Equal(t, []string{sa.SigBedrockRegistryTool}, codes(wiki))
	skill := find(t, res, models.ShadowKindToolInfra, "arn:aws:agent-registry:us-east-1:123456789012:registry/GhIjKl789012/record/Rec000000006")
	assert.Equal(t, "pdf-skill", skill.DisplayName)
	assert.Equal(t, []string{sa.SigBedrockRegistryTool}, codes(skill))

	// Gateways: tool infrastructure; MCP (explicit or default) raises the signal.
	gw := find(t, res, models.ShadowKindToolInfra, gatewayExternalID("us-east-1", "orders-gw-a1b2c3d4e5"))
	assert.Equal(t, "orders-gw", gw.DisplayName)
	assert.Equal(t, "MCP", gw.Attributes["protocolType"])
	assert.Equal(t, "CUSTOM_JWT", gw.Attributes["authorizerType"])
	assert.Equal(t, "https://orders-gw-a1b2c3d4e5.gateway.bedrock-agentcore.us-east-1.amazonaws.com", gw.Attributes["endpoint"])
	assert.Equal(t, "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/orders-gw-a1b2c3d4e5", gw.Attributes["resourceId"])
	assert.Equal(t, []sa.ToolRef{{Type: "MCP_SERVER", Name: "TGT0000001"}, {Type: "LAMBDA", Name: "TGT0000002"}}, gw.Attributes["tools"])
	assert.Equal(t, 2, gw.Attributes["toolCount"])
	assert.Equal(t, "GATEWAY", gw.Attributes["recordType"], "GATEWAY record merged into the gateway")
	assert.Equal(t, []string{sa.SigBedrockMCPGateway, sa.SigBedrockRegistryTool}, codes(gw))
	billing := find(t, res, models.ShadowKindToolInfra, gatewayExternalID("us-east-1", "billing-gw-f6g7h8i9j0"))
	assert.Equal(t, "HTTP", billing.Attributes["protocolType"])
	assert.Empty(t, codes(billing), "a non-MCP gateway has no MCP gateway signal")
	search := find(t, res, models.ShadowKindToolInfra, gatewayExternalID("us-east-1", "search-gw-k1l2m3n4o5"))
	assert.Equal(t, "MCP", search.Attributes["protocolType"], "absent protocolType defaults to MCP")
	assert.Equal(t, []string{sa.SigBedrockMCPGateway}, codes(search))

	// Classic agents: GetAgent fields and action groups as tools.
	billingAgent := find(t, res, models.ShadowKindPlatformAgent, classicAgentExternalID("us-east-1", "AB12CD34EF"))
	assert.Equal(t, "billing-helper", billingAgent.DisplayName)
	assert.Equal(t, "PREPARED", billingAgent.State)
	assert.Equal(t, "anthropic.claude-3-5-sonnet-20240620-v1:0", billingAgent.Attributes["model"])
	assert.Equal(t, "DEFAULT", billingAgent.Attributes["orchestrationType"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/service-role/AmazonBedrockExecutionRoleForAgents_billing", billingAgent.Attributes["roleArn"])
	assert.Equal(t, "arn:aws:bedrock:us-east-1:123456789012:agent/AB12CD34EF", billingAgent.Attributes["resourceId"])
	assert.Equal(t, []sa.ToolRef{{Type: "action_group", Name: "lookup_invoice"}, {Type: "action_group", Name: "UserInputAction"}}, billingAgent.Attributes["tools"])
	require.NotNil(t, billingAgent.ProviderCreatedAt)
	assert.Equal(t, []string{sa.SigBedrockClassicAgent}, codes(billingAgent))
	hr := find(t, res, models.ShadowKindPlatformAgent, classicAgentExternalID("us-east-1", "XY98ZW76VU"))
	assert.Equal(t, []string{sa.SigBedrockClassicAgent}, codes(hr))
	assert.Nil(t, hr.Attributes["tools"])

	// Runtime in use: SessionCount from the Resource-only dimension set.
	inUse, ok := signal(sup, sa.SigBedrockRuntimeInUse)
	require.True(t, ok)
	assert.Equal(t, int64(7), inUse.Observed["sessionCount"])
	assert.Equal(t, int64(2), inUse.Observed["activeDays"])
	assert.Equal(t, int64(7), sup.Attributes["sessionCount"])
	assert.Equal(t, "2026-11-05", sup.Attributes["lastSessionAt"])
	assert.Equal(t, int64(0), orders.Attributes["sessionCount"])
	_, ok = signal(orders, sa.SigBedrockRuntimeInUse)
	assert.False(t, ok, "SessionCount 0 is not in use")

	// Invocation logging is configured: no logging-off signal anywhere.
	for _, f := range res.Findings {
		_, off := signal(f, sa.SigBedrockInvocationLogsOff)
		assert.False(t, off, f.ExternalID)
	}

	// Dedup: the runtime's own role traffic (CloudTrail and invocation logs)
	// is on the runtime, and there is no principal finding for the role.
	assert.False(t, hasFinding(res, models.ShadowKindPrincipal, "arn:aws:iam::123456789012:role/AgentCoreRuntimeRole"))
	plain, ok := signal(sup, sa.SigBedrockPlainModelUsage)
	require.True(t, ok)
	assert.Equal(t, int64(1), plain.Observed["requests"])
	assert.Equal(t, []sa.UsageDay{{Day: day("2026-11-05"), Model: claude, Requests: 1}}, sup.Usage)
	toolCall, ok := signal(sup, sa.SigBedrockToolCallLog)
	require.True(t, ok)
	assert.Equal(t, int64(1), toolCall.Observed["records"])
	_, ok = signal(sup, sa.SigBedrockToolResultLog)
	assert.True(t, ok)
	assert.Equal(t, []string{claude}, sup.Attributes["models"])
	assert.Equal(t, true, sup.Attributes["deepInspection"])

	// Plain model usage of an IAM user, per day and model, no double counting
	// (the AwsServiceEvent stream record and the repeated EventId are skipped).
	a := find(t, res, models.ShadowKindPrincipal, alice)
	assert.Equal(t, "user/dev-alice", a.DisplayName)
	assert.Equal(t, acct, a.Scope)
	assert.Equal(t, "IAMUser", a.Attributes["principalType"])
	assert.Equal(t, acct, a.Attributes["accountId"])
	assert.Equal(t, models.ShadowOwnerHint{Username: alice, Type: "IAMUser", Source: callLookupEvents}, a.OwnerHint)
	assert.ElementsMatch(t, []sa.UsageDay{
		{Day: day("2026-11-06"), Model: nova, Requests: 2},
		{Day: day("2026-11-08"), Model: claude, Requests: 1},
	}, a.Usage)
	pu, ok := signal(a, sa.SigBedrockPlainModelUsage)
	require.True(t, ok)
	assert.Equal(t, int64(3), pu.Observed["requests"])
	assert.Equal(t, []string{nova, claude}, a.Attributes["models"], "sorted")
	require.NotNil(t, a.FirstUsedAt)
	require.NotNil(t, a.LastUsedAt)
	assert.Equal(t, time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC), *a.FirstUsedAt)
	assert.Equal(t, time.Date(2026, 11, 8, 8, 0, 0, 0, time.UTC), *a.LastUsedAt)
	// Tool result in alice's InvokeModel (Anthropic) record; no tool call.
	_, ok = signal(a, sa.SigBedrockToolResultLog)
	assert.True(t, ok)
	_, ok = signal(a, sa.SigBedrockToolCallLog)
	assert.False(t, ok)

	// Principal only seen in invocation logs (stream record with tool_use).
	bob := find(t, res, models.ShadowKindPrincipal, "arn:aws:iam::123456789012:user/dev-bob")
	assert.Equal(t, []string{sa.SigBedrockToolCallLog}, codes(bob))
	assert.Empty(t, bob.Usage)

	// A role shared by two runtimes cannot be attributed to one: principal
	// finding linked to both. A classic agent's role: linked to the agent.
	shared := find(t, res, models.ShadowKindPrincipal, sharedRole)
	assert.Equal(t, "AssumedRole", shared.Attributes["principalType"])
	assert.ElementsMatch(t, []sa.Relation{
		{ExternalID: rtOrders, Kind: models.ShadowKindToolInfra, Relation: "used_by_agent", Reason: "the AgentCore runtimes share this execution role"},
		{ExternalID: rtBroken, Kind: models.ShadowKindRuntime, Relation: "used_by_agent", Reason: "the AgentCore runtimes share this execution role"},
	}, shared.Related)
	ag := find(t, res, models.ShadowKindPrincipal, agentRole)
	assert.Equal(t, []sa.Relation{{
		ExternalID: classicAgentExternalID("us-east-1", "AB12CD34EF"), Kind: models.ShadowKindPlatformAgent,
		Relation: "used_by_agent", Reason: "a classic Bedrock agent runs as this role",
	}}, ag.Related)

	// Negative cases of plain usage: control-plane events, AwsServiceEvent
	// only, events outside the window.
	for _, n := range []string{"admin", "stream-bot", "old-user"} {
		assert.False(t, hasFinding(res, models.ShadowKindPrincipal, "arn:aws:iam::123456789012:user/"+n), n)
	}

	// Every attribute key is one the sanitiser keeps.
	for _, f := range res.Findings {
		assert.Equal(t, len(f.Attributes), len(sa.SanitizeAttributes(f.Attributes)), "%s %v", f.ExternalID, f.Attributes)
		for _, s := range f.Signals {
			_, known := sa.Def(s.Code)
			assert.True(t, known, s.Code)
		}
	}
	// 3 runtimes, 3 gateways, 2 classic agents, 3 registry records, 4 principals.
	assert.Equal(t, 15, len(res.Findings), findingIDs(res))
}

func TestScanRetention(t *testing.T) {
	h := newHarness(t)
	res := h.scan(t, h.conn(true))
	out, err := json.Marshal(res)
	require.NoError(t, err)
	for _, m := range []string{markerPrompt, markerKey, testSecret, "api_key=", "instructions", "template"} {
		assert.NotContains(t, string(out), m)
		assert.NotContains(t, h.logs.String(), m)
	}
	assert.NotEmpty(t, h.logs.String())
}

func TestScanRequests(t *testing.T) {
	h := newHarness(t)
	h.scan(t, h.conn(true))
	f := h.fake

	// Pagination: every paginated call fetched two pages, the second with
	// the first page's token.
	pages := map[string]func(capturedReq) string{
		"ListAgentRuntimes":     func(r capturedReq) string { return r.query.Get("nextToken") },
		"ListGateways":          func(r capturedReq) string { return r.query.Get("nextToken") },
		"ListGatewayTargets":    func(r capturedReq) string { return r.query.Get("nextToken") },
		"ListRegistries":        jsonField("nextToken"),
		"ListRegistryRecords":   jsonField("nextToken"),
		"ListAgents":            jsonField("nextToken"),
		"ListAgentActionGroups": jsonField("nextToken"),
		"FilterLogEvents":       jsonField("nextToken"),
		"LookupEvents":          jsonField("NextToken"),
		"ListMetrics":           cborField("NextToken"),
		"GetMetricData":         cborField("NextToken"),
	}
	want := map[string]string{
		"ListAgentRuntimes": "rt-page-2", "ListGateways": "gw-page-2", "ListGatewayTargets": "tg-page-2",
		"ListRegistries": "reg-page-2", "ListRegistryRecords": "rec-page-2", "ListAgents": "ag-page-2",
		"ListAgentActionGroups": "agp-page-2", "FilterLogEvents": "logs-page-2", "LookupEvents": "ct-page-2",
		"ListMetrics": "lm-page-2", "GetMetricData": "gmd-page-2",
	}
	for op, tok := range pages {
		var got []string
		for _, r := range f.requests(op) {
			got = append(got, tok(r))
		}
		assert.Contains(t, got, "", "%s first page", op)
		assert.Contains(t, got, want[op], "%s second page", op)
	}

	// restJson1: AgentCore.
	rt := f.requests("ListAgentRuntimes")[0]
	assert.Equal(t, "POST", rt.method)
	assert.Equal(t, "/runtimes/", rt.path)
	assert.Equal(t, url.Values{"maxResults": {"100"}}, rt.query)
	assert.Empty(t, rt.body, "ListAgentRuntimes has no body")
	assert.Contains(t, rt.header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="+testKeyID+"/")
	assert.NotEmpty(t, rt.header.Get("X-Amz-Date"))
	get := f.requests("GetAgentRuntime")
	require.Len(t, get, 3)
	assert.Equal(t, "GET", get[0].method)
	assert.Equal(t, "/runtimes/support_agent-AbCdEf1234/", get[0].path)
	assert.Empty(t, get[0].query)
	lg := f.requests("ListGateways")[0]
	assert.Equal(t, "GET", lg.method)
	assert.Equal(t, url.Values{"maxResults": {"100"}}, lg.query)
	assert.Equal(t, "/gateways/orders-gw-a1b2c3d4e5/", f.requests("GetGateway")[0].path)
	lt := f.requests("ListGatewayTargets")[0]
	assert.Equal(t, "/gateways/orders-gw-a1b2c3d4e5/targets/", lt.path)
	assert.Equal(t, url.Values{"maxResults": {"100"}}, lt.query)

	// restJson1: agent-registry-control (POST lists with JSON bodies).
	lr := f.requests("ListRegistries")[0]
	assert.Equal(t, "POST", lr.method)
	assert.Equal(t, "application/json", lr.header.Get("Content-Type"))
	assert.JSONEq(t, `{"maxResults":100}`, string(lr.body))
	rr := f.requests("ListRegistryRecords")[0]
	assert.Equal(t, "/registries/AbCdEf123456/records-list", rr.path)
	assert.JSONEq(t, `{"maxResults":100}`, string(rr.body))

	// restJson1: bedrock-agent.
	la := f.requests("ListAgents")[0]
	assert.Equal(t, "POST", la.method)
	assert.Equal(t, "/agents/", la.path)
	assert.Equal(t, "application/json", la.header.Get("Content-Type"))
	assert.JSONEq(t, `{"maxResults":100}`, string(la.body))
	assert.Equal(t, "/agents/AB12CD34EF/", f.requests("GetAgent")[0].path)
	ag := f.requests("ListAgentActionGroups")[0]
	assert.Equal(t, "POST", ag.method)
	assert.Equal(t, "/agents/AB12CD34EF/agentversions/DRAFT/actiongroups/", ag.path)
	assert.JSONEq(t, `{"maxResults":100}`, string(ag.body))

	// restJson1: bedrock.
	lc := f.requests("GetModelInvocationLoggingConfiguration")[0]
	assert.Equal(t, "GET", lc.method)
	assert.Equal(t, "/logging/modelinvocations", lc.path)

	// awsJson1_1: logs.
	fl := f.requests("FilterLogEvents")[0]
	assert.Equal(t, "POST", fl.method)
	assert.Equal(t, "/", fl.path)
	assert.Equal(t, "Logs_20140328.FilterLogEvents", fl.header.Get("X-Amz-Target"))
	assert.Equal(t, "application/x-amz-json-1.1", fl.header.Get("Content-Type"))
	w := sa.NewWindow(testNow, 30)
	assert.JSONEq(t, `{"logGroupName":"bedrock-invocations","startTime":`+itoa(w.Start.UnixMilli())+`,"endTime":`+itoa(w.End.UnixMilli())+`,"limit":100}`, string(fl.body))

	// awsJson1_1: cloudtrail.
	ct := f.requests("LookupEvents")[0]
	assert.Equal(t, "POST", ct.method)
	assert.Equal(t, "/", ct.path)
	assert.Equal(t, "CloudTrail_20131101.LookupEvents", ct.header.Get("X-Amz-Target"))
	assert.Equal(t, "application/x-amz-json-1.1", ct.header.Get("Content-Type"))
	assert.JSONEq(t, `{"LookupAttributes":[{"AttributeKey":"EventSource","AttributeValue":"bedrock.amazonaws.com"}],`+
		`"StartTime":`+itoa(w.Start.Unix())+`,"EndTime":`+itoa(w.End.Unix())+`,"MaxResults":50}`, string(ct.body))

	// smithy-rpc-v2-cbor: cloudwatch.
	lm := f.requests("ListMetrics")[0]
	assert.Equal(t, "POST", lm.method)
	assert.Equal(t, "/service/GraniteServiceVersion20100801/operation/ListMetrics", lm.path)
	assert.Equal(t, "application/cbor", lm.header.Get("Content-Type"))
	assert.Equal(t, "application/cbor", lm.header.Get("Accept"))
	assert.Equal(t, "rpc-v2-cbor", lm.header.Get("Smithy-Protocol"))
	assert.Equal(t, "true", lm.header.Get("X-Amzn-Query-Mode"))
	body := decodeCBOR(t, lm.body)
	assert.Equal(t, cbor.String("AWS/Bedrock-AgentCore"), body["Namespace"])
	assert.Equal(t, cbor.String("SessionCount"), body["MetricName"])
	gm := decodeCBOR(t, f.requests("GetMetricData")[0].body)
	assert.Equal(t, &cbor.Tag{ID: 1, Value: cbor.Float64(float64(w.Start.Unix()))}, gm["StartTime"])
	qs, ok := gm["MetricDataQueries"].(cbor.List)
	require.True(t, ok)
	require.Len(t, qs, 2)
	q0, _ := qs[0].(cbor.Map)
	assert.Equal(t, cbor.String("m0"), q0["Id"])
	ms, _ := q0["MetricStat"].(cbor.Map)
	assert.Equal(t, cbor.String("Sum"), ms["Stat"])
	assert.Equal(t, cbor.Uint(86400), ms["Period"])
	metric, _ := ms["Metric"].(cbor.Map)
	dims, _ := metric["Dimensions"].(cbor.List)
	assert.Len(t, dims, 2, "the least specific dimension set naming the runtime")

	// No STS call without a role; every request carried the right signing
	// name (checked by the fake).
	assert.Empty(t, f.requests("AssumeRole"))
}

func jsonField(name string) func(capturedReq) string {
	return func(r capturedReq) string {
		var m map[string]any
		_ = json.Unmarshal(r.body, &m)
		s, _ := m[name].(string)
		return s
	}
}

func cborField(name string) func(capturedReq) string {
	return func(r capturedReq) string {
		v, err := cbor.Decode(r.body)
		if err != nil {
			return ""
		}
		m, _ := v.(cbor.Map)
		s, _ := m[name].(cbor.String)
		return string(s)
	}
}

func decodeCBOR(t *testing.T, b []byte) cbor.Map {
	t.Helper()
	v, err := cbor.Decode(b)
	require.NoError(t, err)
	m, ok := v.(cbor.Map)
	require.True(t, ok)
	return m
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// ---- deep inspection and invocation logging --------------------------------

func TestScanDeepInspectionOff(t *testing.T) {
	h := newHarness(t)
	h.fake.forbidden["FilterLogEvents"] = true
	res := h.scan(t, h.conn(false))
	c := call(res, callFilterLogs)
	assert.Equal(t, models.ShadowCallSkipped, c.Outcome)
	assert.Equal(t, "deep inspection is off", c.Message)
	for _, f := range res.Findings {
		_, tc := signal(f, sa.SigBedrockToolCallLog)
		_, tr := signal(f, sa.SigBedrockToolResultLog)
		assert.False(t, tc || tr, f.ExternalID)
		assert.Nil(t, f.Attributes["deepInspection"])
	}
	// Metadata and usage still come in.
	assert.True(t, hasFinding(res, models.ShadowKindPrincipal, alice))
	assert.False(t, hasFinding(res, models.ShadowKindPrincipal, "arn:aws:iam::123456789012:user/dev-bob"))
}

func TestScanInvocationLoggingOff(t *testing.T) {
	h := newHarness(t)
	h.fake.variant["GetModelInvocationLoggingConfiguration"] = "off"
	h.fake.forbidden["FilterLogEvents"] = true
	res := h.scan(t, h.conn(true))
	c := call(res, callFilterLogs)
	assert.Equal(t, models.ShadowCallSkipped, c.Outcome)
	assert.Equal(t, "model invocation logging is off", c.Message)
	assert.Equal(t, models.ShadowCallOK, call(res, callLoggingConfig).Outcome)

	for id, kind := range map[string]string{
		rtSupport: models.ShadowKindRuntime, rtOrders: models.ShadowKindToolInfra, rtBroken: models.ShadowKindRuntime,
	} {
		f := find(t, res, kind, id)
		_, ok := signal(f, sa.SigBedrockInvocationLogsOff)
		assert.True(t, ok, id)
		assert.Equal(t, false, f.Attributes["invocationLogging"])
	}
	_, ok := signal(find(t, res, models.ShadowKindPrincipal, alice), sa.SigBedrockInvocationLogsOff)
	assert.True(t, ok, "principal with traffic in the region")
	// Not on agents, gateways or registry records.
	_, ok = signal(find(t, res, models.ShadowKindPlatformAgent, classicAgentExternalID("us-east-1", "AB12CD34EF")), sa.SigBedrockInvocationLogsOff)
	assert.False(t, ok)
}

func TestScanInvocationLogsS3Only(t *testing.T) {
	h := newHarness(t)
	h.fake.variant["GetModelInvocationLoggingConfiguration"] = "s3"
	h.fake.forbidden["FilterLogEvents"] = true
	res := h.scan(t, h.conn(true))
	c := call(res, callFilterLogs)
	assert.Equal(t, models.ShadowCallSkipped, c.Outcome)
	assert.Equal(t, "invocation logs are delivered to S3 only", c.Message)
	sup := find(t, res, models.ShadowKindRuntime, rtSupport)
	assert.Equal(t, true, sup.Attributes["invocationLogging"])
	_, ok := signal(sup, sa.SigBedrockInvocationLogsOff)
	assert.False(t, ok)
}

func TestScanMultiRegion(t *testing.T) {
	h := newHarness(t)
	res := h.scan(t, h.conn(true, "us-east-1", "eu-west-1"))
	// dev-alice: one more call on 2026-11-06 with nova in eu-west-1, summed
	// into the same principal and day.
	a := find(t, res, models.ShadowKindPrincipal, alice)
	assert.ElementsMatch(t, []sa.UsageDay{
		{Day: day("2026-11-06"), Model: nova, Requests: 3},
		{Day: day("2026-11-08"), Model: claude, Requests: 1},
	}, a.Usage)
	pu, _ := signal(a, sa.SigBedrockPlainModelUsage)
	assert.Equal(t, int64(4), pu.Observed["requests"])
	// eu-west-1 has no logging config: alice had traffic there.
	_, ok := signal(a, sa.SigBedrockInvocationLogsOff)
	assert.True(t, ok)
	// The us-east-1 runtimes are not affected by eu-west-1's config.
	_, ok = signal(find(t, res, models.ShadowKindRuntime, rtSupport), sa.SigBedrockInvocationLogsOff)
	assert.False(t, ok)
	// Calls in both regions merge.
	assert.Equal(t, models.ShadowCallOK, call(res, callListRuntimes).Outcome)
	regions := map[string]bool{}
	for _, r := range h.fake.requests("ListAgentRuntimes") {
		regions[r.region] = true
	}
	assert.Equal(t, map[string]bool{"us-east-1": true, "eu-west-1": true}, regions)
	// eu-west-1 lists no agents, runtimes or gateways: no findings there
	// (the negative case of the inventory signals).
	for _, f := range res.Findings {
		assert.NotEqual(t, "eu-west-1", f.Scope, f.ExternalID)
	}
	// No runtimes in eu-west-1: no ListMetrics there.
	for _, r := range h.fake.requests("ListMetrics") {
		assert.Equal(t, "us-east-1", r.region)
	}
}

// ---- errors ---------------------------------------------------------------------

func TestScanAuthFailureStopsEarly(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("ListAgentRuntimes", fakeErr{status: 401, code: "UnrecognizedClientException"})
	res := h.scan(t, h.conn(true))
	require.Len(t, res.Calls, 1)
	assert.Equal(t, callListRuntimes, res.Calls[0].Call)
	assert.Equal(t, models.ShadowCallAuthFailed, res.Calls[0].Outcome)
	assert.Empty(t, res.Findings)
	assert.Equal(t, []string{"ListAgentRuntimes"}, h.fake.allOps())
}

func TestScanAuthFailure403Code(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("ListAgentRuntimes", fakeErr{status: 403, code: "InvalidSignatureException"})
	res := h.scan(t, h.conn(false))
	require.Len(t, res.Calls, 1)
	assert.Equal(t, models.ShadowCallAuthFailed, res.Calls[0].Outcome)
	assert.Contains(t, res.Calls[0].Message, "InvalidSignatureException")
}

func TestScanPermissionDeniedOnOneCall(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("ListGateways", fakeErr{status: 403, code: "AccessDeniedException"})
	res := h.scan(t, h.conn(true))
	c := call(res, callListGateways)
	assert.Equal(t, models.ShadowCallPermissionDenied, c.Outcome)
	assert.Contains(t, c.Message, "AccessDeniedException")
	assert.Equal(t, models.ShadowCallOK, call(res, callListRuntimes).Outcome)
	assert.Equal(t, models.ShadowCallOK, call(res, callLookupEvents).Outcome)
	assert.Equal(t, models.ShadowCallOK, call(res, callListAgents).Outcome)
	assert.False(t, hasFinding(res, models.ShadowKindToolInfra, gatewayExternalID("us-east-1", "orders-gw-a1b2c3d4e5")))
	assert.True(t, hasFinding(res, models.ShadowKindRuntime, rtSupport))
}

func TestScanThrottleThenSuccess(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("ListAgents", fakeErr{status: 429, code: "ThrottlingException", retryAfter: "0"})
	h.fake.failWith("LookupEvents", fakeErr{status: 400, code: "ThrottlingException", retryAfter: "0"})
	res := h.scan(t, h.conn(false))
	assert.Equal(t, models.ShadowCallOK, call(res, callListAgents).Outcome)
	assert.Equal(t, models.ShadowCallOK, call(res, callLookupEvents).Outcome)
	assert.True(t, hasFinding(res, models.ShadowKindPlatformAgent, classicAgentExternalID("us-east-1", "AB12CD34EF")))
	assert.Len(t, h.fake.requests("ListAgents"), 3, "one retry, then two pages")
}

func TestScanThrottleExhausted(t *testing.T) {
	h := newHarness(t)
	throttle := fakeErr{status: 429, code: "ThrottlingException"}
	h.fake.failWith("ListAgents", throttle, throttle, throttle, throttle)
	res := h.scan(t, h.conn(false))
	assert.Equal(t, models.ShadowCallRateLimited, call(res, callListAgents).Outcome)
}

func TestScanMalformedResponse(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("ListAgents", fakeErr{raw: `{"agentSummaries": [`})
	h.fake.failWith("ListMetrics", fakeErr{raw: "\xff\x00not cbor"})
	res := h.scan(t, h.conn(false))
	assert.Equal(t, models.ShadowCallUnsupported, call(res, callListAgents).Outcome)
	assert.Equal(t, models.ShadowCallUnsupported, call(res, callListMetrics).Outcome)
	assert.Equal(t, models.ShadowCallOK, call(res, callListRuntimes).Outcome)
}

func TestScanCloudTrailShapeChange(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("LookupEvents", fakeErr{raw: `{"Events":[{"EventId":"x","EventName":"InvokeModel","EventSource":"bedrock.amazonaws.com","CloudTrailEvent":"not json"}]}`})
	res := h.scan(t, h.conn(false))
	assert.Equal(t, models.ShadowCallUnsupported, call(res, callLookupEvents).Outcome)
}

func TestScanAssumeRole(t *testing.T) {
	h := newHarness(t)
	conn := h.conn(false)
	conn.Config.RoleARN = "arn:aws:iam::123456789012:role/AmpShadowDiscovery"
	conn.Config.ExternalID = "ext-123"
	res := h.scan(t, conn)
	assert.Equal(t, models.ShadowCallOK, call(res, callListRuntimes).Outcome)
	ar := h.fake.requests("AssumeRole")
	require.NotEmpty(t, ar)
	form, err := url.ParseQuery(string(ar[0].body))
	require.NoError(t, err)
	assert.Equal(t, "AssumeRole", form.Get("Action"))
	assert.Equal(t, "2011-06-15", form.Get("Version"))
	assert.Equal(t, conn.Config.RoleARN, form.Get("RoleArn"))
	assert.Equal(t, "ext-123", form.Get("ExternalId"))
	assert.Equal(t, "wso2-agent-manager-shadow-discovery", form.Get("RoleSessionName"))
	assert.Contains(t, ar[0].header.Get("Content-Type"), "application/x-www-form-urlencoded")
	assert.Contains(t, ar[0].header.Get("Authorization"), "Credential="+testKeyID+"/")
	rt := h.fake.requests("ListAgentRuntimes")[0]
	assert.Contains(t, rt.header.Get("Authorization"), "Credential=ASIAIOSFODNN7EXAMPLE/")
	assert.Equal(t, "FwoGZXIvYXdzEXAMPLESESSIONTOKEN", rt.header.Get("X-Amz-Security-Token"))
}

func TestScanAssumeRoleDenied(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("AssumeRole", fakeErr{status: 403, code: "AccessDenied"})
	conn := h.conn(false)
	conn.Config.RoleARN = "arn:aws:iam::123456789012:role/AmpShadowDiscovery"
	res := h.scan(t, conn)
	require.Len(t, res.Calls, 1)
	assert.Equal(t, models.ShadowCallAuthFailed, res.Calls[0].Outcome)
	assert.Contains(t, res.Calls[0].Message, "AccessDenied")
}

func TestScanNoRegions(t *testing.T) {
	h := newHarness(t)
	conn := h.conn(false)
	conn.Config.Regions = []string{" "}
	res := h.scan(t, conn)
	require.Len(t, res.Calls, 1)
	assert.Equal(t, models.ShadowCallFailed, res.Calls[0].Outcome)
	assert.Empty(t, h.fake.allOps())
}

func TestCloudTrailPacing(t *testing.T) {
	h := newHarness(t)
	h.c.trailInterval = 150 * time.Millisecond
	h.scan(t, h.conn(false))
	reqs := h.fake.requests("LookupEvents")
	require.Len(t, reqs, 2)
	assert.GreaterOrEqual(t, reqs[1].at.Sub(reqs[0].at), 140*time.Millisecond)
}

// ---- Test() -------------------------------------------------------------------

func TestConnectionTest(t *testing.T) {
	h := newHarness(t)
	info := h.c.Test(context.Background(), h.conn(true))
	assert.True(t, info.OK)
	require.Len(t, info.Checks, 7)
	for _, c := range info.Checks {
		assert.Equal(t, models.ShadowCallOK, c.Outcome, c.Name)
		assert.NotEmpty(t, c.Unlocks, c.Name)
	}
	assert.Empty(t, h.fake.requests("FilterLogEvents"), "Test never reads log content")
	lr := h.fake.requests("ListAgentRuntimes")[0]
	assert.Equal(t, "1", lr.query.Get("maxResults"))
}

func TestConnectionTestAuthFailure(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("ListAgentRuntimes", fakeErr{status: 401, code: "UnrecognizedClientException"})
	info := h.c.Test(context.Background(), h.conn(false))
	assert.False(t, info.OK)
	require.Len(t, info.Checks, 1)
	assert.Equal(t, models.ShadowCallAuthFailed, info.Checks[0].Outcome)
	assert.Equal(t, []string{sa.SigBedrockAgentCoreRuntime, sa.SigBedrockRuntimeNotReady}, info.Checks[0].Unlocks)
}

func TestConnectionTestPartialPermissions(t *testing.T) {
	h := newHarness(t)
	h.fake.failWith("ListGateways", fakeErr{status: 403, code: "AccessDeniedException"})
	h.fake.failWith("LookupEvents", fakeErr{status: 400, code: "AccessDeniedException"})
	info := h.c.Test(context.Background(), h.conn(false))
	assert.True(t, info.OK, "the inventory capabilities passed")
	byName := map[string]models.ShadowConnectionCheck{}
	for _, c := range info.Checks {
		byName[c.Name] = c
	}
	assert.Equal(t, models.ShadowCallPermissionDenied, byName[callListGateways].Outcome)
	assert.Equal(t, models.ShadowCallPermissionDenied, byName[callLookupEvents].Outcome)
	assert.Equal(t, models.ShadowCallOK, byName[callListAgents].Outcome)
}

func TestConnectionTestNoRegion(t *testing.T) {
	h := newHarness(t)
	conn := h.conn(false)
	conn.Config.Regions = nil
	info := h.c.Test(context.Background(), conn)
	assert.False(t, info.OK)
	require.Len(t, info.Checks, 1)
	assert.Equal(t, models.ShadowCallFailed, info.Checks[0].Outcome)
}

// ---- units ----------------------------------------------------------------------

func TestNormalizePrincipal(t *testing.T) {
	cases := []struct{ in, norm, key, kind string }{
		{"arn:aws:sts::123456789012:assumed-role/MyRole/session-name", "arn:aws:iam::123456789012:role/MyRole", "123456789012|MyRole", "AssumedRole"},
		{"arn:aws:iam::123456789012:role/service-role/MyRole", "arn:aws:iam::123456789012:role/MyRole", "123456789012|MyRole", "AssumedRole"},
		{"arn:aws-cn:sts::123456789012:assumed-role/R/s", "arn:aws-cn:iam::123456789012:role/R", "123456789012|R", "AssumedRole"},
		{"arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/alice", "", "IAMUser"},
		{"arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:root", "", "Root"},
		{"arn:aws:sts::123456789012:federated-user/bob", "arn:aws:sts::123456789012:federated-user/bob", "", "FederatedUser"},
		{"not-an-arn", "not-an-arn", "", ""},
	}
	for _, c := range cases {
		norm, key, kind := normalizePrincipal(c.in)
		assert.Equal(t, c.norm, norm, c.in)
		assert.Equal(t, c.key, key, c.in)
		assert.Equal(t, c.kind, kind, c.in)
	}
}

func TestModelName(t *testing.T) {
	assert.Equal(t, claude, modelName(claude))
	assert.Equal(t, claude, modelName("arn:aws:bedrock:us-east-1::foundation-model/"+claude))
	assert.Equal(t, "us.anthropic.claude-sonnet-4", modelName("arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4"))
	assert.Equal(t, "", modelName(""))
}

func TestParseInvocationRecord(t *testing.T) {
	rec := func(input, output string) string {
		return `{"schemaType":"ModelInvocationLog","timestamp":"2026-11-05T10:00:00Z","modelId":"m",` +
			`"identity":{"arn":"arn:aws:iam::1:user/u"},"input":{"inputBodyJson":` + input + `},"output":{"outputBodyJson":` + output + `}}`
	}
	cases := []struct {
		name          string
		in, out       string
		use, toolBack bool
	}{
		{"converse stopReason", `{}`, `{"stopReason":"tool_use"}`, true, false},
		{"converse toolUse block", `{}`, `{"output":{"message":{"content":[{"toolUse":{"name":"x"}}]}},"stopReason":"end_turn"}`, true, false},
		{"converse plain", `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`, `{"output":{"message":{"content":[{"text":"x"}]}},"stopReason":"end_turn"}`, false, false},
		{"converse toolResult", `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"1","content":[]}}]}]}`, `{"stopReason":"end_turn"}`, false, true},
		{"converse toolResult null", `{"messages":[{"role":"user","content":[{"toolResult":null}]}]}`, `{}`, false, false},
		{"anthropic stop_reason", `{}`, `{"stop_reason":"tool_use","content":[]}`, true, false},
		{"anthropic tool_use block", `{}`, `{"content":[{"type":"tool_use","name":"calc"}],"stop_reason":"end_turn"}`, true, false},
		{"anthropic text", `{"messages":[{"role":"user","content":"hello"}]}`, `{"content":[{"type":"text","text":"x"}],"stop_reason":"end_turn"}`, false, false},
		{"anthropic tool_result", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t"}]}]}`, `{"stop_reason":"max_tokens"}`, false, true},
		{"anthropic stream", `{}`, `[{"type":"content_block_start","content_block":{"type":"tool_use"}}]`, true, false},
		{"anthropic stream delta", `{}`, `[{"type":"message_delta","delta":{"stop_reason":"tool_use"}}]`, true, false},
		{"anthropic stream text", `{}`, `[{"type":"content_block_start","content_block":{"type":"text"}},{"type":"message_delta","delta":{"stop_reason":"end_turn"}}]`, false, false},
		{"converse stream", `{}`, `[{"contentBlockStart":{"start":{"toolUse":{"name":"x"}}}},{"messageStop":{"stopReason":"tool_use"}}]`, true, false},
		{"absent bodies", `null`, `null`, false, false},
		{"unexpected body", `"text body"`, `42`, false, false},
	}
	for _, c := range cases {
		r, ok := parseInvocationRecord(rec(c.in, c.out))
		require.True(t, ok, c.name)
		assert.Equal(t, c.use, r.toolUse, c.name)
		assert.Equal(t, c.toolBack, r.toolResult, c.name)
		assert.Equal(t, "arn:aws:iam::1:user/u", r.identity, c.name)
	}
	_, ok := parseInvocationRecord("not json")
	assert.False(t, ok)
}

func TestPaginateBound(t *testing.T) {
	n, err := paginate(context.Background(), 3, func() bool { return true }, func(context.Context) (int, error) { return 2, nil })
	assert.Equal(t, 6, n)
	require.Error(t, err)
	assert.Equal(t, models.ShadowCallOK, sa.OutcomeOf(err))
	assert.Contains(t, sa.MessageOf(err), "stopped after 3 pages")
}

func TestAWSErrorScrubsURLs(t *testing.T) {
	err := awsError(&url.Error{Op: "Post", URL: "https://logs.us-east-1.amazonaws.com/?nextToken=abc123", Err: context.DeadlineExceeded})
	assert.NotContains(t, sa.MessageOf(err), "nextToken")
	assert.True(t, strings.HasPrefix(sa.OutcomeOf(err), "failed"))
}

// TestScanUnselectedServices: an unticked service is never called, its calls
// are recorded as "not selected", and its findings and signals are absent.
// The other services are scanned as usual.
func TestScanUnselectedServices(t *testing.T) {
	h := newHarness(t)
	conn := h.conn(true)
	conn.Config.DisabledServices = []string{sa.OptBedrockRegistry, sa.OptBedrockCloudTrail, sa.OptBedrockInvocationLogs}
	res := h.scan(t, conn)

	for _, op := range []string{
		"ListRegistries", "ListRegistryRecords", "LookupEvents",
		"GetModelInvocationLoggingConfiguration", "FilterLogEvents",
	} {
		assert.Empty(t, h.fake.requests(op), "%s must not be called", op)
	}
	for _, c := range []string{callListRegistries, callListRecords, callLookupEvents, callLoggingConfig, callFilterLogs} {
		r := call(res, c)
		assert.Equal(t, models.ShadowCallSkipped, r.Outcome, c)
		assert.Equal(t, sa.ReasonServiceOff, r.Message, c)
	}
	// Selected services still run.
	assert.NotEmpty(t, h.fake.requests("ListAgentRuntimes"))
	assert.NotEmpty(t, h.fake.requests("ListAgents"))
	assert.Equal(t, models.ShadowCallOK, call(res, callListRuntimes).Outcome)
	for _, f := range res.Findings {
		assert.NotEqual(t, models.ShadowKindPrincipal, f.Kind, "identities come from CloudTrail, which is off")
		for _, code := range []string{
			sa.SigBedrockRegistryAgent, sa.SigBedrockRegistryTool, sa.SigBedrockPlainModelUsage,
			sa.SigBedrockInvocationLogsOff, sa.SigBedrockToolCallLog, sa.SigBedrockToolResultLog,
		} {
			_, has := signal(f, code)
			assert.False(t, has, "%s has %s", f.ExternalID, code)
		}
	}
}

func TestScanOnlyCloudTrail(t *testing.T) {
	h := newHarness(t)
	conn := h.conn(false)
	conn.Config.DisabledServices = []string{
		sa.OptBedrockAgentCore, sa.OptBedrockRegistry, sa.OptBedrockClassicAgents,
		sa.OptBedrockMetrics, sa.OptBedrockInvocationLogs,
	}
	res := h.scan(t, conn)
	ops := map[string]bool{}
	for _, op := range h.fake.allOps() {
		ops[op] = true
	}
	assert.Equal(t, map[string]bool{"LookupEvents": true}, ops, "only CloudTrail is called")
	assert.True(t, hasFinding(res, models.ShadowKindPrincipal, alice))
	for _, f := range res.Findings {
		assert.Equal(t, models.ShadowKindPrincipal, f.Kind)
	}
}

func TestConnectionTestUnselectedServices(t *testing.T) {
	h := newHarness(t)
	conn := h.conn(true)
	conn.Config.DisabledServices = []string{sa.OptBedrockAgentCore, sa.OptBedrockClassicAgents, sa.OptBedrockCloudTrail}
	info := h.c.Test(context.Background(), conn)
	skipped := 0
	for _, c := range info.Checks {
		if c.Outcome == models.ShadowCallSkipped {
			skipped++
			assert.Equal(t, sa.ReasonServiceOff, c.Message, c.Name)
		}
	}
	assert.Equal(t, 4, skipped, "runtimes, gateways, classic agents and CloudTrail")
	assert.Empty(t, h.fake.requests("ListAgentRuntimes"))
	assert.Empty(t, h.fake.requests("LookupEvents"))
	assert.True(t, info.OK, "no inventory or model-call service is selected, and the selected ones work")
}
