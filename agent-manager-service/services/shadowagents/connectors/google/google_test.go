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

package google

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func TestProvider(t *testing.T) {
	assert.Equal(t, models.ShadowProviderGoogle, New(http.DefaultClient, nil).Provider())
}

func TestScanFindings(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)

	for _, call := range []string{callEngines, callAgents, callMCPServers, callTimeSeries, callLogEntries} {
		r := callResult(t, res, call)
		assert.Equal(t, models.ShadowCallOK, r.Outcome, "%s: %s", call, r.Message)
	}
	// 3 engines; 1 registry agent not on Agent Runtime; 2 MCP servers. The
	// two registry agents on engines A and B and the built-in Google agent
	// make no finding of their own.
	kinds := map[string]int{}
	for _, fd := range res.Findings {
		kinds[fd.Kind]++
	}
	assert.Equal(t, map[string]int{
		models.ShadowKindRuntime: 3, models.ShadowKindPlatformAgent: 1, models.ShadowKindToolInfra: 2,
	}, kinds)

	t.Run("engine A: registry merge, usage, creator", func(t *testing.T) {
		a := findingOf(t, res, models.ShadowKindRuntime, engineA)
		assert.Equal(t, "support-agent", a.DisplayName)
		assert.Equal(t, "projects/my-agents-project/locations/us-central1", a.Scope)
		assert.Equal(t, "google-adk", a.Attributes["framework"])
		assert.Equal(t, "agents.global.org-111111111111.system.id.goog/resources/aiplatform/projects/123456789012/locations/us-central1/reasoningEngines/1234567890123456789", a.Attributes["serviceAccount"])
		assert.Equal(t, "https://github.com/example/support-agent.git", a.Attributes["repositoryUrl"])
		assert.Equal(t, map[string]string{"team": "cx"}, a.Attributes["labels"])
		assert.Equal(t, "us-central1", a.Attributes["location"])
		assert.Equal(t, testProject, a.Attributes["project"])
		assert.Equal(t, "//aiplatform.googleapis.com/projects/123456789012/locations/us-central1/reasoningEngines/1234567890123456789", a.Attributes["runtimeReference"])
		assert.Equal(t, []string{"Ticket triage"}, a.Attributes["skills"])
		assert.Equal(t, []string{"A2A_AGENT"}, a.Attributes["protocolType"])
		require.NotNil(t, a.ProviderCreatedAt)
		assert.Equal(t, time.Date(2026, 10, 1, 10, 0, 0, 123456000, time.UTC), *a.ProviderCreatedAt)

		for _, code := range []string{sa.SigGoogleAgentEngine, sa.SigGoogleRegistryAgent, sa.SigGoogleEngineInUse, sa.SigGoogleEngineCreatedBy} {
			_, ok := signalOf(a, code)
			assert.True(t, ok, code)
		}
		inUse, _ := signalOf(a, sa.SigGoogleEngineInUse)
		assert.EqualValues(t, 65, inUse.Observed["requests"])
		assert.Equal(t, callTimeSeries, inUse.Source)
		// 25 (200) + 4 (500) on 10 Nov, 36 on 9 Nov; the zero day is left out.
		assert.ElementsMatch(t, []sa.UsageDay{
			{Day: day(2026, 11, 10), Requests: 29},
			{Day: day(2026, 11, 9), Requests: 36},
		}, a.Usage)
		require.NotNil(t, a.LastUsedAt)
		assert.Equal(t, day(2026, 11, 10), *a.LastUsedAt)
		assert.Equal(t, day(2026, 11, 9), *a.FirstUsedAt)

		// Created by dev@, later updated by other@: the creator is the owner.
		assert.Equal(t, "dev@example.com", a.OwnerHint.Email)
		assert.Equal(t, "user", a.OwnerHint.Type)
		assert.Contains(t, a.OwnerHint.Source, "CreateReasoningEngine")
		require.NotNil(t, a.OwnerHint.CreatedAt)
		assert.Equal(t, time.Date(2026, 10, 1, 10, 0, 0, 123000000, time.UTC), *a.OwnerHint.CreatedAt)
		created, _ := signalOf(a, sa.SigGoogleEngineCreatedBy)
		assert.EqualValues(t, 1, created.Observed["creates"])
		assert.EqualValues(t, 1, created.Observed["updates"])

		score, verdict := sa.Score(a.Kind, codes(a))
		assert.Equal(t, models.ShadowVerdictAgent, verdict)
		assert.Equal(t, 80, score)
	})

	t.Run("engine B: registry by agentId URN with the project number; zero requests", func(t *testing.T) {
		b := findingOf(t, res, models.ShadowKindRuntime, engineB)
		assert.Equal(t, "orders-agent", b.DisplayName)
		assert.Equal(t, "langgraph", b.Attributes["framework"])
		assert.Equal(t, "orders-agent@my-agents-project.iam.gserviceaccount.com", b.Attributes["serviceAccount"])
		assert.NotContains(t, b.Attributes, "repositoryUrl")
		assert.Equal(t, "projects/123456789012/locations/us-central1/reasoningEngines/9876543210987654321", b.Attributes["runtimeReference"])
		_, ok := signalOf(b, sa.SigGoogleRegistryAgent)
		assert.True(t, ok)
		_, ok = signalOf(b, sa.SigGoogleEngineInUse)
		assert.False(t, ok, "all-zero request counts must not mark the engine in use")
		assert.Empty(t, b.Usage)
		assert.Nil(t, b.LastUsedAt)
		assert.Equal(t, "ci-deployer@my-agents-project.iam.gserviceaccount.com", b.OwnerHint.Email)
		assert.Equal(t, "service_account", b.OwnerHint.Type)
	})

	t.Run("engine C: us multi-region, creator from the operation name", func(t *testing.T) {
		e := findingOf(t, res, models.ShadowKindRuntime, engineC)
		assert.Equal(t, "us", e.Attributes["location"])
		assert.Equal(t, "custom", e.Attributes["framework"])
		assert.Equal(t, "ops@example.com", e.OwnerHint.Email)
		assert.Equal(t, []sa.UsageDay{{Day: day(2026, 10, 25), Requests: 7}}, e.Usage)
		_, ok := signalOf(e, sa.SigGoogleRegistryAgent)
		assert.False(t, ok)
	})

	t.Run("registry agent without a runtime engine", func(t *testing.T) {
		h := findingOf(t, res, models.ShadowKindPlatformAgent, "urn:agent:projects-123456789012:projects:123456789012:locations:us-central1:run:services:helpdesk-bot")
		assert.Equal(t, "helpdesk-bot", h.DisplayName)
		assert.Equal(t, []string{"A2A_AGENT"}, h.Attributes["protocolType"])
		assert.Equal(t, []string{"Answer FAQ", "ticket"}, h.Attributes["skills"])
		assert.Equal(t, "helpdesk-bot@my-agents-project.iam.gserviceaccount.com", h.Attributes["serviceAccount"])
		assert.Equal(t, "langchain", h.Attributes["framework"])
		assert.Equal(t, "2.1.0", h.Attributes["agentVersion"])
		assert.NotContains(t, h.Attributes, "runtimeReference")
		require.Len(t, h.Signals, 1)
		assert.Equal(t, sa.SigGoogleRegistryAgent, h.Signals[0].Code)
		assert.Equal(t, true, h.Signals[0].Observed["a2a"])
		_, verdict := sa.Score(h.Kind, codes(h))
		assert.Equal(t, models.ShadowVerdictAgent, verdict)
	})

	t.Run("MCP servers are tool infrastructure with label and origin only", func(t *testing.T) {
		bq := findingOf(t, res, models.ShadowKindToolInfra, "urn:mcp:googleapis.com:projects:123456789012:locations:global:bigquery")
		assert.Equal(t, []sa.MCPServerRef{{Label: "BigQuery MCP server", Origin: "https://bigquery.googleapis.com"}}, bq.Attributes["mcpServers"])
		assert.Equal(t, "global", bq.Attributes["location"])
		require.Len(t, bq.Signals, 1)
		assert.Equal(t, sa.SigGoogleRegistryMCP, bq.Signals[0].Code)
		_, verdict := sa.Score(bq.Kind, codes(bq))
		assert.Equal(t, models.ShadowVerdictToolInfra, verdict)
		crm := findingOf(t, res, models.ShadowKindToolInfra, "urn:mcp:projects-123456789012:projects:123456789012:locations:us-central1:run:services:crm-mcp")
		assert.Equal(t, []sa.MCPServerRef{{Label: "crm-mcp", Origin: "https://crm-mcp-abc123-uc.a.run.app"}}, crm.Attributes["mcpServers"])
	})

	t.Run("every attribute key is allowed and survives sanitising", func(t *testing.T) {
		for _, fd := range res.Findings {
			clean := sa.SanitizeAttributes(fd.Attributes)
			assert.Equal(t, len(fd.Attributes), len(clean), "finding %s has a disallowed attribute: %v", fd.ExternalID, fd.Attributes)
		}
	})
}

func codes(f *sa.Finding) []string {
	out := make([]string, 0, len(f.Signals))
	for _, s := range f.Signals {
		out = append(out, s.Code)
	}
	return out
}

func TestScanRequests(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	c.Scan(context.Background(), f.conn(t), testWindow)

	t.Run("reasoningEngines.list: regional and multi-region hosts", func(t *testing.T) {
		paths := map[string]bool{}
		for _, r := range f.requests("engines") {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "100", r.Query.Get("pageSize"))
			assert.Empty(t, r.Query.Get("filter"))
			assert.Equal(t, "application/json", r.Header.Get("Accept"))
			paths[r.Path] = true
		}
		assert.Equal(t, map[string]bool{
			"/regional/us-central1/v1/projects/my-agents-project/locations/us-central1/reasoningEngines": true,
			"/multiregion/us/v1/projects/my-agents-project/locations/us/reasoningEngines":                true,
			"/multiregion/eu/v1/projects/my-agents-project/locations/eu/reasoningEngines":                true,
		}, paths)
	})

	t.Run("Agent Registry: v1 agents and mcpServers in every location incl. global", func(t *testing.T) {
		for _, route := range []string{"agents", "mcp"} {
			coll := map[string]string{"agents": "agents", "mcp": "mcpServers"}[route]
			paths := map[string]bool{}
			for _, r := range f.requests(route) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "100", r.Query.Get("pageSize"))
				paths[r.Path] = true
			}
			want := map[string]bool{}
			for _, l := range []string{"us-central1", "global", "us", "eu"} {
				want["/v1/projects/my-agents-project/locations/"+l+"/"+coll] = true
			}
			assert.Equal(t, want, paths, route)
		}
	})

	t.Run("timeSeries.list: filter, daily ALIGN_SUM, window", func(t *testing.T) {
		reqs := f.requests("timeseries")
		require.NotEmpty(t, reqs)
		r := reqs[0]
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v3/projects/my-agents-project/timeSeries", r.Path)
		assert.Equal(t, `metric.type="aiplatform.googleapis.com/reasoning_engine/request_count"`, r.Query.Get("filter"))
		assert.Equal(t, "2026-10-01T00:00:00Z", r.Query.Get("interval.startTime"))
		assert.Equal(t, "2026-11-10T12:00:00Z", r.Query.Get("interval.endTime"))
		assert.Equal(t, "86400s", r.Query.Get("aggregation.alignmentPeriod"))
		assert.Equal(t, "ALIGN_SUM", r.Query.Get("aggregation.perSeriesAligner"))
		assert.Empty(t, r.Query.Get("aggregation.crossSeriesReducer"))
		assert.Equal(t, "FULL", r.Query.Get("view"))
	})

	t.Run("entries.list: POST body", func(t *testing.T) {
		reqs := f.requests("logs")
		require.NotEmpty(t, reqs)
		r := reqs[0]
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v2/entries:list", r.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body map[string]any
		require.NoError(t, json.Unmarshal(r.Body, &body))
		assert.Equal(t, []any{"projects/my-agents-project"}, body["resourceNames"])
		assert.Equal(t, "timestamp asc", body["orderBy"])
		assert.EqualValues(t, 1000, body["pageSize"])
		assert.NotContains(t, body, "pageToken")
		assert.Equal(t, `logName="projects/my-agents-project/logs/cloudaudit.googleapis.com%2Factivity"`+
			` AND protoPayload.serviceName="aiplatform.googleapis.com"`+
			` AND protoPayload.methodName:"ReasoningEngineService"`+
			` AND timestamp>="2026-10-01T00:00:00Z" AND timestamp<="2026-11-10T12:00:00Z"`, body["filter"])
	})

	t.Run("one token for the whole scan", func(t *testing.T) {
		assert.Len(t, f.requests("token"), 1)
	})
}

func TestScanPagination(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)

	tokens := func(route, loc string) []string {
		var out []string
		for _, r := range f.requests(route) {
			if loc == "" || strings.Contains(r.Path, "/locations/"+loc+"/") {
				if route == "logs" {
					var b listLogEntriesRequest
					require.NoError(t, json.Unmarshal(r.Body, &b))
					out = append(out, b.PageToken)
					continue
				}
				out = append(out, r.Query.Get("pageToken"))
			}
		}
		return out
	}
	assert.Equal(t, []string{"", "engines-page-2"}, tokens("engines", "us-central1"))
	assert.Equal(t, []string{"", "agents-page-2"}, tokens("agents", "us-central1"))
	assert.Equal(t, []string{"", "mcp-page-2"}, tokens("mcp", "global"))
	assert.Equal(t, []string{"", "ts-page-2"}, tokens("timeseries", ""))
	// Page 2 of the logs is empty but has a token: paging goes on.
	assert.Equal(t, []string{"", "logs-page-2", "logs-page-3"}, tokens("logs", ""))

	// Items add up over pages and scopes.
	assert.Equal(t, 3, callResult(t, res, callEngines).Items)
	assert.Equal(t, 5, callResult(t, res, callAgents).Items)
	assert.Equal(t, 2, callResult(t, res, callMCPServers).Items)
	assert.Equal(t, 5, callResult(t, res, callTimeSeries).Items)
	assert.Equal(t, 7, callResult(t, res, callLogEntries).Items)
}

func TestScanPageLimitIsRecorded(t *testing.T) {
	f := newFakeGoogle(t)
	f.setOverride("engines", func(w http.ResponseWriter, _ *http.Request) {
		serveJSON(w, `{"reasoningEngines":[],"nextPageToken":"more"}`)
	})
	c := newTestConnector(f)
	conn := f.conn(t)
	conn.Config.IncludeGlobalAndMultiRegion = false
	res := c.Scan(context.Background(), conn, testWindow)
	assert.Len(t, f.requests("engines"), maxEnginePages)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callEngines).Outcome)
	limit := callResult(t, res, callEngines+" (page limit)")
	assert.Equal(t, models.ShadowCallSkipped, limit.Outcome)
	assert.Contains(t, limit.Message, "stopped after 20 pages")
}

func TestMonitoringWindowCappedToRetention(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	w := sa.NewWindow(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC), 90)
	c.Scan(context.Background(), f.conn(t), w)
	r := f.requests("timeseries")[0]
	assert.Equal(t, "2026-09-29T12:00:00Z", r.Query.Get("interval.startTime"), "6 weeks before the end")
	assert.Equal(t, "2026-11-10T12:00:00Z", r.Query.Get("interval.endTime"))
	// The audit log keeps 400 days: the whole window is read.
	var body listLogEntriesRequest
	require.NoError(t, json.Unmarshal(f.requests("logs")[0].Body, &body))
	assert.Contains(t, body.Filter, `timestamp>="2026-08-12T00:00:00Z"`)
}

func TestMonitoringPointsCountedOnce(t *testing.T) {
	f := newFakeGoogle(t)
	// The same series served on two pages (e.g. a repeated page): its points
	// must not be counted twice.
	f.setOverride("timeseries", func(w http.ResponseWriter, r *http.Request) {
		body := readFixture("timeseries_page1.json")
		if r.URL.Query().Get("pageToken") == "" {
			body = []byte(strings.Replace(string(body), `"ts-page-2"`, `"again"`, 1))
		} else {
			body = []byte(strings.Replace(string(body), `"ts-page-2"`, `""`, 1))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)
	a := findingOf(t, res, models.ShadowKindRuntime, engineA)
	assert.ElementsMatch(t, []sa.UsageDay{{Day: day(2026, 11, 10), Requests: 29}, {Day: day(2026, 11, 9), Requests: 36}}, a.Usage)
	s, _ := signalOf(a, sa.SigGoogleEngineInUse)
	assert.EqualValues(t, 65, s.Observed["requests"])
}

func TestAuditLogThrottle(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	c.Scan(context.Background(), f.conn(t), testWindow)
	require.Len(t, f.requests("logs"), 3)
	// One wait before every entries.list request but the first, each at
	// most the 1-second interval.
	require.Len(t, c.waits, 2)
	for _, w := range c.waits {
		assert.Greater(t, w, time.Duration(0))
		assert.LessOrEqual(t, w, time.Second)
	}
}

func TestRetention(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)
	out, err := json.Marshal(res)
	require.NoError(t, err)
	info := c.Test(context.Background(), f.conn(t))
	testOut, err := json.Marshal(info)
	require.NoError(t, err)
	for _, m := range retentionMarkers {
		assert.NotContains(t, string(out), m, "result")
		assert.NotContains(t, string(testOut), m, "test result")
		assert.NotContains(t, c.logs.String(), m, "logs")
	}
	// No query strings in logs either.
	assert.NotContains(t, c.logs.String(), "pageToken")
	assert.Contains(t, c.logs.String(), "Shadow agent discovery provider call")
}

func TestScanTokenEndpointRefusesKey(t *testing.T) {
	f := newFakeGoogle(t)
	f.setOverride("token", serveError(http.StatusBadRequest, "token_error.json"))
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)

	first := callResult(t, res, callEngines)
	assert.Equal(t, models.ShadowCallAuthFailed, first.Outcome)
	assert.Contains(t, first.Message, "token endpoint refused")
	for _, call := range []string{callAgents, callMCPServers} {
		assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, call).Outcome, call)
	}
	assert.Empty(t, f.requests(""), "no API call is made without a token")
	assert.Empty(t, res.Findings)
}

func TestScanInvalidServiceAccountKey(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	conn := f.conn(t)
	conn.Secret.ServiceAccountJSON = `{"type":"authorized_user"}`
	res := c.Scan(context.Background(), conn, testWindow)
	r := callResult(t, res, callToken)
	assert.Equal(t, models.ShadowCallAuthFailed, r.Outcome)
	assert.Contains(t, r.Message, "not a valid JSON key file")
	assert.Empty(t, f.requests("token"))
	assert.Empty(t, f.requests(""))
}

func TestScanUnauthorizedStopsEarly(t *testing.T) {
	f := newFakeGoogle(t)
	f.setOverride("engines", serveError(http.StatusUnauthorized, "error_401.json"))
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)
	r := callResult(t, res, callEngines)
	assert.Equal(t, models.ShadowCallAuthFailed, r.Outcome)
	assert.Contains(t, r.Message, "UNAUTHENTICATED")
	assert.Len(t, f.requests(""), 1, "the scan stops after the first 401")
	assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, callAgents).Outcome)
	assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, callMCPServers).Outcome)
}

func TestScanRegistryDisabledIsPermissionDenied(t *testing.T) {
	f := newFakeGoogle(t)
	f.setOverride("agents", serveError(http.StatusForbidden, "error_403_service_disabled.json"))
	f.setOverride("mcp", serveError(http.StatusForbidden, "error_403_service_disabled.json"))
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)

	agents := callResult(t, res, callAgents)
	assert.Equal(t, models.ShadowCallPermissionDenied, agents.Outcome)
	assert.Contains(t, agents.Message, "PERMISSION_DENIED")
	assert.Contains(t, agents.Message, "4 of 4 scopes failed")
	assert.Equal(t, models.ShadowCallPermissionDenied, callResult(t, res, callMCPServers).Outcome)
	for _, call := range []string{callEngines, callTimeSeries, callLogEntries} {
		assert.Equal(t, models.ShadowCallOK, callResult(t, res, call).Outcome, call)
	}
	a := findingOf(t, res, models.ShadowKindRuntime, engineA)
	_, ok := signalOf(a, sa.SigGoogleRegistryAgent)
	assert.False(t, ok)
	_, ok = signalOf(a, sa.SigGoogleEngineInUse)
	assert.True(t, ok)
	assert.Len(t, res.Findings, 3)
}

func TestScanRateLimitedThenOK(t *testing.T) {
	f := newFakeGoogle(t)
	calls := 0
	f.setOverride("timeseries", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			serveError(http.StatusTooManyRequests, "error_429.json")(w, r)
			return
		}
		f.defaultHandler("timeseries")(w, r)
	})
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callTimeSeries).Outcome)
	assert.Equal(t, 3, calls)
	a := findingOf(t, res, models.ShadowKindRuntime, engineA)
	_, ok := signalOf(a, sa.SigGoogleEngineInUse)
	assert.True(t, ok)
}

func TestScanMalformedJSON(t *testing.T) {
	f := newFakeGoogle(t)
	f.setOverride("engines", func(w http.ResponseWriter, _ *http.Request) { serveJSON(w, `{"reasoningEngines": [`) })
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)
	r := callResult(t, res, callEngines)
	assert.Equal(t, models.ShadowCallUnsupported, r.Outcome)
	// Registry still runs; metrics and logs have no engine to match.
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callAgents).Outcome)
	assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, callTimeSeries).Outcome)
	assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, callLogEntries).Outcome)
	assert.Empty(t, f.requests("timeseries"))
	assert.Empty(t, f.requests("logs"))
	// Without the engines, the registry agents of engines A and B are
	// platform agents of their own.
	kinds := map[string]int{}
	for _, fd := range res.Findings {
		kinds[fd.Kind]++
	}
	assert.Equal(t, 3, kinds[models.ShadowKindPlatformAgent])
}

func TestScanWrongShapeIsUnsupported(t *testing.T) {
	f := newFakeGoogle(t)
	f.setOverride("timeseries", func(w http.ResponseWriter, _ *http.Request) { serveJSON(w, `{"timeSeries": {"not": "a list"}}`) })
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)
	r := callResult(t, res, callTimeSeries)
	assert.Equal(t, models.ShadowCallUnsupported, r.Outcome)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callLogEntries).Outcome)
}

func TestScanSettings(t *testing.T) {
	t.Run("invalid locations and projects never reach a URL", func(t *testing.T) {
		f := newFakeGoogle(t)
		c := newTestConnector(f)
		conn := f.conn(t)
		conn.Config.ProjectIDs = []string{testProject, "bad/project\"", testProject}
		conn.Config.Locations = []string{"US-Central1", "evil.example.com/x#"}
		conn.Config.IncludeGlobalAndMultiRegion = false
		res := c.Scan(context.Background(), conn, testWindow)
		cfg := callResult(t, res, callConfig)
		assert.Equal(t, models.ShadowCallFailed, cfg.Outcome)
		assert.Contains(t, cfg.Message, "is not a valid location")
		assert.Contains(t, cfg.Message, "is not a valid project ID")
		for _, r := range f.requests("") {
			assert.NotContains(t, r.Path, "evil")
			assert.NotContains(t, r.Path, "bad")
		}
		assert.Len(t, f.requests("engines"), 2, "us-central1 (lower-cased, de-duplicated) only, two pages")
	})

	t.Run("no project", func(t *testing.T) {
		f := newFakeGoogle(t)
		c := newTestConnector(f)
		conn := f.conn(t)
		conn.Config.ProjectIDs = nil
		res := c.Scan(context.Background(), conn, testWindow)
		assert.Equal(t, models.ShadowCallFailed, callResult(t, res, callConfig).Outcome)
		assert.Empty(t, f.requests(""))
		assert.Empty(t, f.requests("token"))
	})

	t.Run("global in locations is a registry location only", func(t *testing.T) {
		st, problems := readSettings(sa.Connection{Config: models.ShadowConnectionConfig{
			ProjectIDs: []string{"p-1"}, Locations: []string{"europe-west1", "global"},
		}})
		assert.Empty(t, problems)
		assert.Equal(t, []string{"europe-west1"}, st.runtimeLocations)
		assert.Equal(t, []string{"europe-west1", "global"}, st.registryLocations)
	})
}

func TestScanEmptyProjectRaisesNothing(t *testing.T) {
	f := newFakeGoogle(t)
	for _, route := range []string{"engines", "agents", "mcp"} {
		f.setOverride(route, func(w http.ResponseWriter, _ *http.Request) { serveJSON(w, `{}`) })
	}
	c := newTestConnector(f)
	res := c.Scan(context.Background(), f.conn(t), testWindow)
	assert.Empty(t, res.Findings)
	assert.Equal(t, models.ShadowCallOK, callResult(t, res, callEngines).Outcome)
	assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, callTimeSeries).Outcome)
	assert.Equal(t, models.ShadowCallSkipped, callResult(t, res, callLogEntries).Outcome)
}

// Deep inspection has no effect on this connector: it reads no content
// source (the audit log is read for method, resource and principal only).
// Both settings call exactly the same endpoints, and the fake fails the
// test on any endpoint it does not know.
func TestDeepInspectionCallsNoContentEndpoint(t *testing.T) {
	paths := func(deep bool) []string {
		f := newFakeGoogle(t)
		c := newTestConnector(f)
		conn := f.conn(t)
		conn.Config.DeepInspection = deep
		c.Scan(context.Background(), conn, testWindow)
		var out []string
		for _, r := range f.requests("") {
			out = append(out, r.Method+" "+r.Path)
		}
		sort.Strings(out)
		return out
	}
	assert.Equal(t, paths(false), paths(true))
}

func TestSignalConditions(t *testing.T) {
	s := &scanner{c: &Connector{}, findings: sa.NewFindings(), aliases: map[string]map[string]bool{}}
	s.addEngine(testProject, "us-central1", &reasoningEngine{Name: engineA})
	e := s.engines[0]

	t.Run("built-in Google agents are left out", func(t *testing.T) {
		s.addRegistryAgent(testProject, "global", &registryAgent{AgentID: "urn:agent:googleapis.com:projects:1:locations:global:x", Name: "projects/1/locations/global/agents/x"})
		assert.Len(t, s.findings.All(), 1)
	})

	t.Run("registry agent referencing an unknown engine is a platform agent", func(t *testing.T) {
		s.addRegistryAgent(testProject, "us-central1", &registryAgent{
			AgentID: "urn:agent:projects-1:projects:1:locations:us-central1:aiplatform:reasoningEngines:42",
			Name:    "projects/1/locations/us-central1/agents/a",
		})
		f, ok := s.findings.Lookup(models.ShadowKindPlatformAgent, "urn:agent:projects-1:projects:1:locations:us-central1:aiplatform:reasoningEngines:42")
		require.True(t, ok)
		assert.Equal(t, "projects/1/locations/us-central1/reasoningEngines/42", f.Attributes["runtimeReference"])
	})

	t.Run("in use needs a count above zero", func(t *testing.T) {
		s.applyUsage(e, map[time.Time]int64{day(2026, 11, 1): 0})
		_, ok := signalOf(e.finding, sa.SigGoogleEngineInUse)
		assert.False(t, ok)
		s.applyUsage(e, map[time.Time]int64{day(2026, 11, 1): 1})
		_, ok = signalOf(e.finding, sa.SigGoogleEngineInUse)
		assert.True(t, ok)
	})

	t.Run("created-by needs a ReasoningEngineService create or update on a known engine", func(t *testing.T) {
		entry := func(method, resource string) *logEntry {
			var le logEntry
			raw := `{"insertId":"` + method + resource + `","timestamp":"2026-10-01T00:00:00Z","protoPayload":{"serviceName":"aiplatform.googleapis.com","methodName":"` + method + `","resourceName":"` + resource + `","authenticationInfo":{"principalEmail":"x@example.com"}}}`
			require.NoError(t, json.Unmarshal([]byte(raw), &le))
			return &le
		}
		seen := map[string]bool{}
		for _, le := range []*logEntry{
			entry("google.cloud.aiplatform.v1.ReasoningEngineService.DeleteReasoningEngine", engineA),
			entry("google.cloud.aiplatform.v1.ReasoningEngineService.QueryReasoningEngine", engineA),
			entry("google.cloud.aiplatform.v1.EndpointService.CreateEndpoint", engineA),
			entry("google.cloud.aiplatform.v1.ReasoningEngineService.CreateReasoningEngine", "projects/1/locations/us-central1/reasoningEngines/404"),
		} {
			s.auditEntry(le, seen)
		}
		_, ok := signalOf(e.finding, sa.SigGoogleEngineCreatedBy)
		assert.False(t, ok)
		assert.Empty(t, e.finding.OwnerHint.Email)

		s.auditEntry(entry("google.cloud.aiplatform.v1beta1.ReasoningEngineService.UpdateReasoningEngine", engineA), seen)
		sig, ok := signalOf(e.finding, sa.SigGoogleEngineCreatedBy)
		assert.True(t, ok)
		assert.EqualValues(t, 1, sig.Observed["updates"])
		assert.Equal(t, "x@example.com", e.finding.OwnerHint.Email)
		// The same entry again (same insertId) is not counted twice.
		s.auditEntry(entry("google.cloud.aiplatform.v1beta1.ReasoningEngineService.UpdateReasoningEngine", engineA), seen)
		sig, _ = signalOf(e.finding, sa.SigGoogleEngineCreatedBy)
		assert.EqualValues(t, 1, sig.Observed["updates"])
	})

	t.Run("redacted principal: signal without an owner hint", func(t *testing.T) {
		s2 := &scanner{c: &Connector{}, findings: sa.NewFindings(), aliases: map[string]map[string]bool{}}
		s2.addEngine(testProject, "us-central1", &reasoningEngine{Name: engineA})
		var le logEntry
		require.NoError(t, json.Unmarshal([]byte(`{"protoPayload":{"methodName":"google.cloud.aiplatform.v1.ReasoningEngineService.CreateReasoningEngine","resourceName":"`+engineA+`","authenticationInfo":{}}}`), &le))
		s2.auditEntry(&le, map[string]bool{})
		_, ok := signalOf(s2.engines[0].finding, sa.SigGoogleEngineCreatedBy)
		assert.True(t, ok)
		assert.Equal(t, models.ShadowOwnerHint{}, s2.engines[0].finding.OwnerHint)
	})
}

func TestEngineReferences(t *testing.T) {
	ref, ok := parseEngineRef("//aiplatform.googleapis.com/projects/123/locations/us-central1/reasoningEngines/77")
	assert.True(t, ok)
	assert.Equal(t, engineRef{project: "123", location: "us-central1", id: "77"}, ref)
	ref, ok = parseEngineRef("principal://agents.global.org-1.system.id.goog/resources/aiplatform/projects/123/locations/eu/reasoningEngines/88")
	assert.True(t, ok)
	assert.Equal(t, engineRef{project: "123", location: "eu", id: "88"}, ref)
	ref, ok = parseEngineRef("projects/123/locations/us/reasoningEngines/99/operations/5")
	assert.True(t, ok)
	assert.Equal(t, "99", ref.id)
	_, ok = parseEngineRef("//run.googleapis.com/projects/123/locations/us-central1/services/x")
	assert.False(t, ok)
	ref, ok = parseEngineURN("urn:agent:projects-123:projects:123:locations:us-central1:aiplatform:reasoningEngines:77")
	assert.True(t, ok)
	assert.Equal(t, engineRef{project: "123", location: "us-central1", id: "77"}, ref)
	_, ok = parseEngineURN("urn:agent:projects-123:projects:123:locations:us-central1:run:services:x")
	assert.False(t, ok)

	t.Run("project number vs project ID", func(t *testing.T) {
		s := &scanner{findings: sa.NewFindings(), aliases: map[string]map[string]bool{}}
		s.addEngine("proj-a", "us-central1", &reasoningEngine{Name: "projects/proj-a/locations/us-central1/reasoningEngines/1"})
		s.addEngine("proj-b", "us-central1", &reasoningEngine{Name: "projects/proj-b/locations/us-central1/reasoningEngines/1"})
		// Two engines share the ID: a number with no known alias matches neither.
		assert.Nil(t, s.findEngine(engineRef{project: "555", location: "us-central1", id: "1"}))
		s.addAlias("proj-b", "555")
		assert.Equal(t, "proj-b", s.findEngine(engineRef{project: "555", location: "us-central1", id: "1"}).project)
		assert.Equal(t, "proj-a", s.findEngine(engineRef{project: "proj-a", location: "us-central1", id: "1"}).project)
		// A unique engine ID resolves even when the project is unknown.
		s.addEngine("proj-a", "europe-west1", &reasoningEngine{Name: "projects/proj-a/locations/europe-west1/reasoningEngines/2"})
		assert.NotNil(t, s.findEngine(engineRef{project: "999", location: "europe-west1", id: "2"}))
		assert.Nil(t, s.findEngine(engineRef{project: "proj-a", location: "us-east1", id: "2"}))
	})
}

func TestTypedValueAndPointDay(t *testing.T) {
	parse := func(raw string) (int64, bool) {
		var v typedValue
		require.NoError(t, json.Unmarshal([]byte(raw), &v))
		return v.count()
	}
	n, ok := parse(`{"int64Value":"25"}`)
	assert.True(t, ok)
	assert.EqualValues(t, 25, n)
	n, ok = parse(`{"int64Value":7}`)
	assert.True(t, ok)
	assert.EqualValues(t, 7, n)
	n, ok = parse(`{"doubleValue":2.6}`)
	assert.True(t, ok)
	assert.EqualValues(t, 3, n)
	_, ok = parse(`{"int64Value":"x"}`)
	assert.False(t, ok)
	_, ok = parse(`{"boolValue":true}`)
	assert.False(t, ok)

	d, ok := pointDay("2026-11-09T12:00:00Z", "2026-11-10T12:00:00Z")
	assert.True(t, ok)
	assert.Equal(t, day(2026, 11, 10), d)
	d, ok = pointDay("2026-11-09T00:00:00Z", "2026-11-10T00:00:00Z")
	assert.True(t, ok)
	assert.Equal(t, day(2026, 11, 9), d)
	d, ok = pointDay("", "2026-03-26T18:56:27Z")
	assert.True(t, ok)
	assert.Equal(t, day(2026, 3, 26), d)
	_, ok = pointDay("", "")
	assert.False(t, ok)
}

func TestConnectionTest(t *testing.T) {
	t.Run("all capabilities", func(t *testing.T) {
		f := newFakeGoogle(t)
		c := newTestConnector(f)
		info := c.Test(context.Background(), f.conn(t))
		assert.True(t, info.OK)
		require.Len(t, info.Checks, 5)
		for _, ch := range info.Checks {
			assert.Equal(t, models.ShadowCallOK, ch.Outcome, ch.Name)
			assert.NotEmpty(t, ch.Unlocks, ch.Name)
		}
		assert.Equal(t, []string{sa.SigGoogleAgentEngine}, info.Checks[0].Unlocks)
		for _, r := range f.requests("") {
			if r.Method == http.MethodGet {
				assert.Equal(t, "1", r.Query.Get("pageSize"), r.Path)
			} else {
				var b listLogEntriesRequest
				require.NoError(t, json.Unmarshal(r.Body, &b))
				assert.Equal(t, 1, b.PageSize)
			}
		}
		assert.Equal(t, "HEADERS", f.requests("timeseries")[0].Query.Get("view"))
		assert.Contains(t, f.requests("mcp")[0].Path, "/locations/global/")
		assert.Contains(t, f.requests("engines")[0].Path, "/regional/us-central1/")
	})

	t.Run("registry disabled: still OK, the check says what is missed", func(t *testing.T) {
		f := newFakeGoogle(t)
		f.setOverride("agents", serveError(http.StatusForbidden, "error_403_service_disabled.json"))
		c := newTestConnector(f)
		info := c.Test(context.Background(), f.conn(t))
		assert.True(t, info.OK)
		assert.Equal(t, models.ShadowCallPermissionDenied, info.Checks[1].Outcome)
		assert.Equal(t, []string{sa.SigGoogleRegistryAgent}, info.Checks[1].Unlocks)
		assert.Equal(t, models.ShadowCallOK, info.Checks[2].Outcome)
	})

	t.Run("token refused", func(t *testing.T) {
		f := newFakeGoogle(t)
		f.setOverride("token", serveError(http.StatusBadRequest, "token_error.json"))
		c := newTestConnector(f)
		info := c.Test(context.Background(), f.conn(t))
		assert.False(t, info.OK)
		assert.Equal(t, models.ShadowCallAuthFailed, info.Checks[0].Outcome)
		for _, ch := range info.Checks[1:] {
			assert.Equal(t, models.ShadowCallSkipped, ch.Outcome)
		}
		assert.Empty(t, f.requests(""))
	})

	t.Run("engines denied: not OK", func(t *testing.T) {
		f := newFakeGoogle(t)
		f.setOverride("engines", serveError(http.StatusForbidden, "error_403_service_disabled.json"))
		c := newTestConnector(f)
		info := c.Test(context.Background(), f.conn(t))
		assert.False(t, info.OK)
		assert.Equal(t, models.ShadowCallPermissionDenied, info.Checks[0].Outcome)
		assert.Equal(t, models.ShadowCallOK, info.Checks[3].Outcome)
	})

	t.Run("invalid key and missing settings", func(t *testing.T) {
		f := newFakeGoogle(t)
		c := newTestConnector(f)
		conn := f.conn(t)
		conn.Secret.ServiceAccountJSON = "not json"
		info := c.Test(context.Background(), conn)
		assert.False(t, info.OK)
		assert.Equal(t, checkToken, info.Checks[0].Name)
		assert.Equal(t, models.ShadowCallAuthFailed, info.Checks[0].Outcome)

		conn = f.conn(t)
		conn.Config.Locations = nil
		conn.Config.IncludeGlobalAndMultiRegion = false
		info = c.Test(context.Background(), conn)
		assert.False(t, info.OK)
		assert.Equal(t, checkSettings, info.Checks[0].Name)
		assert.Empty(t, f.requests(""))
	})
}

func TestScanServiceAccountKeyNotKnownToGoogle(t *testing.T) {
	f := newFakeGoogle(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(other)
	require.NoError(t, err)
	conn := f.conn(t)
	conn.Secret.ServiceAccountJSON = keyFileJSON(t, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))

	res := newTestConnector(f).Scan(context.Background(), conn, testWindow)
	assert.Equal(t, models.ShadowCallAuthFailed, callResult(t, res, callEngines).Outcome)
	assert.Len(t, f.requests("token"), 1)
	assert.Empty(t, f.requests(""))
}

// TestScanUnselectedServices: with the Agent Registry, Cloud Monitoring and
// the audit logs unticked, only the engines are read; the other calls are
// recorded as "not selected" and their signals are absent.
func TestScanUnselectedServices(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	conn := f.conn(t)
	conn.Config.DisabledServices = []string{sa.OptGoogleRegistry, sa.OptGoogleMonitoring, sa.OptGoogleAuditLogs}
	res := c.Scan(context.Background(), conn, testWindow)

	for _, route := range []string{"agents", "mcp", "timeseries", "logs"} {
		assert.Empty(t, f.requests(route), "%s must not be called", route)
	}
	assert.NotEmpty(t, f.requests("engines"))
	for _, call := range []string{callAgents, callMCPServers, callTimeSeries, callLogEntries} {
		r := callResult(t, res, call)
		assert.Equal(t, models.ShadowCallSkipped, r.Outcome, call)
		assert.Equal(t, sa.ReasonServiceOff, r.Message, call)
	}
	assert.NotEmpty(t, res.Findings)
	for _, fd := range res.Findings {
		assert.Equal(t, models.ShadowKindRuntime, fd.Kind, "only engines without the registry")
		for _, s := range fd.Signals {
			assert.Equal(t, sa.SigGoogleAgentEngine, s.Code, fd.ExternalID)
		}
	}
}

func TestConnectionTestUnselectedServices(t *testing.T) {
	f := newFakeGoogle(t)
	c := newTestConnector(f)
	conn := f.conn(t)
	conn.Config.DisabledServices = []string{sa.OptGoogleMonitoring, sa.OptGoogleAuditLogs}
	info := c.Test(context.Background(), conn)
	assert.True(t, info.OK)
	skipped := map[string]bool{}
	for _, ch := range info.Checks {
		if ch.Outcome == models.ShadowCallSkipped {
			skipped[ch.Name] = ch.Message == sa.ReasonServiceOff
		}
	}
	assert.Equal(t, map[string]bool{checkMetrics: true, checkAuditLogs: true}, skipped)
	assert.Empty(t, f.requests("timeseries"))
	assert.Empty(t, f.requests("logs"))
}
