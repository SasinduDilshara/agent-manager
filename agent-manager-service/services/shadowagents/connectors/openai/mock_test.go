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
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Fixtures (testdata/) and the official example or schema each follows
// (sources as in evidence/openai.md):
//
//   projects.{1,2}.json                  OAS list-projects 200 example (ProjectListResponse / Project)
//   api_keys.proj_*.json                 OAS list-project-api-keys 200 example (ProjectApiKey; user and service_account owners)
//   audit_logs.{1,2}.json                OAS AuditLog x-oaiMeta example and list-audit-logs list wrapper (session, null and api_key actors)
//   usage_completions.{1,2}.json         OAS usage/completions example (UsageResponse / UsageCompletionsResult + api_source)
//   costs.{1,2}.json                     OAS costs example (CostsResult)
//   web_search_calls.{1,2}.json          OAS usage/web_search_calls example (organization.usage.web_searches.result)
//   file_search_calls.{1,2}.json         OAS usage/file_search_calls example (organization.usage.file_searches.result)
//   code_interpreter_sessions.{1,2}.json OAS usage/code_interpreter_sessions example
//   agents.proj_*.json                   DOCS beta agents list 200 example (AgentListResource / AgentResource; MCP item per OAS L101088)
//   sessions.proj_*.json                 DOCS beta agents sessions list 200 example (SessionResource)
//   chat_completions.proj_*.json         OAS listChatCompletions 200 example (ChatCompletionList)
//   batches.proj_*.json                  OAS listBatches 200 example (ListBatchesResponse / Batch)
//   file-out*.jsonl                      Batch guide output line shape ({id, custom_id, response:{status_code, request_id, body}, error})
//   file-in*.jsonl                       Batch guide input line shape ({custom_id, method, url, body})
//   error_archived_project.json          OAS ErrorResponse (400 for an archived project)
//   error_permission_plain.json          OAS PermissionErrorResponse with a plain string error
//   error_agents_beta.json               Agents errors guide 400 invalid_beta (ErrorBodyResource)
//
// Fixtures carry retention markers in content fields (instructions, tool
// parameters, arguments, messages, MCP headers and URLs, metadata, user
// agents): none may appear in a result or a log line.

const (
	markerPrompt = "SECRET-PROMPT-MARKER"
	markerKey    = "sk-test-SECRETSECRETSECRET"
	adminKey     = "sk-test-SECRETSECRETSECRET-ADMIN"
	alphaKey     = "sk-test-SECRETSECRETSECRET-ALPHA"
	betaKey      = "sk-test-SECRETSECRETSECRET-BETA"
)

var testNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// mockOpenAI serves the fixtures as the OpenAI API under /v1. The first
// page of a listing is <name>.1.json, the page after a cursor <name>.2.json.
type mockOpenAI struct {
	t   *testing.T
	mu  sync.Mutex
	req []*http.Request
	// override, when it returns true, has served the request.
	override func(w http.ResponseWriter, r *http.Request) bool
	// forbidContent fails the test if a content endpoint is called.
	forbidContent bool
}

func newMock(t *testing.T) (*mockOpenAI, *httptest.Server) {
	t.Helper()
	m := &mockOpenAI{t: t}
	srv := httptest.NewTLSServer(m)
	t.Cleanup(srv.Close)
	return m, srv
}

func (m *mockOpenAI) requests() []*http.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*http.Request(nil), m.req...)
}

// requestsTo returns the requests whose path is p.
func (m *mockOpenAI) requestsTo(p string) []*http.Request {
	var out []*http.Request
	for _, r := range m.requests() {
		if r.URL.Path == p {
			out = append(out, r)
		}
	}
	return out
}

func (m *mockOpenAI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.req = append(m.req, r.Clone(context.Background()))
	m.mu.Unlock()
	if m.override != nil && m.override(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	auth := r.Header.Get("Authorization")
	page := "1"
	if r.URL.Query().Get("after") != "" || r.URL.Query().Get("page") != "" {
		page = "2"
	}
	project := ""
	switch auth {
	case "Bearer " + alphaKey:
		project = "proj_alpha"
	case "Bearer " + betaKey:
		project = "proj_beta"
	}
	isAdmin := auth == "Bearer "+adminKey
	content := path == "/chat/completions" || path == "/batches" || strings.HasPrefix(path, "/files/")
	if content && m.forbidContent {
		m.t.Errorf("content endpoint %s called with deep inspection off", path)
	}
	switch {
	case strings.HasPrefix(path, "/organization/"):
		if !isAdmin {
			writeStatus(w, http.StatusUnauthorized, `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}`)
			return
		}
	case project == "":
		writeStatus(w, http.StatusUnauthorized, `{"error":{"type":"invalid_request_error","code":"invalid_api_key","message":"Authentication or project context was missing","param":null}}`)
		return
	}
	switch {
	case path == "/organization/projects":
		m.serve(w, "projects."+page+".json")
	case strings.HasPrefix(path, "/organization/projects/") && strings.HasSuffix(path, "/api_keys"):
		pid := strings.TrimSuffix(strings.TrimPrefix(path, "/organization/projects/"), "/api_keys")
		if pid == "proj_old" {
			m.serveStatus(w, http.StatusBadRequest, "error_archived_project.json")
			return
		}
		m.serve(w, "api_keys."+pid+"."+page+".json")
	case path == "/organization/audit_logs":
		m.serve(w, "audit_logs."+page+".json")
	case path == "/organization/usage/completions":
		m.serve(w, "usage_completions."+page+".json")
	case path == "/organization/costs":
		m.serve(w, "costs."+page+".json")
	case path == "/organization/usage/web_search_calls":
		m.serve(w, "web_search_calls."+page+".json")
	case path == "/organization/usage/file_search_calls":
		m.serve(w, "file_search_calls."+page+".json")
	case path == "/organization/usage/code_interpreter_sessions":
		m.serve(w, "code_interpreter_sessions."+page+".json")
	case path == "/agents":
		m.serve(w, "agents."+project+"."+page+".json")
	case path == "/agents/sessions":
		m.serve(w, "sessions."+project+"."+page+".json")
	case path == "/chat/completions":
		m.serve(w, "chat_completions."+project+"."+page+".json")
	case path == "/batches":
		m.serve(w, "batches."+project+"."+page+".json")
	case strings.HasPrefix(path, "/files/") && strings.HasSuffix(path, "/content"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/files/"), "/content")
		m.serve(w, id+".jsonl")
	default:
		writeStatus(w, http.StatusNotFound, `{"error":{"message":"not found","type":"invalid_request_error","param":null,"code":null}}`)
	}
}

func (m *mockOpenAI) serve(w http.ResponseWriter, name string) {
	m.serveStatus(w, http.StatusOK, name)
}

func (m *mockOpenAI) serveStatus(w http.ResponseWriter, status int, name string) {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		m.t.Errorf("missing fixture %s", name)
		writeStatus(w, http.StatusNotFound, `{"error":{"message":"no fixture","type":"invalid_request_error","param":null,"code":null}}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeStatus(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func testConn(srvURL string, deep bool) sa.Connection {
	return sa.Connection{
		ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		OUID:     "ou",
		Name:     "openai",
		Provider: models.ShadowProviderOpenAI,
		Config: models.ShadowConnectionConfig{
			Endpoints:      map[string]string{sa.EPOpenAIAPI: srvURL + "/v1"},
			DeepInspection: deep,
		},
		Secret: models.ShadowConnectionSecret{
			APIKey:     adminKey,
			ScopedKeys: map[string]string{"proj_alpha": alphaKey, "proj_beta": betaKey},
		},
	}
}

func testWindow() sa.Window { return sa.NewWindow(testNow, 30) }

// newTestConnector returns a connector over srv's client and the buffer
// its debug logs go to.
func newTestConnector(srv *httptest.Server) (sa.Connector, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return New(srv.Client(), logger), &buf
}

func runScan(t *testing.T, deep bool) (*sa.Result, *mockOpenAI, *bytes.Buffer) {
	t.Helper()
	m, srv := newMock(t)
	c, logs := newTestConnector(srv)
	res := c.Scan(context.Background(), testConn(srv.URL, deep), testWindow())
	return res, m, logs
}

func callResult(t *testing.T, res *sa.Result, call string) models.ShadowScanCallResult {
	t.Helper()
	for _, c := range res.Calls {
		if c.Call == call {
			return c
		}
	}
	t.Fatalf("no call result for %q; have %+v", call, res.Calls)
	return models.ShadowScanCallResult{}
}

func finding(t *testing.T, res *sa.Result, kind, id string) *sa.Finding {
	t.Helper()
	for _, f := range res.Findings {
		if f.Kind == kind && f.ExternalID == id {
			return f
		}
	}
	t.Fatalf("no %s finding %q", kind, id)
	return nil
}

func signal(f *sa.Finding, code, source string) (sa.Signal, bool) {
	for _, s := range f.Signals {
		if s.Code == code && (source == "" || s.Source == source) {
			return s, true
		}
	}
	return sa.Signal{}, false
}
