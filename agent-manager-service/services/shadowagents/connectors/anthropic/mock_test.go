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

// Fixtures in testdata/ copy the official example shapes of the evidence
// (evidence/anthropic.md, anthropic_cloud_variants.md); values are changed
// only to build multi-page and positive/negative cases, and marker strings
// sit in content fields that must never be stored:
//
//	workspaces_p1/p2.json      §2.6 List Workspaces example ({data, has_more, first_id, last_id})
//	users_p1/p2.json           §2.6b List Users example
//	api_keys_p1/p2.json        §2.5 List API Keys example (2026-10-21: scope, principal, created_by)
//	usage_p1/p2.json           §2.3 usage guide example (all dimensions present, ungrouped ones null;
//	                           envelope has_more, next_page, data_refreshed_at)
//	cost_p1/p2.json            §2.4 cost reference example; requests null when grouped by cost_type (guide)
//	{aws,gcp}_{usage,cost}.json §2.3/§2.4 shapes with the federated_actor group.actor (cloud variants §2.1)
//	agents_p1/p2.json          §2.1 List Agents example (data, next_page) + a custom tool and an archived agent
//	sessions_p1/p2.json        §2.2 List Sessions example (full agent snapshot, github_repository resource)
//	events_p1/p2.json          §2.2b List Events example + agent.tool_use / agent.mcp_tool_use items
//	batches_p1/p2.json         §2.7 List Message Batches example
//	batch_results_plain.jsonl  §2.7 results JSONL, verbatim from the batch-processing guide
//	batch_results_tooluse.jsonl §2.7 MessageBatchIndividualResponse with tool_use content and stop_reason

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Test credentials. The marker substring must never appear in a result or
// a log line.
const (
	secretMarker  = "sk-test-SECRETSECRETSECRET"
	adminKey      = secretMarker + "-admin"
	wsKey         = secretMarker + "-workspace"
	awsSecret     = "aws-secret-SECRETSECRETSECRET"
	wsA           = "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ"
	wsB           = "wrkspc_01BBBBBBBBBBBBBBBBBBBBBB"
	keyA          = "apikey_01Rj2N8SVvo6BePZj99NhmiT"
	keyB          = "apikey_02ServiceAcctKeyXXXXXX"
	keyC          = "apikey_03OrgScopedKeyXXXXXXXX"
	agent1        = "agent_011CZkYpogX7uDKUyvBTophP"
	agentArchived = "agent_03ArchivedAgentXXXXXXXXX"
	gcpProject    = "my-proj"
	gcpWorkspace  = "wrkspc_01GoogleWorkspaceXXXXX"
	gcpToken      = "ya29.test-token"
	awsAccessKey  = "AKIAEXAMPLEEXAMPLE12"
	awsTempKey    = "ASIATEMPEXAMPLE12345"
	awsTempToken  = "temp-session-token"
)

// recorded is one request the mock received.
type recorded struct {
	Platform string // fp, aws, gcp
	Region   string
	WS       string // workspace in the URL (Google)
	Route    string // API path with IDs replaced, e.g. /v1/sessions/{id}/events
	Path     string
	RawQuery string
	Header   http.Header
}

// mockServer speaks the documented Anthropic wire protocol for the first
// party API, Claude Platform on AWS (/aws/{region}), Claude Models on
// Google Cloud (/gcp/...), the Google token endpoint (/token) and STS
// (/sts/{region}).
type mockServer struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	requests []recorded
	// override answers a "platform route" (e.g. "fp /v1/agents") instead of
	// the fixtures; returning false falls back to the fixtures.
	override map[string]func(w http.ResponseWriter, r *http.Request) bool
	// forbid fails the test when a "platform route" is hit.
	forbid map[string]bool
	// stsCalls counts AssumeRole requests.
	stsCalls int
}

func newMock(t *testing.T) *mockServer {
	t.Helper()
	m := &mockServer{t: t, override: map[string]func(http.ResponseWriter, *http.Request) bool{}, forbid: map[string]bool{}}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockServer) hits(platformRoute string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.requests {
		if r.Platform+" "+r.Route == platformRoute {
			n++
		}
	}
	return n
}

func (m *mockServer) requestsTo(platformRoute string) []recorded {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []recorded
	for _, r := range m.requests {
		if r.Platform+" "+r.Route == platformRoute {
			out = append(out, r)
		}
	}
	return out
}

func routeOf(p string) string {
	parts := strings.Split(p, "/")
	switch {
	case len(parts) == 5 && parts[2] == "sessions" && parts[4] == "events":
		parts[3] = "{id}"
	case len(parts) == 6 && parts[2] == "messages" && parts[5] == "results":
		parts[4] = "{id}"
	}
	return strings.Join(parts, "/")
}

func (m *mockServer) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/token":
		m.serveToken(w, r)
		return
	case strings.HasPrefix(p, "/sts/"):
		m.serveSTS(w, r)
		return
	}
	rec := recorded{Platform: "fp", Path: p, RawQuery: r.URL.RawQuery, Header: r.Header.Clone()}
	api := p
	switch {
	case strings.HasPrefix(p, "/aws/"):
		rest := strings.TrimPrefix(p, "/aws/")
		i := strings.Index(rest, "/")
		rec.Platform, rec.Region, api = "aws", rest[:i], rest[i:]
	case strings.HasPrefix(p, "/gcp/"):
		rec.Platform = "gcp"
		org := "/gcp/v1/projects/" + gcpProject + "/locations/global/claudeOrganization/invoke"
		wsPrefix := "/gcp/v1/projects/" + gcpProject + "/locations/global/workspaces/"
		switch {
		case strings.HasPrefix(p, org):
			api = strings.TrimPrefix(p, org)
		case strings.HasPrefix(p, wsPrefix):
			rest := strings.TrimPrefix(p, wsPrefix)
			i := strings.Index(rest, "/invoke/")
			if i < 0 {
				m.t.Errorf("Google workspace URL without /invoke: %s", p)
				http.NotFound(w, r)
				return
			}
			rec.WS, api = rest[:i], rest[i+len("/invoke"):]
		default:
			m.t.Errorf("unexpected Google URL %s", p)
			http.NotFound(w, r)
			return
		}
	}
	rec.Route = routeOf(api)
	m.mu.Lock()
	m.requests = append(m.requests, rec)
	fn := m.override[rec.Platform+" "+rec.Route]
	forbidden := m.forbid[rec.Platform+" "+rec.Route]
	m.mu.Unlock()
	if forbidden {
		m.t.Errorf("forbidden call made: %s %s", rec.Platform, rec.Route)
		http.Error(w, "forbidden in this test", http.StatusTeapot)
		return
	}
	m.checkHeaders(rec, r)
	if fn != nil && fn(w, r) {
		return
	}
	m.serveFixture(w, r, rec)
}

// checkHeaders asserts the documented headers of each platform and route.
func (m *mockServer) checkHeaders(rec recorded, r *http.Request) {
	t := m.t
	h := r.Header
	if got := h.Get("anthropic-version"); got != "2026-10-21" {
		t.Errorf("%s %s: anthropic-version = %q", rec.Platform, rec.Route, got)
	}
	org := strings.HasPrefix(rec.Route, "/v1/organizations/")
	wantBeta := ""
	switch {
	case strings.HasPrefix(rec.Route, "/v1/organizations/analytics/"):
		wantBeta = "analytics-usage-cost-2026-08-24"
	case strings.HasPrefix(rec.Route, "/v1/agents"), strings.HasPrefix(rec.Route, "/v1/sessions"):
		wantBeta = "managed-agents-2026-04-01"
	}
	if got := h.Get("anthropic-beta"); got != wantBeta {
		t.Errorf("%s %s: anthropic-beta = %q, want %q", rec.Platform, rec.Route, got, wantBeta)
	}
	switch rec.Platform {
	case "fp":
		if org {
			if h.Get("x-api-key") != adminKey || h.Get("Authorization") != "" {
				t.Errorf("%s: want the Admin key in x-api-key only", rec.Route)
			}
			if h.Get("anthropic-workspace-id") != "" {
				t.Errorf("%s: unexpected anthropic-workspace-id", rec.Route)
			}
		} else {
			if h.Get("Authorization") != "Bearer "+wsKey || h.Get("x-api-key") != "" {
				t.Errorf("%s: want the workspace key as a bearer token", rec.Route)
			}
			if h.Get("anthropic-workspace-id") != wsA {
				t.Errorf("%s: anthropic-workspace-id = %q", rec.Route, h.Get("anthropic-workspace-id"))
			}
		}
	case "aws":
		auth := h.Get("Authorization")
		scope := "/" + rec.Region + "/aws-external-anthropic/aws4_request"
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") || !strings.Contains(auth, scope) {
			t.Errorf("aws %s: not SigV4 for aws-external-anthropic in %s: %q", rec.Route, rec.Region, auth)
		}
		if h.Get("X-Amz-Date") == "" || h.Get("x-api-key") != "" {
			t.Errorf("aws %s: want X-Amz-Date and no x-api-key", rec.Route)
		}
		if !org && h.Get("anthropic-workspace-id") == "" {
			t.Errorf("aws %s: workspace route without anthropic-workspace-id", rec.Route)
		}
	case "gcp":
		if h.Get("Authorization") != "Bearer "+gcpToken || h.Get("x-api-key") != "" {
			t.Errorf("gcp %s: want the Google access token as a bearer token", rec.Route)
		}
		if h.Get("anthropic-workspace-id") != "" {
			t.Errorf("gcp %s: anthropic-workspace-id must not be sent", rec.Route)
		}
	}
}

func (m *mockServer) serveFixture(w http.ResponseWriter, r *http.Request, rec recorded) {
	q := r.URL.Query()
	byID := func(name string) string {
		if q.Get("after_id") == "" {
			return name + "_p1.json"
		}
		return name + "_p2.json"
	}
	byCursor := func(name string) string {
		if q.Get("page") == "" {
			return name + "_p1.json"
		}
		return name + "_p2.json"
	}
	var file string
	switch rec.Route {
	case "/v1/organizations/workspaces":
		file = byID("workspaces")
	case "/v1/organizations/users":
		file = byID("users")
	case "/v1/organizations/api_keys":
		file = byID("api_keys")
	case "/v1/organizations/analytics/usage", "/v1/organizations/analytics/cost":
		name := "usage"
		if strings.HasSuffix(rec.Route, "cost") {
			name = "cost"
		}
		if rec.Platform != "fp" {
			file = rec.Platform + "_" + name + ".json"
		} else {
			file = byCursor(name)
		}
	case "/v1/agents":
		file = byCursor("agents")
	case "/v1/sessions":
		if q.Get("agent_id") != agent1 {
			writeJSON(w, `{"data":[],"next_page":null,"prev_page":null}`)
			return
		}
		file = byCursor("sessions")
	case "/v1/sessions/{id}/events":
		file = byCursor("events")
	case "/v1/messages/batches":
		file = byID("batches")
	case "/v1/messages/batches/{id}/results":
		file = "batch_results_plain.jsonl"
		if strings.Contains(rec.Path, "msgbatch_01ToolUse") {
			file = "batch_results_tooluse.jsonl"
		}
	default:
		m.t.Errorf("unexpected route %s %s", rec.Platform, rec.Route)
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		m.t.Errorf("fixture %s: %v", file, err)
		http.Error(w, "no fixture", http.StatusInternalServerError)
		return
	}
	w.Header().Set("request-id", "req_018EeWyXxfu5pfWkrYcMdjWG")
	if strings.HasSuffix(file, ".jsonl") {
		w.Header().Set("Content-Type", "application/x-jsonl")
		_, _ = w.Write(b)
		return
	}
	writeJSON(w, string(b))
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

// anthropicError writes the documented error shape (anthropic.md §2.0).
func anthropicError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"type":"error","error":{"type":%q,"message":%q},"request_id":"req_011CSHoEeqs5C35K2UUqR7Fy"}`, typ, msg)
}

// serveToken is the Google OAuth token endpoint (JWT-bearer grant).
func (m *mockServer) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
		http.Error(w, "bad token request", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.PostForm.Get("assertion") == "" {
		m.t.Errorf("token request: grant_type %q", r.PostForm.Get("grant_type"))
	}
	writeJSON(w, `{"access_token":"`+gcpToken+`","token_type":"Bearer","expires_in":3600}`)
}

// serveSTS answers AssumeRole (AWS query protocol: form-encoded POST, XML).
func (m *mockServer) serveSTS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("Action") != "AssumeRole" || r.PostForm.Get("Version") != "2011-06-15" {
		m.t.Errorf("STS: unexpected request %v", r.PostForm)
	}
	if r.PostForm.Get("RoleArn") != "arn:aws:iam::123456789012:role/AmpShadowDiscovery" || r.PostForm.Get("ExternalId") != "ext-123" {
		m.t.Errorf("STS: RoleArn %q ExternalId %q", r.PostForm.Get("RoleArn"), r.PostForm.Get("ExternalId"))
	}
	m.mu.Lock()
	m.stsCalls++
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>` +
		`<Credentials><AccessKeyId>` + awsTempKey + `</AccessKeyId><SecretAccessKey>temp-secret</SecretAccessKey>` +
		`<SessionToken>` + awsTempToken + `</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials>` +
		`<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/AmpShadowDiscovery/s</Arn><AssumedRoleId>AROA:s</AssumedRoleId></AssumedRoleUser>` +
		`</AssumeRoleResult><ResponseMetadata><RequestId>r-1</RequestId></ResponseMetadata></AssumeRoleResponse>`))
}

// serviceAccountJSON returns a Google service account key file with a fresh
// RSA key.
func serviceAccountJSON(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": gcpProject, "private_key_id": "k1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "scanner@my-proj.iam.gserviceaccount.com", "client_id": "1",
		"token_uri": "https://oauth2.googleapis.com/token",
	})
	return string(b)
}

func queryOf(t *testing.T, raw string) url.Values {
	t.Helper()
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("query %q: %v", raw, err)
	}
	return q
}
