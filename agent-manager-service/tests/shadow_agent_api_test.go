//go:build integration

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

package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/config"
	"github.com/wso2/agent-manager/agent-manager-service/db"
	"github.com/wso2/agent-manager/agent-manager-service/middleware/jwtassertion"
	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	"github.com/wso2/agent-manager/agent-manager-service/services"
	"github.com/wso2/agent-manager/agent-manager-service/spec"
	"github.com/wso2/agent-manager/agent-manager-service/tests/apitestutils"
	"github.com/wso2/agent-manager/agent-manager-service/wiring"
)

const shadowTestAdminKey = "sk-admin-SHADOWTESTSECRET-0123456789"

// shadowTestProjectKey is proj_alpha's project key in the fake.
const shadowTestProjectKey = "sk-proj-SHADOWTESTSECRET-alpha-0123"

// fakeOpenAIAdmin serves the OpenAI connector's fixtures (official response
// shapes, see the connector's testdata) for the Admin API calls: page 2 of a
// list when the request carries a cursor.
func fakeOpenAIAdmin(t *testing.T) *httptest.Server {
	t.Helper()
	dir := filepath.Join("..", "services", "shadowagents", "connectors", "openai", "testdata")
	serve := func(w http.ResponseWriter, name string) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"message":"not found","type":"invalid_request_error"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Project routes take proj_alpha's project key (never the Admin key).
		if !strings.HasPrefix(r.URL.Path, "/v1/organization/") {
			if r.Header.Get("Authorization") != "Bearer "+shadowTestProjectKey {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}`))
				return
			}
			page := "1"
			if r.URL.Query().Get("after") != "" {
				page = "2"
			}
			switch p := strings.TrimPrefix(r.URL.Path, "/v1/"); {
			case p == "agents":
				serve(w, "agents.proj_alpha.1.json")
			case p == "agents/sessions":
				serve(w, "sessions.proj_alpha."+page+".json")
			case p == "chat/completions":
				serve(w, "chat_completions.proj_alpha."+page+".json")
			case p == "batches":
				serve(w, "batches.proj_alpha."+page+".json")
			case strings.HasPrefix(p, "files/") && strings.HasSuffix(p, "/content"):
				serve(w, strings.TrimSuffix(strings.TrimPrefix(p, "files/"), "/content")+".jsonl")
			default:
				serve(w, "missing")
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+shadowTestAdminKey {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}`))
			return
		}
		page := "1"
		if r.URL.Query().Get("after") != "" || r.URL.Query().Get("page") != "" {
			page = "2"
		}
		p := strings.TrimPrefix(r.URL.Path, "/v1/organization/")
		switch {
		case p == "projects":
			serve(w, "projects."+page+".json")
		case strings.HasPrefix(p, "projects/") && strings.HasSuffix(p, "/api_keys"):
			proj := strings.TrimSuffix(strings.TrimPrefix(p, "projects/"), "/api_keys")
			if proj == "proj_old" {
				w.WriteHeader(http.StatusBadRequest)
				serve(w, "error_archived_project.json")
				return
			}
			serve(w, "api_keys."+proj+"."+page+".json")
		case p == "usage/completions":
			serve(w, "usage_completions."+page+".json")
		case p == "costs":
			serve(w, "costs."+page+".json")
		case p == "usage/web_search_calls":
			serve(w, "web_search_calls."+page+".json")
		case p == "usage/file_search_calls":
			serve(w, "file_search_calls."+page+".json")
		case p == "usage/code_interpreter_sessions":
			serve(w, "code_interpreter_sessions."+page+".json")
		case p == "audit_logs":
			serve(w, "audit_logs."+page+".json")
		default:
			serve(w, "missing")
		}
	}))
}

type shadowAPI struct {
	t   *testing.T
	app http.Handler
	org string
}

func (a shadowAPI) do(method, path string, body any) (int, []byte) {
	a.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(a.t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, fmt.Sprintf("/api/v1/orgs/%s/shadow-agents%s", a.org, path), &buf)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	a.app.ServeHTTP(rr, req)
	return rr.Code, rr.Body.Bytes()
}

func decodeInto[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(b, &v), string(b))
	return v
}

func TestShadowAgentDiscoveryAPI(t *testing.T) {
	ctx := context.Background()
	org := "shadow-org-" + uuid.NewString()[:6]
	ouID := "ou-" + uuid.NewString()
	agentLookups := 0
	oc := apitestutils.CreateMockOpenChoreoClient()
	oc.GetComponentFunc = func(_ context.Context, _ string, projName, agentName string) (*models.AgentResponse, error) {
		agentLookups++
		return &models.AgentResponse{Name: agentName, ProjectName: projName}, nil
	}
	app := apitestutils.MakeAppClientWithDeps(t, wiring.TestClients{OpenChoreoClient: oc},
		jwtassertion.NewMockMiddlewareWithOUID(t, ouID))
	api := shadowAPI{t: t, app: app, org: org}
	fake := fakeOpenAIAdmin(t)
	defer fake.Close()

	// Providers catalog.
	code, body := api.do(http.MethodGet, "/providers", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	providers := decodeInto[spec.ShadowProviderListResponse](t, body)
	assert.Len(t, providers.Providers, 5)
	assert.NotEmpty(t, providers.Signals)
	assert.EqualValues(t, 60, providers.Scoring.AgentThreshold)

	// Connect OpenAI, pointed at the fake.
	connReq := map[string]any{
		"name": "OpenAI test", "provider": "openai",
		"endpoints": map[string]string{"api": fake.URL + "/v1"},
		"settings":  map[string]any{"apiKey": shadowTestAdminKey},
	}
	code, body = api.do(http.MethodPost, "/connections", connReq)
	require.Equal(t, http.StatusCreated, code, string(body))
	assert.NotContains(t, string(body), "SHADOWTESTSECRET", "the secret is never returned")
	conn := decodeInto[spec.ShadowConnectionResponse](t, body)
	assert.Equal(t, "sk-a…6789", conn.SecretHints["apiKey"])
	require.Len(t, conn.EndpointWarnings, 1, "a local endpoint is not an official host")

	code, _ = api.do(http.MethodPost, "/connections", connReq)
	assert.Equal(t, http.StatusConflict, code, "duplicate name")
	code, _ = api.do(http.MethodPost, "/connections", map[string]any{"name": "x", "provider": "acme", "settings": map[string]any{}})
	assert.Equal(t, http.StatusBadRequest, code)

	// The stored credential is encrypted.
	var stored models.ShadowConnection
	require.NoError(t, db.GetDB().WithContext(ctx).Where("id = ?", conn.Id).First(&stored).Error)
	assert.NotContains(t, string(stored.SecretEncrypted), "SHADOWTESTSECRET")

	// Test the connection.
	code, body = api.do(http.MethodPost, "/connections/"+conn.Id+"/test", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	assert.True(t, decodeInto[spec.ShadowConnectionTest](t, body).Ok, string(body))

	// Queue a scan and run it the way the worker does.
	code, body = api.do(http.MethodPost, "/scans", map[string]any{"lookbackDays": 30})
	require.Equal(t, http.StatusAccepted, code, string(body))
	scan := decodeInto[spec.ShadowScanResponse](t, body)
	code, _ = api.do(http.MethodPost, "/scans", map[string]any{})
	assert.Equal(t, http.StatusConflict, code, "one active scan per org")

	key, err := hex.DecodeString(config.GetConfig().EncryptionKey)
	require.NoError(t, err)
	repo := repositories.NewShadowAgentRepository(db.GetDB())
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	services.NewShadowAgentScanner(repo, wiring.ProvideShadowConnectors(logger), key, logger).RunOnce(ctx)

	code, body = api.do(http.MethodGet, "/scans/"+scan.Id, nil)
	require.Equal(t, http.StatusOK, code)
	scan = decodeInto[spec.ShadowScanResponse](t, body)
	require.Contains(t, []string{"succeeded", "partial"}, scan.Status, string(body))
	require.Len(t, scan.Results, 1)
	assert.Positive(t, scan.Results[0].FindingsCount, string(body))

	// Findings.
	code, body = api.do(http.MethodGet, "/findings?kind=api_key", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	list := decodeInto[spec.ShadowFindingListResponse](t, body)
	require.NotEmpty(t, list.Findings)
	var alpha *spec.ShadowFindingSummary
	for i := range list.Findings {
		if list.Findings[i].ExternalId == "key_alpha1" {
			alpha = &list.Findings[i]
		}
	}
	require.NotNil(t, alpha, string(body))
	assert.Equal(t, "alice@example.com", *alpha.OwnerHint.Email)
	assert.Positive(t, alpha.Score)

	code, body = api.do(http.MethodGet, "/findings/"+alpha.Id, nil)
	require.Equal(t, http.StatusOK, code)
	detail := decodeInto[spec.ShadowFindingDetail](t, body)
	assert.NotEmpty(t, detail.Signals)
	require.NotEmpty(t, detail.Keys)
	assert.Equal(t, "sk-abc...def", detail.Keys[0].RedactedHint)
	assert.Empty(t, detail.Retirement.State)

	code, body = api.do(http.MethodGet, "/summary", nil)
	require.Equal(t, http.StatusOK, code)
	summary := decodeInto[spec.ShadowAgentSummary](t, body)
	assert.EqualValues(t, 1, summary.Connections)
	assert.Positive(t, summary.TotalFindings)

	// Review, onboard, retirement guard.
	code, _ = api.do(http.MethodPatch, "/findings/"+alpha.Id, map[string]any{"status": "reviewed"})
	assert.Equal(t, http.StatusOK, code)
	code, body = api.do(http.MethodPost, "/findings/"+alpha.Id+"/onboarding", map[string]any{"projectName": "default", "agentName": "alpha"})
	require.Equal(t, http.StatusOK, code, string(body))
	assert.Equal(t, 1, agentLookups)
	onboarded := decodeInto[spec.ShadowFindingDetail](t, body)
	assert.Equal(t, "onboarded", onboarded.Status)
	assert.Equal(t, "monitoring", onboarded.Retirement.State)
	code, _ = api.do(http.MethodPost, "/findings/"+alpha.Id+"/onboarding", map[string]any{"projectName": "default", "agentName": "alpha"})
	assert.Equal(t, http.StatusConflict, code)
	code, _ = api.do(http.MethodPost, "/findings/"+alpha.Id+"/retirement/confirm", nil)
	assert.Equal(t, http.StatusConflict, code, "not ready before 7 days without direct usage")

	// Retention: no secret or prompt anywhere in the stored data or logs.
	for _, table := range []string{"shadow_connections", "shadow_scans", "shadow_findings", "shadow_finding_signals", "shadow_api_keys", "shadow_usage_daily"} {
		var dump string
		require.NoError(t, db.GetDB().WithContext(ctx).Raw(
			fmt.Sprintf("SELECT COALESCE(string_agg(t::text, ' '), '') FROM %s t WHERE ou_id = ?", table), ouID).Scan(&dump).Error)
		assert.NotContains(t, dump, "SHADOWTESTSECRET", table)
		assert.NotContains(t, dump, "SECRET-PROMPT-MARKER", table)
	}
	assert.NotContains(t, logs.String(), "SHADOWTESTSECRET")

	// Another org sees nothing of this one.
	other := shadowAPI{t: t, org: "other-" + uuid.NewString()[:6], app: apitestutils.MakeAppClientWithDeps(t,
		wiring.TestClients{OpenChoreoClient: oc}, jwtassertion.NewMockMiddlewareWithOUID(t, "ou-"+uuid.NewString()))}
	code, _ = other.do(http.MethodGet, "/findings/"+alpha.Id, nil)
	assert.Equal(t, http.StatusNotFound, code)
	code, _ = other.do(http.MethodGet, "/connections/"+conn.Id, nil)
	assert.Equal(t, http.StatusNotFound, code)

	// Delete the connection: its findings go with it.
	code, _ = api.do(http.MethodDelete, "/connections/"+conn.Id, nil)
	assert.Equal(t, http.StatusNoContent, code)
	code, body = api.do(http.MethodGet, "/findings", nil)
	require.Equal(t, http.StatusOK, code)
	assert.Empty(t, decodeInto[spec.ShadowFindingListResponse](t, body).Findings)
}

// TestShadowAgentDiscoveryAPI_ProjectKeysOnly covers a connection without an
// Admin API key end to end: the provider catalog says so, the connection is
// accepted with a project key alone, the test and the scan read only the
// project routes, tool-call evidence lands on a project finding, a project
// finding cannot be retired, and an Admin key can be added and removed.
func TestShadowAgentDiscoveryAPI_ProjectKeysOnly(t *testing.T) {
	ctx := context.Background()
	org := "shadow-org-" + uuid.NewString()[:6]
	ouID := "ou-" + uuid.NewString()
	oc := apitestutils.CreateMockOpenChoreoClient()
	oc.GetComponentFunc = func(_ context.Context, _ string, projName, agentName string) (*models.AgentResponse, error) {
		return &models.AgentResponse{Name: agentName, ProjectName: projName}, nil
	}
	app := apitestutils.MakeAppClientWithDeps(t, wiring.TestClients{OpenChoreoClient: oc},
		jwtassertion.NewMockMiddlewareWithOUID(t, ouID))
	api := shadowAPI{t: t, app: app, org: org}
	fake := fakeOpenAIAdmin(t)
	defer fake.Close()

	// The catalog marks the Admin key optional and recommended, names the
	// credential choice and lists capabilities.
	code, body := api.do(http.MethodGet, "/providers", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	providers := decodeInto[spec.ShadowProviderListResponse](t, body)
	for _, p := range providers.Providers {
		assert.NotEmpty(t, p.Capabilities, p.Provider)
		if p.Provider == "bedrock" {
			require.NotNil(t, p.CredentialChoice, "Bedrock needs at least one service")
			assert.Len(t, p.CredentialChoice.Fields, 6)
			continue
		}
		if p.Provider != "openai" && p.Provider != "anthropic" {
			assert.Nil(t, p.CredentialChoice, p.Provider)
			continue
		}
		require.NotNil(t, p.CredentialChoice, p.Provider)
		assert.Equal(t, []string{"apiKey", "scopedKeys"}, p.CredentialChoice.Fields)
		for _, f := range p.Fields {
			if f.Key == "apiKey" {
				assert.False(t, f.Required, p.Provider)
				require.NotNil(t, f.Recommended, p.Provider)
				assert.True(t, *f.Recommended, p.Provider)
			}
		}
	}

	// Neither credential: refused with the choice's message.
	code, body = api.do(http.MethodPost, "/connections", map[string]any{
		"name": "none", "provider": "openai", "settings": map[string]any{},
	})
	require.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, string(body), "at least one project key")

	// A project key alone is accepted.
	code, body = api.do(http.MethodPost, "/connections", map[string]any{
		"name": "OpenAI projects", "provider": "openai",
		"endpoints": map[string]string{"api": fake.URL + "/v1"},
		"settings": map[string]any{
			"scopedKeys": map[string]any{"proj_alpha": shadowTestProjectKey}, "deepInspection": true,
		},
	})
	require.Equal(t, http.StatusCreated, code, string(body))
	conn := decodeInto[spec.ShadowConnectionResponse](t, body)
	assert.NotContains(t, conn.SecretHints, "apiKey")
	assert.Contains(t, conn.SecretHints, "scopedKeys.proj_alpha")

	// The test skips the organization checks and passes on the project key.
	code, body = api.do(http.MethodPost, "/connections/"+conn.Id+"/test", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	test := decodeInto[spec.ShadowConnectionTest](t, body)
	assert.True(t, test.Ok, string(body))
	skipped := 0
	for _, ch := range test.Checks {
		if ch.Outcome == "skipped" && ch.Message != nil && strings.Contains(*ch.Message, "Admin API key") {
			skipped++
		}
	}
	assert.Equal(t, 7, skipped, string(body))

	// Scan the way the worker does.
	code, body = api.do(http.MethodPost, "/scans", map[string]any{"lookbackDays": 30})
	require.Equal(t, http.StatusAccepted, code, string(body))
	scan := decodeInto[spec.ShadowScanResponse](t, body)
	key, err := hex.DecodeString(config.GetConfig().EncryptionKey)
	require.NoError(t, err)
	repo := repositories.NewShadowAgentRepository(db.GetDB())
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	services.NewShadowAgentScanner(repo, wiring.ProvideShadowConnectors(logger), key, logger).RunOnce(ctx)
	code, body = api.do(http.MethodGet, "/scans/"+scan.Id, nil)
	require.Equal(t, http.StatusOK, code)
	scan = decodeInto[spec.ShadowScanResponse](t, body)
	require.Len(t, scan.Results, 1)
	for _, c := range scan.Results[0].Calls {
		if strings.HasPrefix(c.Call, "GET /v1/organization/") {
			assert.Equal(t, "skipped", c.Outcome, c.Call)
		}
	}

	code, body = api.do(http.MethodGet, "/findings", nil)
	require.Equal(t, http.StatusOK, code, string(body))
	list := decodeInto[spec.ShadowFindingListResponse](t, body)
	kinds := map[string]int{}
	var project, agent *spec.ShadowFindingSummary
	for i := range list.Findings {
		f := &list.Findings[i]
		kinds[f.Kind]++
		switch {
		case f.Kind == "project" && f.ExternalId == "proj_alpha":
			project = f
		case f.Kind == "platform_agent" && f.ExternalId == "agent_alpha":
			agent = f
		}
	}
	assert.Equal(t, map[string]int{"platform_agent": 1, "project": 1}, kinds, string(body))
	require.NotNil(t, project, string(body))
	require.NotNil(t, agent, string(body))
	assert.Equal(t, "Project proj_alpha", project.DisplayName)

	code, body = api.do(http.MethodGet, "/findings/"+project.Id, nil)
	require.Equal(t, http.StatusOK, code)
	detail := decodeInto[spec.ShadowFindingDetail](t, body)
	codes := map[string]bool{}
	for _, s := range detail.Signals {
		codes[s.Code] = true
	}
	assert.True(t, codes["openai.tool_call_stored_completion"], string(body))
	linked := false
	for _, r := range detail.Related {
		if r.Relation == "agent_in_project" && r.FindingId == agent.Id {
			linked = true
		}
		assert.NotEqual(t, "candidate_key", r.Relation, "no candidate keys without the Admin key")
	}
	assert.True(t, linked, "the project finding links its agent: %s", string(body))

	// A project finding can be onboarded but never retired.
	code, body = api.do(http.MethodPost, "/findings/"+project.Id+"/onboarding", map[string]any{"projectName": "default", "agentName": "alpha"})
	require.Equal(t, http.StatusOK, code, string(body))
	onboarded := decodeInto[spec.ShadowFindingDetail](t, body)
	assert.Empty(t, onboarded.Retirement.State, "a project finding has no credential to retire")
	code, _ = api.do(http.MethodPost, "/findings/"+project.Id+"/retirement/confirm", nil)
	assert.Equal(t, http.StatusConflict, code)

	// Add an Admin key, then remove it again.
	code, body = api.do(http.MethodPut, "/connections/"+conn.Id, map[string]any{
		"name": "OpenAI projects", "provider": "openai", "settings": map[string]any{"apiKey": shadowTestAdminKey},
	})
	require.Equal(t, http.StatusOK, code, string(body))
	assert.Contains(t, decodeInto[spec.ShadowConnectionResponse](t, body).SecretHints, "apiKey")
	code, body = api.do(http.MethodPut, "/connections/"+conn.Id, map[string]any{
		"name": "OpenAI projects", "provider": "openai", "settings": map[string]any{}, "removeSecrets": []string{"apiKey"},
	})
	require.Equal(t, http.StatusOK, code, string(body))
	assert.NotContains(t, decodeInto[spec.ShadowConnectionResponse](t, body).SecretHints, "apiKey")
	// Removing the project keys too would leave no credential.
	code, body = api.do(http.MethodPut, "/connections/"+conn.Id, map[string]any{
		"name": "OpenAI projects", "provider": "openai", "settings": map[string]any{"scopedKeys": map[string]any{}},
	})
	assert.Equal(t, http.StatusBadRequest, code, string(body))

	// Retention.
	for _, table := range []string{"shadow_connections", "shadow_scans", "shadow_findings", "shadow_finding_signals"} {
		var dump string
		require.NoError(t, db.GetDB().WithContext(ctx).Raw(
			fmt.Sprintf("SELECT COALESCE(string_agg(t::text, ' '), '') FROM %s t WHERE ou_id = ?", table), ouID).Scan(&dump).Error)
		assert.NotContains(t, dump, "SHADOWTESTSECRET", table)
		assert.NotContains(t, dump, "SECRET-PROMPT-MARKER", table)
	}
	assert.NotContains(t, logs.String(), "SHADOWTESTSECRET")

	code, _ = api.do(http.MethodDelete, "/connections/"+conn.Id, nil)
	assert.Equal(t, http.StatusNoContent, code)
}
