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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/clients/auditstoresvc"
	"github.com/wso2/agent-manager/agent-manager-service/clients/clientmocks"
	"github.com/wso2/agent-manager/agent-manager-service/config"
	"github.com/wso2/agent-manager/agent-manager-service/controllers"
	"github.com/wso2/agent-manager/agent-manager-service/middleware"
	"github.com/wso2/agent-manager/agent-manager-service/middleware/jwtassertion"
	"github.com/wso2/agent-manager/agent-manager-service/rbac"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	"github.com/wso2/agent-manager/agent-manager-service/repositories/repomocks"
	"github.com/wso2/agent-manager/agent-manager-service/services"
)

const emptySearchResponse = `{"timed_out":false,"_shards":{"failed":0},"hits":{"total":{"value":0,"relation":"eq"},"hits":[]},` +
	`"aggregations":{"categories":{"buckets":{}}}}`

func emptyAttributionRepo() *repomocks.AuditAttributionRepositoryMock {
	return &repomocks.AuditAttributionRepositoryMock{
		ListLLMProxyAgentsFunc: func(context.Context, string) ([]repositories.AuditLLMProxyAgent, error) {
			return []repositories.AuditLLMProxyAgent{}, nil
		},
		ListAgentIdentitiesFunc: func(context.Context, string) ([]repositories.AuditAgentIdentity, error) {
			return []repositories.AuditAgentIdentity{}, nil
		},
		ListAgentArtifactsFunc: func(context.Context, string) ([]repositories.AuditAgentArtifact, error) {
			return []repositories.AuditAgentArtifact{}, nil
		},
	}
}

// auditMux builds the audit route exactly as MakeHTTPHandler does, through a
// real RouteRegistrar, so permission and org checks are under test too.
func auditMux(t *testing.T, enabled bool, store *clientmocks.AuditStoreClientMock) *http.ServeMux {
	t.Helper()
	cfg := config.Config{}
	cfg.AuditQuery.Enabled = enabled
	var client auditstoresvc.AuditStoreClient
	if store != nil {
		client = store
	}
	svc := services.NewAuditQueryService(cfg, client, services.NewAuditAgentResolver(emptyAttributionRepo(), ""),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	registerAuditRoutes(middleware.NewRouteRegistrar(mux, nil, audit.NewNoopRecorder()), controllers.NewAuditController(svc))
	return mux
}

func callAudit(t *testing.T, mux *http.ServeMux, target string, claims *jwtassertion.TokenClaims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if claims != nil {
		req = req.WithContext(jwtassertion.ContextWithTokenClaimsAndScope(req.Context(), claims))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func auditReader(ouID, handle string) *jwtassertion.TokenClaims {
	return &jwtassertion.TokenClaims{Sub: "user-a", OuId: ouID, OuHandle: handle, Scope: rbac.ObservabilityLogRead.Scope()}
}

func TestAuditRoute_RequiresLogReadPermission(t *testing.T) {
	store := &clientmocks.AuditStoreClientMock{} // Search nil: a call would panic
	mux := auditMux(t, true, store)

	rec := callAudit(t, mux, "/orgs/acme/audit/events", &jwtassertion.TokenClaims{
		Sub: "user-a", OuId: "ou-a", OuHandle: "acme", Scope: rbac.AgentRead.Scope(),
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, store.SearchCalls())

	rec = callAudit(t, mux, "/orgs/acme/audit/events", nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, store.SearchCalls())
}

func TestAuditRoute_ScopesToTheTokensOrgNotThePath(t *testing.T) {
	var sent string
	store := &clientmocks.AuditStoreClientMock{SearchFunc: func(_ context.Context, body []byte) ([]byte, error) {
		sent = string(body)
		return []byte(emptySearchResponse), nil
	}}
	mux := auditMux(t, true, store)

	// The path names another org; the token decides.
	rec := callAudit(t, mux, "/orgs/victim/audit/events", auditReader("ou-attacker", "attacker"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, sent, `"event.ouId":"ou-attacker"`)
	assert.Contains(t, sent, `"gateway.organization":"attacker"`)
	assert.NotContains(t, sent, "victim")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	for _, k := range []string{"events", "nextCursor", "total", "totalRelation", "categoryCounts"} {
		assert.Contains(t, body, k)
	}
	assert.Nil(t, body["nextCursor"])
	assert.Equal(t, []any{}, body["events"])
	counts := body["categoryCounts"].(map[string]any)
	for _, c := range services.AuditCategories {
		assert.Contains(t, counts, c)
	}

	// Org-like query parameters cannot widen the scope either.
	rec = callAudit(t, mux, "/orgs/attacker/audit/events?orgName=victim&ouId=ou-victim", auditReader("ou-attacker", "attacker"))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, sent, "victim")
}

func TestAuditRoute_PassesFilters(t *testing.T) {
	var sent string
	store := &clientmocks.AuditStoreClientMock{SearchFunc: func(_ context.Context, body []byte) ([]byte, error) {
		sent = string(body)
		return []byte(emptySearchResponse), nil
	}}
	mux := auditMux(t, true, store)
	rec := callAudit(t, mux, "/orgs/acme/audit/events?startTime=2026-11-01T00:00:00Z&endTime=2026-11-02T00:00:00Z"+
		"&category=LLM&category=mcp&outcome=DENIED,FAILED&agent=proj/bot&environment=prod&actor=alice&search=echo&limit=7&sort=asc",
		auditReader("ou-a", "acme"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	for _, want := range []string{
		`"size":8`, `"order":"asc"`, `"post_filter"`, `"gateway.environment":"prod"`, `"event.projectName":"proj"`,
		`*alice*`, `*echo*`, `"policy_denied"`, `2026-11-01T00:00:00Z`, `2026-11-02T00:00:00Z`,
	} {
		assert.Contains(t, sent, want)
	}
}

func TestAuditRoute_ValidationErrors(t *testing.T) {
	store := &clientmocks.AuditStoreClientMock{} // never called
	mux := auditMux(t, true, store)
	for name, query := range map[string]string{
		"bad start time":          "startTime=yesterday",
		"bad end time":            "endTime=2026-13-01",
		"start after end":         "startTime=2026-11-02T00:00:00Z&endTime=2026-11-01T00:00:00Z",
		"range over 186 days":     "startTime=2026-01-01T00:00:00Z&endTime=2026-11-01T00:00:00Z",
		"limit not a number":      "limit=ten",
		"limit too large":         "limit=201",
		"limit zero":              "limit=0",
		"bad sort":                "sort=random",
		"bad category":            "category=SECRETS",
		"bad outcome":             "outcome=MAYBE",
		"bad agent":               "agent=a/b/c",
		"tampered cursor":         "cursor=bm9wZQ",
		"oversized search string": "search=" + strings.Repeat("x", 300),
	} {
		t.Run(name, func(t *testing.T) {
			rec := callAudit(t, mux, "/orgs/acme/audit/events?"+query, auditReader("ou-a", "acme"))
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		})
	}
	assert.Empty(t, store.SearchCalls())
}

func TestAuditRoute_StoreErrorIs502WithGenericMessage(t *testing.T) {
	const internal = "dial tcp 10.43.61.206:9200: connection refused; index amp-audit-2026.11.04"
	store := &clientmocks.AuditStoreClientMock{SearchFunc: func(context.Context, []byte) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s", auditstoresvc.ErrStoreUnavailable, internal)
	}}
	rec := callAudit(t, auditMux(t, true, store), "/orgs/acme/audit/events", auditReader("ou-a", "acme"))
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.NotContains(t, rec.Body.String(), "10.43")
	assert.NotContains(t, rec.Body.String(), "amp-audit")
	assert.Contains(t, rec.Body.String(), "Audit log store is unavailable")
}

func TestAuditRoute_DisabledIs503(t *testing.T) {
	rec := callAudit(t, auditMux(t, false, nil), "/orgs/acme/audit/events", auditReader("ou-a", "acme"))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestAuditRoute_ReadingTheTrailIsAudited(t *testing.T) {
	meta := audit.NewRouteMeta("GET /orgs/{orgName}/audit/events", []string{"orgName"},
		[]rbac.Permission{rbac.ObservabilityLogRead})
	assert.True(t, meta.Audited, "reading the audit trail must itself be recorded")
	assert.Equal(t, audit.ActionAuditRead, meta.Action)
	assert.Equal(t, audit.ClassRead, meta.Action.Class())
}
