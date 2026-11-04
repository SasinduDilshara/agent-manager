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
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/clients/auditstoresvc"
	"github.com/wso2/agent-manager/agent-manager-service/clients/clientmocks"
	"github.com/wso2/agent-manager/agent-manager-service/config"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
)

func auditTestService(store *clientmocks.AuditStoreClientMock) *auditQueryService {
	cfg := config.Config{}
	cfg.AuditQuery.Enabled = true
	svc := NewAuditQueryService(cfg, store, NewAuditAgentResolver(auditTestRepo(), ""), slog.New(slog.NewTextHandler(io.Discard, nil))).(*auditQueryService)
	svc.now = func() time.Time { return auditFixtureTime.Add(time.Hour) }
	return svc
}

// fakeSearchResponse renders an OpenSearch response holding the given docs.
func fakeSearchResponse(t *testing.T, docs []map[string]any, total int64, relation string) []byte {
	t.Helper()
	type hit struct {
		ID     string `json:"_id"`
		Source any    `json:"_source"`
		Sort   []any  `json:"sort"`
	}
	hits := make([]hit, 0, len(docs))
	for i, d := range docs {
		hits = append(hits, hit{ID: fmt.Sprintf("doc-%d", i), Source: d, Sort: []any{1793799288935 - int64(i), fmt.Sprintf("doc-%d", i)}})
	}
	resp := map[string]any{
		"timed_out": false,
		"_shards":   map[string]any{"failed": 0},
		"hits":      map[string]any{"total": map[string]any{"value": total, "relation": relation}, "hits": hits},
		"aggregations": map[string]any{"categories": map[string]any{"buckets": map[string]any{
			"OPERATIONAL": map[string]any{"doc_count": 5}, "LLM": map[string]any{"doc_count": 7},
			"MCP": map[string]any{"doc_count": 9}, "A2A": map[string]any{"doc_count": 3}, "OTHER": map[string]any{"doc_count": 1},
		}}},
	}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	return b
}

func TestAuditQueryService_ListEvents(t *testing.T) {
	docs := loadGatewayFixture(t)[:3]
	var sent []byte
	store := &clientmocks.AuditStoreClientMock{
		SearchFunc: func(_ context.Context, body []byte) ([]byte, error) {
			sent = body
			return fakeSearchResponse(t, docs, 12000, "gte"), nil
		},
	}
	resp, err := auditTestService(store).ListEvents(context.Background(), AuditQuery{
		OUID: auditTestOUID, OrgHandle: auditTestOrgHandle, Limit: 2,
	})
	require.NoError(t, err)

	assert.Contains(t, string(sent), auditTestOUID)
	assert.Contains(t, string(sent), `"size":3`)

	require.Len(t, resp.Events, 2, "the extra hit only signals a next page")
	assert.Equal(t, "llm:chat", resp.Events[0].Action)
	require.NotNil(t, resp.NextCursor.Get())
	assert.Equal(t, int64(12000), resp.Total)
	assert.Equal(t, "gte", resp.TotalRelation)
	assert.Equal(t, int64(7), resp.CategoryCounts.LLM)
	assert.Equal(t, int64(9), resp.CategoryCounts.MCP)

	// The cursor resumes after the last returned event.
	after, err := decodeAuditCursor(*resp.NextCursor.Get(), false)
	require.NoError(t, err)
	assert.Equal(t, "doc-1", after[1])

	// Last page: no cursor.
	store.SearchFunc = func(_ context.Context, _ []byte) ([]byte, error) {
		return fakeSearchResponse(t, docs[:1], 1, "eq"), nil
	}
	resp, err = auditTestService(store).ListEvents(context.Background(), AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle, Limit: 2})
	require.NoError(t, err)
	assert.Nil(t, resp.NextCursor.Get())
	assert.Equal(t, "eq", resp.TotalRelation)

	b, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"nextCursor":null`)
}

func TestAuditQueryService_Errors(t *testing.T) {
	q := AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle}
	t.Run("disabled", func(t *testing.T) {
		svc := NewAuditQueryService(config.Config{}, nil, NewAuditAgentResolver(auditTestRepo(), ""), slog.Default())
		_, err := svc.ListEvents(context.Background(), q)
		require.ErrorIs(t, err, ErrAuditQueryDisabled)
	})
	t.Run("invalid query never reaches the store", func(t *testing.T) {
		store := &clientmocks.AuditStoreClientMock{} // Search nil: panics if called
		bad := q
		bad.Limit = 500
		_, err := auditTestService(store).ListEvents(context.Background(), bad)
		require.ErrorIs(t, err, ErrAuditInvalidQuery)
	})
	for name, search := range map[string]func(context.Context, []byte) ([]byte, error){
		"store unavailable": func(context.Context, []byte) ([]byte, error) {
			return nil, fmt.Errorf("%w: dial tcp: refused", auditstoresvc.ErrStoreUnavailable)
		},
		"unreadable response": func(context.Context, []byte) ([]byte, error) { return []byte("<html>"), nil },
		"timed out search": func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"timed_out":true,"hits":{"hits":[]}}`), nil
		},
		"failed shards": func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"timed_out":false,"_shards":{"failed":1},"hits":{"hits":[]}}`), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := auditTestService(&clientmocks.AuditStoreClientMock{SearchFunc: search}).ListEvents(context.Background(), q)
			require.ErrorIs(t, err, ErrAuditStoreUnavailable)
		})
	}
	t.Run("attribution failure is an internal error, not a store error", func(t *testing.T) {
		repo := auditTestRepo()
		repo.ListAgentArtifactsFunc = func(context.Context, string) ([]repositories.AuditAgentArtifact, error) {
			return nil, errors.New("db down")
		}
		cfg := config.Config{}
		cfg.AuditQuery.Enabled = true
		svc := NewAuditQueryService(cfg, &clientmocks.AuditStoreClientMock{}, NewAuditAgentResolver(repo, ""), slog.Default())
		_, err := svc.ListEvents(context.Background(), q)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrAuditStoreUnavailable)
		assert.NotErrorIs(t, err, ErrAuditInvalidQuery)
	})
	t.Run("an unreadable document does not hide the page", func(t *testing.T) {
		store := &clientmocks.AuditStoreClientMock{SearchFunc: func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"hits":{"total":{"value":1,"relation":"eq"},"hits":[{"_id":"x","_source":"not-an-object","sort":[1,"x"]}]}}`), nil
		}}
		resp, err := auditTestService(store).ListEvents(context.Background(), q)
		require.NoError(t, err)
		require.Len(t, resp.Events, 1)
		assert.Equal(t, "x", resp.Events[0].Id)
		assert.True(t, strings.HasPrefix(resp.Events[0].Summary, "api:invoke"))
	})
}
