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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
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

// captureSink keeps every record the recorder writes, after redaction.
type captureSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureSink) Write(_ context.Context, events []audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, events...)
	return nil
}

func (c *captureSink) Name() string { return "capture" }

// recordedAuditReads runs fn with a real recorder and returns the audit:read
// records it wrote, redacted as they would reach the trail.
func recordedAuditReads(t *testing.T, fn func(ctx context.Context)) []audit.Event {
	t.Helper()
	sink := &captureSink{}
	rec := audit.NewRecorder(sink, slog.New(slog.NewTextHandler(io.Discard, nil)), audit.Config{})
	fn(audit.WithRecorder(context.Background(), rec))
	require.NoError(t, rec.Close(context.Background()))
	var out []audit.Event
	for _, e := range sink.events {
		if e.Action == audit.ActionAuditRead {
			out = append(out, e)
		}
	}
	return out
}

func TestAuditQueryService_RecordsWhatWasSearched(t *testing.T) {
	docs := loadGatewayFixture(t)[:3]
	store := &clientmocks.AuditStoreClientMock{
		SearchFunc: func(_ context.Context, _ []byte) ([]byte, error) {
			return fakeSearchResponse(t, docs, 42, "eq"), nil
		},
	}
	start := auditFixtureTime.Add(-2 * time.Hour)
	end := auditFixtureTime
	// Word-shaped, so the secret-shaped masker leaves it alone.
	search := strings.Repeat("tool ", auditSearchDetailMax/5) + "x"
	cursor, err := encodeAuditCursor([]json.RawMessage{json.RawMessage("1793799288935"), json.RawMessage(`"doc-9"`)}, true)
	require.NoError(t, err)

	records := recordedAuditReads(t, func(ctx context.Context) {
		_, err := auditTestService(store).ListEvents(ctx, AuditQuery{
			OUID: auditTestOUID, OrgHandle: auditTestOrgHandle,
			Start: start, End: end,
			Categories:  []string{"mcp"},
			Agents:      []string{"default/ext-audit-agent"},
			Project:     "default",
			Environment: "default",
			Outcomes:    []string{"STARTED", "DENIED"},
			Actor:       "alice",
			Search:      search,
			Limit:       2,
			Cursor:      cursor,
			Ascending:   true,
		})
		require.NoError(t, err)
	})
	require.Len(t, records, 1)
	e := records[0]
	assert.Equal(t, audit.ClassRead, e.ActionClass)
	assert.Equal(t, audit.OutcomeSuccess, e.Outcome)
	assert.Equal(t, 200, e.StatusCode, "the record carries the status the caller received")
	assert.Equal(t, auditTestOUID, e.OUID)
	assert.Equal(t, auditTestOrgHandle, e.OrgHandle)

	d := e.Details
	assert.NotContains(t, d, "_droppedKeys", "every detail must be declared in the action's schema")
	assert.Equal(t, start.UTC().Format(time.RFC3339), d["startTime"])
	assert.Equal(t, end.UTC().Format(time.RFC3339), d["endTime"])
	assert.Equal(t, []string{"MCP"}, d["categories"], "normalised values are recorded")
	assert.Equal(t, []string{"default/ext-audit-agent"}, d["agents"])
	assert.Equal(t, []string{"STARTED", "DENIED"}, d["outcomes"])
	assert.Equal(t, "default", d["project"])
	assert.Equal(t, "default", d["environment"])
	assert.Equal(t, "alice", d["actor"])
	assert.Equal(t, search, d["search"])
	assert.Equal(t, false, d["searchTruncated"])
	assert.EqualValues(t, 2, d["limit"])
	assert.Equal(t, "asc", d["sort"])
	assert.Equal(t, true, d["cursorUsed"])
	assert.EqualValues(t, 2, d["resultCount"], "the page returned, not the extra look-ahead hit")
	assert.EqualValues(t, 42, d["totalMatched"])

	b, err := json.Marshal(e)
	require.NoError(t, err)
	assert.NotContains(t, string(b), cursor, "the cursor value is never recorded")
}

func TestAuditQueryService_RecordsDefaultsAndFailures(t *testing.T) {
	t.Run("defaults are the effective query", func(t *testing.T) {
		store := &clientmocks.AuditStoreClientMock{SearchFunc: func(_ context.Context, _ []byte) ([]byte, error) {
			return fakeSearchResponse(t, nil, 0, "eq"), nil
		}}
		records := recordedAuditReads(t, func(ctx context.Context) {
			_, err := auditTestService(store).ListEvents(ctx, AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle})
			require.NoError(t, err)
		})
		require.Len(t, records, 1)
		d := records[0].Details
		now := auditFixtureTime.Add(time.Hour)
		assert.Equal(t, now.Add(-24*time.Hour).UTC().Format(time.RFC3339), d["startTime"])
		assert.Equal(t, now.UTC().Format(time.RFC3339), d["endTime"])
		assert.EqualValues(t, AuditDefaultLimit, d["limit"])
		assert.Equal(t, "desc", d["sort"])
		assert.Equal(t, false, d["cursorUsed"])
		assert.Equal(t, false, d["searchTruncated"])
		assert.EqualValues(t, 0, d["resultCount"])
		assert.Equal(t, []string{}, d["categories"])
	})

	t.Run("store failure records the search without the transport cause", func(t *testing.T) {
		store := &clientmocks.AuditStoreClientMock{SearchFunc: func(_ context.Context, _ []byte) ([]byte, error) {
			return nil, fmt.Errorf("%w: dial tcp 10.43.0.9:9200 index amp-audit-x", auditstoresvc.ErrStoreUnavailable)
		}}
		records := recordedAuditReads(t, func(ctx context.Context) {
			_, err := auditTestService(store).ListEvents(ctx, AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle, Agents: []string{"ext-audit-agent"}})
			require.ErrorIs(t, err, ErrAuditStoreUnavailable)
		})
		require.Len(t, records, 1)
		e := records[0]
		assert.Equal(t, audit.OutcomeFailure, e.Outcome)
		assert.Equal(t, 502, e.StatusCode)
		assert.Equal(t, ErrAuditStoreUnavailable.Error(), e.ErrorMessage)
		assert.Equal(t, []string{"ext-audit-agent"}, e.Details["agents"])
		assert.EqualValues(t, 0, e.Details["resultCount"])
		assert.NotContains(t, e.Details, "totalMatched")
	})

	t.Run("invalid query is recorded as a failure", func(t *testing.T) {
		store := &clientmocks.AuditStoreClientMock{}
		records := recordedAuditReads(t, func(ctx context.Context) {
			_, err := auditTestService(store).ListEvents(ctx, AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle, Outcomes: []string{"MAYBE"}})
			require.ErrorIs(t, err, ErrAuditInvalidQuery)
		})
		require.Len(t, records, 1)
		assert.Equal(t, audit.OutcomeFailure, records[0].Outcome)
		assert.Equal(t, 400, records[0].StatusCode)
		assert.Equal(t, []string{"MAYBE"}, records[0].Details["outcomes"], "a rejected query is recorded as sent")
	})

	t.Run("over-long search text is truncated in the record", func(t *testing.T) {
		store := &clientmocks.AuditStoreClientMock{}
		records := recordedAuditReads(t, func(ctx context.Context) {
			_, err := auditTestService(store).ListEvents(ctx, AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle, Search: strings.Repeat("tool ", 60)})
			require.ErrorIs(t, err, ErrAuditInvalidQuery)
		})
		require.Len(t, records, 1)
		assert.Equal(t, strings.Repeat("tool ", 60)[:auditSearchDetailMax], records[0].Details["search"])
		assert.Equal(t, true, records[0].Details["searchTruncated"])
	})

	t.Run("a pasted token in the search text is masked", func(t *testing.T) {
		store := &clientmocks.AuditStoreClientMock{SearchFunc: func(_ context.Context, _ []byte) ([]byte, error) {
			return fakeSearchResponse(t, nil, 0, "eq"), nil
		}}
		jwtLike := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl"
		records := recordedAuditReads(t, func(ctx context.Context) {
			_, err := auditTestService(store).ListEvents(ctx, AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle, Search: jwtLike})
			require.NoError(t, err)
		})
		require.Len(t, records, 1)
		assert.NotContains(t, records[0].Details["search"], "eyJhbGciOiJIUzI1NiJ9")
	})

	t.Run("disabled API records the attempt with 503", func(t *testing.T) {
		records := recordedAuditReads(t, func(ctx context.Context) {
			svc := NewAuditQueryService(config.Config{}, nil, NewAuditAgentResolver(auditTestRepo(), ""), slog.Default())
			_, err := svc.ListEvents(ctx, AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle, Actor: "alice"})
			require.ErrorIs(t, err, ErrAuditQueryDisabled)
		})
		require.Len(t, records, 1)
		assert.Equal(t, 503, records[0].StatusCode)
		assert.Equal(t, audit.OutcomeFailure, records[0].Outcome)
		assert.Equal(t, "alice", records[0].Details["actor"])
	})

	t.Run("a read the controller rejected is recorded with its filters and 400", func(t *testing.T) {
		records := recordedAuditReads(t, func(ctx context.Context) {
			auditTestService(&clientmocks.AuditStoreClientMock{}).RecordRejectedRead(ctx,
				AuditQuery{OUID: auditTestOUID, OrgHandle: auditTestOrgHandle, Agents: []string{"bot"}, Search: "echo"},
				&AuditParamError{Param: "limit", Message: "Invalid 'limit'"})
		})
		require.Len(t, records, 1)
		e := records[0]
		assert.Equal(t, 400, e.StatusCode)
		assert.Equal(t, audit.OutcomeFailure, e.Outcome)
		assert.Equal(t, "limit", e.Details["rejectedParameter"])
		assert.Equal(t, []string{"bot"}, e.Details["agents"])
		assert.Equal(t, "echo", e.Details["search"])
		assert.NotContains(t, e.Details, "_droppedKeys")
	})
}

func TestAuditQueryStatus(t *testing.T) {
	assert.Equal(t, 200, AuditQueryStatus(nil))
	assert.Equal(t, 400, AuditQueryStatus(invalidAuditQuery("x")))
	assert.Equal(t, 400, AuditQueryStatus(&AuditParamError{Param: "sort", Message: "bad"}))
	assert.Equal(t, 503, AuditQueryStatus(ErrAuditQueryDisabled))
	assert.Equal(t, 502, AuditQueryStatus(fmt.Errorf("%w: x", ErrAuditStoreUnavailable)))
	assert.Equal(t, 500, AuditQueryStatus(errors.New("db down")))
}
