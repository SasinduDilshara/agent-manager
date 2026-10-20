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

package ocauditsvc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/clients/requests"
)

// tokenSource hands out t1, t2, ... and counts invalidations.
type tokenSource struct {
	mu          sync.Mutex
	issued      int
	invalidated int
	cached      string
}

func (s *tokenSource) GetToken(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == "" {
		s.issued++
		s.cached = "t" + strconv.Itoa(s.issued)
	}
	return s.cached, nil
}

func (s *tokenSource) InvalidateToken() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidated++
	s.cached = ""
}

// noRetries keeps transport retries out of these tests: they are about the
// client's own handling of the Observer's statuses.
var noRetries = requests.RequestRetryConfig{
	RetryWaitMin: time.Millisecond, RetryWaitMax: time.Millisecond,
	RetryOnStatus: func(int) bool { return false },
}

func newTestClient(t *testing.T, handler http.HandlerFunc) (Client, *tokenSource) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	tokens := &tokenSource{}
	c, err := NewClient(&Config{BaseURL: srv.URL + "/", AuthProvider: tokens, RetryConfig: noRetries})
	require.NoError(t, err)
	return c, tokens
}

func TestNewClientRequiresItsConfig(t *testing.T) {
	_, err := NewClient(nil)
	require.Error(t, err)
	_, err = NewClient(&Config{AuthProvider: &tokenSource{}})
	require.Error(t, err)
	_, err = NewClient(&Config{BaseURL: "http://observer:8080"})
	require.Error(t, err)
}

func TestQueryAuditLogsSendsTheQueryWithItsToken(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody QueryRequest
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		_ = json.NewEncoder(w).Encode(QueryResponse{Records: []Record{{EventID: "e1"}}, Total: 7})
	})

	resp, err := c.QueryAuditLogs(context.Background(), QueryRequest{
		StartTime: "2026-10-20T09:00:00Z", EndTime: "2026-10-20T10:00:00Z",
		Resource: ResourceFilter{Namespaces: []string{"ou-acme"}},
	})
	require.NoError(t, err)
	assert.Equal(t, queryPath, gotPath, "base URL's trailing slash is not doubled")
	assert.Equal(t, "Bearer t1", gotAuth)
	assert.Equal(t, []string{"ou-acme"}, gotBody.Resource.Namespaces)
	assert.Equal(t, int64(7), resp.Total)
	require.Len(t, resp.Records, 1)
}

func TestQueryFilterValuesUsesItsRoute(t *testing.T) {
	var gotPath string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(FilterValuesResponse{Filter: "action", Values: []FilterValue{{Value: "llm:call", Count: 3}}})
	})
	resp, err := c.QueryFilterValues(context.Background(), FilterValuesRequest{Filter: "action"})
	require.NoError(t, err)
	assert.Equal(t, filterValuesPath, gotPath)
	assert.Equal(t, "action", resp.Filter)
}

// TestRetriesOnceWithAFreshTokenOn401: a revoked or rotated cached token gets
// one more try with a new one.
func TestRetriesOnceWithAFreshTokenOn401(t *testing.T) {
	var seen []string
	c, tokens := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "Bearer t1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(QueryResponse{Total: 1})
	})
	resp, err := c.QueryAuditLogs(context.Background(), QueryRequest{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), resp.Total)
	assert.Equal(t, []string{"Bearer t1", "Bearer t2"}, seen)
	assert.Equal(t, 1, tokens.invalidated)
}

func TestA401AfterTheRetryIsAccessDenied(t *testing.T) {
	calls := 0
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := c.QueryAuditLogs(context.Background(), QueryRequest{})
	require.ErrorIs(t, err, ErrAccessDenied)
	assert.Equal(t, 2, calls, "one retry, not a loop")
}

func TestObserverStatusesMapToSentinels(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusNotImplemented, ErrNotSupported},
		{http.StatusBadRequest, ErrInvalidRequest},
		{http.StatusForbidden, ErrAccessDenied},
	}
	for _, c := range cases {
		client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(`{"error":"x"}`))
		})
		_, err := client.QueryAuditLogs(context.Background(), QueryRequest{})
		require.ErrorIs(t, err, c.want, "status %d", c.status)
	}

	client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := client.QueryAuditLogs(context.Background(), QueryRequest{})
	require.Error(t, err)
	for _, sentinel := range []error{ErrNotSupported, ErrInvalidRequest, ErrAccessDenied} {
		assert.False(t, errors.Is(err, sentinel), "a 500 is a failure, not %v", sentinel)
	}
}
