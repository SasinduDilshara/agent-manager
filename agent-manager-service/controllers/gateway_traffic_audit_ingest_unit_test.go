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

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/services"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// trafficServiceStub records what the controller hands the traffic-log feed.
type trafficServiceStub struct {
	calls  int
	caller services.GatewayAuditCaller
	body   []byte
	result *services.GatewayAuditIngestResult
	err    error
}

func (s *trafficServiceStub) Ingest(_ context.Context, caller services.GatewayAuditCaller, body []byte) (*services.GatewayAuditIngestResult, error) {
	s.calls++
	s.caller, s.body = caller, body
	if s.err != nil {
		return nil, s.err
	}
	if s.result != nil {
		return s.result, nil
	}
	return &services.GatewayAuditIngestResult{Accepted: 1, RejectReasons: map[string]int{}}, nil
}

const trafficBody = `{"timestamp":"2026-10-20T09:15:02.481Z","status":200}` + "\n"

func trafficRequest(body string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/internal/v1/audit/traffic-events", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/x-ndjson")
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	return req
}

func serveTraffic(ctrl GatewayInternalController, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctrl.IngestTrafficAuditEvents(rec, req)
	return rec
}

func newTrafficController(t *testing.T, svc services.GatewayTrafficAuditIngestService, maxBytes int64) (GatewayInternalController, *ingestFixture) {
	t.Helper()
	return newInternalController(t, GatewayAuditIngest{}, GatewayTrafficAuditIngest{Service: svc, MaxBodyBytes: maxBytes})
}

func TestIngestTrafficAuditEvents_RequiresAGatewayKey(t *testing.T) {
	svc := &trafficServiceStub{}
	ctrl, _ := newTrafficController(t, svc, 1<<20)
	assert.Equal(t, http.StatusUnauthorized, serveTraffic(ctrl, trafficRequest(trafficBody, nil)).Code)
	assert.Equal(t, http.StatusUnauthorized,
		serveTraffic(ctrl, trafficRequest(trafficBody, map[string]string{"api-key": uuid.NewString() + "-x"})).Code)
	assert.Zero(t, svc.calls)
}

// TestIngestTrafficAuditEvents_FeedsAreIndependent: each feed is switched on
// on its own; one being on says nothing about the other.
func TestIngestTrafficAuditEvents_FeedsAreIndependent(t *testing.T) {
	ctrl, fx := newIngestController(t, &ingestServiceStub{}, 1<<20) // OTel on, traffic off
	assert.Equal(t, http.StatusUnauthorized, serveTraffic(ctrl, trafficRequest(trafficBody, nil)).Code,
		"hidden from an unauthenticated caller")
	assert.Equal(t, http.StatusNotFound,
		serveTraffic(ctrl, trafficRequest(trafficBody, map[string]string{"api-key": fx.token})).Code)

	ctrl, fx = newTrafficController(t, &trafficServiceStub{}, 1<<20) // traffic on, OTel off
	rec := httptest.NewRecorder()
	ctrl.IngestAuditEvents(rec, ingestRequest([]byte(ingestBody), map[string]string{"api-key": fx.token}))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestIngestTrafficAuditEvents_CallerComesFromTheCredential(t *testing.T) {
	svc := &trafficServiceStub{}
	ctrl, fx := newTrafficController(t, svc, 1<<20)
	rec := serveTraffic(ctrl, trafficRequest(trafficBody, map[string]string{"api-key": fx.token}))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, fx.gatewayID, svc.caller.GatewayID)
	assert.Equal(t, ingestTestOUID, svc.caller.OUID)
	assert.Equal(t, trafficBody, string(svc.body))
	var counts map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &counts))
	assert.Equal(t, float64(1), counts["accepted"])
}

func TestIngestTrafficAuditEvents_RequiresNDJSON(t *testing.T) {
	ctrl, fx := newTrafficController(t, &trafficServiceStub{}, 1<<20)
	for _, ct := range []string{"application/json", "text/plain", ""} {
		rec := serveTraffic(ctrl, trafficRequest(trafficBody, map[string]string{"api-key": fx.token, "Content-Type": ct}))
		assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code, "content type %q", ct)
	}
}

func TestIngestTrafficAuditEvents_BoundsTheBatch(t *testing.T) {
	svc := &trafficServiceStub{}
	ctrl, fx := newTrafficController(t, svc, 64)
	rec := serveTraffic(ctrl, trafficRequest(strings.Repeat(trafficBody, 3), map[string]string{"api-key": fx.token}))
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Zero(t, svc.calls)
}

func TestIngestTrafficAuditEvents_StatusesFollowTheSinksRetryRules(t *testing.T) {
	cases := []struct {
		err        error
		status     int
		retryAfter string
	}{
		{fmt.Errorf("%w: garbage", utils.ErrMalformedAuditBatch), http.StatusBadRequest, ""},
		{fmt.Errorf("%w: sink down", utils.ErrAuditIngestUnavailable), http.StatusServiceUnavailable, "5"},
		{fmt.Errorf("unexpected"), http.StatusInternalServerError, ""},
	}
	for _, c := range cases {
		ctrl, fx := newTrafficController(t, &trafficServiceStub{err: c.err}, 1<<20)
		rec := serveTraffic(ctrl, trafficRequest(trafficBody, map[string]string{"api-key": fx.token}))
		assert.Equal(t, c.status, rec.Code, "error %v", c.err)
		assert.Equal(t, c.retryAfter, rec.Header().Get("Retry-After"), "error %v", c.err)
	}
}
