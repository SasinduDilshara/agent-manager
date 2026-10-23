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
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories/repomocks"
	"github.com/wso2/agent-manager/agent-manager-service/services"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

const ingestTestOUID = "ou-acme"

// ingestServiceStub records what the controller hands the ingest service.
type ingestServiceStub struct {
	calls  int
	caller services.GatewayAuditCaller
	body   []byte
	result *services.GatewayAuditIngestResult
	err    error
}

func (s *ingestServiceStub) Ingest(_ context.Context, caller services.GatewayAuditCaller, body []byte) (*services.GatewayAuditIngestResult, error) {
	s.calls++
	s.caller, s.body = caller, body
	if s.err != nil {
		return nil, s.err
	}
	if s.result != nil {
		return s.result, nil
	}
	return &services.GatewayAuditIngestResult{Accepted: 1}, nil
}

// ingestFixture is a gateway with a valid registration token, served by the
// real token verification over a mocked repository. The stored hash is the
// form PlatformGatewayService.VerifyToken checks: hex(SHA-256(token || salt)).
type ingestFixture struct {
	gatewayID string
	token     string
}

func newIngestController(t *testing.T, svc services.GatewayAuditIngestService, maxBytes int64) (GatewayInternalController, *ingestFixture) {
	t.Helper()
	return newInternalController(t, GatewayAuditIngest{Service: svc, MaxBodyBytes: maxBytes}, GatewayTrafficAuditIngest{})
}

// newInternalController builds the controller with the given feeds over the
// real token verification.
func newInternalController(
	t *testing.T, otel GatewayAuditIngest, traffic GatewayTrafficAuditIngest,
) (GatewayInternalController, *ingestFixture) {
	t.Helper()
	gateway := &models.Gateway{UUID: uuid.New(), Name: "edge", OUID: ingestTestOUID}
	prefix := uuid.New().String()
	fx := &ingestFixture{gatewayID: gateway.UUID.String(), token: prefix + "-secretpart"}
	salt := []byte("0123456789abcdef0123456789abcdef")
	sum := sha256.Sum256(append([]byte(fx.token), salt...))
	stored := &models.GatewayToken{
		UUID: uuid.New(), GatewayUUID: gateway.UUID, TokenPrefix: prefix,
		TokenHash: hex.EncodeToString(sum[:]), Salt: hex.EncodeToString(salt), Status: "active",
	}
	repo := &repomocks.GatewayRepositoryMock{
		GetActiveTokenByPrefixFunc: func(_ context.Context, p string) (*models.GatewayToken, error) {
			if p != prefix {
				return nil, gorm.ErrRecordNotFound
			}
			return stored, nil
		},
		GetByUUIDFunc: func(id string) (*models.Gateway, error) {
			if id != fx.gatewayID {
				return nil, gorm.ErrRecordNotFound
			}
			return gateway, nil
		},
	}
	ctrl := NewGatewayInternalController(services.NewPlatformGatewayService(repo, nil), nil, nil, nil, otel, traffic)
	return ctrl, fx
}

func ingestRequest(body []byte, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/internal/v1/audit/gateway-events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	return req
}

func serveIngest(ctrl GatewayInternalController, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctrl.IngestAuditEvents(rec, req)
	return rec
}

const ingestBody = `{"resourceLogs":[]}`

func TestIngestAuditEvents_RequiresAGatewayKey(t *testing.T) {
	svc := &ingestServiceStub{}
	ctrl, fx := newIngestController(t, svc, 1<<20)

	rec := serveIngest(ctrl, ingestRequest([]byte(ingestBody), nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rec = serveIngest(ctrl, ingestRequest([]byte(ingestBody), map[string]string{"api-key": uuid.NewString() + "-wrong"}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// The right prefix with the wrong secret is refused as well.
	prefix := strings.TrimSuffix(fx.token, "-secretpart")
	rec = serveIngest(ctrl, ingestRequest([]byte(ingestBody), map[string]string{"api-key": prefix + "-forged"}))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Zero(t, svc.calls)
}

// TestIngestAuditEvents_DisabledIsHiddenFromUnauthenticatedCallers: whether
// the ingest is on is answered only to a gateway.
func TestIngestAuditEvents_DisabledIsHiddenFromUnauthenticatedCallers(t *testing.T) {
	ctrl, fx := newIngestController(t, nil, 1<<20)

	rec := serveIngest(ctrl, ingestRequest([]byte(ingestBody), nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rec = serveIngest(ctrl, ingestRequest([]byte(ingestBody), map[string]string{"api-key": fx.token}))
	assert.Equal(t, http.StatusNotFound, rec.Code, "a 4xx the publisher drops, not a 5xx it resends forever")
}

// TestIngestAuditEvents_CallerComesFromTheCredential: the organization and
// gateway of a batch are the key's, whatever the body says.
func TestIngestAuditEvents_CallerComesFromTheCredential(t *testing.T) {
	svc := &ingestServiceStub{}
	ctrl, fx := newIngestController(t, svc, 1<<20)

	rec := serveIngest(ctrl, ingestRequest([]byte(ingestBody), map[string]string{"api-key": fx.token}))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, svc.calls)
	assert.Equal(t, fx.gatewayID, svc.caller.GatewayID)
	assert.Equal(t, ingestTestOUID, svc.caller.OUID)
	assert.JSONEq(t, `{}`, rec.Body.String())
}

func TestIngestAuditEvents_RequiresJSON(t *testing.T) {
	svc := &ingestServiceStub{}
	ctrl, fx := newIngestController(t, svc, 1<<20)
	for _, ct := range []string{"application/x-protobuf", "text/plain", ""} {
		rec := serveIngest(ctrl, ingestRequest([]byte(ingestBody), map[string]string{"api-key": fx.token, "Content-Type": ct}))
		assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code, "content type %q", ct)
	}
	rec := serveIngest(ctrl, ingestRequest([]byte(ingestBody),
		map[string]string{"api-key": fx.token, "Content-Type": "application/json; charset=utf-8"}))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func TestIngestAuditEvents_DecodesGzip(t *testing.T) {
	svc := &ingestServiceStub{}
	ctrl, fx := newIngestController(t, svc, 1<<20)
	rec := serveIngest(ctrl, ingestRequest(gzipped(t, []byte(ingestBody)),
		map[string]string{"api-key": fx.token, "Content-Encoding": "gzip"}))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, ingestBody, string(svc.body))

	rec = serveIngest(ctrl, ingestRequest([]byte(ingestBody), map[string]string{"api-key": fx.token, "Content-Encoding": "br"}))
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

// TestIngestAuditEvents_BoundsTheBatch: the limit holds on the wire and after
// decompression, so a small gzip bomb is refused too.
func TestIngestAuditEvents_BoundsTheBatch(t *testing.T) {
	svc := &ingestServiceStub{}
	ctrl, fx := newIngestController(t, svc, 64)

	big := []byte(`{"resourceLogs":[` + strings.Repeat(" ", 100) + `]}`)
	rec := serveIngest(ctrl, ingestRequest(big, map[string]string{"api-key": fx.token}))
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	bomb := gzipped(t, big)
	require.Less(t, len(bomb), 64, "compressed below the limit")
	rec = serveIngest(ctrl, ingestRequest(bomb, map[string]string{"api-key": fx.token, "Content-Encoding": "gzip"}))
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	exact := []byte(`{"resourceLogs":[` + strings.Repeat(" ", 64-19) + `]}`)
	require.Len(t, exact, 64)
	rec = serveIngest(ctrl, ingestRequest(exact, map[string]string{"api-key": fx.token}))
	assert.Equal(t, http.StatusOK, rec.Code, "a batch exactly at the limit is accepted")
	assert.Equal(t, 1, svc.calls)
}

// TestIngestAuditEvents_StatusesFollowThePublishersRetryRules: the publisher
// resends 429/5xx and drops other 4xx, so only a batch that can never be
// accepted may be a 4xx.
func TestIngestAuditEvents_StatusesFollowThePublishersRetryRules(t *testing.T) {
	cases := []struct {
		err        error
		status     int
		retryAfter string
	}{
		{fmt.Errorf("%w: bad json", utils.ErrMalformedAuditBatch), http.StatusBadRequest, ""},
		{fmt.Errorf("%w: sink down", utils.ErrAuditIngestUnavailable), http.StatusServiceUnavailable, "5"},
		{fmt.Errorf("unexpected"), http.StatusInternalServerError, ""},
	}
	for _, c := range cases {
		ctrl, fx := newIngestController(t, &ingestServiceStub{err: c.err}, 1<<20)
		rec := serveIngest(ctrl, ingestRequest([]byte(ingestBody), map[string]string{"api-key": fx.token}))
		assert.Equal(t, c.status, rec.Code, "error %v", c.err)
		assert.Equal(t, c.retryAfter, rec.Header().Get("Retry-After"), "error %v", c.err)
	}
}

// TestIngestAuditEvents_ReportsPartialSuccess: records refused inside an
// accepted batch are reported the OTLP way, with int64 as a string.
func TestIngestAuditEvents_ReportsPartialSuccess(t *testing.T) {
	svc := &ingestServiceStub{result: &services.GatewayAuditIngestResult{
		Accepted: 3, Rejected: 2, RejectReasons: map[string]int{"unexpected-scope": 1, "bad-timestamp": 1},
	}}
	ctrl, fx := newIngestController(t, svc, 1<<20)
	rec := serveIngest(ctrl, ingestRequest([]byte(ingestBody), map[string]string{"api-key": fx.token}))
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		PartialSuccess struct {
			RejectedLogRecords string `json:"rejectedLogRecords"`
			ErrorMessage       string `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "2", resp.PartialSuccess.RejectedLogRecords)
	assert.Equal(t, "records not accepted: bad-timestamp=1, unexpected-scope=1", resp.PartialSuccess.ErrorMessage)
}
