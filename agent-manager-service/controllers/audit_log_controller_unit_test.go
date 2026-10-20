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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/middleware"
	"github.com/wso2/agent-manager/agent-manager-service/services"
	"github.com/wso2/agent-manager/agent-manager-service/spec"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// trailServiceStub stands in for the audit trail service. export, when set,
// is what Export writes and returns.
type trailServiceStub struct {
	ouID   string
	query  services.AuditTrailQuery
	export func(w io.Writer) (*spec.AuditLogExportManifest, error)
	err    error
}

func (s *trailServiceStub) Query(_ context.Context, ouID string, q services.AuditTrailQuery) (*spec.AuditLogListResponse, error) {
	s.ouID, s.query = ouID, q
	if s.err != nil {
		return nil, s.err
	}
	return &spec.AuditLogListResponse{Records: []spec.AuditLogRecord{}, Total: 0}, nil
}

func (s *trailServiceStub) FilterValues(_ context.Context, ouID, filter string, q services.AuditTrailQuery, _ string, _ int) (*spec.AuditLogFilterValuesResponse, error) {
	s.ouID, s.query = ouID, q
	if s.err != nil {
		return nil, s.err
	}
	return &spec.AuditLogFilterValuesResponse{Filter: filter, Values: []spec.AuditLogFilterValue{}}, nil
}

func (s *trailServiceStub) Export(_ context.Context, ouID string, q services.AuditTrailQuery, w io.Writer) (*spec.AuditLogExportManifest, error) {
	s.ouID, s.query = ouID, q
	if s.export != nil {
		return s.export(w)
	}
	return &spec.AuditLogExportManifest{}, s.err
}

const trailWindow = "startTime=2026-10-20T09:00:00Z&endTime=2026-10-20T10:00:00Z"

func trailRequest(path, rawQuery string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path+"?"+rawQuery, nil)
	return req.WithContext(middleware.WithResolvedOrg(req.Context(), middleware.ResolvedOrg{OUID: "ou-org"}))
}

// unwrapOnlyWriter wraps a ResponseWriter the way the audit and analytics
// middleware do: it exposes the writer by Unwrap and implements nothing else.
type unwrapOnlyWriter struct{ http.ResponseWriter }

func (u unwrapOnlyWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }

func TestQueryAuditLogs_ParsesTheQuery(t *testing.T) {
	svc := &trailServiceStub{}
	rec := httptest.NewRecorder()
	NewAuditLogController(svc).QueryAuditLogs(rec, trailRequest("/orgs/acme/audit-logs",
		trailWindow+"&action=llm:call&action=agent:deploy&agent=support-agent&search=gpt&limit=250&sortOrder=asc"))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ou-org", svc.ouID, "the organization is the token's, not the path's")
	assert.Equal(t, time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC), svc.query.StartTime)
	assert.Equal(t, []string{"llm:call", "agent:deploy"}, svc.query.Actions)
	assert.Equal(t, []string{"support-agent"}, svc.query.Agents)
	assert.Equal(t, "gpt", svc.query.Search)
	assert.Equal(t, 250, svc.query.Limit)
	assert.Equal(t, "asc", svc.query.SortOrder)
}

func TestQueryAuditLogs_Defaults(t *testing.T) {
	svc := &trailServiceStub{}
	rec := httptest.NewRecorder()
	NewAuditLogController(svc).QueryAuditLogs(rec, trailRequest("/orgs/acme/audit-logs", trailWindow))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 100, svc.query.Limit)
	assert.Equal(t, "desc", svc.query.SortOrder)
}

func TestQueryAuditLogs_RejectsABadQuery(t *testing.T) {
	for _, q := range []string{
		"endTime=2026-10-20T10:00:00Z",
		"startTime=yesterday&endTime=2026-10-20T10:00:00Z",
		trailWindow + "&limit=many",
	} {
		svc := &trailServiceStub{}
		rec := httptest.NewRecorder()
		NewAuditLogController(svc).QueryAuditLogs(rec, trailRequest("/orgs/acme/audit-logs", q))
		assert.Equal(t, http.StatusBadRequest, rec.Code, "query %q", q)
		assert.Empty(t, svc.ouID, "the service is not called for %q", q)
	}
}

func TestAuditLogs_ErrorStatuses(t *testing.T) {
	cases := []struct {
		err    error
		status int
	}{
		{fmt.Errorf("%w: window too long", utils.ErrInvalidAuditQuery), http.StatusBadRequest},
		{utils.ErrAuditTrailNotSupported, http.StatusNotImplemented},
		{utils.ErrAuditTrailNotConfigured, http.StatusServiceUnavailable},
		{fmt.Errorf("%w: connection refused", utils.ErrAuditTrailUnavailable), http.StatusServiceUnavailable},
		{errors.New("boom"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		NewAuditLogController(&trailServiceStub{err: c.err}).QueryAuditLogs(rec, trailRequest("/orgs/acme/audit-logs", trailWindow))
		assert.Equal(t, c.status, rec.Code, "error %v", c.err)
		if c.status == http.StatusServiceUnavailable || c.status == http.StatusInternalServerError {
			assert.NotContains(t, rec.Body.String(), "connection refused", "internal detail is logged, not returned")
		}
	}
}

// TestExportAuditLogs_RefusedBeforeAnyRecordKeepsItsStatus: an export refused
// before its first byte answers with an error status, not a 200 download.
func TestExportAuditLogs_RefusedBeforeAnyRecordKeepsItsStatus(t *testing.T) {
	cases := []struct {
		err    error
		status int
	}{
		{utils.ErrAuditExportTooLarge, http.StatusBadRequest},
		{utils.ErrAuditExportNotRecorded, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		svc := &trailServiceStub{export: func(io.Writer) (*spec.AuditLogExportManifest, error) { return nil, c.err }}
		rec := httptest.NewRecorder()
		NewAuditLogController(svc).ExportAuditLogs(rec, trailRequest("/orgs/acme/audit-logs/export", trailWindow))
		assert.Equal(t, c.status, rec.Code, "error %v", c.err)
		assert.Empty(t, rec.Header().Get("Content-Disposition"), "no download for a refused export")
	}
}

// TestExportAuditLogs_StreamsThroughMiddlewareWrappers: the export is a 200
// download that is flushed as it goes, through a writer wrapper that only
// unwraps — which is how the service's middleware hands it the connection.
func TestExportAuditLogs_StreamsThroughMiddlewareWrappers(t *testing.T) {
	line := `{"eventId":"` + strings.Repeat("x", 1000) + `"}` + "\n"
	svc := &trailServiceStub{export: func(w io.Writer) (*spec.AuditLogExportManifest, error) {
		for i := 0; i < 200; i++ { // ~200 KiB, past the flush threshold
			if _, err := io.WriteString(w, line); err != nil {
				return nil, err
			}
		}
		_, err := io.WriteString(w, `{"manifest":{"complete":true}}`+"\n")
		return &spec.AuditLogExportManifest{Complete: true}, err
	}}
	rec := httptest.NewRecorder()
	NewAuditLogController(svc).ExportAuditLogs(unwrapOnlyWriter{rec}, trailRequest("/orgs/acme/audit-logs/export", trailWindow))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/x-ndjson", rec.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="audit-logs-20261020T090000Z-20261020T100000Z.ndjson"`,
		rec.Header().Get("Content-Disposition"))
	assert.True(t, rec.Flushed, "the export is flushed to the client, not held until the end")
	assert.True(t, strings.HasSuffix(rec.Body.String(), `{"manifest":{"complete":true}}`+"\n"))
	assert.Equal(t, 201, strings.Count(rec.Body.String(), "\n"))
}

// TestExportAuditLogs_FailureMidStreamLeavesNoManifest: once records are out
// the status is 200, so a later failure can only end the file early — which
// the missing manifest line shows.
func TestExportAuditLogs_FailureMidStreamLeavesNoManifest(t *testing.T) {
	svc := &trailServiceStub{export: func(w io.Writer) (*spec.AuditLogExportManifest, error) {
		_, _ = io.WriteString(w, `{"eventId":"e1"}`+"\n")
		return nil, fmt.Errorf("%w: store went away", utils.ErrAuditTrailUnavailable)
	}}
	rec := httptest.NewRecorder()
	NewAuditLogController(svc).ExportAuditLogs(rec, trailRequest("/orgs/acme/audit-logs/export", trailWindow))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `{"eventId":"e1"}`+"\n", rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "manifest")
}

// TestExportAuditLogs_EmptyExportIsStillADownload: an export with no records
// writes only its manifest, and that is still a file.
func TestExportAuditLogs_EmptyExportIsStillADownload(t *testing.T) {
	svc := &trailServiceStub{export: func(w io.Writer) (*spec.AuditLogExportManifest, error) {
		_, err := io.WriteString(w, `{"manifest":{"complete":true,"exportedCount":0}}`+"\n")
		return &spec.AuditLogExportManifest{Complete: true}, err
	}}
	rec := httptest.NewRecorder()
	NewAuditLogController(svc).ExportAuditLogs(rec, trailRequest("/orgs/acme/audit-logs/export", trailWindow))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Content-Disposition"))
}
