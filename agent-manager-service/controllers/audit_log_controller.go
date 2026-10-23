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
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/middleware"
	"github.com/wso2/agent-manager/agent-manager-service/middleware/logger"
	"github.com/wso2/agent-manager/agent-manager-service/services"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// AuditLogController serves the organization's audit trail.
type AuditLogController interface {
	QueryAuditLogs(w http.ResponseWriter, r *http.Request)
	QueryAuditLogFilterValues(w http.ResponseWriter, r *http.Request)
	ExportAuditLogs(w http.ResponseWriter, r *http.Request)
}

type auditLogController struct {
	service services.AuditTrailService
}

// NewAuditLogController creates the audit log controller.
func NewAuditLogController(service services.AuditTrailService) AuditLogController {
	return &auditLogController{service: service}
}

// QueryAuditLogs handles GET /orgs/{orgName}/audit-logs.
func (c *auditLogController) QueryAuditLogs(w http.ResponseWriter, r *http.Request) {
	q, err := parseAuditTrailQuery(r.URL.Query(), true)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	// The organization is the token's, never the path's or the query's.
	resp, err := c.service.Query(r.Context(), middleware.OUIDFromRequest(r), q)
	if err != nil {
		writeAuditTrailError(w, r, "query audit logs", err)
		return
	}
	utils.WriteSuccessResponse(w, http.StatusOK, resp)
}

// QueryAuditLogFilterValues handles GET /orgs/{orgName}/audit-logs/filter-values.
func (c *auditLogController) QueryAuditLogFilterValues(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	q, err := parseAuditTrailQuery(params, false)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	maxValues := 0
	if raw := params.Get("maxValues"); raw != "" {
		if maxValues, err = strconv.Atoi(raw); err != nil {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "maxValues must be an integer")
			return
		}
	}
	resp, err := c.service.FilterValues(r.Context(), middleware.OUIDFromRequest(r),
		params.Get("filter"), q, params.Get("valueSearch"), maxValues)
	if err != nil {
		writeAuditTrailError(w, r, "query audit log filter values", err)
		return
	}
	utils.WriteSuccessResponse(w, http.StatusOK, resp)
}

// ExportAuditLogs handles GET /orgs/{orgName}/audit-logs/export.
//
// The response is streamed: once the first record is written the status is
// 200, so a failure afterwards can only end the stream early. That is why the
// export ends with a manifest line, whose absence marks a cut-off file.
//
// An export can run far longer than the server's write timeout, which bounds a
// whole response. It is replaced here by a rolling deadline that each flush
// renews, so a long export completes while a client that stops reading is
// still cut off.
func (c *auditLogController) ExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	q, err := parseAuditTrailQuery(r.URL.Query(), false)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	out := &deferredStreamWriter{w: w, rc: http.NewResponseController(w), filename: exportFilename(q)}
	out.extendDeadline(r)
	_, err = c.service.Export(r.Context(), middleware.OUIDFromRequest(r), q, out)
	if err != nil {
		if !out.started {
			writeAuditTrailError(w, r, "export audit logs", err)
			return
		}
		logger.GetLogger(r.Context()).Error("Audit export ended early; the file has no manifest line", "error", err)
		// Deliver the records written so far: the file is cut off either way,
		// and its missing manifest line already says so.
		out.flush()
		return
	}
	if !out.started {
		out.start()
	}
	out.flush()
}

// deferredStreamWriter sets the download headers and a 200 status only when the
// first byte is written, so an export refused before any record (too large,
// store unavailable, export not recorded) can still answer with an error status.
type deferredStreamWriter struct {
	w http.ResponseWriter
	// rc reaches the connection through the middleware's writer wrappers,
	// which expose it by Unwrap rather than implementing Flush themselves.
	rc         *http.ResponseController
	buf        *bufio.Writer
	filename   string
	started    bool
	sinceFlush int
	// deadlineUnsupported is set once SetWriteDeadline has failed.
	deadlineUnsupported bool
}

// exportFlushBytes is how much of an export is buffered before it is pushed to
// the client, so a long export streams instead of accumulating in memory.
const exportFlushBytes = 64 * 1024

// exportWriteWindow is how long an export may go without completing a flush:
// the time to read a page from the store and push it to the client.
const exportWriteWindow = 2 * time.Minute

// extendDeadline moves the write deadline exportWriteWindow ahead. A writer
// that cannot set one keeps the server's, which is logged once.
func (d *deferredStreamWriter) extendDeadline(r *http.Request) {
	if err := d.rc.SetWriteDeadline(time.Now().Add(exportWriteWindow)); err != nil && !d.deadlineUnsupported {
		d.deadlineUnsupported = true
		if r != nil {
			logger.GetLogger(r.Context()).Warn("Audit export cannot extend the write deadline; a long export may be cut off", "error", err)
		}
	}
}

func (d *deferredStreamWriter) start() {
	d.started = true
	h := d.w.Header()
	h.Set("Content-Type", "application/x-ndjson")
	h.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", d.filename))
	h.Set("Cache-Control", "no-store")
	d.w.WriteHeader(http.StatusOK)
	d.buf = bufio.NewWriterSize(d.w, exportFlushBytes)
}

func (d *deferredStreamWriter) Write(p []byte) (int, error) {
	if !d.started {
		d.start()
	}
	n, err := d.buf.Write(p)
	if err != nil {
		return n, err
	}
	d.sinceFlush += n
	if d.sinceFlush >= exportFlushBytes {
		d.sinceFlush = 0
		if err := d.buf.Flush(); err != nil {
			return n, err
		}
		if err := d.rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return n, err
		}
		d.extendDeadline(nil)
	}
	return n, nil
}

func (d *deferredStreamWriter) flush() {
	if d.buf != nil {
		_ = d.buf.Flush()
	}
	_ = d.rc.Flush()
}

func exportFilename(q services.AuditTrailQuery) string {
	return fmt.Sprintf("audit-logs-%s-%s.ndjson",
		q.StartTime.UTC().Format("20060102T150405Z"), q.EndTime.UTC().Format("20060102T150405Z"))
}

// writeAuditTrailError maps the service's sentinel errors onto statuses. A
// refused export (the intent record could not be written) is a 503.
func writeAuditTrailError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	log := logger.GetLogger(r.Context())
	switch {
	case errors.Is(err, utils.ErrInvalidAuditQuery), errors.Is(err, utils.ErrAuditExportTooLarge):
		utils.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, utils.ErrAuditTrailNotSupported):
		utils.WriteErrorResponse(w, http.StatusNotImplemented, err.Error())
	case errors.Is(err, utils.ErrAuditTrailNotConfigured):
		utils.WriteErrorResponse(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, utils.ErrAuditTrailUnavailable):
		log.Error("Audit trail unavailable", "operation", operation, "error", err)
		utils.WriteErrorResponse(w, http.StatusServiceUnavailable, utils.ErrAuditTrailUnavailable.Error())
	case errors.Is(err, utils.ErrAuditExportNotRecorded), errors.Is(err, audit.ErrRecorderUnavailable):
		log.Error("Audit export refused: it could not be recorded", "error", err)
		utils.WriteErrorResponse(w, http.StatusServiceUnavailable, "The export could not be recorded, so it was not started")
	default:
		log.Error("Audit trail request failed", "operation", operation, "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to read the audit trail")
	}
}

// parseAuditTrailQuery reads the window, paging and filters from the query
// string. Bounds and vocabularies are checked by the service.
func parseAuditTrailQuery(params url.Values, withPaging bool) (services.AuditTrailQuery, error) {
	var q services.AuditTrailQuery
	var err error
	if q.StartTime, err = parseAuditTime(params, "startTime"); err != nil {
		return q, err
	}
	if q.EndTime, err = parseAuditTime(params, "endTime"); err != nil {
		return q, err
	}
	if withPaging {
		q.Limit = 100
		if raw := params.Get("limit"); raw != "" {
			if q.Limit, err = strconv.Atoi(raw); err != nil {
				return q, fmt.Errorf("limit must be an integer")
			}
		}
		q.SortOrder = "desc"
		if raw := params.Get("sortOrder"); raw != "" {
			q.SortOrder = raw
		}
	}
	q.Actions = params["action"]
	q.Results = params["result"]
	q.Categories = params["category"]
	q.ActorIDs = params["actorId"]
	q.ActorTypes = params["actorType"]
	q.ResourceTypes = params["resourceType"]
	q.ResourceNames = params["resourceName"]
	q.Projects = params["project"]
	q.Environments = params["environment"]
	q.Agents = params["agent"]
	q.RequestIDs = params["requestId"]
	q.EventIDs = params["eventId"]
	q.Sources = params["source"]
	q.Search = params.Get("search")
	return q, nil
}

func parseAuditTime(params url.Values, name string) (time.Time, error) {
	raw := params.Get(name)
	if raw == "" {
		return time.Time{}, fmt.Errorf("%s is required", name)
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be an RFC3339 timestamp", name)
	}
	return t, nil
}
