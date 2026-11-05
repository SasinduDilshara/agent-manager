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
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/middleware"
	"github.com/wso2/agent-manager/agent-manager-service/middleware/logger"
	"github.com/wso2/agent-manager/agent-manager-service/services"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// AuditController serves the org's audit trail.
type AuditController interface {
	ListAuditEvents(w http.ResponseWriter, r *http.Request)
}

type auditController struct {
	svc services.AuditQueryService
}

// NewAuditController creates the controller.
func NewAuditController(svc services.AuditQueryService) AuditController {
	return &auditController{svc: svc}
}

// queryList returns a repeatable query parameter, also accepting
// comma-separated values in one occurrence.
func queryList(r *http.Request, name string) []string {
	var out []string
	for _, v := range r.URL.Query()[name] {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func parseOptionalTime(r *http.Request, name string) (time.Time, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}

// ListAuditEvents handles GET /orgs/{orgName}/audit/events.
//
// The organization comes from the caller's token (RequireOrgMatch), never from
// the path or the query: every record returned is scoped to it.
func (c *auditController) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger(r.Context())
	ouID := middleware.OUIDFromRequest(r)
	orgHandle := middleware.OrgHandleFromRequest(r)
	if ouID == "" || orgHandle == "" {
		utils.WriteErrorResponse(w, http.StatusForbidden, "missing organization in token")
		return
	}

	query := r.URL.Query()
	q := services.AuditQuery{
		OUID:        ouID,
		OrgHandle:   orgHandle,
		Categories:  queryList(r, "category"),
		Agents:      queryList(r, "agent"),
		Project:     query.Get("project"),
		Environment: query.Get("environment"),
		Outcomes:    queryList(r, "outcome"),
		Actor:       query.Get("actor"),
		Search:      query.Get("search"),
		Cursor:      query.Get("cursor"),
	}
	// Every parameter is parsed before any is rejected, so a refused read is
	// recorded with everything else the caller sent.
	var paramErr *services.AuditParamError
	reject := func(param, msg string) {
		if paramErr == nil {
			paramErr = &services.AuditParamError{Param: param, Message: msg}
		}
	}
	var err error
	if q.Start, err = parseOptionalTime(r, "startTime"); err != nil {
		reject("startTime", "Invalid 'startTime' format, expected RFC3339")
	}
	if q.End, err = parseOptionalTime(r, "endTime"); err != nil {
		reject("endTime", "Invalid 'endTime' format, expected RFC3339")
	}
	if v := query.Get("limit"); v != "" {
		limit, convErr := strconv.Atoi(v)
		if convErr != nil || limit < 1 || limit > services.AuditMaxLimit {
			reject("limit", fmt.Sprintf("Invalid 'limit', must be an integer between 1 and %d", services.AuditMaxLimit))
		} else {
			q.Limit = limit
		}
	}
	switch query.Get("sort") {
	case "", "desc":
	case "asc":
		q.Ascending = true
	default:
		reject("sort", "Invalid 'sort', must be 'asc' or 'desc'")
	}
	if paramErr != nil {
		c.svc.RecordRejectedRead(r.Context(), q, paramErr)
		utils.WriteErrorResponse(w, http.StatusBadRequest, paramErr.Message)
		return
	}

	resp, err := c.svc.ListEvents(r.Context(), q)
	status := services.AuditQueryStatus(err)
	switch status {
	case http.StatusOK:
		utils.WriteSuccessResponse(w, status, resp)
	case http.StatusBadRequest:
		utils.WriteErrorResponse(w, status, err.Error())
	case http.StatusServiceUnavailable:
		utils.WriteErrorResponse(w, status, "Audit log query is not enabled on this deployment")
	case http.StatusBadGateway:
		// The cause is logged by the service; the caller learns only that the
		// store could not answer.
		utils.WriteErrorResponse(w, status, "Audit log store is unavailable")
	default:
		log.Error("Failed to query audit events", "ouID", ouID, "error", err)
		utils.WriteErrorResponse(w, status, "Failed to query audit events")
	}
}
