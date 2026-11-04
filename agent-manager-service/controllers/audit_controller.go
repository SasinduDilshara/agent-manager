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
	"errors"
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
	start, err := parseOptionalTime(r, "startTime")
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "Invalid 'startTime' format, expected RFC3339")
		return
	}
	end, err := parseOptionalTime(r, "endTime")
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusBadRequest, "Invalid 'endTime' format, expected RFC3339")
		return
	}
	limit := 0
	if v := query.Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > services.AuditMaxLimit {
			utils.WriteErrorResponse(w, http.StatusBadRequest, "Invalid 'limit', must be an integer between 1 and 200")
			return
		}
	}
	ascending := false
	switch query.Get("sort") {
	case "", "desc":
	case "asc":
		ascending = true
	default:
		utils.WriteErrorResponse(w, http.StatusBadRequest, "Invalid 'sort', must be 'asc' or 'desc'")
		return
	}

	resp, err := c.svc.ListEvents(r.Context(), services.AuditQuery{
		OUID:        ouID,
		OrgHandle:   orgHandle,
		Start:       start,
		End:         end,
		Categories:  queryList(r, "category"),
		Agents:      queryList(r, "agent"),
		Project:     query.Get("project"),
		Environment: query.Get("environment"),
		Outcomes:    queryList(r, "outcome"),
		Actor:       query.Get("actor"),
		Search:      query.Get("search"),
		Limit:       limit,
		Cursor:      query.Get("cursor"),
		Ascending:   ascending,
	})
	switch {
	case err == nil:
		utils.WriteSuccessResponse(w, http.StatusOK, resp)
	case errors.Is(err, services.ErrAuditInvalidQuery):
		utils.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrAuditQueryDisabled):
		utils.WriteErrorResponse(w, http.StatusServiceUnavailable, "Audit log query is not enabled on this deployment")
	case errors.Is(err, services.ErrAuditStoreUnavailable):
		// The cause is logged by the service; the caller learns only that the
		// store could not answer.
		utils.WriteErrorResponse(w, http.StatusBadGateway, "Audit log store is unavailable")
	default:
		log.Error("Failed to query audit events", "ouID", ouID, "error", err)
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to query audit events")
	}
}
