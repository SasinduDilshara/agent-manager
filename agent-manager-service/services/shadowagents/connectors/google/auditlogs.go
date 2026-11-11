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

package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// listLogEntriesRequest is the v2 ListLogEntriesRequest body.
type listLogEntriesRequest struct {
	ResourceNames []string `json:"resourceNames"`
	Filter        string   `json:"filter"`
	OrderBy       string   `json:"orderBy"`
	PageSize      int      `json:"pageSize"`
	PageToken     string   `json:"pageToken,omitempty"`
}

// listLogEntriesResponse is the v2 ListLogEntriesResponse.
type listLogEntriesResponse struct {
	Entries       []logEntry `json:"entries"`
	NextPageToken string     `json:"nextPageToken"`
}

// logEntry holds the LogEntry and AuditLog fields the connector reads. The
// audit log's request, metadata and caller IP are not declared, so they are
// never decoded; response is decoded only for its name (an operation name
// that holds the new engine's ID).
type logEntry struct {
	InsertID     string `json:"insertId"`
	Timestamp    string `json:"timestamp"`
	ProtoPayload *struct {
		ServiceName        string `json:"serviceName"`
		MethodName         string `json:"methodName"`
		ResourceName       string `json:"resourceName"`
		AuthenticationInfo *struct {
			PrincipalEmail   string `json:"principalEmail"`
			PrincipalSubject string `json:"principalSubject"`
		} `json:"authenticationInfo"`
		Response json.RawMessage `json:"response"`
	} `json:"protoPayload"`
}

// auditFilter selects Admin Activity entries of aiplatform.googleapis.com
// in the window. methodName:"ReasoningEngineService" (substring match) is
// a narrowing hint only: the method names are not in Google's audited
// operations table, so the connector matches them again, leniently.
func auditFilter(project string, start, end time.Time) string {
	return fmt.Sprintf(`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity"`+
		` AND protoPayload.serviceName="aiplatform.googleapis.com"`+
		` AND protoPayload.methodName:"ReasoningEngineService"`+
		` AND timestamp>="%s" AND timestamp<="%s"`,
		project, start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
}

// throttleLogs keeps entries.list at no more than one request per
// logInterval.
func (s *scanner) throttleLogs(ctx context.Context) error {
	if !s.lastLogCall.IsZero() {
		if wait := s.c.logInterval - time.Since(s.lastLogCall); wait > 0 {
			if err := s.c.sleep(ctx, wait); err != nil {
				return err
			}
		}
	}
	s.lastLogCall = time.Now()
	return nil
}

// auditLogs reads the project's Admin Activity audit log for engine
// creates and updates, for owner hints.
func (s *scanner) auditLogs(ctx context.Context, project string) {
	if !s.hasEngines(project) {
		s.deferSkip(callLogEntries, "no Agent Runtime engine was found to match audit logs to")
		return
	}
	if !s.proceed(ctx, callLogEntries) {
		return
	}
	base, err := baseURL(s.conn, sa.EPGoogleLogging)
	if err != nil {
		s.record(callLogEntries, 0, &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()})
		return
	}
	u := base + "/v2/entries:list"
	filter := auditFilter(project, s.w.Start, s.w.End)
	seen := map[string]bool{}
	s.paginate(ctx, callLogEntries, maxLogPages, func(token string) (string, int, error) {
		if err := s.throttleLogs(ctx); err != nil {
			return "", 0, &sa.CallError{Outcome: models.ShadowCallFailed, Message: "cancelled: " + err.Error()}
		}
		body := listLogEntriesRequest{
			ResourceNames: []string{"projects/" + project},
			Filter:        filter,
			OrderBy:       "timestamp asc",
			PageSize:      logPageSize,
			PageToken:     token,
		}
		var resp listLogEntriesResponse
		if err := s.api.DoJSON(ctx, sa.Request{Method: http.MethodPost, URL: u, Body: body}, &resp); err != nil {
			return "", 0, err
		}
		for i := range resp.Entries {
			s.auditEntry(&resp.Entries[i], seen)
		}
		// An empty page with a token means the search ran out of time, not
		// that there is nothing left: keep paging.
		return resp.NextPageToken, len(resp.Entries), nil
	})
}

// auditEntry turns a ReasoningEngineService create or update on a known
// engine into an owner hint and an info signal.
func (s *scanner) auditEntry(le *logEntry, seen map[string]bool) {
	p := le.ProtoPayload
	if p == nil || !strings.Contains(p.MethodName, "ReasoningEngineService") {
		return
	}
	if p.ServiceName != "" && p.ServiceName != "aiplatform.googleapis.com" {
		return
	}
	method := lastDotSegment(p.MethodName)
	var kind string
	switch {
	case strings.HasPrefix(method, "Create"):
		kind = "create"
	case strings.HasPrefix(method, "Update"):
		kind = "update"
	default:
		return
	}
	ref, ok := parseEngineRef(p.ResourceName)
	if !ok && len(p.Response) > 0 {
		// A create names the parent; its long-running operation's name
		// (.../reasoningEngines/ID/operations/OP) holds the engine ID.
		var op struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(p.Response, &op) == nil {
			ref, ok = parseEngineRef(op.Name)
		}
	}
	if !ok {
		return
	}
	e := s.findEngine(ref)
	if e == nil {
		return
	}
	if le.InsertID != "" {
		if seen[le.InsertID] {
			return
		}
		seen[le.InsertID] = true
	}
	observed := map[string]any{"creates": 0, "updates": 0}
	if kind == "create" {
		observed["creates"] = 1
	} else {
		observed["updates"] = 1
	}
	e.finding.AddSignal(sa.Signal{Code: sa.SigGoogleEngineCreatedBy, Source: callLogEntries, Observed: observed})

	var email, subject string
	if a := p.AuthenticationInfo; a != nil {
		email, subject = strings.TrimSpace(a.PrincipalEmail), strings.TrimSpace(a.PrincipalSubject)
	}
	if email == "" && subject == "" {
		return
	}
	// The creator wins; without a create in the window, the latest updater.
	if e.owner == "create" {
		return
	}
	hint := models.ShadowOwnerHint{
		Email:     email,
		Type:      principalType(email),
		Source:    "Admin Activity audit log: " + method,
		CreatedAt: parseTime(le.Timestamp),
	}
	if email == "" {
		hint.Username = subject
	}
	e.finding.OwnerHint = sa.MinimiseOwnerHint(hint)
	e.owner = kind
}

func principalType(email string) string {
	switch {
	case email == "":
		return "principal"
	case strings.HasSuffix(strings.ToLower(email), ".gserviceaccount.com"):
		return "service_account"
	default:
		return "user"
	}
}

func lastDotSegment(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}
