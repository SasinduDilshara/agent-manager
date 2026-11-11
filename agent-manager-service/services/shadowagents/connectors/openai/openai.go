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

// Package openai is the Shadow Agent Discovery connector for the OpenAI API
// platform. The Admin key reads projects, project API keys, usage, costs
// and audit logs (/v1/organization/*); optional project keys read the
// project's agents (/v1/agents, beta) and, with deep inspection, its stored
// chat completions and batch files.
package openai

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Call names, as stored in scan results and signal sources.
const (
	callProjects         = "GET /v1/organization/projects"
	callAPIKeys          = "GET /v1/organization/projects/{project_id}/api_keys"
	callAPIKeysArchived  = "GET /v1/organization/projects/{project_id}/api_keys (archived projects)"
	callAuditLogs        = "GET /v1/organization/audit_logs"
	callUsage            = "GET /v1/organization/usage/completions"
	callCosts            = "GET /v1/organization/costs"
	callWebSearch        = "GET /v1/organization/usage/web_search_calls"
	callFileSearch       = "GET /v1/organization/usage/file_search_calls"
	callCodeInterpreter  = "GET /v1/organization/usage/code_interpreter_sessions"
	callAgents           = "GET /v1/agents"
	callSessions         = "GET /v1/agents/sessions"
	callChatCompletions  = "GET /v1/chat/completions"
	callBatches          = "GET /v1/batches"
	callFileContent      = "GET /v1/files/{file_id}/content"
	callProjectKeysMiss  = "Project key calls (projects without a project key)"
	suffixPageLimit      = " (page limit)"
	suffixNotAttributed  = " (not attributed)"
	suffixOnProject      = " (on the project finding)"
	reasonDeepOff        = "deep inspection is off"
	reasonNoProjectKey   = "no project key"
	reasonNoAdminKey     = "the connection has no Admin API key"
	reasonNeedsAdminKey  = "needs the Admin API key, which this connection does not have"
	reasonAdminRejected  = "not checked: the Admin key was rejected"
	apiSourceAgents      = "agents_api"
	headerBeta           = "OpenAI-Beta"
	headerBetaAgents     = "agents=v1"
	relationUsedByAgent  = "used_by_agent"
	stateActive          = "active"
	stateArchived        = "archived"
	stateExpired         = "expired"
	ownerTypeUser        = "user"
	ownerTypeServiceAcct = "service_account"
)

// Bounds.
const (
	// listPageSize is the largest page the list endpoints accept (1-100).
	listPageSize = 100
	// maxListPages bounds one cursor listing (10,000 items).
	maxListPages = 100
	// maxAuditPages bounds the api_key.created audit events read (5,000).
	maxAuditPages = 50
	// usageDailyLimit is the most 1d buckets a usage page holds.
	usageDailyLimit = 31
	// costsDailyLimit is the most 1d buckets a costs page holds (1-180).
	costsDailyLimit = 180
	// maxUsagePages bounds one usage or costs read.
	maxUsagePages = 100
	// Sessions: the most recent sessions per project, in pages of 50.
	sessionsPageSize      = 50
	maxSessionsPerProject = 100
	// Deep inspection bounds, per project.
	maxStoredCompletions = 200
	maxBatchesPerProject = 20
	maxBatchListPages    = 5
	maxFileBytes         = 5 << 20
)

// Connector scans one OpenAI organization.
type Connector struct {
	httpClient *http.Client
	logger     *slog.Logger
}

// New returns the OpenAI connector. httpClient is the redirect-guarded
// client (sa.NewHTTPClient); logger receives sanitized summaries only.
func New(httpClient *http.Client, logger *slog.Logger) sa.Connector {
	if httpClient == nil {
		httpClient = sa.NewHTTPClient(nil)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Connector{httpClient: httpClient, logger: logger}
}

// Provider returns models.ShadowProviderOpenAI.
func (c *Connector) Provider() string { return models.ShadowProviderOpenAI }

// api returns a client that sends key as a bearer token.
func (c *Connector) api(key string) *sa.API {
	return &sa.API{
		HTTP:   c.httpClient,
		Logger: c.logger,
		Header: func(h http.Header) { h.Set("Authorization", "Bearer "+key) },
	}
}

// baseURL is the connection's OpenAI API base, e.g. https://api.openai.com/v1.
func baseURL(conn sa.Connection) (string, error) {
	base, err := sa.Expand(sa.EndpointOf(conn, sa.EPOpenAIAPI), nil)
	if err != nil {
		return "", err
	}
	if base == "" {
		return "", errors.New("the OpenAI API endpoint is not set")
	}
	return base, nil
}

func betaAgentsHeader() http.Header {
	return http.Header{headerBeta: []string{headerBetaAgents}}
}

// listAll follows an after/has_more listing, calling fn for every item
// until fn returns false. It returns true when maxPages was reached with
// more pages left.
func listAll[T any](ctx context.Context, api *sa.API, u string, q url.Values, hdr http.Header,
	pageSize, maxPages int, fn func(T) bool,
) (bool, error) {
	after := ""
	for page := 0; page < maxPages; page++ {
		pq := cloneValues(q)
		pq.Set("limit", strconv.Itoa(pageSize))
		if after != "" {
			pq.Set("after", after)
		}
		var p listPage[T]
		if err := api.DoJSON(ctx, sa.Request{Method: http.MethodGet, URL: u, Query: pq, Header: hdr}, &p); err != nil {
			return false, err
		}
		if p.Data == nil {
			return false, sa.Unsupported("the response has no data list")
		}
		for _, it := range *p.Data {
			if !fn(it) {
				return false, nil
			}
		}
		if !p.HasMore {
			return false, nil
		}
		next := ""
		if p.LastID != nil {
			next = *p.LastID
		}
		if next == "" || next == after {
			return false, sa.Unsupported("has_more is true but last_id does not advance")
		}
		after = next
	}
	return true, nil
}

// readBuckets follows a usage or costs listing (page/next_page), calling
// fn for every result with the UTC day of its bucket. It returns the number
// of results and true when maxUsagePages was reached with more pages left.
func readBuckets[T any](ctx context.Context, api *sa.API, u string, q url.Values, limit int,
	fn func(day time.Time, r T),
) (int, bool, error) {
	rows := 0
	page := ""
	for i := 0; i < maxUsagePages; i++ {
		pq := cloneValues(q)
		pq.Set("limit", strconv.Itoa(limit))
		if page != "" {
			pq.Set("page", page)
		}
		var p usagePage[T]
		if err := api.DoJSON(ctx, sa.Request{Method: http.MethodGet, URL: u, Query: pq}, &p); err != nil {
			return rows, false, err
		}
		if p.Data == nil {
			return rows, false, sa.Unsupported("the response has no data list")
		}
		for _, b := range *p.Data {
			day := sa.DayOf(time.Unix(b.StartTime, 0))
			for _, r := range b.Results {
				rows++
				fn(day, r)
			}
		}
		if !p.HasMore {
			return rows, false, nil
		}
		next := ""
		if p.NextPage != nil {
			next = *p.NextPage
		}
		if next == "" || next == page {
			return rows, false, sa.Unsupported("has_more is true but next_page does not advance")
		}
		page = next
	}
	return rows, true, nil
}

func cloneValues(q url.Values) url.Values {
	out := url.Values{}
	for k, vs := range q {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// statusOf returns the HTTP status of a failed call, or 0.
func statusOf(err error) int {
	var ce *sa.CallError
	if errors.As(err, &ce) {
		return ce.Status
	}
	return 0
}

func unixTime(sec int64) *time.Time {
	if sec <= 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

func unixPtr(sec *int64) *time.Time {
	if sec == nil {
		return nil
	}
	return unixTime(*sec)
}

// widenLast moves a finding's LastUsedAt forward to t (FirstUsedAt comes
// only from usage in the window).
func widenLast(f *sa.Finding, t time.Time) {
	t = t.UTC()
	if f.LastUsedAt == nil || t.After(*f.LastUsedAt) {
		f.LastUsedAt = &t
	}
}

// addAttrValue adds v to the string list attribute key of f.
func addAttrValue(f *sa.Finding, key, v string) {
	if v == "" {
		return
	}
	list, _ := f.Attributes[key].([]string)
	for _, s := range list {
		if s == v {
			return
		}
	}
	f.Attributes[key] = append(list, v)
}

// redactedHint keeps OpenAI's redacted_value ("sk-abc...def"). A value that
// does not look redacted is reduced to a hint, in case a full key ever
// appears there.
func redactedHint(v string) string {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "...") || strings.Contains(v, "…") || strings.Contains(v, "*") {
		return sa.Truncate(v, 64)
	}
	return sa.SecretHint(v)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
