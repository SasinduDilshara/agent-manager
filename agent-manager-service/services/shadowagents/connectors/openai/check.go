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

package openai

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Connection check names.
const (
	checkProjects        = "Projects (Admin key)"
	checkAPIKeys         = "Project API keys (Admin key)"
	checkUsage           = "Completions usage (Admin key)"
	checkCosts           = "Costs (Admin key)"
	checkSearch          = "Web and file search usage (Admin key)"
	checkCodeInterpreter = "Code interpreter usage (Admin key)"
	checkAuditLogs       = "Audit logs (Admin key)"
)

// Test checks the Admin key with one cheap read per capability (limit 1),
// and each project key with a read of its agents (and, with deep
// inspection, of its stored completions and batches). OK means the Admin
// key can read projects and usage.
func (c *Connector) Test(ctx context.Context, conn sa.Connection) models.ShadowConnectionTestInfo {
	info := models.ShadowConnectionTestInfo{Checks: []models.ShadowConnectionCheck{}}
	base, err := baseURL(conn)
	if err != nil {
		info.Checks = append(info.Checks, models.ShadowConnectionCheck{
			Name: checkProjects, Outcome: models.ShadowCallFailed, Message: sa.ScrubText(err.Error()),
		})
		return info
	}
	add := func(name string, unlocks []string, err error) bool {
		info.Checks = append(info.Checks, models.ShadowConnectionCheck{
			Name: name, Outcome: sa.OutcomeOf(err), Message: sa.MessageOf(err), Unlocks: unlocks,
		})
		return err == nil
	}
	get := func(api *sa.API, path string, q url.Values, hdr http.Header) error {
		q.Set("limit", "1")
		var out map[string]any
		return api.DoJSON(ctx, sa.Request{Method: http.MethodGet, URL: base + path, Query: q, Header: hdr}, &out)
	}

	type adminCheck struct {
		name    string
		unlocks []string
		run     func(api *sa.API) error
	}
	since := strconv.FormatInt(time.Now().Add(-24*time.Hour).Unix(), 10)
	usageQ := func(groupBy string) url.Values {
		q := url.Values{"start_time": []string{since}, "bucket_width": []string{"1d"}}
		if groupBy != "" {
			q.Set("group_by[]", groupBy)
		}
		return q
	}
	firstProject := ""
	checks := []adminCheck{
		{checkProjects, nil, func(api *sa.API) error {
			var p listPage[project]
			q := url.Values{"include_archived": []string{"true"}, "limit": []string{"1"}}
			err := api.DoJSON(ctx, sa.Request{Method: http.MethodGet, URL: base + "/organization/projects", Query: q}, &p)
			if err == nil && p.Data != nil && len(*p.Data) > 0 {
				firstProject = (*p.Data)[0].ID
			}
			return err
		}},
		{checkAPIKeys, nil, func(api *sa.API) error {
			if firstProject == "" {
				return nil
			}
			return get(api, "/organization/projects/"+url.PathEscape(firstProject)+"/api_keys",
				url.Values{"owner_project_access": []string{"any"}}, nil)
		}},
		{checkUsage, []string{sa.SigOpenAIPlainUsage, sa.SigOpenAIAgentsAPIUsage}, func(api *sa.API) error {
			return get(api, "/organization/usage/completions", usageQ("api_source"), nil)
		}},
		{checkCosts, []string{sa.SigOpenAIAgentsAPIUsage}, func(api *sa.API) error {
			return get(api, "/organization/costs", usageQ("api_source"), nil)
		}},
		{checkSearch, []string{sa.SigOpenAIHostedSearch}, func(api *sa.API) error {
			return get(api, "/organization/usage/web_search_calls", usageQ("api_key_id"), nil)
		}},
		{checkCodeInterpreter, []string{sa.SigOpenAICodeInterpreter, sa.SigOpenAICodeInterpreterPrj}, func(api *sa.API) error {
			return get(api, "/organization/usage/code_interpreter_sessions", usageQ("project_id"), nil)
		}},
		{checkAuditLogs, nil, func(api *sa.API) error {
			return get(api, "/organization/audit_logs", url.Values{"event_types[]": []string{"api_key.created"}}, nil)
		}},
	}

	adminKey := strings.TrimSpace(conn.Secret.APIKey)
	projectsOK, usageOK := false, false
	if adminKey == "" {
		// Project keys only: the organization checks cannot run.
		for _, ch := range checks {
			info.Checks = append(info.Checks, models.ShadowConnectionCheck{
				Name: ch.name, Outcome: models.ShadowCallSkipped, Message: reasonNeedsAdminKey, Unlocks: ch.unlocks,
			})
		}
	} else {
		admin := c.api(adminKey)
		rejected := false
		for _, ch := range checks {
			if rejected {
				info.Checks = append(info.Checks, models.ShadowConnectionCheck{
					Name: ch.name, Outcome: models.ShadowCallSkipped, Message: reasonAdminRejected, Unlocks: ch.unlocks,
				})
				continue
			}
			err := ch.run(admin)
			ok := add(ch.name, ch.unlocks, err)
			switch ch.name {
			case checkProjects:
				projectsOK = ok
				rejected = sa.OutcomeOf(err) == models.ShadowCallAuthFailed
			case checkUsage:
				usageOK = ok
			}
		}
	}

	projectChecks, projectChecksOK := 0, 0
	for _, pid := range sortedKeys(conn.Secret.ScopedKeys) {
		key := strings.TrimSpace(conn.Secret.ScopedKeys[pid])
		if key == "" {
			continue
		}
		api := c.api(key)
		projectChecks++
		if add("Agents (project "+pid+")", []string{sa.SigOpenAIAgentObject},
			get(api, "/agents", url.Values{}, betaAgentsHeader())) {
			projectChecksOK++
		}
		if conn.Config.DeepInspection {
			add("Stored chat completions (project "+pid+")", []string{sa.SigOpenAIToolCallCompletion},
				get(api, "/chat/completions", url.Values{}, nil))
			add("Batches (project "+pid+")", []string{sa.SigOpenAIToolCallBatch, sa.SigOpenAIToolResultBatch},
				get(api, "/batches", url.Values{}, nil))
		}
	}
	if adminKey != "" {
		info.OK = projectsOK && usageOK
	} else {
		// Without an Admin key the connection works when every project key
		// can list its project's agents.
		info.OK = projectChecks > 0 && projectChecksOK == projectChecks
	}
	c.logger.Info("Shadow agent discovery OpenAI connection test finished",
		"connectionId", conn.ID.String(), "ok", info.OK, "checks", len(info.Checks))
	return info
}
