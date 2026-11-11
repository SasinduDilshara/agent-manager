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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Connection test check names.
const (
	checkSettings   = "Connection settings"
	checkToken      = "Service account key"
	checkEngines    = "Agent Runtime engines (reasoningEngines.list)"
	checkAgents     = "Agent Registry agents (ListAgents)"
	checkMCPServers = "Agent Registry MCP servers (ListMcpServers)"
	checkMetrics    = "Cloud Monitoring (reasoning_engine/request_count)"
	checkAuditLogs  = "Admin Activity audit logs (entries.list)"
)

type probe struct {
	name    string
	unlocks []string
	run     func(ctx context.Context) error
}

// Test implements sa.Connector: one cheap read per capability in the first
// configured project. The connection is OK when Agent Runtime engines can
// be listed; the other checks say which signals a scan would miss.
func (c *Connector) Test(ctx context.Context, conn sa.Connection) models.ShadowConnectionTestInfo {
	st, problems := readSettings(conn)
	if len(st.projects) == 0 || len(st.runtimeLocations) == 0 {
		return models.ShadowConnectionTestInfo{OK: false, Checks: []models.ShadowConnectionCheck{{
			Name: checkSettings, Outcome: models.ShadowCallFailed, Message: sa.ScrubText(strings.Join(problems, "; ")),
		}}}
	}
	api, err := c.newAPI(ctx, conn)
	if err != nil {
		return models.ShadowConnectionTestInfo{OK: false, Checks: []models.ShadowConnectionCheck{{
			Name: checkToken, Outcome: sa.OutcomeOf(err), Message: sa.MessageOf(err),
			Unlocks: []string{sa.SigGoogleAgentEngine, sa.SigGoogleRegistryAgent, sa.SigGoogleEngineInUse, sa.SigGoogleRegistryMCP, sa.SigGoogleEngineCreatedBy},
		}}}
	}
	project := st.projects[0]
	runtimeLoc := st.runtimeLocations[0]
	registryLoc := runtimeLoc
	mcpLoc := runtimeLoc
	if conn.Config.IncludeGlobalAndMultiRegion {
		mcpLoc = globalLocation
	}
	one := url.Values{"pageSize": {"1"}}
	now := time.Now().UTC()

	probes := []probe{
		{checkEngines, []string{sa.SigGoogleAgentEngine}, func(ctx context.Context) error {
			base, err := runtimeBase(conn, runtimeLoc)
			if err != nil {
				return &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()}
			}
			u := base + "/v1/projects/" + url.PathEscape(project) + "/locations/" + url.PathEscape(runtimeLoc) + "/reasoningEngines"
			return api.GetJSON(ctx, u, one, &listEnginesResponse{})
		}},
		{checkAgents, []string{sa.SigGoogleRegistryAgent}, func(ctx context.Context) error {
			u, err := registryURL(conn, project, registryLoc, "agents")
			if err != nil {
				return &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()}
			}
			return api.GetJSON(ctx, u, one, &listAgentsResponse{})
		}},
		{checkMCPServers, []string{sa.SigGoogleRegistryMCP}, func(ctx context.Context) error {
			u, err := registryURL(conn, project, mcpLoc, "mcpServers")
			if err != nil {
				return &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()}
			}
			return api.GetJSON(ctx, u, one, &listMCPServersResponse{})
		}},
		{checkMetrics, []string{sa.SigGoogleEngineInUse}, func(ctx context.Context) error {
			base, err := baseURL(conn, sa.EPGoogleMonitoring)
			if err != nil {
				return &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()}
			}
			q := url.Values{
				"filter":             {`metric.type="` + requestCountMetric + `"`},
				"interval.startTime": {now.Add(-time.Hour).Format(time.RFC3339)},
				"interval.endTime":   {now.Format(time.RFC3339)},
				"view":               {"HEADERS"},
				"pageSize":           {"1"},
			}
			return api.GetJSON(ctx, base+"/v3/projects/"+url.PathEscape(project)+"/timeSeries", q, &listTimeSeriesResponse{})
		}},
		{checkAuditLogs, []string{sa.SigGoogleEngineCreatedBy}, func(ctx context.Context) error {
			base, err := baseURL(conn, sa.EPGoogleLogging)
			if err != nil {
				return &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()}
			}
			body := listLogEntriesRequest{
				ResourceNames: []string{"projects/" + project},
				Filter:        auditFilter(project, now.Add(-24*time.Hour), now),
				OrderBy:       "timestamp desc",
				PageSize:      1,
			}
			return api.DoJSON(ctx, sa.Request{Method: http.MethodPost, URL: base + "/v2/entries:list", Body: body}, &listLogEntriesResponse{})
		}},
	}

	info := models.ShadowConnectionTestInfo{}
	authFailed := false
	for _, p := range probes {
		check := models.ShadowConnectionCheck{Name: p.name, Unlocks: p.unlocks}
		if opt := checkService[p.name]; opt != "" && !sa.ServiceEnabled(conn.Config, opt) {
			check.Outcome, check.Message = models.ShadowCallSkipped, sa.ReasonServiceOff
			info.Checks = append(info.Checks, check)
			continue
		}
		if authFailed {
			check.Outcome, check.Message = models.ShadowCallSkipped, "not called: authentication failed"
			info.Checks = append(info.Checks, check)
			continue
		}
		err := p.run(ctx)
		check.Outcome, check.Message = sa.OutcomeOf(err), sa.MessageOf(err)
		if check.Outcome == models.ShadowCallAuthFailed {
			authFailed = true
		}
		info.Checks = append(info.Checks, check)
	}
	info.OK = info.Checks[0].Outcome == models.ShadowCallOK
	return info
}

// checkService is the optional service each check belongs to; the engines
// check always runs.
var checkService = map[string]string{
	checkAgents: sa.OptGoogleRegistry, checkMCPServers: sa.OptGoogleRegistry,
	checkMetrics: sa.OptGoogleMonitoring, checkAuditLogs: sa.OptGoogleAuditLogs,
}
