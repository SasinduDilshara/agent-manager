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

package anthropic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Test implements sa.Connector: one cheap read (limit=1) per capability.
// The connection is OK when the Admin API key can list API keys or, without
// an Admin key, when every workspace key can list its Managed Agents.
func (c *Connector) Test(ctx context.Context, conn sa.Connection) models.ShadowConnectionTestInfo {
	s := c.newScan(conn, sa.Window{})
	var checks []models.ShadowConnectionCheck
	ok := false

	p, err := s.firstPartyPlatform()
	switch {
	case err != nil:
		checks = append(checks, failedCheck("Admin API key: list API keys", err, nil))
	case strings.TrimSpace(conn.Secret.APIKey) == "":
		for _, name := range []string{"Admin API key: list API keys", "Usage analytics", "Cost analytics"} {
			checks = append(checks, models.ShadowConnectionCheck{
				Name: name, Outcome: models.ShadowCallSkipped, Message: reasonNeedsAdminKey,
			})
		}
	default:
		keys := s.probe(ctx, p.orgAPI, "Admin API key: list API keys", p.orgURL("/v1/organizations/api_keys"),
			url.Values{"limit": {"1"}}, nil, []string{"API key inventory", "Owner hints"})
		checks = append(checks, keys)
		ok = keys.Outcome == models.ShadowCallOK
		if keys.Outcome == models.ShadowCallAuthFailed {
			break
		}
		checks = append(checks, s.analyticsProbes(ctx, p, "")...)
	}
	wsChecks, wsChecksOK := 0, 0
	if p != nil {
		for _, ws := range sortedKeys(conn.Secret.ScopedKeys) {
			if api, has := p.wsAPI(ws); has {
				probes := s.workspaceProbes(ctx, p, api, ws, "Workspace "+ws+": ")
				wsChecks++
				if len(probes) > 0 && probes[0].Outcome == models.ShadowCallOK {
					wsChecksOK++
				}
				checks = append(checks, probes...)
			}
		}
	}
	if strings.TrimSpace(conn.Secret.APIKey) == "" && err == nil {
		ok = wsChecks > 0 && wsChecksOK == wsChecks
	}
	if conn.Config.IncludeCloudVariants {
		checks = append(checks, s.awsProbes(ctx)...)
		checks = append(checks, s.gcpProbes(ctx)...)
	}
	return models.ShadowConnectionTestInfo{OK: ok, Checks: checks}
}

// analyticsProbes checks the usage and cost analytics over the last full day.
func (s *scan) analyticsProbes(ctx context.Context, p *platform, label string) []models.ShadowConnectionCheck {
	day := sa.DayOf(s.now)
	spans, _, _ := analyticsSpans(sa.Window{Start: day.AddDate(0, 0, -1), End: s.now}, s.now)
	if len(spans) == 0 {
		return nil
	}
	hdr := http.Header{headerBeta: {betaAnalytics}}
	q := analyticsQuery(spans[0], []string{p.analyticsGroupBy[0]})
	q.Set("limit", "1")
	usage := s.probe(ctx, p.orgAPI, label+"Usage analytics", p.orgURL("/v1/organizations/analytics/usage"), q, hdr,
		signalNames(sa.SigAnthropicPlainUsage, sa.SigAnthropicManagedAgentUsage, sa.SigAnthropicServerWebSearch))
	if usage.Outcome == models.ShadowCallAuthFailed {
		return []models.ShadowConnectionCheck{usage}
	}
	cq := analyticsQuery(spans[0], []string{"cost_type"})
	cq.Set("limit", "1")
	cost := s.probe(ctx, p.orgAPI, label+"Cost analytics", p.orgURL("/v1/organizations/analytics/cost"), cq, hdr,
		signalNames(sa.SigAnthropicServerCodeExec))
	return []models.ShadowConnectionCheck{usage, cost}
}

// workspaceProbes checks the Managed Agents and (with deep inspection) the
// message batches of one workspace.
func (s *scan) workspaceProbes(ctx context.Context, p *platform, api *sa.API, ws, label string) []models.ShadowConnectionCheck {
	unlocks := signalNames(sa.SigAnthropicManagedAgent)
	if s.conn.Config.DeepInspection {
		unlocks = append(unlocks, signalNames(sa.SigAnthropicSessionToolUse)...)
	}
	agents := s.probe(ctx, api, label+"Managed Agents", p.wsURL(ws, "/v1/agents"), url.Values{"limit": {"1"}},
		p.wsHeaders(ws, betaManagedAgents), unlocks)
	out := []models.ShadowConnectionCheck{agents}
	batchName := label + "Message batches"
	batchUnlocks := signalNames(sa.SigAnthropicToolCallBatch)
	switch {
	case !s.conn.Config.DeepInspection:
		out = append(out, models.ShadowConnectionCheck{Name: batchName, Outcome: models.ShadowCallSkipped, Message: "deep inspection is off", Unlocks: batchUnlocks})
	case agents.Outcome == models.ShadowCallAuthFailed:
		out = append(out, models.ShadowConnectionCheck{Name: batchName, Outcome: models.ShadowCallSkipped, Message: "not called: the credential was rejected", Unlocks: batchUnlocks})
	default:
		out = append(out, s.probe(ctx, api, batchName, p.wsURL(ws, "/v1/messages/batches"), url.Values{"limit": {"1"}},
			p.wsHeaders(ws, ""), batchUnlocks))
	}
	return out
}

func (s *scan) awsProbes(ctx context.Context) []models.ShadowConnectionCheck {
	cfg := s.conn.Config
	regions := cleanList(cfg.Regions)
	if len(regions) == 0 || strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(s.conn.Secret.SecretAccessKey) == "" {
		return []models.ShadowConnectionCheck{{Name: "Claude Platform on AWS", Outcome: models.ShadowCallSkipped, Message: "not configured"}}
	}
	configured := cleanList(cfg.AWSWorkspaceIDs)
	var out []models.ShadowConnectionCheck
	for _, region := range regions {
		label := "Claude Platform on AWS (" + region + "): "
		p, err := s.awsPlatform(region)
		if err != nil {
			out = append(out, failedCheck(label+"workspaces", err, nil))
			continue
		}
		if len(configured) == 0 {
			wsCheck := s.probe(ctx, p.orgAPI, label+"List workspaces", p.orgURL("/v1/organizations/workspaces"),
				url.Values{"limit": {"1"}}, nil, signalNames(sa.SigAnthropicManagedAgent))
			out = append(out, wsCheck)
			if wsCheck.Outcome == models.ShadowCallAuthFailed {
				continue
			}
		}
		out = append(out, s.analyticsProbes(ctx, p, label)...)
		if len(configured) > 0 {
			out = append(out, s.workspaceProbes(ctx, p, p.orgAPI, configured[0], label+"Workspace "+configured[0]+": ")...)
		}
	}
	return out
}

func (s *scan) gcpProbes(ctx context.Context) []models.ShadowConnectionCheck {
	cfg := s.conn.Config
	project := strings.TrimSpace(cfg.GCPProjectID)
	if project == "" || strings.TrimSpace(s.conn.Secret.ServiceAccountJSON) == "" {
		return []models.ShadowConnectionCheck{{Name: "Claude Models on Google Cloud", Outcome: models.ShadowCallSkipped, Message: "not configured"}}
	}
	label := "Claude Models on Google Cloud (" + project + "): "
	p, err := s.gcpPlatform(ctx, project)
	if err != nil {
		return []models.ShadowConnectionCheck{failedCheck(label+"Usage analytics", err, nil)}
	}
	out := s.analyticsProbes(ctx, p, label)
	for _, ws := range cleanList(cfg.GCPWorkspaceIDs) {
		out = append(out, s.workspaceProbes(ctx, p, p.orgAPI, ws, label+"Workspace "+ws+": ")...)
	}
	return out
}

// probe makes one GET and checks the response has a data list.
func (s *scan) probe(ctx context.Context, api *sa.API, name, u string, q url.Values, h http.Header, unlocks []string) models.ShadowConnectionCheck {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var env struct {
		Data *json.RawMessage `json:"data"`
	}
	err := api.DoJSON(ctx, sa.Request{Method: http.MethodGet, URL: u, Query: q, Header: h}, &env)
	if err == nil && env.Data == nil {
		err = errNoData()
	}
	return models.ShadowConnectionCheck{Name: name, Outcome: sa.OutcomeOf(err), Message: sa.MessageOf(err), Unlocks: unlocks}
}

func failedCheck(name string, err error, unlocks []string) models.ShadowConnectionCheck {
	return models.ShadowConnectionCheck{Name: name, Outcome: sa.OutcomeOf(err), Message: sa.MessageOf(err), Unlocks: unlocks}
}

// signalNames returns the catalog names of signal codes.
func signalNames(codes ...string) []string {
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		if d, ok := sa.Def(c); ok {
			out = append(out, d.Name)
		}
	}
	return out
}
