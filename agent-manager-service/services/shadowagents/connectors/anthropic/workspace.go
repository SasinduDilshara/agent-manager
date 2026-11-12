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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Session event types that are tool use (anthropic.md §2.2b).
var toolUseEventTypes = []string{"agent.tool_use", "agent.custom_tool_use", "agent.mcp_tool_use"}

// workspaces runs the workspace routes (Managed Agents, sessions, session
// events, message batches) for each workspace. noneReason is recorded when
// there is no workspace to scan.
func (s *scan) workspaces(ctx context.Context, p *platform, ids []string, noneReason string) {
	if len(ids) == 0 {
		for _, call := range []string{callAgents, callSessions, callEvents, callBatches, callBatchResults} {
			s.calls.Skip(p.call(call), noneReason)
		}
		return
	}
	if !s.conn.Config.DeepInspection {
		for _, call := range []string{callEvents, callBatches, callBatchResults} {
			s.calls.Skip(p.call(call), "deep inspection is off")
		}
	}
	for _, ws := range ids {
		if ctx.Err() != nil {
			return
		}
		api, ok := p.wsAPI(ws)
		if !ok {
			continue
		}
		s.workspace(ctx, p, api, ws)
	}
	// A call never made because there was nothing to read is still listed.
	s.calls.Skip(p.call(callAgents), noneReason)
	s.calls.Skip(p.call(callSessions), "no Managed Agents to read sessions of")
	if s.conn.Config.DeepInspection {
		s.calls.Skip(p.call(callBatches), noneReason)
		s.calls.Skip(p.call(callEvents), "no sessions to read events of")
		s.calls.Skip(p.call(callBatchResults), "no ended batch with results in the window")
	}
}

// sessionRef is a session whose events deep inspection may read.
type sessionRef struct {
	id    string
	agent *sa.Finding
}

func (s *scan) workspace(ctx context.Context, p *platform, api *sa.API, ws string) {
	agents, err := s.listAgents(ctx, p, api, ws)
	if sa.OutcomeOf(err) == models.ShadowCallAuthFailed {
		// The workspace credential is rejected: the other routes would be
		// too. Record that for them rather than calling them.
		s.calls.Record(p.call(callSessions), 0, err)
		if s.conn.Config.DeepInspection {
			s.calls.Record(p.call(callEvents), 0, err)
			s.calls.Record(p.call(callBatches), 0, err)
		}
		return
	}
	var refs []sessionRef
	for _, a := range agents {
		s.wsAgents[p.wsScope(ws)] = append(s.wsAgents[p.wsScope(ws)], a.ExternalID)
		ids := s.listSessions(ctx, p, api, ws, a)
		for i, id := range ids {
			if i == maxEventSessionsPerAgent || len(refs) == maxEventSessionsPerWorkspace {
				break
			}
			refs = append(refs, sessionRef{id: id, agent: a})
		}
	}
	if !s.conn.Config.DeepInspection {
		return
	}
	for _, r := range refs {
		s.sessionEvents(ctx, p, api, ws, r)
	}
	s.batches(ctx, p, api, ws)
}

// listAgents lists the workspace's Managed Agents, archived ones included,
// and makes each a platform_agent finding (anthropic.md §2.1). The system
// prompt and the custom tools' schemas are never decoded.
func (s *scan) listAgents(ctx context.Context, p *platform, api *sa.API, ws string) ([]*sa.Finding, error) {
	var out []*sa.Finding
	q := url.Values{"include_archived": {"true"}, "limit": {"100"}}
	call := p.call(callAgents)
	n, _, err := listByCursor(ctx, api, p.wsURL(ws, "/v1/agents"), q, p.wsHeaders(ws, betaManagedAgents), maxAgentPages, nil,
		func(items []agent) bool {
			for i := range items {
				if f := s.addAgent(p, ws, &items[i], call); f != nil {
					out = append(out, f)
				}
			}
			return true
		})
	s.calls.Record(call, n, err)
	return out, err
}

func (s *scan) addAgent(p *platform, ws string, a *agent, source string) *sa.Finding {
	if a.ID == "" {
		return nil
	}
	f := s.agentFinding(p, a.ID)
	f.DisplayName = a.Name
	if f.DisplayName == "" {
		f.DisplayName = a.ID
	}
	f.Scope = p.wsScope(ws)
	archived := a.ArchivedAt != nil && *a.ArchivedAt != ""
	f.State = "active"
	if archived {
		f.State = "archived"
	}
	if t, ok := parseTime(a.CreatedAt); ok {
		f.ProviderCreatedAt = &t
	}
	attrs := f.Attributes
	attrs["workspace"] = ws
	attrs["archived"] = archived
	attrs["state"] = f.State
	if a.Version > 0 {
		attrs["agentVersion"] = a.Version
	}
	if a.Model != nil && a.Model.ID != "" {
		attrs["model"] = a.Model.ID
	}
	if d := deref(a.Description); d != "" {
		attrs["description"] = d
	}
	if a.ExecutionIdentity != nil && a.ExecutionIdentity.Type == "aws_role" && a.ExecutionIdentity.RoleARN != "" {
		attrs["roleArn"] = a.ExecutionIdentity.RoleARN
	}
	var tools []sa.ToolRef
	for _, t := range a.Tools {
		switch t.Type {
		case "mcp_toolset":
			tools = append(tools, sa.ToolRef{Type: t.Type, Name: t.MCPServerName})
		case "custom":
			tools = append(tools, sa.ToolRef{Type: t.Type, Name: t.Name})
		default: // agent_toolset_20260401 and future toolsets
			named := false
			for _, c := range t.Configs {
				if c.Enabled != nil && !*c.Enabled {
					continue
				}
				name := c.Name
				if name == "" {
					name = c.Type
				}
				tools = append(tools, sa.ToolRef{Type: t.Type, Name: name})
				named = true
			}
			if !named {
				tools = append(tools, sa.ToolRef{Type: t.Type})
			}
		}
	}
	if len(tools) > 0 {
		attrs["tools"] = tools
	}
	attrs["toolCount"] = len(a.Tools)
	var mcp []sa.MCPServerRef
	for _, m := range a.MCPServers {
		mcp = append(mcp, sa.MCPServerRef{Label: m.Name, Origin: sa.Origin(m.URL)})
	}
	if len(mcp) > 0 {
		attrs["mcpServers"] = mcp
	}
	var skills []string
	for _, sk := range a.Skills {
		if sk.SkillID != "" {
			skills = append(skills, sk.SkillID)
		}
	}
	if len(skills) > 0 {
		attrs["skills"] = skills
	}
	f.AddSignal(sa.Signal{Code: sa.SigAnthropicManagedAgent, Source: source, Observed: map[string]any{"archived": archived}})
	return f
}

// listSessions reads the agent's sessions, newest first and bounded, for
// the last session time, a session count and the GitHub repository the
// sessions mount (anthropic.md §2.2). It returns the session IDs, newest
// first.
func (s *scan) listSessions(ctx context.Context, p *platform, api *sa.API, ws string, a *sa.Finding) []string {
	q := url.Values{"agent_id": {a.ExternalID}, "include_archived": {"true"}, "order": {"desc"}}
	var ids []string
	var last *time.Time
	count := 0
	repo := ""
	n, _, err := listByCursor(ctx, api, p.wsURL(ws, "/v1/sessions"), q, p.wsHeaders(ws, betaManagedAgents), maxSessionPages, nil,
		func(items []session) bool {
			for _, ss := range items {
				if count == maxSessionsPerAgent {
					return false
				}
				count++
				if ss.ID != "" {
					ids = append(ids, ss.ID)
				}
				for _, ts := range []string{ss.CreatedAt, ss.UpdatedAt} {
					t, ok := parseTime(ts)
					if !ok {
						continue
					}
					if last == nil || t.After(*last) {
						t := t
						last = &t
					}
					if s.inWindow(t) {
						a.ObserveUse(t)
					}
				}
				for _, r := range ss.Resources {
					if repo == "" && r.Type == "github_repository" {
						repo = sa.RepositoryURL(r.URL)
					}
				}
			}
			return count < maxSessionsPerAgent
		})
	s.calls.Record(p.call(callSessions), n, err)
	a.Attributes["sessionCount"] = count
	if last != nil {
		a.Attributes["lastSessionAt"] = last.Format(time.RFC3339)
	}
	if repo != "" {
		a.Attributes["repositoryUrl"] = repo
	}
	return ids
}

// sessionEvents reads a session's tool-use events (deep inspection) and
// keeps only how many there were and when (anthropic.md §2.2b). The event
// input is never decoded.
func (s *scan) sessionEvents(ctx context.Context, p *platform, api *sa.API, ws string, r sessionRef) {
	q := url.Values{"types[]": toolUseEventTypes}
	tool := map[string]bool{}
	for _, t := range toolUseEventTypes {
		tool[t] = true
	}
	var uses int64
	read := 0
	n, _, err := listByCursor(ctx, api, p.wsURL(ws, "/v1/sessions/"+url.PathEscape(r.id)+"/events"), q,
		p.wsHeaders(ws, betaManagedAgents), maxEventPages, nil, func(items []event) bool {
			for _, e := range items {
				if read == maxEventsPerSession {
					return false
				}
				read++
				if !tool[e.Type] {
					continue
				}
				uses++
				if t, ok := parseTime(e.ProcessedAt); ok && s.inWindow(t) {
					r.agent.ObserveUse(t)
				}
			}
			return read < maxEventsPerSession
		})
	s.calls.Record(p.call(callEvents), n, err)
	if uses > 0 {
		r.agent.AddSignal(sa.Signal{
			Code: sa.SigAnthropicSessionToolUse, Source: p.call(callEvents),
			Observed: map[string]any{"toolUseEvents": uses, "sessions": 1},
		})
	}
}

// batches reads the results of the workspace's recent ended batches (deep
// inspection, anthropic.md §2.7) and counts the results with tool use.
// Batches belong to a workspace, not a key, so the signal goes to a key
// only when exactly one key that can act in the workspace had usage.
func (s *scan) batches(ctx context.Context, p *platform, api *sa.API, ws string) {
	since := s.now.Add(-batchRetention)
	if s.w.Start.After(since) {
		since = s.w.Start
	}
	var picked []string
	q := url.Values{"limit": {"100"}}
	n, err := listByID(ctx, api, p.wsURL(ws, "/v1/messages/batches"), q, p.wsHeaders(ws, ""), maxBatchListPages,
		func(items []batch) bool {
			for _, b := range items {
				if len(picked) == maxBatchesPerWorkspace {
					return false
				}
				created, ok := parseTime(b.CreatedAt)
				if b.ID == "" || b.ProcessingStatus != "ended" || b.RequestCounts.Succeeded == 0 || !ok || created.Before(since) {
					continue
				}
				picked = append(picked, b.ID)
			}
			return len(picked) < maxBatchesPerWorkspace
		})
	s.calls.Record(p.call(callBatches), n, err)
	if sa.OutcomeOf(err) == models.ShadowCallAuthFailed {
		return
	}
	var withTools, toolResults int64
	for _, id := range picked {
		if ctx.Err() != nil {
			return
		}
		lines, tools, rerr := s.batchResults(ctx, p, api, ws, id)
		s.calls.Record(p.call(callBatchResults), lines, rerr)
		if tools > 0 {
			withTools++
			toolResults += tools
		}
	}
	if withTools == 0 {
		return
	}
	sig := sa.Signal{
		Code: sa.SigAnthropicToolCallBatch, Source: p.call(callBatchResults),
		Observed: map[string]any{"batchesWithToolUse": withTools, "toolUseResults": toolResults},
	}
	hasAdmin := strings.TrimSpace(s.conn.Secret.APIKey) != ""
	candidates := s.keysUsedIn(ws)
	if hasAdmin && len(candidates) == 1 {
		s.keyFinding(p, candidates[0]).AddSignal(sig)
		return
	}
	// Batches belong to the workspace, not to a key: when the key is not
	// known, the evidence goes on the workspace's own finding.
	f := s.workspaceFinding(p, ws)
	f.AddSignal(sig)
	reason := fmt.Sprintf("%d keys that can act in the workspace had usage in the window", len(candidates))
	switch {
	case !hasAdmin:
		reason = "the connection has no Admin API key, so the workspace's keys are not known"
	default:
		for _, id := range candidates {
			f.Related = append(f.Related, sa.Relation{
				ExternalID: id, Kind: models.ShadowKindAPIKey, Relation: "candidate_key",
				Reason: "had usage in the window and can act in this workspace",
			})
		}
	}
	s.calls.Skip(p.call(fmt.Sprintf("tool calls in batch results of workspace %s (on the workspace finding)", ws)), fmt.Sprintf(
		"%d batch results with tool use in %d batches; put on the workspace's finding, not on a key: %s", toolResults, withTools, reason))
}

// workspaceFinding returns the finding of a workspace, creating it, linked
// to the Managed Agents found in the workspace.
func (s *scan) workspaceFinding(p *platform, ws string) *sa.Finding {
	id := p.wsScope(ws)
	if f, ok := s.findings.Lookup(models.ShadowKindProject, id); ok {
		return f
	}
	f := s.findings.Get(models.ShadowKindProject, id)
	f.DisplayName = "Workspace " + ws
	f.Scope = id
	f.State = "active"
	f.Attributes["workspace"] = ws
	for _, agentID := range s.wsAgents[id] {
		f.Related = append(f.Related, sa.Relation{
			ExternalID: agentID, Kind: models.ShadowKindPlatformAgent, Relation: "agent_in_project", Reason: "agent in this workspace",
		})
	}
	return f
}

// batchResults reads one batch's results file in memory, bounded, and
// counts the results with a tool call: result.type == "succeeded" and
// stop_reason == "tool_use" or a content block of type "tool_use". The URL
// is built from the base URL, not taken from results_url (the official SDK
// does the same; anthropic_cloud_variants.md §2.9).
func (s *scan) batchResults(ctx context.Context, p *platform, api *sa.API, ws, id string) (lines int, tools int64, err error) {
	h := p.wsHeaders(ws, "")
	h.Set("Accept", "application/x-jsonl")
	req := sa.Request{Method: http.MethodGet, URL: p.wsURL(ws, "/v1/messages/batches/"+url.PathEscape(id)+"/results"), Header: h}
	malformed := 0
	err = api.EachLine(ctx, req, maxBatchResultBytes, func(line []byte) bool {
		lines++
		var r batchResultLine
		if json.Unmarshal(line, &r) != nil {
			malformed++
			return true
		}
		if batchLineHasToolUse(&r) {
			tools++
		}
		return true
	})
	if err == nil && lines > 0 && malformed == lines {
		err = sa.Unsupported("the batch results file is not JSONL of the documented shape")
	}
	return lines, tools, err
}

func batchLineHasToolUse(r *batchResultLine) bool {
	if r.Result.Type != "succeeded" || r.Result.Message == nil {
		return false
	}
	if r.Result.Message.StopReason == "tool_use" {
		return true
	}
	for _, c := range r.Result.Message.Content {
		if c.Type == "tool_use" {
			return true
		}
	}
	return false
}

// keysUsedIn returns the listed keys that can act in workspace ws (bound to
// it, or organization-scoped) and had requests in the window.
func (s *scan) keysUsedIn(ws string) []string {
	var out []string
	for _, k := range s.keys {
		bound, listed := s.keyWorkspace[k.KeyID]
		if !listed || (bound != "" && bound != ws) {
			continue
		}
		if _, used := s.keyLastUsed[k.KeyID]; used {
			out = append(out, k.KeyID)
		}
	}
	return out
}
