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
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// listAgents lists the agents of every project that has a project key
// (the Admin key cannot call /v1/agents), and their recent sessions.
func (s *scan) listAgents(ctx context.Context) {
	ids := s.scopedProjects()
	s.noteProjectsWithoutKey(ids)
	if len(ids) == 0 {
		s.calls.Skip(callAgents, reasonNoProjectKey)
		s.calls.Skip(callSessions, reasonNoProjectKey)
		return
	}
	sessionsRead := false
	for _, pid := range ids {
		if ctx.Err() != nil {
			break
		}
		api := s.projectAPI(pid)
		var got []agent
		truncated, err := listAll(ctx, api, s.base+"/agents", url.Values{"order": []string{"desc"}}, betaAgentsHeader(),
			listPageSize, maxListPages, func(a agent) bool {
				got = append(got, a)
				return true
			})
		// A 400/404 here usually means the beta contract changed; it is
		// recorded and the scan goes on.
		s.calls.Record(callAgents, len(got), err)
		if truncated {
			s.pageLimit(callAgents, maxListPages)
		}
		for _, a := range got {
			s.addAgent(pid, a)
		}
		if err == nil && !truncated {
			s.agentsComplete[pid] = true
		}
		if len(s.agents[pid]) > 0 {
			s.listSessions(ctx, api, pid)
			sessionsRead = true
		}
	}
	if !sessionsRead {
		s.calls.Skip(callSessions, "no agents")
	}
}

// noteProjectsWithoutKey reports the active projects that have no project
// key, for which agents, stored completions and batches are not read.
func (s *scan) noteProjectsWithoutKey(withKey []string) {
	has := map[string]bool{}
	for _, id := range withKey {
		has[id] = true
	}
	missing, active := 0, 0
	for _, p := range s.projects {
		if p.archived() {
			continue
		}
		active++
		if !has[p.ID] {
			missing++
		}
	}
	if missing > 0 {
		s.calls.Skip(callProjectKeysMiss, fmt.Sprintf(
			"%d of %s have no project key: their agents, stored chat completions and batches are not read",
			missing, plural(active, "active project", "active projects")))
	}
}

func (s *scan) addAgent(projectID string, a agent) {
	if a.ID == "" {
		return
	}
	if _, dup := s.fs.Lookup(models.ShadowKindPlatformAgent, a.ID); dup {
		return
	}
	f := s.fs.Get(models.ShadowKindPlatformAgent, a.ID)
	f.DisplayName = a.Name
	if strings.TrimSpace(f.DisplayName) == "" {
		f.DisplayName = a.ID
	}
	f.Scope = projectID
	f.State = stateActive
	if s.projectArchived(projectID) {
		f.State = stateArchived
		f.Attributes["archived"] = true
	}
	f.ProviderCreatedAt = unixTime(a.CreatedAt)
	tools, mcp := toolRefs(a.Tools)
	f.Attributes["model"] = a.Model
	f.Attributes["project"] = s.projectLabel(projectID)
	f.Attributes["toolCount"] = int64(len(a.Tools))
	if len(tools) > 0 {
		f.Attributes["tools"] = tools
	}
	if len(mcp) > 0 {
		f.Attributes["mcpServers"] = mcp
	}
	f.AddSignal(sa.Signal{
		Code: sa.SigOpenAIAgentObject, Source: callAgents,
		Observed: map[string]any{"toolCount": int64(len(a.Tools)), "mcpServerCount": int64(len(mcp))},
	})
	s.agents[projectID] = append(s.agents[projectID], a.ID)
}

// toolRefs keeps each tool's type and name (an MCP tool's server label) and
// each MCP server's label and URL origin. Nothing else of a tool is kept.
func toolRefs(tools []agentTool) ([]sa.ToolRef, []sa.MCPServerRef) {
	refs := make([]sa.ToolRef, 0, len(tools))
	var mcp []sa.MCPServerRef
	for _, t := range tools {
		if t.Type == "" {
			continue
		}
		name := t.Name
		if t.Type == "mcp" {
			name = t.ServerLabel
			mcp = append(mcp, sa.MCPServerRef{Label: t.ServerLabel, Origin: mcpOrigin(t)})
		}
		refs = append(refs, sa.ToolRef{Type: t.Type, Name: name})
	}
	return refs, mcp
}

// mcpOrigin finds the scheme and host of an MCP tool's server. The
// persisted agent tool documents server_label, transport and
// connection_origin but not their inner shape, so the URL is looked for,
// leniently, in server_url, transport.url / transport.server_url and a
// URL-valued connection_origin. Only sa.Origin of it is kept.
func mcpOrigin(t agentTool) string {
	if o := sa.Origin(t.ServerURL); o != "" {
		return o
	}
	var tr struct {
		URL       string `json:"url"`
		ServerURL string `json:"server_url"`
	}
	if len(t.Transport) > 0 && json.Unmarshal(t.Transport, &tr) == nil {
		if o := sa.Origin(tr.ServerURL); o != "" {
			return o
		}
		if o := sa.Origin(tr.URL); o != "" {
			return o
		}
	}
	var origin string
	if len(t.ConnectionOrigin) > 0 && json.Unmarshal(t.ConnectionOrigin, &origin) == nil {
		if strings.HasPrefix(origin, "https://") || strings.HasPrefix(origin, "http://") {
			return sa.Origin(origin)
		}
	}
	return ""
}

// listSessions reads the most recent sessions of a project (bounded) and
// records, per agent, how many were active in the window and when the last
// one was active. Session content (instructions snapshot, errors, required
// actions) is not decoded.
func (s *scan) listSessions(ctx context.Context, api *sa.API, projectID string) {
	type activity struct {
		count int64
		last  int64
	}
	byAgent := map[string]*activity{}
	n := 0
	_, err := listAll(ctx, api, s.base+"/agents/sessions", url.Values{"order": []string{"desc"}}, betaAgentsHeader(),
		sessionsPageSize, maxSessionsPerProject/sessionsPageSize, func(ss agentSession) bool {
			n++
			if ss.Agent != nil && ss.Agent.ID != "" {
				a := byAgent[ss.Agent.ID]
				if a == nil {
					a = &activity{}
					byAgent[ss.Agent.ID] = a
				}
				if ss.LastActiveAt >= s.w.Start.Unix() {
					a.count++
				}
				if ss.LastActiveAt > a.last {
					a.last = ss.LastActiveAt
				}
			}
			return n < maxSessionsPerProject
		})
	s.calls.Record(callSessions, n, err)
	for _, id := range sortedKeys(byAgent) {
		f, ok := s.fs.Lookup(models.ShadowKindPlatformAgent, id)
		if !ok {
			continue
		}
		a := byAgent[id]
		f.Attributes["sessionCount"] = a.count
		if t := unixTime(a.last); t != nil {
			f.Attributes["lastSessionAt"] = t.Format(time.RFC3339)
			if !t.Before(s.w.Start) {
				f.ObserveUse(*t)
			}
		}
	}
}
