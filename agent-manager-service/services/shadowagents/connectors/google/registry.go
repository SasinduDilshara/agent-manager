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
	"net/url"
	"strconv"
	"strings"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// System attribute keys of an Agent Registry Agent (Struct values).
const (
	attrFramework        = "agentregistry.googleapis.com/system/Framework"
	attrRuntimeIdentity  = "agentregistry.googleapis.com/system/RuntimeIdentity"
	attrRuntimeReference = "agentregistry.googleapis.com/system/RuntimeReference"
)

// listAgentsResponse is the v1 ListAgentsResponse.
type listAgentsResponse struct {
	Agents        []registryAgent `json:"agents"`
	NextPageToken string          `json:"nextPageToken"`
}

// registryAgent holds the fields of the v1 Agent the connector keeps. The
// Agent Card content, skill descriptions and examples are not declared, so
// they are never decoded.
type registryAgent struct {
	Name        string `json:"name"`
	AgentID     string `json:"agentId"`
	Location    string `json:"location"`
	DisplayName string `json:"displayName"`
	Version     string `json:"version"`
	CreateTime  string `json:"createTime"`
	Protocols   []struct {
		Type string `json:"type"`
	} `json:"protocols"`
	Skills []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"skills"`
	Attributes map[string]json.RawMessage `json:"attributes"`
}

// listMCPServersResponse is the v1 ListMcpServersResponse.
type listMCPServersResponse struct {
	MCPServers    []mcpServer `json:"mcpServers"`
	NextPageToken string      `json:"nextPageToken"`
}

// mcpServer holds the fields of the v1 McpServer the connector keeps; tools
// (descriptions, annotations) are not declared.
type mcpServer struct {
	Name        string `json:"name"`
	MCPServerID string `json:"mcpServerId"`
	DisplayName string `json:"displayName"`
	CreateTime  string `json:"createTime"`
	Interfaces  []struct {
		URL string `json:"url"`
	} `json:"interfaces"`
}

// attrString reads one string field of a Struct attribute, leniently: a
// missing key or another shape gives "".
func attrString(attrs map[string]json.RawMessage, key, field string) string {
	raw, ok := attrs[key]
	if !ok {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	v, _ := m[field].(string)
	return strings.TrimSpace(v)
}

func registryURL(conn sa.Connection, project, location, collection string) (string, error) {
	base, err := baseURL(conn, sa.EPGoogleRegistry)
	if err != nil {
		return "", err
	}
	return base + "/v1/projects/" + url.PathEscape(project) + "/locations/" + url.PathEscape(location) + "/" + collection, nil
}

// listAgents lists the Agent Registry agents of one project and location.
func (s *scanner) listAgents(ctx context.Context, project, location string) {
	if !s.proceed(ctx, callAgents) {
		return
	}
	u, err := registryURL(s.conn, project, location, "agents")
	if err != nil {
		s.record(callAgents, 0, &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()})
		return
	}
	s.paginate(ctx, callAgents, maxRegistryPages, func(token string) (string, int, error) {
		q := url.Values{"pageSize": {strconv.Itoa(registryPageSize)}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var resp listAgentsResponse
		if err := s.api.GetJSON(ctx, u, q, &resp); err != nil {
			return "", 0, err
		}
		for i := range resp.Agents {
			s.addRegistryAgent(project, location, &resp.Agents[i])
		}
		return resp.NextPageToken, len(resp.Agents), nil
	})
}

// addRegistryAgent merges an agent into the engine it runs on, or records
// it as a platform agent. Google's built-in agents are left out.
func (s *scanner) addRegistryAgent(project, location string, a *registryAgent) {
	if strings.HasPrefix(a.AgentID, builtinAgentPrefix) {
		return
	}
	if m := projectSegRE.FindStringSubmatch(a.Name); m != nil {
		s.addAlias(project, m[1])
	}
	runtimeURI := attrString(a.Attributes, attrRuntimeReference, "uri")
	principal := attrString(a.Attributes, attrRuntimeIdentity, "principal")
	framework := attrString(a.Attributes, attrFramework, "framework")

	ref, ok := parseEngineRef(runtimeURI)
	if !ok {
		ref, ok = parseEngineURN(a.AgentID)
	}
	if !ok {
		ref, ok = parseEngineRef(principal)
	}
	reference := runtimeURI
	if reference == "" && ok {
		reference = "projects/" + ref.project + "/locations/" + ref.location + "/reasoningEngines/" + ref.id
	}

	protocols := make([]string, 0, len(a.Protocols))
	for _, p := range a.Protocols {
		if p.Type != "" {
			protocols = append(protocols, p.Type)
		}
	}
	skills := make([]string, 0, len(a.Skills))
	for _, sk := range a.Skills {
		name := sk.Name
		if name == "" {
			name = sk.ID
		}
		if name != "" {
			skills = append(skills, name)
		}
	}
	signal := sa.Signal{Code: sa.SigGoogleRegistryAgent, Source: callAgents, Observed: map[string]any{"a2a": hasA2A(protocols)}}

	if ok {
		if e := s.findEngine(ref); e != nil {
			f := e.finding
			f.AddSignal(signal)
			f.Attributes["runtimeReference"] = reference
			setIfAbsent(f.Attributes, "framework", framework)
			setIfAbsent(f.Attributes, "serviceAccount", principal)
			if len(skills) > 0 {
				if _, has := f.Attributes["skills"]; !has {
					f.Attributes["skills"] = skills
				}
			}
			if len(protocols) > 0 {
				if _, has := f.Attributes["protocolType"]; !has {
					f.Attributes["protocolType"] = protocols
				}
			}
			return
		}
	}

	id := a.AgentID
	if id == "" {
		id = a.Name
	}
	if id == "" {
		return
	}
	loc := strings.ToLower(a.Location)
	if loc == "" {
		loc = location
	}
	f := s.findings.Get(models.ShadowKindPlatformAgent, id)
	f.DisplayName = sa.SanitizeName(a.DisplayName)
	if f.DisplayName == "" {
		f.DisplayName = lastSegment(a.Name)
	}
	f.Scope = scopeOf(project, location)
	f.Attributes["project"] = project
	f.Attributes["location"] = loc
	setIfAbsent(f.Attributes, "framework", framework)
	setIfAbsent(f.Attributes, "serviceAccount", principal)
	setIfAbsent(f.Attributes, "agentVersion", a.Version)
	setIfAbsent(f.Attributes, "runtimeReference", reference)
	if len(protocols) > 0 {
		f.Attributes["protocolType"] = protocols
	}
	if len(skills) > 0 {
		f.Attributes["skills"] = skills
	}
	if f.ProviderCreatedAt == nil {
		f.ProviderCreatedAt = parseTime(a.CreateTime)
	}
	f.AddSignal(signal)
}

func hasA2A(protocols []string) bool {
	for _, p := range protocols {
		if p == "A2A_AGENT" {
			return true
		}
	}
	return false
}

func setIfAbsent(attrs map[string]any, key, value string) {
	if value == "" {
		return
	}
	if _, ok := attrs[key]; !ok {
		attrs[key] = value
	}
}

// listMCPServers lists the Agent Registry MCP servers of one project and
// location. Google remote MCP servers exist only in the global location.
func (s *scanner) listMCPServers(ctx context.Context, project, location string) {
	if !s.proceed(ctx, callMCPServers) {
		return
	}
	u, err := registryURL(s.conn, project, location, "mcpServers")
	if err != nil {
		s.record(callMCPServers, 0, &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()})
		return
	}
	s.paginate(ctx, callMCPServers, maxRegistryPages, func(token string) (string, int, error) {
		q := url.Values{"pageSize": {strconv.Itoa(registryPageSize)}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var resp listMCPServersResponse
		if err := s.api.GetJSON(ctx, u, q, &resp); err != nil {
			return "", 0, err
		}
		for i := range resp.MCPServers {
			s.addMCPServer(project, location, &resp.MCPServers[i])
		}
		return resp.NextPageToken, len(resp.MCPServers), nil
	})
}

// addMCPServer records an MCP server as tool infrastructure: its label and
// the origin of its URL only.
func (s *scanner) addMCPServer(project, location string, m *mcpServer) {
	if m.Name != "" {
		if seg := projectSegRE.FindStringSubmatch(m.Name); seg != nil {
			s.addAlias(project, seg[1])
		}
	}
	id := m.MCPServerID
	if id == "" {
		id = m.Name
	}
	if id == "" {
		return
	}
	label := sa.SanitizeName(m.DisplayName)
	if label == "" {
		label = lastSegment(m.Name)
	}
	origin := ""
	for _, i := range m.Interfaces {
		if origin = sa.Origin(i.URL); origin != "" {
			break
		}
	}
	f := s.findings.Get(models.ShadowKindToolInfra, id)
	f.DisplayName = label
	f.Scope = scopeOf(project, location)
	f.Attributes["project"] = project
	f.Attributes["location"] = location
	f.Attributes["mcpServers"] = []sa.MCPServerRef{{Label: label, Origin: origin}}
	if f.ProviderCreatedAt == nil {
		f.ProviderCreatedAt = parseTime(m.CreateTime)
	}
	f.AddSignal(sa.Signal{Code: sa.SigGoogleRegistryMCP, Source: callMCPServers, Observed: map[string]any{}})
}
