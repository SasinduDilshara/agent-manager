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

package bedrock

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	ac "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	actypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// scanRuntimes lists the region's AgentCore runtimes (evidence §2.1) and
// reads each one (§2.2). It returns the listing error, so the caller can
// stop on an authentication failure.
func (s *scan) scanRuntimes(ctx context.Context, rc *regionClients) error {
	p := ac.NewListAgentRuntimesPaginator(rc.agentCore, &ac.ListAgentRuntimesInput{MaxResults: aws.Int32(pageSize), NextToken: nil})
	var ids []string
	n, err := paginate(ctx, maxPages, p.HasMorePages, func(ctx context.Context) (int, error) {
		out, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, rt := range out.AgentRuntimes {
			// The docs do not say whether the list has one row per runtime or
			// per version; dedupe on the runtime ID (evidence §2.1).
			id := str(rt.AgentRuntimeId)
			if id == "" || s.runtimeByID[rc.region+"|"+id] != nil {
				continue
			}
			f := s.runtimeFromSummary(rc.region, rt)
			if f == nil {
				continue
			}
			ids = append(ids, id)
		}
		return len(out.AgentRuntimes), nil
	})
	s.calls.Record(callListRuntimes, n, err)
	if isAuthFailure(err) {
		return err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		s.getRuntime(ctx, rc, id)
	}
	return err
}

func (s *scan) runtimeFromSummary(region string, rt actypes.AgentRuntime) *sa.Finding {
	arn := str(rt.AgentRuntimeArn)
	if arn == "" {
		return nil
	}
	f := s.fs.Get(models.ShadowKindRuntime, arn)
	f.DisplayName = sa.SanitizeName(str(rt.AgentRuntimeName))
	f.Scope = region
	f.State = string(rt.Status)
	f.Attributes["region"] = region
	f.Attributes["resourceId"] = arn
	f.Attributes["agentVersion"] = str(rt.AgentRuntimeVersion)
	f.Attributes["status"] = string(rt.Status)
	// description is @sensitive in the model (evidence §2.1): never stored.
	if rt.Status == actypes.AgentRuntimeStatusReady {
		f.AddSignal(sa.Signal{Code: sa.SigBedrockAgentCoreRuntime, Source: callListRuntimes, Observed: map[string]any{"ready": true}})
	} else {
		f.AddSignal(sa.Signal{Code: sa.SigBedrockRuntimeNotReady, Source: callListRuntimes, Observed: map[string]any{"status": string(rt.Status)}})
	}
	s.runtimeByARN[arn] = f
	s.runtimeByID[region+"|"+str(rt.AgentRuntimeId)] = f
	s.regionRuntimes[region] = append(s.regionRuntimes[region], f)
	return f
}

// getRuntime adds the execution role, protocol and artifact of a runtime.
// environmentVariables (a @sensitive map), description, authorizer and
// network settings are never read into the finding.
func (s *scan) getRuntime(ctx context.Context, rc *regionClients, id string) {
	out, err := rc.agentCore.GetAgentRuntime(ctx, &ac.GetAgentRuntimeInput{AgentRuntimeId: aws.String(id), AgentRuntimeVersion: nil})
	if err != nil {
		s.calls.Record(callGetRuntime, 0, awsError(err))
		return
	}
	s.calls.Record(callGetRuntime, 1, nil)
	f := s.runtimeByID[rc.region+"|"+id]
	if f == nil {
		return
	}
	if role := str(out.RoleArn); role != "" {
		f.Attributes["roleArn"] = role
		if key := roleKey(role); key != "" {
			s.runtimesByRole[key] = append(s.runtimesByRole[key], f)
		}
	}
	if out.ProtocolConfiguration != nil && out.ProtocolConfiguration.ServerProtocol != "" {
		f.Attributes["serverProtocol"] = string(out.ProtocolConfiguration.ServerProtocol)
		if out.ProtocolConfiguration.ServerProtocol == actypes.ServerProtocolMcp {
			// The design notes a runtime can host an MCP server: that is tool
			// infrastructure agents call, not an agent.
			markMCPServerRuntime(f)
		}
	}
	switch a := out.AgentRuntimeArtifact.(type) {
	case *actypes.AgentRuntimeArtifactMemberContainerConfiguration:
		f.Attributes["agentKind"] = "container"
		f.Attributes["image"] = str(a.Value.ContainerUri)
	case *actypes.AgentRuntimeArtifactMemberCodeConfiguration:
		// Code deployments (S3 bucket, entry point, language runtime) have
		// no allowed attribute beyond the artifact kind.
		f.Attributes["agentKind"] = "code"
	}
	f.ProviderCreatedAt = timePtr(out.CreatedAt)
}

// scanGateways lists the region's AgentCore gateways (evidence §2.3), reads
// each one and lists its targets (§2.4). Gateways are tool infrastructure.
func (s *scan) scanGateways(ctx context.Context, rc *regionClients) {
	p := ac.NewListGatewaysPaginator(rc.agentCore, &ac.ListGatewaysInput{MaxResults: aws.Int32(pageSize), NextToken: nil})
	var gws []actypes.GatewaySummary
	n, err := paginate(ctx, maxPages, p.HasMorePages, func(ctx context.Context) (int, error) {
		out, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		gws = append(gws, out.Items...)
		return len(out.Items), nil
	})
	s.calls.Record(callListGateways, n, err)
	for _, g := range gws {
		if ctx.Err() != nil {
			return
		}
		s.gateway(ctx, rc, g)
	}
}

// gatewayExternalID is stable across scans whether or not GetGateway
// succeeds: ListGateways returns no ARN (evidence §2.3).
func gatewayExternalID(region, gatewayID string) string {
	return "bedrock-agentcore:" + region + ":gateway/" + gatewayID
}

func (s *scan) gateway(ctx context.Context, rc *regionClients, g actypes.GatewaySummary) {
	id := str(g.GatewayId)
	if id == "" || s.gatewayByID[rc.region+"|"+id] != nil {
		return
	}
	f := s.fs.Get(models.ShadowKindToolInfra, gatewayExternalID(rc.region, id))
	s.gatewayByID[rc.region+"|"+id] = f
	f.DisplayName = sa.SanitizeName(str(g.Name))
	f.Scope = rc.region
	f.State = string(g.Status)
	f.ProviderCreatedAt = timePtr(g.CreatedAt)
	f.Attributes["region"] = rc.region
	f.Attributes["status"] = string(g.Status)
	f.Attributes["authorizerType"] = string(g.AuthorizerType)
	protocol := g.ProtocolType

	out, err := rc.agentCore.GetGateway(ctx, &ac.GetGatewayInput{GatewayIdentifier: aws.String(id)})
	if err != nil {
		s.calls.Record(callGetGateway, 0, awsError(err))
	} else {
		s.calls.Record(callGetGateway, 1, nil)
		f.Attributes["resourceId"] = str(out.GatewayArn)
		if u := sa.Origin(str(out.GatewayUrl)); u != "" {
			f.Attributes["endpoint"] = u
		}
		if out.AuthorizerType != "" {
			f.Attributes["authorizerType"] = string(out.AuthorizerType)
		}
		if out.ProtocolType != "" {
			protocol = out.ProtocolType
		}
		if role := str(out.RoleArn); role != "" {
			f.Attributes["roleArn"] = role
		}
	}
	// protocolType is optional with default MCP, and MCP is its only value
	// (evidence §2.3), so an absent value means MCP.
	if protocol == "" {
		protocol = actypes.GatewayProtocolTypeMcp
	}
	f.Attributes["protocolType"] = string(protocol)
	if protocol == actypes.GatewayProtocolTypeMcp {
		source := callGetGateway
		if err != nil {
			source = callListGateways
		}
		f.AddSignal(sa.Signal{Code: sa.SigBedrockMCPGateway, Source: source, Observed: map[string]any{"protocolType": string(protocol)}})
	}
	s.gatewayTargets(ctx, rc, id, f)
}

// gatewayTargets records each target's type and ID as a tool reference.
// The target name and description are @sensitive in the model and the
// target configuration can carry inline API schemas, so neither is read
// (GetGatewayTarget is not called).
func (s *scan) gatewayTargets(ctx context.Context, rc *regionClients, gatewayID string, f *sa.Finding) {
	p := ac.NewListGatewayTargetsPaginator(rc.agentCore, &ac.ListGatewayTargetsInput{
		GatewayIdentifier: aws.String(gatewayID), MaxResults: aws.Int32(pageSize), NextToken: nil,
	})
	var tools []sa.ToolRef
	n, err := paginate(ctx, maxPages, p.HasMorePages, func(ctx context.Context) (int, error) {
		out, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, t := range out.Items {
			typ := string(t.TargetType)
			if typ == "" {
				typ = "target"
			}
			tools = append(tools, sa.ToolRef{Type: typ, Name: str(t.TargetId)})
		}
		return len(out.Items), nil
	})
	s.calls.Record(callListTargets, n, err)
	if len(tools) > 0 {
		f.Attributes["tools"] = tools
		f.Attributes["toolCount"] = len(tools)
	}
}

// markMCPServerRuntime reclassifies a runtime that hosts an MCP server as tool
// infrastructure: its agent signal becomes the MCP server info signal.
func markMCPServerRuntime(f *sa.Finding) {
	f.Kind = models.ShadowKindToolInfra
	kept := f.Signals[:0]
	for _, sig := range f.Signals {
		if sig.Code != sa.SigBedrockAgentCoreRuntime {
			kept = append(kept, sig)
		}
	}
	f.Signals = kept
	f.AddSignal(sa.Signal{Code: sa.SigBedrockRuntimeMCPServer, Source: callGetRuntime, Observed: map[string]any{"mcp": true}})
}
