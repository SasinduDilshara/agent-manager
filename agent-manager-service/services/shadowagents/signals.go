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

package shadowagents

import (
	"sort"

	"github.com/wso2/agent-manager/agent-manager-service/models"
)

// Signal groups. A group is one kind of evidence; however many signals of a
// group a finding has (a tool call seen in a batch and in a stored
// completion, plain usage on 30 days), the group counts once, at its highest
// weight. That keeps related evidence about the same workload from adding up.
const (
	GroupAgentObject     = "agent_object"
	GroupAgentAPIUsage   = "agent_api_usage"
	GroupToolCall        = "tool_call"
	GroupToolResult      = "tool_result"
	GroupHostedTools     = "hosted_tools"
	GroupToolsConfigured = "tools_configured"
	GroupRuntimeInUse    = "runtime_in_use"
	GroupPlainUsage      = "plain_usage"
	GroupInfo            = "info"
)

// Tier weights (approved for Method 1).
const (
	WeightDefinitive = 60
	WeightHigh       = 35
	WeightMedium     = 20
	WeightLow        = 5
	WeightInfo       = 0
)

// Verdict thresholds, the same rule as the source repo scan (Method 2): an
// agent needs 60 or more and at least one definitive or high signal; a
// possible agent needs 30 to 59 and at least one high signal.
const (
	AgentThreshold         = 60
	PossibleAgentThreshold = 30
	MaxScore               = 100
)

// SignalDef describes a signal: its scoring and the exact condition, in the
// provider's official field names, that raises it.
type SignalDef struct {
	Code      string
	Provider  string
	Name      string
	Group     string
	Tier      string
	Weight    int
	Condition string
}

func def(code, provider, name, group, tier, condition string) SignalDef {
	return SignalDef{
		Code: code, Provider: provider, Name: name, Group: group, Tier: tier,
		Weight: tierWeight(tier), Condition: condition,
	}
}

func tierWeight(tier string) int {
	switch tier {
	case models.ShadowTierDefinitive:
		return WeightDefinitive
	case models.ShadowTierHigh:
		return WeightHigh
	case models.ShadowTierMedium:
		return WeightMedium
	case models.ShadowTierLow:
		return WeightLow
	default:
		return WeightInfo
	}
}

// Signal codes. The conditions below are the design's signal tables as
// corrected against the providers' official references (see the evidence
// log); docs/shadow-agent-discovery.md lists them for users.
const (
	SigOpenAIAgentObject        = "openai.agent_object"
	SigOpenAIAgentsAPIUsage     = "openai.agents_api_usage"
	SigOpenAIHostedSearch       = "openai.hosted_search"
	SigOpenAICodeInterpreter    = "openai.code_interpreter"
	SigOpenAICodeInterpreterPrj = "openai.code_interpreter_project"
	SigOpenAIToolCallCompletion = "openai.tool_call_stored_completion"
	SigOpenAIToolCallBatch      = "openai.tool_call_batch"
	SigOpenAIToolResultBatch    = "openai.tool_result_batch"
	SigOpenAIPlainUsage         = "openai.plain_usage"

	SigAnthropicManagedAgent      = "anthropic.managed_agent"
	SigAnthropicManagedAgentUsage = "anthropic.managed_agent_usage"
	SigAnthropicServerWebSearch   = "anthropic.server_web_search"
	SigAnthropicServerCodeExec    = "anthropic.server_code_execution"
	SigAnthropicToolCallBatch     = "anthropic.tool_call_batch"
	SigAnthropicSessionToolUse    = "anthropic.session_tool_use"
	SigAnthropicPlainUsage        = "anthropic.plain_usage"

	SigBedrockAgentCoreRuntime  = "bedrock.agentcore_runtime"
	SigBedrockClassicAgent      = "bedrock.classic_agent"
	SigBedrockRegistryAgent     = "bedrock.registry_agent_record"
	SigBedrockRegistryTool      = "bedrock.registry_tool_record"
	SigBedrockToolCallLog       = "bedrock.tool_call_invocation_log"
	SigBedrockToolResultLog     = "bedrock.tool_result_invocation_log"
	SigBedrockRuntimeInUse      = "bedrock.runtime_in_use"
	SigBedrockMCPGateway        = "bedrock.mcp_gateway"
	SigBedrockPlainModelUsage   = "bedrock.plain_model_usage"
	SigBedrockRuntimeNotReady   = "bedrock.agentcore_runtime_not_ready"
	SigBedrockRuntimeMCPServer  = "bedrock.agentcore_runtime_mcp_server"
	SigBedrockInvocationLogsOff = "bedrock.invocation_logging_off"

	SigGoogleAgentEngine     = "google.agent_runtime_engine"
	SigGoogleRegistryAgent   = "google.registry_agent"
	SigGoogleEngineInUse     = "google.engine_in_use"
	SigGoogleRegistryMCP     = "google.registry_mcp_server"
	SigGoogleEngineCreatedBy = "google.engine_created_by"

	SigFoundryAgentObject   = "foundry.agent_object"
	SigFoundryClassicAgent  = "foundry.classic_agent"
	SigFoundryUsesTools     = "foundry.uses_tools"
	SigFoundryToolCallResp  = "foundry.tool_call_stored_response"
	SigFoundryPlainUsage    = "foundry.plain_usage"
	SigFoundryPossibleDupOf = "foundry.external_possible_duplicate"
)

var catalog = func() map[string]SignalDef {
	defs := []SignalDef{
		// OpenAI
		def(SigOpenAIAgentObject, models.ShadowProviderOpenAI, "Agent object", GroupAgentObject, models.ShadowTierDefinitive,
			`GET /v1/agents (OpenAI-Beta: agents=v1, project key): any item in data`),
		def(SigOpenAIAgentsAPIUsage, models.ShadowProviderOpenAI, "Agents API usage", GroupAgentAPIUsage, models.ShadowTierHigh,
			`usage/completions grouped by api_source: a result with api_source == "agents_api" and num_model_requests > 0 (costs: amount.value > 0)`),
		def(SigOpenAIHostedSearch, models.ShadowProviderOpenAI, "Hosted web or file search", GroupHostedTools, models.ShadowTierMedium,
			`usage/web_search_calls or usage/file_search_calls grouped by api_key_id: num_requests > 0`),
		def(SigOpenAICodeInterpreter, models.ShadowProviderOpenAI, "Code interpreter", GroupHostedTools, models.ShadowTierMedium,
			`usage/code_interpreter_sessions grouped by project_id: num_sessions > 0, in a project where this is the only key with usage`),
		def(SigOpenAICodeInterpreterPrj, models.ShadowProviderOpenAI, "Code interpreter in the project", GroupInfo, models.ShadowTierInfo,
			`usage/code_interpreter_sessions grouped by project_id: num_sessions > 0; it can only be grouped by project, and several keys of the project have usage`),
		def(SigOpenAIToolCallCompletion, models.ShadowProviderOpenAI, "Tool call in a stored chat completion", GroupToolCall, models.ShadowTierHigh,
			`GET /v1/chat/completions (store=true only): choices[].message.tool_calls non-empty, finish_reason == "tool_calls", or the deprecated function_call`),
		def(SigOpenAIToolCallBatch, models.ShadowProviderOpenAI, "Tool call in a batch result", GroupToolCall, models.ShadowTierHigh,
			`GET /v1/batches -> GET /v1/files/{output_file_id}/content: chat body as for stored completions; responses body: an output item of a tool call type (function_call, web_search_call, file_search_call, computer_call, mcp_call, ...)`),
		def(SigOpenAIToolResultBatch, models.ShadowProviderOpenAI, "Tool result sent back", GroupToolResult, models.ShadowTierHigh,
			`GET /v1/files/{input_file_id}/content of a batch: a responses input item with type == "function_call_output", or a chat message with role == "tool"`),
		def(SigOpenAIPlainUsage, models.ShadowProviderOpenAI, "Plain usage", GroupPlainUsage, models.ShadowTierLow,
			`usage/completions grouped by api_key_id: num_model_requests > 0 for the key`),

		// Anthropic
		def(SigAnthropicManagedAgent, models.ShadowProviderAnthropic, "Managed Agent object", GroupAgentObject, models.ShadowTierDefinitive,
			`GET /v1/agents?include_archived=true (managed-agents beta, workspace key): any item in data (archived_at == null means active)`),
		def(SigAnthropicManagedAgentUsage, models.ShadowProviderAnthropic, "Managed Agent usage", GroupAgentAPIUsage, models.ShadowTierHigh,
			`analytics usage grouped by agent_id: a row with group.agent_id != null and usage.requests > 0`),
		def(SigAnthropicServerWebSearch, models.ShadowProviderAnthropic, "Server web search", GroupHostedTools, models.ShadowTierMedium,
			`analytics usage grouped by api_key_id (by actor on the cloud-hosted variants): usage.server_tool_use.web_search_requests > 0; rows with an agent_id count for the agent`),
		def(SigAnthropicServerCodeExec, models.ShadowProviderAnthropic, "Server code execution", GroupHostedTools, models.ShadowTierMedium,
			`analytics cost grouped by api_key_id (by actor on the cloud-hosted variants) and cost_type: a row with group.cost_type == "code_execution" and cost.amount > 0`),
		def(SigAnthropicToolCallBatch, models.ShadowProviderAnthropic, "Tool call in a batch result", GroupToolCall, models.ShadowTierHigh,
			`GET /v1/messages/batches -> results_url: result.type == "succeeded" and result.message.stop_reason == "tool_use", or a content[] block with type == "tool_use"`),
		def(SigAnthropicSessionToolUse, models.ShadowProviderAnthropic, "Tool use inside a session", GroupToolCall, models.ShadowTierHigh,
			`GET /v1/sessions/{session_id}/events: events of type agent.tool_use, agent.custom_tool_use or agent.mcp_tool_use`),
		def(SigAnthropicPlainUsage, models.ShadowProviderAnthropic, "Plain usage", GroupPlainUsage, models.ShadowTierLow,
			`analytics usage grouped by api_key_id (by actor on the cloud-hosted variants): usage.requests > 0 in rows without an agent_id`),

		// Amazon Bedrock / AgentCore
		def(SigBedrockAgentCoreRuntime, models.ShadowProviderBedrock, "AgentCore runtime", GroupAgentObject, models.ShadowTierDefinitive,
			`ListAgentRuntimes / GetAgentRuntime: a runtime with status == "READY"`),
		def(SigBedrockRuntimeNotReady, models.ShadowProviderBedrock, "AgentCore runtime not ready", GroupInfo, models.ShadowTierInfo,
			`ListAgentRuntimes: a runtime whose status is not "READY" (e.g. CREATE_FAILED, UPDATING)`),
		def(SigBedrockRuntimeMCPServer, models.ShadowProviderBedrock, "AgentCore runtime hosting an MCP server", GroupInfo, models.ShadowTierInfo,
			`GetAgentRuntime: protocolConfiguration.serverProtocol == "MCP" (an MCP server agents call, not an agent itself)`),
		def(SigBedrockClassicAgent, models.ShadowProviderBedrock, "Classic Bedrock agent", GroupAgentObject, models.ShadowTierDefinitive,
			`ListAgents (bedrock-agent): any agent in agentSummaries`),
		def(SigBedrockRegistryAgent, models.ShadowProviderBedrock, "Agent Registry agent record", GroupAgentObject, models.ShadowTierDefinitive,
			`agent-registry ListRegistryRecords: a record with recordType == "AGENT"`),
		def(SigBedrockRegistryTool, models.ShadowProviderBedrock, "Agent Registry tool record", GroupInfo, models.ShadowTierInfo,
			`agent-registry ListRegistryRecords: a record with recordType MCP or GATEWAY (tool infrastructure, not an agent)`),
		def(SigBedrockToolCallLog, models.ShadowProviderBedrock, "Tool call in invocation logs", GroupToolCall, models.ShadowTierHigh,
			`Model invocation logs: output.outputBodyJson has stopReason == "tool_use" or a toolUse content block (Converse), or stop_reason == "tool_use" / a content block with type == "tool_use" (Anthropic InvokeModel body)`),
		def(SigBedrockToolResultLog, models.ShadowProviderBedrock, "Tool result sent back", GroupToolResult, models.ShadowTierHigh,
			`Model invocation logs: input.inputBodyJson messages contain a toolResult content block (Converse) or a content block with type == "tool_result" (Anthropic InvokeModel body)`),
		def(SigBedrockRuntimeInUse, models.ShadowProviderBedrock, "Runtime in use", GroupRuntimeInUse, models.ShadowTierMedium,
			`CloudWatch AWS/Bedrock-AgentCore: SessionCount > 0 for the runtime`),
		def(SigBedrockMCPGateway, models.ShadowProviderBedrock, "MCP gateway", GroupInfo, models.ShadowTierInfo,
			`GetGateway: protocolType == "MCP" (tool infrastructure, not an agent itself)`),
		def(SigBedrockPlainModelUsage, models.ShadowProviderBedrock, "Plain model usage", GroupPlainUsage, models.ShadowTierLow,
			`CloudTrail LookupEvents (EventSource bedrock.amazonaws.com): InvokeModel / InvokeModelWithResponseStream / Converse / ConverseStream events with eventType == "AwsApiCall" from the principal`),
		def(SigBedrockInvocationLogsOff, models.ShadowProviderBedrock, "Invocation logging off", GroupInfo, models.ShadowTierInfo,
			`GetModelInvocationLoggingConfiguration returns no logging config: code-built agents show only plain model usage`),

		// Google Agent Platform
		def(SigGoogleAgentEngine, models.ShadowProviderGoogle, "Agent Runtime engine", GroupAgentObject, models.ShadowTierDefinitive,
			`reasoningEngines.list: any engine; spec.agentFramework names the framework`),
		def(SigGoogleRegistryAgent, models.ShadowProviderGoogle, "Agent Registry agent", GroupAgentObject, models.ShadowTierDefinitive,
			`Agent Registry ListAgents: any agent entry (merged into the engine its RuntimeReference names)`),
		def(SigGoogleEngineInUse, models.ShadowProviderGoogle, "Engine in use", GroupRuntimeInUse, models.ShadowTierMedium,
			`Cloud Monitoring aiplatform.googleapis.com/reasoning_engine/request_count: count > 0 for the engine's reasoning_engine_id resource label`),
		def(SigGoogleRegistryMCP, models.ShadowProviderGoogle, "Registry MCP server", GroupInfo, models.ShadowTierInfo,
			`Agent Registry ListMcpServers: any entry (an MCP server, not an agent)`),
		def(SigGoogleEngineCreatedBy, models.ShadowProviderGoogle, "Engine change in Admin Activity logs", GroupInfo, models.ShadowTierInfo,
			`Cloud Audit Logs (Admin Activity), protoPayload.serviceName == "aiplatform.googleapis.com": a ReasoningEngineService method on the engine (owner hint only)`),

		// Microsoft Foundry Agent Service
		def(SigFoundryAgentObject, models.ShadowProviderFoundry, "Foundry agent object", GroupAgentObject, models.ShadowTierDefinitive,
			`GET {projectEndpoint}/agents?api-version=v1: any item in data (state == "enabled" means active)`),
		def(SigFoundryClassicAgent, models.ShadowProviderFoundry, "Foundry classic agent", GroupAgentObject, models.ShadowTierDefinitive,
			`GET {projectEndpoint}/assistants (classic Agent Service): any item in data`),
		def(SigFoundryUsesTools, models.ShadowProviderFoundry, "Uses tools / MCP", GroupToolsConfigured, models.ShadowTierMedium,
			`versions.latest.definition.tools is non-empty, or a classic agent's tools[] is non-empty (MCP tools carry server_label and server_url, connector_id or project_connection_id)`),
		def(SigFoundryToolCallResp, models.ShadowProviderFoundry, "Tool call in stored responses", GroupToolCall, models.ShadowTierHigh,
			`GET {projectEndpoint}/openai/v1/responses: an output item of a tool call type (function_call, mcp_call, openapi_call or any other *_call type)`),
		def(SigFoundryPlainUsage, models.ShadowProviderFoundry, "Plain usage", GroupPlainUsage, models.ShadowTierLow,
			`Azure Monitor metrics: AzureOpenAIRequests or ModelRequests > 0 for the deployment named in definition.model`),
		def(SigFoundryPossibleDupOf, models.ShadowProviderFoundry, "Possibly registered elsewhere", GroupInfo, models.ShadowTierInfo,
			`kind == "external": Foundry stores no endpoint for external agents, so a finding from another provider with the same name is flagged as a possible duplicate`),
	}
	m := make(map[string]SignalDef, len(defs))
	for _, d := range defs {
		m[d.Code] = d
	}
	return m
}()

// Def returns the definition of a signal code.
func Def(code string) (SignalDef, bool) {
	d, ok := catalog[code]
	return d, ok
}

// Defs returns every signal definition, ordered by provider then weight.
func Defs() []SignalDef {
	out := make([]SignalDef, 0, len(catalog))
	for _, d := range catalog {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		if out[i].Weight != out[j].Weight {
			return out[i].Weight > out[j].Weight
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// Score returns a finding's score and verdict from its signal codes. Each
// group counts once, at the highest weight among its signals; unknown codes
// count nothing. A finding of tool infrastructure is never an agent.
func Score(kind string, codes []string) (int, string) {
	best := map[string]SignalDef{}
	for _, c := range codes {
		d, ok := catalog[c]
		if !ok {
			continue
		}
		if cur, seen := best[d.Group]; !seen || d.Weight > cur.Weight {
			best[d.Group] = d
		}
	}
	score := 0
	hasDefinitive, hasHigh := false, false
	for _, d := range best {
		score += d.Weight
		switch d.Tier {
		case models.ShadowTierDefinitive:
			hasDefinitive = true
		case models.ShadowTierHigh:
			hasHigh = true
		}
	}
	if score > MaxScore {
		score = MaxScore
	}
	if kind == models.ShadowKindToolInfra {
		return score, models.ShadowVerdictToolInfra
	}
	switch {
	case score >= AgentThreshold && (hasDefinitive || hasHigh):
		return score, models.ShadowVerdictAgent
	case score >= PossibleAgentThreshold && hasHigh:
		return score, models.ShadowVerdictPossibleAgent
	default:
		return score, models.ShadowVerdictLLMConsumer
	}
}
