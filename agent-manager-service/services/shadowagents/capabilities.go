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

import "github.com/wso2/agent-manager/agent-manager-service/models"

// CapabilitySpec is one thing a scan can analyze, and what the connection
// needs for it. The console shows it in "What can Agent Manager analyze?",
// evaluated against the connection form.
type CapabilitySpec struct {
	Key         string
	Title       string
	Description string
	// Signals are the signal codes the capability can produce.
	Signals []string
	// Needs are field or option keys that must all be present: a secret or
	// text field with a value (or a stored secret), a key map with at least
	// one key, a list with at least one item, or a ticked checkbox. Empty
	// means the provider's required fields are enough.
	Needs []string
}

// CredentialChoice requires at least one of Fields to be set: a credential
// (a secret or a key map with a key) or a ticked service option.
type CredentialChoice struct {
	Fields  []string
	Message string
}

// Field and option keys used by capabilities and credential choices.
const (
	FieldAPIKey     = "apiKey"
	FieldScopedKeys = "scopedKeys"
)

// providerCapabilities is what each provider's scan can analyze. It follows
// the connectors: a capability lists the signals its calls produce and the
// fields those calls need (evidence: evidence/*.md and the official docs).
var providerCapabilities = map[string][]CapabilitySpec{
	models.ShadowProviderOpenAI: {
		{
			Key: "openai.inventory", Title: "Projects, API keys, owners and creators",
			Description: "Every project and its API keys, with the owner, status and last use of each key, and who created " +
				"it (audit logs). Only the Admin API key can list these.",
			Needs: []string{FieldAPIKey},
		},
		{
			Key: "openai.usage", Title: "Usage and cost per API key",
			Description: "Daily requests, tokens and cost per key and model, and when each key was first and last used. " +
				"This is how workloads that call OpenAI without an agent object are found.",
			Signals: []string{SigOpenAIPlainUsage},
			Needs:   []string{FieldAPIKey},
		},
		{
			Key: "openai.agentsUsage", Title: "Agents API usage per key",
			Description: "Usage that came through the Agents API (api_source agents_api), for each key.",
			Signals:     []string{SigOpenAIAgentsAPIUsage},
			Needs:       []string{FieldAPIKey},
		},
		{
			Key: "openai.hostedTools", Title: "Hosted tools: web search, file search and code interpreter",
			Description: "How often each key used OpenAI's hosted tools, a sign of an agent.",
			Signals:     []string{SigOpenAIHostedSearch, SigOpenAICodeInterpreter, SigOpenAICodeInterpreterPrj},
			Needs:       []string{FieldAPIKey},
		},
		{
			Key: "openai.agents", Title: "Agent objects and their sessions",
			Description: "The agents in each project you add a project key for, with their tools and MCP servers, and " +
				"when they last ran. The Admin key cannot read agents, and cannot read a project key's secret either.",
			Signals: []string{SigOpenAIAgentObject},
			Needs:   []string{FieldScopedKeys},
		},
		{
			Key: "openai.toolCalls", Title: "Tool calls in stored chat completions and batches",
			Description: "Read in memory with each project key. Tied to an API key when the Admin key shows that exactly " +
				"one key of the project had usage; otherwise shown on the project's own finding.",
			Signals: []string{SigOpenAIToolCallCompletion, SigOpenAIToolCallBatch, SigOpenAIToolResultBatch},
			Needs:   []string{FieldScopedKeys, OptDeepInspection},
		},
		{
			Key: "openai.retirement", Title: "Verify that a retired key is gone",
			Description: "After you revoke a direct key, the next scan checks that the project's key list no longer returns it.",
			Needs:       []string{FieldAPIKey},
		},
	},
	models.ShadowProviderAnthropic: {
		{
			Key: "anthropic.inventory", Title: "Workspaces, API keys and creators",
			Description: "Every workspace and API key, with its status and the user or service account that created it. " +
				"Only an Admin credential can list these.",
			Needs: []string{FieldAPIKey},
		},
		{
			Key: "anthropic.usage", Title: "Usage and cost per API key and model",
			Description: "Daily requests, tokens and cost per key, model and product, and when each key was first and last " +
				"used. This is how workloads that call the Messages API without a Managed Agent are found.",
			Signals: []string{SigAnthropicPlainUsage},
			Needs:   []string{FieldAPIKey},
		},
		{
			Key: "anthropic.agentUsage", Title: "Managed Agent usage",
			Description: "Usage per Managed Agent, from the usage analytics.",
			Signals:     []string{SigAnthropicManagedAgentUsage},
			Needs:       []string{FieldAPIKey},
		},
		{
			Key: "anthropic.serverTools", Title: "Server tools: web search and code execution",
			Description: "How often each key used Anthropic's server tools, a sign of an agent.",
			Signals:     []string{SigAnthropicServerWebSearch, SigAnthropicServerCodeExec},
			Needs:       []string{FieldAPIKey},
		},
		{
			Key: "anthropic.agents", Title: "Managed Agents and their sessions",
			Description: "The Managed Agents in each workspace you add a workspace key for, with their tools and MCP " +
				"servers, and when they last ran. These are workspace endpoints.",
			Signals: []string{SigAnthropicManagedAgent},
			Needs:   []string{FieldScopedKeys},
		},
		{
			Key: "anthropic.sessionTools", Title: "Tool use inside sessions",
			Description: "Read in memory from each session's events, with the workspace key.",
			Signals:     []string{SigAnthropicSessionToolUse},
			Needs:       []string{FieldScopedKeys, OptDeepInspection},
		},
		{
			Key: "anthropic.batches", Title: "Tool calls in message batches",
			Description: "Read in memory with each workspace key. Tied to an API key when the Admin key shows that exactly " +
				"one key of the workspace had usage; otherwise shown on the workspace's own finding.",
			Signals: []string{SigAnthropicToolCallBatch},
			Needs:   []string{FieldScopedKeys, OptDeepInspection},
		},
		{
			Key: "anthropic.retirement", Title: "Verify that a retired key is gone",
			Description: "After you revoke a direct key, the next scan checks that the key is inactive, archived or expired.",
			Needs:       []string{FieldAPIKey},
		},
		{
			Key: "anthropic.aws", Title: "Claude Platform on AWS",
			Description: "Workspaces, usage and cost, Managed Agents, sessions and (with deep inspection) batches in each " +
				"AWS region you list.",
			Signals: []string{SigAnthropicPlainUsage, SigAnthropicManagedAgent, SigAnthropicManagedAgentUsage},
			Needs:   []string{OptCloudVariants, "regions", "accessKeyId", "secretAccessKey"},
		},
		{
			Key: "anthropic.gcp", Title: "Claude Models on Google Cloud",
			Description: "Usage and cost analytics for the Google Cloud project, and Managed Agents, sessions and batches " +
				"in the workspaces you list.",
			Signals: []string{SigAnthropicPlainUsage, SigAnthropicManagedAgent},
			Needs:   []string{OptCloudVariants, "gcpProjectId", "serviceAccountJson"},
		},
	},
	models.ShadowProviderFoundry: {
		{
			Key: "foundry.agents", Title: "Foundry projects and agents",
			Description: "Prompt, hosted, workflow and external agents in every Foundry project, with their tools and MCP servers.",
			Signals:     []string{SigFoundryAgentObject, SigFoundryUsesTools},
		},
		{
			Key: "foundry.usage", Title: "Usage of each agent's model deployment",
			Description: "Requests on the deployment an agent's model names, from Azure Monitor.",
			Signals:     []string{SigFoundryPlainUsage},
		},
		{
			Key: "foundry.classic", Title: "Classic agents",
			Description: "Agents created with the classic Assistants-based API (retires 31 March 2027).",
			Signals:     []string{SigFoundryClassicAgent},
			Needs:       []string{OptClassicAgents},
		},
		{
			Key: "foundry.toolCalls", Title: "Tool calls in stored responses",
			Description: "Read in memory from the project's stored responses.",
			Signals:     []string{SigFoundryToolCallResp},
			Needs:       []string{OptDeepInspection},
		},
		{
			Key: "foundry.duplicates", Title: "Possible duplicates of external agents",
			Description: "An external agent with the same name as a finding from another connection is flagged as a possible duplicate.",
			Signals:     []string{SigFoundryPossibleDupOf},
		},
		{
			Key: "foundry.allSubscriptions", Title: "Every subscription the app can read",
			Description: "Without this, only the subscription IDs you list are scanned.",
			Needs:       []string{OptAllSubscriptions},
		},
	},
	models.ShadowProviderBedrock: {
		{
			Key: "bedrock.agentcore", Title: "AgentCore runtimes and gateways",
			Description: "Agent runtimes in each region (MCP-server runtimes are shown as tool infrastructure), and MCP gateways.",
			Signals:     []string{SigBedrockAgentCoreRuntime, SigBedrockRuntimeNotReady, SigBedrockRuntimeMCPServer, SigBedrockMCPGateway},
			Needs:       []string{OptBedrockAgentCore},
		},
		{
			Key: "bedrock.registry", Title: "AWS Agent Registry",
			Description: "Agent and tool records in the registries; a record for a known runtime is merged into it.",
			Signals:     []string{SigBedrockRegistryAgent, SigBedrockRegistryTool},
			Needs:       []string{OptBedrockRegistry},
		},
		{
			Key: "bedrock.classic", Title: "Classic Bedrock agents",
			Description: "Bedrock agents and their action groups.",
			Signals:     []string{SigBedrockClassicAgent},
			Needs:       []string{OptBedrockClassicAgents},
		},
		{
			Key: "bedrock.runtimeUse", Title: "Runtime activity",
			Description: "Sessions per AgentCore runtime, from CloudWatch metrics.",
			Signals:     []string{SigBedrockRuntimeInUse},
			Needs:       []string{OptBedrockAgentCore, OptBedrockMetrics},
		},
		{
			Key: "bedrock.modelCalls", Title: "Direct model calls per identity",
			Description: "InvokeModel and Converse calls per IAM user or role, from CloudTrail (last 90 days). This is how " +
				"workloads that call Bedrock without an agent are found.",
			Signals: []string{SigBedrockPlainModelUsage},
			Needs:   []string{OptBedrockCloudTrail},
		},
		{
			Key: "bedrock.loggingStatus", Title: "Model invocation logging status",
			Description: "Whether model invocation logging is turned on in each region.",
			Signals:     []string{SigBedrockInvocationLogsOff},
			Needs:       []string{OptBedrockInvocationLogs},
		},
		{
			Key: "bedrock.invocationLogs", Title: "Tool calls in model invocation logs",
			Description: "Read in memory from the invocation log group. Only when model invocation logging is turned on in the account.",
			Signals:     []string{SigBedrockToolCallLog, SigBedrockToolResultLog},
			Needs:       []string{OptBedrockInvocationLogs, OptDeepInspection},
		},
	},
	models.ShadowProviderGoogle: {
		{
			Key: "google.engines", Title: "Agent Runtime engines",
			Description: "Reasoning engines in each project and location, with their framework and source.",
			Signals:     []string{SigGoogleAgentEngine},
		},
		{
			Key: "google.registry", Title: "Agent Registry agents and MCP servers",
			Description: "Registered agents (MCP servers are shown as tool infrastructure); an agent that runs on an engine is merged into it.",
			Signals:     []string{SigGoogleRegistryAgent, SigGoogleRegistryMCP},
			Needs:       []string{OptGoogleRegistry},
		},
		{
			Key: "google.engineUse", Title: "Engine activity",
			Description: "Requests per engine, from Cloud Monitoring (kept six weeks).",
			Signals:     []string{SigGoogleEngineInUse},
			Needs:       []string{OptGoogleMonitoring},
		},
		{
			Key: "google.creators", Title: "Who created or updated each engine",
			Description: "From the Admin Activity audit logs.",
			Signals:     []string{SigGoogleEngineCreatedBy},
			Needs:       []string{OptGoogleAuditLogs},
		},
		{
			Key: "google.globalMulti", Title: "Global registry and us/eu multi-regions",
			Description: "Also scans the global Agent Registry location and the us and eu multi-region Agent Runtime endpoints.",
			Needs:       []string{OptGlobalMulti},
		},
	},
}

// providerCredentialChoices are the providers whose required credential is
// one of several fields.
var providerCredentialChoices = map[string]CredentialChoice{
	models.ShadowProviderOpenAI: {
		Fields:  []string{FieldAPIKey, FieldScopedKeys},
		Message: "Add an Admin API key (recommended) or at least one project key.",
	},
	models.ShadowProviderAnthropic: {
		Fields:  []string{FieldAPIKey, FieldScopedKeys},
		Message: "Add an Admin API key (recommended) or at least one workspace key.",
	},
	models.ShadowProviderBedrock: {
		Fields: []string{
			OptBedrockAgentCore, OptBedrockRegistry, OptBedrockClassicAgents,
			OptBedrockMetrics, OptBedrockCloudTrail, OptBedrockInvocationLogs,
		},
		Message: "Select at least one Bedrock service to scan.",
	},
}

// sourceCapabilities is what the source code analysis of a repository host
// (GitHub, Azure DevOps) will analyze: the design's detectors D1 to D12. The
// analysis is added separately; the console marks these as not available yet.
func sourceCapabilities(prefix string) []CapabilitySpec {
	return []CapabilitySpec{
		{
			Key: prefix + ".dependencies", Title: "Agent framework and model SDK dependencies",
			Description: "Agent frameworks, MCP and A2A SDKs and model SDKs in manifests and lockfiles (detectors D1, D10).",
		},
		{
			Key: prefix + ".code", Title: "Agent, MCP and tool-calling code",
			Description: "Agent framework imports, MCP client and server code, and tool calling with a model SDK in source files " +
				"(detectors D2, D4, D7, D8).",
		},
		{
			Key: prefix + ".config", Title: "MCP client configuration and A2A agent cards",
			Description: ".mcp.json, mcp.json and Spring application.yml MCP clients, and .well-known/agent-card.json (detectors D3, D5).",
		},
		{
			Key: prefix + ".iac", Title: "Agent platform infrastructure as code",
			Description: "Agent platform resources in Terraform, CloudFormation and Bicep (detector D6).",
		},
		{
			Key: prefix + ".definitions", Title: "Agent and prompt definition files",
			Description: "*.prompty and agent.yaml files (detector D9).",
		},
		{
			Key: prefix + ".ciEnv", Title: "LLM environment variable names in CI and .env examples",
			Description: "Model provider variable names (never values) in pipeline definitions, Helm and Kubernetes files and " +
				".env.example (detector D11).",
			Needs: []string{OptReadCIAndEnv},
		},
		{
			Key: prefix + ".developerTooling", Title: "Developer AI tooling",
			Description: ".vscode/mcp.json, .cursor/mcp.json, AGENTS.md and CLAUDE.md, as context only (detector D12).",
		},
		{
			Key: prefix + ".secrets", Title: "Hard-coded provider keys",
			Description: "The type, file and line of a hard-coded key, never the value or a hash of it.",
		},
	}
}

func init() {
	providerCapabilities[models.ShadowProviderGitHub] = sourceCapabilities("github")
	providerCapabilities[models.ShadowProviderAzureDevOps] = sourceCapabilities("azureDevOps")
}

// Capabilities returns what a provider's scan can analyze.
func Capabilities(provider string) []CapabilitySpec {
	return providerCapabilities[provider]
}

// CredentialChoiceOf returns the provider's credential choice, if it has one.
func CredentialChoiceOf(provider string) (CredentialChoice, bool) {
	c, ok := providerCredentialChoices[provider]
	return c, ok
}
