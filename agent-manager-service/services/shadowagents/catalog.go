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
	"fmt"
	"strings"

	"github.com/wso2/agent-manager/agent-manager-service/models"
)

// Field kinds of a connection form.
const (
	FieldText     = "text"
	FieldSecret   = "secret"
	FieldTextarea = "textarea"
	FieldList     = "list"
	FieldCheckbox = "checkbox"
	FieldKeyMap   = "key_map"
)

// EndpointSpec is one provider endpoint a connection calls. Default is the
// official base URL, or the official pattern with placeholders.
type EndpointSpec struct {
	Key          string
	Label        string
	Default      string
	Placeholders []string
	// OfficialHostSuffixes are the hosts the provider officially serves the
	// endpoint from; the UI warns (and nothing more) when a user enters a
	// host outside them.
	OfficialHostSuffixes []string
	// Option, when set, names the checkbox that enables this endpoint.
	Option string
}

// FieldSpec is one field of a provider's connection form.
type FieldSpec struct {
	Key         string
	Label       string
	Kind        string
	Required    bool
	Placeholder string
	Help        string
	// DefaultBool is a checkbox's initial state.
	DefaultBool bool
	// Option, when set, names the checkbox that shows this field; a
	// Required field with an Option is required only when it is ticked.
	// "!key" shows the field while the checkbox is not ticked.
	Option string
	// Recommended marks an optional field the console recommends.
	Recommended bool
	// Section is a heading the console shows the field under.
	Section string
}

// PermissionSpec explains one credential the customer creates, and the
// least privilege it needs.
type PermissionSpec struct {
	Title string
	Items []string
	// Policy is a ready-to-use role or policy document, when there is one.
	Policy string
	Note   string
}

// ProviderSpec describes a provider to the UI: how to connect, what to
// grant and what the scan can find.
type ProviderSpec struct {
	Provider    string
	DisplayName string
	Description string
	Endpoints   []EndpointSpec
	Fields      []FieldSpec
	Permissions []PermissionSpec
	Docs        []string
	// SourceHost marks a source repository host (GitHub, Azure DevOps): its
	// source code analysis is added separately.
	SourceHost bool
}

// Endpoint keys.
const (
	EPOpenAIAPI = "api"

	EPAnthropicAPI        = "api"
	EPAnthropicAWS        = "awsVariant"
	EPAnthropicAWSSTS     = "awsSts"
	EPAnthropicGCP        = "gcpVariant"
	EPAnthropicGCPToken   = "gcpToken"
	EPAzureLogin          = "login"
	EPAzureARM            = "arm"
	EPBedrockSTS          = "sts"
	EPBedrockAgentCore    = "agentcoreControl"
	EPBedrockRegistry     = "agentRegistry"
	EPBedrockAgent        = "bedrockAgent"
	EPBedrock             = "bedrock"
	EPBedrockCloudWatch   = "cloudwatch"
	EPBedrockLogs         = "logs"
	EPBedrockCloudTrail   = "cloudtrail"
	EPGoogleToken         = "token"
	EPGoogleAIPlatform    = "aiplatform"
	EPGoogleAIPlatformRep = "aiplatformMultiRegion"
	EPGoogleRegistry      = "agentRegistry"
	EPGoogleMonitoring    = "monitoring"
	EPGoogleLogging       = "logging"
	EPGitHubAPI           = "api"
	EPAzureDevOps         = "azureDevOps"
)

// Option (checkbox) keys.
const (
	OptDeepInspection   = "deepInspection"
	OptAllSubscriptions = "allSubscriptions"
	OptClassicAgents    = "includeClassicAgents"
	OptGlobalMulti      = "includeGlobalAndMultiRegion"
	OptCloudVariants    = "includeCloudVariants"
	OptAllRepositories  = "allRepositories"
	OptAllProjects      = "allProjects"
	OptUseEntra         = "useEntra"
	OptReadCIAndEnv     = "readCiAndEnvFiles"
)

// FieldPersonalAccessToken is the GitHub and Azure DevOps token field.
const FieldPersonalAccessToken = "personalAccessToken"

// OptionActive reports whether a field or endpoint with this Option applies,
// given the checkbox values: "" always, "key" when ticked, "!key" when not.
func OptionActive(option string, values map[string]bool) bool {
	if option == "" {
		return true
	}
	if key, negated := strings.CutPrefix(option, "!"); negated {
		return !values[key]
	}
	return values[option]
}

// OptionKey is the checkbox an Option names, without the "!" prefix.
func OptionKey(option string) string {
	return strings.TrimPrefix(option, "!")
}

// Service options: optional services the user can untick. An unticked
// service is not called, and its endpoint is not shown.
const (
	OptBedrockAgentCore      = "scanAgentCore"
	OptBedrockRegistry       = "scanAgentRegistry"
	OptBedrockClassicAgents  = "scanClassicAgents"
	OptBedrockMetrics        = "readCloudWatchMetrics"
	OptBedrockCloudTrail     = "readCloudTrail"
	OptBedrockInvocationLogs = "readInvocationLogging"

	OptGoogleRegistry   = "scanAgentRegistry"
	OptGoogleMonitoring = "readMonitoring"
	OptGoogleAuditLogs  = "readAuditLogs"
)

// serviceOptions are the option keys stored as DisabledServices when off.
var serviceOptions = map[string]bool{
	OptBedrockAgentCore: true, OptBedrockRegistry: true, OptBedrockClassicAgents: true, OptBedrockMetrics: true,
	OptBedrockCloudTrail: true, OptBedrockInvocationLogs: true, OptGoogleMonitoring: true, OptGoogleAuditLogs: true,
}

// IsServiceOption reports whether an option key turns a service on or off.
func IsServiceOption(key string) bool { return serviceOptions[key] }

// ServiceEnabled reports whether the connection scans an optional service.
func ServiceEnabled(cfg models.ShadowConnectionConfig, key string) bool {
	for _, k := range cfg.DisabledServices {
		if k == key {
			return false
		}
	}
	return true
}

// SectionServices is the heading of the service options in the form.
const SectionServices = "Services to scan"

// ReasonServiceOff is recorded for the calls of an unticked service.
const ReasonServiceOff = "not selected in this connection"

// serviceField is the checkbox of an optional service, ticked by default.
func serviceField(key, label, help string) FieldSpec {
	return FieldSpec{Key: key, Label: label, Kind: FieldCheckbox, DefaultBool: true, Help: help, Section: SectionServices}
}

var deepInspectionField = FieldSpec{
	Key: OptDeepInspection, Label: "Deep inspection", Kind: FieldCheckbox, DefaultBool: false,
	Help: "Read sources that contain prompts or tool payloads (batches, stored responses, logs, session events) " +
		"in memory to detect tool calls. Only counts are kept; the content is never stored. Off by default.",
}

var azureEndpoints = []EndpointSpec{
	{
		Key: EPAzureLogin, Label: "Microsoft Entra login", Default: "https://login.microsoftonline.com",
		OfficialHostSuffixes: []string{"login.microsoftonline.com"},
	},
	{
		Key: EPAzureARM, Label: "Azure Resource Manager", Default: "https://management.azure.com",
		OfficialHostSuffixes: []string{"management.azure.com"},
	},
}

var azureFields = []FieldSpec{
	{Key: "tenantId", Label: "Directory (tenant) ID", Kind: FieldText, Required: true, Placeholder: "e.g. 72f988bf-86f1-41af-91ab-2d7cd011db47"},
	{Key: "clientId", Label: "Application (client) ID", Kind: FieldText, Required: true, Placeholder: "e.g. 0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"},
	{Key: "clientSecret", Label: "Client secret", Kind: FieldSecret, Required: true, Placeholder: "Client secret value"},
	{Key: OptAllSubscriptions, Label: "Scan every subscription the app can read", Kind: FieldCheckbox, DefaultBool: true},
	{
		Key: "subscriptionIds", Label: "Subscription IDs", Kind: FieldList, Placeholder: "e.g. 00000000-0000-0000-0000-000000000000",
		Help: "Used when \"Scan every subscription\" is off.",
	},
}

var providerSpecs = []ProviderSpec{
	{
		Provider:    models.ShadowProviderOpenAI,
		DisplayName: "OpenAI",
		Description: "OpenAI API platform: projects, API keys, usage and costs, audit logs (Admin key), and agents, stored completions and batches (project keys).",
		Endpoints: []EndpointSpec{{
			Key: EPOpenAIAPI, Label: "OpenAI API", Default: "https://api.openai.com/v1",
			OfficialHostSuffixes: []string{"api.openai.com"},
		}},
		Fields: []FieldSpec{
			{
				Key: FieldAPIKey, Label: "Admin API key", Kind: FieldSecret, Recommended: true, Placeholder: "sk-admin-...",
				Help: "Lists every project and API key with its owner, usage and cost, so workloads that call OpenAI " +
					"directly are found. Without it, only the projects you add a project key for are scanned.",
			},
			{
				Key: FieldScopedKeys, Label: "Project keys", Kind: FieldKeyMap, Placeholder: "proj_abc123",
				Help: "Read-only project keys (scope api.all.read) per project ID, for agents, sessions, stored chat " +
					"completions and batches. The Admin key cannot read these. Required if you don't add an Admin API key.",
			},
			deepInspectionField,
		},
		Permissions: []PermissionSpec{
			{Title: "Admin API key (recommended)", Items: []string{
				"Created by an organization owner at platform.openai.com/settings/organization/admin-keys.",
				"Used only for /v1/organization/* (projects, API keys, usage, costs, audit logs). It cannot call /v1/agents and cannot read project keys.",
				"OpenAI documents no read-only Admin key; set an expiry date and store it only here.",
			}},
			{Title: "Project keys (required without an Admin key)", Items: []string{
				"One key per project, ideally a service account key with scopes [\"api.all.read\"].",
				"Unlocks: agent objects and sessions, tool calls in stored chat completions and in batches.",
				"Without an Admin key, only these projects are scanned, and keys, usage, costs and owners are not read.",
			}},
			{Title: "Audit logs", Items: []string{"Owner hints come from audit logs (api_key.created); audit logging must be active for the organization."}},
		},
		Docs: []string{"https://platform.openai.com/docs/api-reference/administration", "https://platform.openai.com/docs/api-reference/usage"},
	},
	{
		Provider:    models.ShadowProviderAnthropic,
		DisplayName: "Anthropic",
		Description: "Claude Developer Platform: workspaces, API keys, usage and cost analytics (Admin key), and Managed Agents, sessions and batches (workspace keys).",
		Endpoints: []EndpointSpec{
			{Key: EPAnthropicAPI, Label: "Anthropic API", Default: "https://api.anthropic.com", OfficialHostSuffixes: []string{"api.anthropic.com"}},
			{
				Key: EPAnthropicAWS, Label: "Claude Platform on AWS", Default: "https://aws-external-anthropic.{region}.api.aws",
				Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".api.aws"}, Option: OptCloudVariants,
			},
			{
				Key: EPAnthropicAWSSTS, Label: "AWS STS (Claude Platform on AWS)", Default: "https://sts.{region}.amazonaws.com",
				Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}, Option: OptCloudVariants,
			},
			{
				Key: EPAnthropicGCP, Label: "Claude Models on Google Cloud (Anthropic managed)", Default: "https://claude.googleapis.com",
				OfficialHostSuffixes: []string{"claude.googleapis.com"}, Option: OptCloudVariants,
			},
			{
				Key: EPAnthropicGCPToken, Label: "Google OAuth token endpoint", Default: "https://oauth2.googleapis.com/token",
				OfficialHostSuffixes: []string{"oauth2.googleapis.com"}, Option: OptCloudVariants,
			},
		},
		Fields: []FieldSpec{
			{
				Key: FieldAPIKey, Label: "Admin API key", Kind: FieldSecret, Recommended: true, Placeholder: "sk-ant-admin01-...",
				Help: "Lists every workspace and API key with its creator, usage and cost, so workloads that call Claude " +
					"directly are found. Without it, only the workspaces you add a workspace key for are scanned.",
			},
			{
				Key: FieldScopedKeys, Label: "Workspace keys", Kind: FieldKeyMap, Placeholder: "wrkspc_01ABC...",
				Help: "Workspace API keys per workspace ID, for Managed Agents, sessions and message batches. These are " +
					"workspace endpoints. Required if you don't add an Admin API key.",
			},
			deepInspectionField,
			{Key: OptCloudVariants, Label: "Also scan Claude Platform on AWS and Claude Models on Google Cloud", Kind: FieldCheckbox, DefaultBool: true},
			{Key: "regions", Label: "AWS regions", Kind: FieldList, Placeholder: "e.g. us-east-1", Option: OptCloudVariants},
			{Key: "accessKeyId", Label: "AWS access key ID", Kind: FieldText, Placeholder: "AKIA...", Option: OptCloudVariants},
			{Key: "secretAccessKey", Label: "AWS secret access key", Kind: FieldSecret, Option: OptCloudVariants},
			{Key: "roleArn", Label: "AWS role to assume", Kind: FieldText, Placeholder: "arn:aws:iam::123456789012:role/AmpShadowDiscovery", Option: OptCloudVariants},
			{Key: "externalId", Label: "AWS external ID", Kind: FieldText, Option: OptCloudVariants},
			{
				Key: "awsWorkspaceIds", Label: "AWS workspace IDs", Kind: FieldList, Placeholder: "wrkspc_...", Option: OptCloudVariants,
				Help: "Leave empty to list workspaces in each region.",
			},
			{Key: "gcpProjectId", Label: "Google Cloud project ID", Kind: FieldText, Placeholder: "e.g. my-project", Option: OptCloudVariants},
			{
				Key: "gcpWorkspaceIds", Label: "Google Cloud workspace IDs", Kind: FieldList, Placeholder: "wrkspc_...", Option: OptCloudVariants,
				Help: "Google Cloud has no workspace list route; enter the workspaces to scan.",
			},
			{Key: "serviceAccountJson", Label: "Google service account key (JSON)", Kind: FieldSecret, Option: OptCloudVariants},
		},
		Permissions: []PermissionSpec{
			{Title: "Admin API key (recommended)", Items: []string{
				"Created by an organization member with the admin role (Console > Settings > Admin keys).",
				"Admin keys always have write access; Anthropic offers no read-only Admin key. Set an expiry date.",
				"Used for /v1/organizations/* (workspaces, API keys, users, usage and cost analytics).",
			}},
			{Title: "Workspace keys (required without an Admin key)", Items: []string{
				"A key per workspace (or a service account key added to the workspaces).",
				"Unlocks: Managed Agents and sessions, session tool use, tool calls in message batches.",
				"Without an Admin key, only these workspaces are scanned, and keys, usage, costs and creators are not read.",
			}},
			{Title: "Claude Platform on AWS (optional)", Items: []string{
				"An IAM principal with a custom read-only policy for the aws-external-anthropic service (the managed AnthropicReadOnlyAccess policy covers workspace resources only); outbound web identity federation must be enabled in the account.",
				"API keys and users are not listed on this variant; owner hints come from the usage actor.",
			}},
			{Title: "Claude Models on Google Cloud (optional)", Items: []string{
				"A service account with roles/claude.viewer (agents, sessions, batches); analytics needs roles/claude.admin.",
			}},
		},
		Docs: []string{"https://platform.claude.com/docs/en/build-with-claude/administration-api"},
	},
	{
		Provider:    models.ShadowProviderBedrock,
		DisplayName: "Amazon Bedrock",
		Description: "AgentCore runtimes, gateways and Agent Registry, classic Bedrock agents, CloudTrail model calls, CloudWatch metrics and (optional) model invocation logs.",
		Endpoints: []EndpointSpec{
			// STS is used only to assume a role, so it shows only when one is set.
			{Key: EPBedrockSTS, Label: "AWS STS", Default: "https://sts.{region}.amazonaws.com", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}, Option: "roleArn"},
			{Key: EPBedrockAgentCore, Label: "AgentCore control plane", Default: "https://bedrock-agentcore-control.{region}.amazonaws.com", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}, Option: OptBedrockAgentCore},
			{Key: EPBedrockRegistry, Label: "AWS Agent Registry", Default: "https://agent-registry-control.{region}.api.aws", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".api.aws"}, Option: OptBedrockRegistry},
			{Key: EPBedrockAgent, Label: "Bedrock Agents", Default: "https://bedrock-agent.{region}.amazonaws.com", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}, Option: OptBedrockClassicAgents},
			{Key: EPBedrock, Label: "Bedrock control plane", Default: "https://bedrock.{region}.amazonaws.com", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}, Option: OptBedrockInvocationLogs},
			{Key: EPBedrockCloudWatch, Label: "CloudWatch", Default: "https://monitoring.{region}.amazonaws.com", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}, Option: OptBedrockMetrics},
			{Key: EPBedrockLogs, Label: "CloudWatch Logs", Default: "https://logs.{region}.amazonaws.com", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}, Option: OptBedrockInvocationLogs},
			{Key: EPBedrockCloudTrail, Label: "CloudTrail", Default: "https://cloudtrail.{region}.amazonaws.com", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}, Option: OptBedrockCloudTrail},
		},
		Fields: []FieldSpec{
			{Key: "regions", Label: "Regions", Kind: FieldList, Required: true, Placeholder: "e.g. us-east-1"},
			{Key: "accessKeyId", Label: "Access key ID", Kind: FieldText, Required: true, Placeholder: "AKIA..."},
			{Key: "secretAccessKey", Label: "Secret access key", Kind: FieldSecret, Required: true},
			{Key: "sessionToken", Label: "Session token", Kind: FieldSecret},
			{
				Key: "roleArn", Label: "Role to assume", Kind: FieldText, Placeholder: "arn:aws:iam::123456789012:role/AmpShadowDiscovery",
				Help: "A cross-account read-only role. When set, the access key is used only to assume it.",
			},
			{Key: "externalId", Label: "External ID", Kind: FieldText},
			deepInspectionField,
			serviceField(OptBedrockAgentCore, "Scan AgentCore runtimes and gateways",
				"AgentCore control plane: runtimes, gateways and gateway targets."),
			serviceField(OptBedrockRegistry, "Scan the AWS Agent Registry", "Agent and tool records in the registries."),
			serviceField(OptBedrockClassicAgents, "Scan classic Bedrock agents", "Bedrock Agents and their action groups."),
			serviceField(OptBedrockMetrics, "Read CloudWatch metrics", "Sessions per AgentCore runtime, to tell live runtimes from idle ones."),
			serviceField(OptBedrockCloudTrail, "Read CloudTrail model calls",
				"InvokeModel and Converse calls per IAM user or role: workloads that call Bedrock directly (last 90 days)."),
			serviceField(OptBedrockInvocationLogs, "Read model invocation logging",
				"Whether model invocation logging is on and, with deep inspection, tool calls in the logs."),
		},
		Permissions: []PermissionSpec{
			{Title: "Read-only IAM policy", Items: []string{
				"Attach to the role (or user) Agent Manager uses. Every action is a Read or List action.",
				"There is no AgentCore read-only managed policy; AmazonBedrockReadOnly and AgentRegistryReadOnlyAccess cover parts of it.",
				"logs:FilterLogEvents is needed only with deep inspection (model invocation logs); scope it to the log group.",
				"You can leave out the actions of services you untick: bedrock-agentcore:* (AgentCore), agent-registry:* (Agent Registry), bedrock:ListAgents/GetAgent/ListAgentActionGroups (classic agents), cloudwatch:* (metrics), cloudtrail:LookupEvents (CloudTrail), bedrock:GetModelInvocationLoggingConfiguration and logs:FilterLogEvents (invocation logging).",
			}, Policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["bedrock-agentcore:ListAgentRuntimes","bedrock-agentcore:GetAgentRuntime","bedrock-agentcore:ListGateways","bedrock-agentcore:GetGateway","bedrock-agentcore:ListGatewayTargets","bedrock-agentcore:GetGatewayTarget","agent-registry:ListRegistries","agent-registry:GetRegistry","agent-registry:ListRegistryRecords","agent-registry:GetRegistryRecord","bedrock:ListAgents","bedrock:GetAgent","bedrock:ListAgentActionGroups","bedrock:GetAgentActionGroup","bedrock:GetModelInvocationLoggingConfiguration","logs:FilterLogEvents","cloudwatch:GetMetricData","cloudwatch:ListMetrics","cloudtrail:LookupEvents"],"Resource":"*"}]}`},
			{Title: "What is off by default", Items: []string{
				"Model invocation logging is off by default; without it, code-built agents show only plain model usage.",
				"CloudTrail event history covers 90 days.",
			}},
		},
		Docs: []string{"https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/Welcome.html", "https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html"},
	},
	{
		Provider:    models.ShadowProviderGoogle,
		DisplayName: "Google Agent Platform",
		Description: "Agent Runtime (reasoning engines), Agent Registry agents and MCP servers, request metrics and Admin Activity audit logs.",
		Endpoints: []EndpointSpec{
			{Key: EPGoogleToken, Label: "OAuth token endpoint", Default: "https://oauth2.googleapis.com/token", OfficialHostSuffixes: []string{"oauth2.googleapis.com"}},
			{Key: EPGoogleAIPlatform, Label: "Agent Runtime (regional)", Default: "https://{location}-aiplatform.googleapis.com", Placeholders: []string{"location"}, OfficialHostSuffixes: []string{"aiplatform.googleapis.com"}},
			{Key: EPGoogleAIPlatformRep, Label: "Agent Runtime (us/eu multi-region)", Default: "https://aiplatform.{location}.rep.googleapis.com", Placeholders: []string{"location"}, OfficialHostSuffixes: []string{".rep.googleapis.com"}, Option: OptGlobalMulti},
			{Key: EPGoogleRegistry, Label: "Agent Registry", Default: "https://agentregistry.googleapis.com", OfficialHostSuffixes: []string{"agentregistry.googleapis.com"}, Option: OptGoogleRegistry},
			{Key: EPGoogleMonitoring, Label: "Cloud Monitoring", Default: "https://monitoring.googleapis.com", OfficialHostSuffixes: []string{"monitoring.googleapis.com"}, Option: OptGoogleMonitoring},
			{Key: EPGoogleLogging, Label: "Cloud Logging", Default: "https://logging.googleapis.com", OfficialHostSuffixes: []string{"logging.googleapis.com"}, Option: OptGoogleAuditLogs},
		},
		Fields: []FieldSpec{
			{Key: "projectIds", Label: "Project IDs", Kind: FieldList, Required: true, Placeholder: "e.g. my-agents-project"},
			{Key: "locations", Label: "Locations", Kind: FieldList, Required: true, Placeholder: "e.g. us-central1"},
			{Key: "serviceAccountJson", Label: "Service account key (JSON)", Kind: FieldSecret, Required: true, Placeholder: "{\"type\": \"service_account\", ...}"},
			{Key: OptGlobalMulti, Label: "Include the global Agent Registry location and the us/eu multi-regions", Kind: FieldCheckbox, DefaultBool: true},
			serviceField(OptGoogleRegistry, "Scan the Agent Registry", "Registered agents and MCP servers."),
			serviceField(OptGoogleMonitoring, "Read Cloud Monitoring metrics", "Requests per Agent Runtime engine, to tell live engines from idle ones."),
			serviceField(OptGoogleAuditLogs, "Read Admin Activity audit logs", "Who created or updated each engine."),
		},
		Permissions: []PermissionSpec{
			{Title: "Service account roles (read-only)", Items: []string{
				"roles/aiplatform.viewer: list Agent Runtime engines.",
				"roles/agentregistry.viewer: list Agent Registry agents and MCP servers (roles/dialogflow.viewer is not enough).",
				"roles/monitoring.viewer: engine request metrics.",
				"roles/logging.viewer: Admin Activity audit logs (always on, kept 400 days).",
				"roles/logging.privateLogViewer only if you want Data Access logs (off by default).",
				"Only roles/aiplatform.viewer is always needed; the others go with the Agent Registry, Cloud Monitoring and audit log options.",
			}},
			{Title: "Key creation", Items: []string{"Organizations created on or after 3 May 2024 block service account key creation by default; an administrator must allow it for this account."}},
		},
		Docs: []string{"https://cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/projects.locations.reasoningEngines/list", "https://docs.cloud.google.com/agent-registry/roles-permissions"},
	},
	{
		Provider:    models.ShadowProviderFoundry,
		DisplayName: "Microsoft Foundry Agent Service",
		Description: "Foundry projects and their agents (prompt, hosted, workflow, external), tools and MCP servers, and deployment usage.",
		Endpoints:   azureEndpoints,
		Fields: append(append([]FieldSpec{}, azureFields...),
			FieldSpec{Key: OptClassicAgents, Label: "Also list classic agents (retires 31 March 2027)", Kind: FieldCheckbox, DefaultBool: true},
			deepInspectionField,
		),
		Permissions: []PermissionSpec{
			{Title: "Entra app with a least-privilege custom role", Items: []string{
				"Plain Reader cannot read agents. Foundry User is not read-only (it can create, delete and invoke, and list keys).",
				"The agents read permission also allows reading threads and messages; Agent Manager calls only the agent metadata endpoints.",
				"For stored responses (deep inspection), add Microsoft.CognitiveServices/accounts/AIServices/responses/read.",
			}, Policy: `{"Name":"Agent Manager Foundry Discovery Reader","IsCustom":true,"Actions":["Microsoft.Resources/subscriptions/read","Microsoft.CognitiveServices/accounts/read","Microsoft.CognitiveServices/accounts/projects/read","Microsoft.CognitiveServices/accounts/deployments/read","Microsoft.Insights/metrics/read"],"NotActions":[],"DataActions":["Microsoft.CognitiveServices/accounts/AIServices/agents/read"],"NotDataActions":[],"AssignableScopes":["/subscriptions/{subscriptionId}"]}`},
		},
		Docs: []string{"https://learn.microsoft.com/en-us/azure/ai-foundry/agents/overview"},
	},
}

// readCIAndEnvField is the source hosts' option for CI pipeline definitions
// and .env example files (the design leaves them configurable).
func readCIAndEnvField(help string) FieldSpec {
	return FieldSpec{Key: OptReadCIAndEnv, Label: "Also read CI pipeline definitions and .env example files", Kind: FieldCheckbox, DefaultBool: true, Help: help}
}

// CallSourceAnalysis is the call a source host's scan records as skipped
// until the source code analysis exists, with ReasonAnalysisUnavailable.
const (
	CallSourceAnalysis        = "Source code analysis"
	ReasonAnalysisUnavailable = "not available yet: the repositories are analysed once source code analysis is added"
)

// Plural is "1 repository" or "3 repositories": n with the singular or
// plural noun.
func Plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// sourceHostSpecs are the source repository hosts (Method 2). Their
// connections are stored now; the source code analysis that scans them is
// added separately, so they have no connector yet.
var sourceHostSpecs = []ProviderSpec{
	{
		Provider:    models.ShadowProviderGitHub,
		DisplayName: "GitHub",
		SourceHost:  true,
		Description: "Repositories of a GitHub organization or user account: agent framework and model SDK dependencies, MCP and A2A configuration, and agent code.",
		Endpoints: []EndpointSpec{{
			Key: EPGitHubAPI, Label: "GitHub API", Default: "https://api.github.com",
			OfficialHostSuffixes: []string{"api.github.com"},
		}},
		Fields: []FieldSpec{
			{
				Key: "organization", Label: "Organization or user account", Kind: FieldText, Required: true, Placeholder: "e.g. my-org",
				Help: "The resource owner of the token. A fine-grained token reaches the repositories of one owner only.",
			},
			{Key: FieldPersonalAccessToken, Label: "Fine-grained personal access token", Kind: FieldSecret, Required: true, Placeholder: "github_pat_..."},
			{Key: OptAllRepositories, Label: "Scan every repository the token can read", Kind: FieldCheckbox, DefaultBool: true},
			{
				Key: "repositories", Label: "Repositories", Kind: FieldList, Required: true, Option: "!" + OptAllRepositories,
				Placeholder: "e.g. payments-service", Help: "Repository names in the organization, one per line.",
			},
			readCIAndEnvField("GitHub Actions workflows (.github/workflows) and files such as .env.example."),
		},
		Permissions: []PermissionSpec{
			{Title: "Fine-grained personal access token (read-only)", Items: []string{
				"In GitHub, open Settings > Developer settings > Personal access tokens > Fine-grained tokens and generate a new token.",
				"Resource owner: the organization or user account to scan.",
				"Repository access: All repositories, or Only select repositories.",
				"Repository permissions: Contents: Read-only. GitHub adds Metadata: Read-only, which is mandatory.",
				"If the organization requires approval of fine-grained tokens, the token can read only public resources until an organization owner approves it.",
				"Do not use a classic token: its repo scope also grants write access.",
			}},
			{Title: "GitHub Enterprise Server", Items: []string{
				"Set the GitHub API endpoint to https://HOSTNAME/api/v3.",
			}},
		},
		Docs: []string{"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"},
	},
	{
		Provider:    models.ShadowProviderAzureDevOps,
		DisplayName: "Azure DevOps",
		SourceHost:  true,
		Description: "Azure Repos repositories of an Azure DevOps organization: agent framework and model SDK dependencies, MCP and A2A configuration, and agent code.",
		Endpoints: []EndpointSpec{
			{
				Key: EPAzureDevOps, Label: "Azure DevOps", Default: "https://dev.azure.com",
				OfficialHostSuffixes: []string{"dev.azure.com"},
			},
			{
				Key: EPAzureLogin, Label: "Microsoft Entra login", Default: "https://login.microsoftonline.com",
				OfficialHostSuffixes: []string{"login.microsoftonline.com"}, Option: OptUseEntra,
			},
		},
		Fields: []FieldSpec{
			{
				Key: "organization", Label: "Organization", Kind: FieldText, Required: true, Placeholder: "e.g. contoso",
				Help: "The organization name in https://dev.azure.com/{organization}.",
			},
			{Key: OptUseEntra, Label: "Sign in with a Microsoft Entra service principal instead of a personal access token", Kind: FieldCheckbox, DefaultBool: false},
			{Key: FieldPersonalAccessToken, Label: "Personal access token", Kind: FieldSecret, Required: true, Option: "!" + OptUseEntra},
			{Key: "tenantId", Label: "Directory (tenant) ID", Kind: FieldText, Required: true, Option: OptUseEntra, Placeholder: "e.g. 72f988bf-86f1-41af-91ab-2d7cd011db47"},
			{Key: "clientId", Label: "Application (client) ID", Kind: FieldText, Required: true, Option: OptUseEntra, Placeholder: "e.g. 0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"},
			{Key: "clientSecret", Label: "Client secret", Kind: FieldSecret, Required: true, Option: OptUseEntra, Placeholder: "Client secret value"},
			{Key: OptAllProjects, Label: "Scan every project the credential can read", Kind: FieldCheckbox, DefaultBool: true},
			{
				Key: "projects", Label: "Projects", Kind: FieldList, Required: true, Option: "!" + OptAllProjects,
				Placeholder: "e.g. Payments", Help: "Project names in the organization, one per line.",
			},
			readCIAndEnvField("Azure Pipelines YAML definitions and files such as .env.example."),
		},
		Permissions: []PermissionSpec{
			{Title: "Personal access token (read-only)", Items: []string{
				"In Azure DevOps, open User settings > Personal access tokens and create a token for this organization only. Global tokens (all accessible organizations) are being retired.",
				"Scopes: Code (read) and Project and team (read).",
				"Organization policies can restrict creating tokens and limit their lifetime.",
			}},
			{Title: "Or a Microsoft Entra service principal", Items: []string{
				"The organization must be connected to a Microsoft Entra tenant.",
				"Register an app in Microsoft Entra ID and create a client secret.",
				"Add the service principal to the organization (Organization settings > Users > Add users), using the Object ID shown under Enterprise applications, not App registrations.",
				"Give it the Basic access level: Stakeholder does not include Azure Repos.",
				"Add it to the Readers group of each project to scan.",
			}},
		},
		Docs: []string{
			"https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate",
			"https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity",
		},
	},
}

// Providers returns the provider catalog.
func Providers() []ProviderSpec {
	return allProviderSpecs
}

var allProviderSpecs = append(append([]ProviderSpec{}, providerSpecs...), sourceHostSpecs...)

// Field returns a provider's field spec.
func (p ProviderSpec) Field(key string) (FieldSpec, bool) {
	for _, f := range p.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return FieldSpec{}, false
}

// Provider returns the spec of one provider.
func Provider(provider string) (ProviderSpec, bool) {
	for _, p := range allProviderSpecs {
		if p.Provider == provider {
			return p, true
		}
	}
	return ProviderSpec{}, false
}

// DefaultEndpoints returns the official endpoints of a provider.
func DefaultEndpoints(provider string) map[string]string {
	p, ok := Provider(provider)
	if !ok {
		return map[string]string{}
	}
	out := make(map[string]string, len(p.Endpoints))
	for _, e := range p.Endpoints {
		out[e.Key] = e.Default
	}
	return out
}
