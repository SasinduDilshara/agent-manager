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

package services

import (
	"strings"

	"github.com/wso2/agent-manager/agent-manager-service/models"
)

// Official documentation of each revocation path.
const (
	docsOpenAIDeleteKey      = "https://developers.openai.com/api/reference/resources/organization/subresources/projects/subresources/api_keys/methods/delete/"
	docsAnthropicUpdateKey   = "https://platform.claude.com/docs/en/api/organization/api_keys/update"
	docsAzureDisableLocal    = "https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth"
	docsFoundryGovernAgents  = "https://learn.microsoft.com/en-us/azure/foundry/control-plane/govern-agent-infrastructure-entra-admin"
	docsAWSAccessKeys        = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html"
	docsAWSDeleteRuntime     = "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_DeleteAgentRuntime.html"
	docsAWSDeleteAgent       = "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-delete.html"
	docsGoogleManageDeployed = "https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/manage-deployed-agents"
	docsGoogleRegistry       = "https://docs.cloud.google.com/agent-registry/manage-agents"
)

// shadowFirstStep is the same for every provider: retire the direct
// credential only after the workload runs through Agent Manager.
const shadowFirstStep = "Make sure the workload now calls its model through the Agent Manager gateway and no longer uses the direct credential. Agent Manager has seen no direct usage for the observation window."

// shadowRetirementGuidance returns the provider's official steps to revoke
// the direct credential behind a finding (see the evidence log,
// retirement_guidance.md). Agent Manager never performs them.
func shadowRetirementGuidance(f *models.ShadowFinding) ShadowRetirementGuidance {
	switch f.Provider {
	case models.ShadowProviderOpenAI:
		return ShadowRetirementGuidance{
			Title: "Delete the OpenAI project API key",
			Steps: []string{
				shadowFirstStep,
				"OpenAI recommends: issue a replacement, update the workload, verify that it works, and then revoke the previous key.",
				"Delete the key from the project's API keys page in the OpenAI dashboard, or with the Admin API: DELETE /v1/organization/projects/{project_id}/api_keys/{api_key_id}. OpenAI keys have no disabled state; deleting also removes service account keys.",
				"Run a scan. The key counts as retired once the project's key list (owner_project_access=any) no longer returns it.",
			},
			DocsURL: docsOpenAIDeleteKey,
		}
	case models.ShadowProviderAnthropic:
		return ShadowRetirementGuidance{
			Title: "Disable or delete the Anthropic API key",
			Steps: []string{
				shadowFirstStep,
				"In Claude Console, open API keys and choose Disable (reversible) or Delete (permanent; the key is archived).",
				"Or with the Admin API: POST /v1/organizations/api_keys/{api_key_id} with {\"status\": \"inactive\"} or {\"status\": \"archived\"}.",
				"Run a scan. The key counts as retired once the key list reports its status as inactive, archived or expired.",
			},
			DocsURL: docsAnthropicUpdateKey,
		}
	case models.ShadowProviderFoundry:
		if strings.Contains(f.ExternalID, "asst_") {
			return ShadowRetirementGuidance{
				Title: "Delete the Foundry classic agent",
				Steps: []string{
					shadowFirstStep,
					"Classic agents have no disabled state. Delete it with DELETE {projectEndpoint}/assistants/{assistantId}?api-version=v1.",
					"Run a scan. The agent counts as retired once the project's classic agent list no longer returns it.",
				},
				DocsURL: docsFoundryGovernAgents,
			}
		}
		return ShadowRetirementGuidance{
			Title: "Disable the Foundry agent",
			Steps: []string{
				shadowFirstStep,
				"In the Foundry portal, open the agent, go to the Details tab and, under Status, select Edit to disable it. Or call POST {projectEndpoint}/agents/{agent_name}:disable?api-version=v1 (reversible with :enable).",
				"Delete the agent only as a last resort (Operate > Assets > Agents > the agent > Edit > ... > Delete agent).",
				"Microsoft says an agent's state can take up to 10 minutes to change. Run a scan: the agent counts as retired once it reports state \"disabled\" or is no longer listed.",
			},
			DocsURL: docsFoundryGovernAgents,
		}
	case models.ShadowProviderBedrock:
		switch f.Kind {
		case models.ShadowKindRuntime:
			return ShadowRetirementGuidance{
				Title: "Delete the AgentCore runtime",
				Steps: []string{
					shadowFirstStep,
					"Delete the runtime with DeleteAgentRuntime (DELETE /runtimes/{agentRuntimeId}/ on the AgentCore control plane). Without a version, every version is deleted.",
					"Deletion is asynchronous. Run a scan: the runtime counts as retired once it reports DELETING or is no longer listed.",
				},
				DocsURL: docsAWSDeleteRuntime,
			}
		case models.ShadowKindPlatformAgent:
			return ShadowRetirementGuidance{
				Title: "Delete the Bedrock agent",
				Steps: []string{
					shadowFirstStep,
					"In the Amazon Bedrock console, open Agents, select the agent, choose Delete and type delete to confirm. Or call DeleteAgent (DELETE /agents/{agentId}/).",
					"Deletion is asynchronous. Run a scan: the agent counts as retired once it reports DELETING or is no longer listed.",
				},
				DocsURL: docsAWSDeleteAgent,
			}
		default:
			return ShadowRetirementGuidance{
				Title: "Stop direct Bedrock calls from this IAM identity",
				Steps: []string{
					shadowFirstStep,
					"For an IAM user: in IAM, open the user's Security credentials, deactivate the access key (Actions > Deactivate), confirm nothing breaks, then delete it (UpdateAccessKey Status=Inactive, then DeleteAccessKey).",
					"For an IAM role: remove or deny bedrock:InvokeModel and bedrock:InvokeModelWithResponseStream in the role's policies, then use Revoke active sessions. Revoking sessions alone does not stop a workload that can assume the role again.",
					"Agent Manager's read-only role cannot read IAM. A scan counts the identity as retired once CloudTrail shows no direct model calls from it for a full day after you confirm.",
				},
				DocsURL: docsAWSAccessKeys,
			}
		}
	case models.ShadowProviderGoogle:
		if f.Kind == models.ShadowKindPlatformAgent {
			return ShadowRetirementGuidance{
				Title: "Remove the Agent Registry entry",
				Steps: []string{
					shadowFirstStep,
					"An automatically registered agent (for example an Agent Runtime engine) is removed by deleting the underlying agent in its runtime.",
					"A manually registered agent: in Agent Registry, open the Agents tab, select the agent, choose Delete and type DELETE (or gcloud agent-registry services delete).",
					"Run a scan. The agent counts as retired once Agent Registry no longer returns it.",
				},
				DocsURL: docsGoogleRegistry,
			}
		}
		return ShadowRetirementGuidance{
			Title: "Delete the Agent Runtime engine",
			Steps: []string{
				shadowFirstStep,
				"On the Agent Platform Deployments page, open the agent's more actions menu and choose Delete. Or call reasoningEngines.delete (DELETE .../reasoningEngines/{id}?force=true to also delete its sessions and memory).",
				"If the workload used a service account key, disable it (gcloud iam service-accounts keys disable) or delete it. Neither revokes short-lived tokens already issued from the key.",
				"Run a scan. The engine counts as retired once reasoningEngines.list no longer returns it.",
			},
			DocsURL: docsGoogleManageDeployed,
		}
	}
	return ShadowRetirementGuidance{
		Title: "Revoke the direct credential at the provider",
		Steps: []string{shadowFirstStep, "Revoke the credential at the provider, then run a scan to verify it."},
	}
}
