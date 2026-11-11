# Shadow Agent Discovery

Shadow Agent Discovery finds agents and LLM workloads that call model providers directly, bypassing Agent Manager, and helps bring them under governance:

1. **Discover** — read-only calls to provider admin and cloud management APIs find agent objects, API keys and identities, with evidence, an owner hint and first/last-used times.
2. **Onboard** — a guided page registers the workload as an Agent Manager agent (externally hosted by default, or platform hosted) and routes its model calls through an organization LLM provider.
3. **Retire** — Agent Manager watches the direct usage drop to zero, then guides the user to revoke the direct credential and verifies it on the next scan. It never revokes anything itself.

This is Method 1 of the design (provider and cloud admin APIs). Method 2 (source repository scanning) is a separate component; the console shows a preview of it on sample data.

## Access

| What | Read | Change |
|---|---|---|
| Providers catalog, connections, scans, findings | `amp:shadow-agent:read` | — |
| Connect providers, test, run scans, review, onboard, confirm retirement | — | `amp:shadow-agent:manage` |

Both are granted to the Agent Manager Admin role only: connections hold provider admin credentials, and findings show the organization's provider usage and owner hints. Onboarding also checks that the target agent exists in the caller's organization. Every change is in the audit trail (`shadow-connection:*` are credential operations; `shadow-scan:create`, `shadow-finding:*`).

## Providers

| Provider | Credential | What a scan reads |
|---|---|---|
| OpenAI | Admin API key (recommended) and/or read-only project keys | Projects, project API keys, completions usage (by key, model, `api_source`), costs, web/file search and code interpreter usage, `api_key.created` audit logs; with project keys: Agents API agents and sessions, and (deep inspection) stored chat completions and batches |
| Anthropic | Admin API key (recommended) and/or workspace keys; optional Claude Platform on AWS and Claude Models on Google Cloud | Workspaces, API keys, users, usage and cost analytics (by key, model, product, agent); with workspace keys: Managed Agents, sessions and (deep inspection) session events and message batches |
| Amazon Bedrock | Access key, optionally assuming a cross-account read-only role | AgentCore runtimes and gateways, Agent Registry records, classic Bedrock agents, CloudWatch AgentCore metrics, CloudTrail model calls, model invocation logging configuration and (deep inspection) invocation logs |
| Google Agent Platform | Service account key | Agent Runtime engines, Agent Registry agents and MCP servers, engine request metrics, Admin Activity audit logs |
| Microsoft Foundry | Entra app with the custom role shown in the console | Foundry projects and agents (and, optionally, classic agents), deployment metrics, and (deep inspection) stored responses |
| GitHub (source repositories) | Fine-grained personal access token: Contents read-only (Metadata read-only is added by GitHub) | Connection test only: the owner, the repositories the token reads, and the contents of one repository. Source code analysis is not available yet |
| Azure DevOps (source repositories) | Personal access token with Code (read) and Project and team (read), or a Microsoft Entra service principal with Basic access and project Readers | Connection test only: the projects, their Azure Repos repositories and the top-level items of one repository. Source code analysis is not available yet |

**Admin key or project keys (OpenAI, Anthropic).** A connection needs an Admin API key or at least one project (OpenAI) or workspace (Anthropic) key; the console recommends the Admin key.

| With | A scan reads |
|---|---|
| Admin API key | Every project/workspace and API key with its owner and creator, usage and cost per key and model, Agents API / Managed Agent usage, hosted and server tools, and the key list that verifies a retirement. This is how workloads that call the provider without an agent object are found. |
| Project / workspace keys | Agent objects and sessions, session tool use, and (deep inspection) stored completions and batches, of the projects or workspaces they belong to. The Admin key cannot read these, and cannot read a project key's secret. |

Without the Admin key the organization routes are not called and the connection is marked *Project keys only (limited)*. A stored Admin key can be removed from the connection (`removeSecrets`). Before saving, **What can Agent Manager analyze?** lists what the form's credentials and options unlock, for every provider.

The console shows, for each provider, the least privilege to grant (with ready-to-use role and policy documents), the official endpoints, and which signals each capability unlocks (**Test connection**).

**Endpoints.** Each connection stores the base URL of every endpoint it calls, prefilled with the official URL or URL pattern (`{region}`, `{location}`). An endpoint can be changed, for example to reach the provider through a proxy; the console warns when a host is not an official one, because the stored credential is sent to it. The HTTP client never follows a redirect to another host.

**Coverage options** (checkboxes, all on by default): every Azure subscription the app can read; the Google `global` Agent Registry location and `us`/`eu` multi-regions; the Anthropic cloud-hosted variants; Foundry classic agents. **Deep inspection** is off by default (see Data retention).

**Services to scan (Amazon Bedrock, Google Agent Platform).** Each service the connector reads is a checkbox, on by default, stored as `config.disabledServices` (an absent key means the service is scanned). Bedrock: AgentCore runtimes and gateways, AWS Agent Registry, classic Bedrock agents, CloudWatch metrics, CloudTrail model calls, model invocation logging. Google: Agent Registry, Cloud Monitoring metrics, Admin Activity audit logs (the Agent Runtime engines are always read). An unticked service is never called: its endpoint field is hidden, its calls are listed as *skipped (not selected in this connection)*, **Test connection** does not probe it, and **What can Agent Manager analyze?** drops the capabilities that need it. A Bedrock connection needs at least one service. The AWS STS endpoint is shown only when a role to assume is entered, because STS is called only to assume it. Grant the least privilege of the selected services only; the permission notes say which action each service needs.

## Scans

A scan reads the chosen history (1 to 90 days, default 30) from every connection, in the background. One scan per organization can be queued or running at a time; scans are leased in the database, so any service replica can run them and a scan whose worker stopped is picked up again. Each connection runs on its own: a provider that fails, refuses a permission or rate limits fails only its own calls, and the scan result lists the outcome of every call. Retries honour `Retry-After`.

Each scan records the findings it saw, so **Scans** > **View findings** lists one scan's findings (`GET .../findings?scanId=`); a finding is still one record merged across scans, so its score, status and last use are the latest. GitHub and Azure DevOps connections are part of a scan and recorded as *Source code analysis: skipped (not available yet)*; until that analysis exists, a scan's findings page shows labelled sample data for them, which is never stored.

**Source repository hosts (GitHub, Azure DevOps).** The connection form takes the organization (or GitHub user account), every repository/project the credential reads or a list of them, and whether CI pipeline definitions and `.env` example files will be read. Azure DevOps signs in with a personal access token or, when **Sign in with a Microsoft Entra service principal** is ticked, with a tenant ID, client ID and client secret; the credential of the other method is not kept. **Test connection** is real and read-only (GitHub REST API 2022-11-28; Azure DevOps REST 7.1, with `X-TFS-FedAuthRedirect: Suppress` so a refused credential is a 401 rather than the sign-in page). What source code analysis will cover (the design's detectors D1 to D12) is shown in **What can Agent Manager analyze?** as coming soon.

Provider history limits apply: CloudTrail keeps 90 days, Azure metrics 93 days, Google metrics six weeks, and Anthropic analytics reads at most 31 days per request from 2026-01-01.

## Findings, signals and scores

A finding is one workload: an agent object, an agent runtime, an API key, a cloud identity, or tool infrastructure (MCP gateways and servers, which are never agents). A **project** finding (an OpenAI project or Anthropic workspace) holds tool calls found in stored completions or batches that cannot be tied to one key, because the Admin key is not set or more than one key of the project had usage; it links to the project's agents and, with the Admin key, to the candidate keys. Evidence about the same workload is aggregated on one finding: usage that belongs to an agent goes to the agent, not also to its key; a Bedrock runtime's own traffic does not create a second finding; a Google Agent Registry entry for an engine is merged into the engine.

Each signal has a tier:

| Tier | Weight | Examples |
|---|---|---|
| Definitive | 60 | An agent object at the provider (OpenAI agent, Anthropic Managed Agent, AgentCore runtime, classic Bedrock agent, Google engine or registry agent, Foundry agent) |
| High | 35 | Agents API / Managed Agent usage; a tool call or a tool result seen in batches, stored completions or responses, session events or invocation logs |
| Medium | 20 | Hosted tools (web or file search, code interpreter or execution); tools or MCP servers configured on an agent; a runtime or engine in use |
| Low | 5 | Plain model usage |
| Info | 0 | Owner and context evidence (an AgentCore runtime that is not ready, an MCP gateway, a possible duplicate) |

Signals are grouped by kind of evidence and each group counts once, at its highest weight, so the same evidence seen by two calls is not counted twice. The score is capped at 100.

| Verdict | Rule |
|---|---|
| Agent | Score 60 or more, with at least one definitive or high signal |
| Possible agent | Score 30 to 59, with at least one high signal |
| LLM consumer | Anything else |

The console's **How the score works** table lists every signal with its exact condition in the provider's field names.

Cross-provider links: a Foundry *external* agent is flagged as a *possible duplicate* of a finding from another provider with the same name (Foundry stores no endpoint for external agents, so they are never merged).

## Data retention

| Data | Kept |
|---|---|
| Provider secrets | Never in plain text: stored AES-GCM encrypted with `ENCRYPTION_KEY`, never returned, logged or audited; the API shows only a redacted hint |
| Provider API keys found | Key ID, name, redacted hint, status, scope and timestamps only |
| Prompts, instructions, completions, tool arguments and results, tool schemas, environment variable values, MCP headers | Never stored or logged |
| Owner hints | Minimised: a name, an email and a username or cloud principal |
| Usage | Daily values per finding, key and model: requests, input and output tokens, cost |
| Evidence | Signal, source call, exact condition and counts; signals older than the scan window age out |

Finding attributes go through an allow-list before they are stored, MCP and agent URLs are reduced to scheme and host, and error messages are scrubbed of anything that looks like a credential.

**Deep inspection** (per connection, off by default) lets a scan read sources that contain prompts or tool payloads — batch files, stored completions and responses, session events, model invocation logs — in memory, to detect tool calls. Reads are bounded, and only booleans and counts are kept.

## Onboarding and retirement

**Onboard** (from a finding) follows the Agent Manager documentation. For an **externally hosted agent** it registers the agent (`provisioning.type: external`), links the finding, and walks through the Setup Agent panel, adding an LLM configuration (an organization LLM provider through the AI gateway), and moving the workload from its direct key to the gateway endpoint and key. For a **platform-hosted agent** it opens the create-from-source page and links the finding to the agent created there. Once linked, the next steps give copy-ready commands with placeholders, taken from the Agent Manager documentation: the instrumentation variables (`pip install amp-instrumentation`, `AMP_OTEL_ENDPOINT`, `AMP_AGENT_API_KEY`, `amp-instrument python main.py`; other languages send OTLP/HTTP to `/v1/traces` with `x-amp-api-key`), the gateway values (`LLM_PROVIDER_URL`, `LLM_PROVIDER_KEY`; for OpenAI, the official client example with the `API-Key` header), and the direct credential to stop using (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`; for Bedrock, Google and Foundry, the cloud credentials it uses). The real values are shown once, in the Setup Agent and Connect to LLM Provider panels; the page never shows or stores them.

**Retire.** Project findings have no credential of their own and are not retired. After onboarding, each scan counts the complete days without direct usage. After 7 days the finding shows the provider's official steps to revoke the direct credential. Once the user confirms, the next scan verifies it: an OpenAI key no longer listed, an Anthropic key `inactive`/`archived`/`expired`, a Foundry agent `disabled`, a runtime or engine no longer returned, or, for an AWS identity (Agent Manager cannot read IAM), a full day of CloudTrail without direct model calls.

## API

All under `/api/v1/orgs/{orgName}/shadow-agents` (see `docs/api_v1_openapi.yaml`, tag *Shadow Agent Discovery*): `providers`, `summary`, `connections` (+ `/{id}`, `/{id}/test`), `scans` (+ `/{id}`), `findings` (+ `/{id}`, `/{id}/onboarding`, `/{id}/retirement/confirm`).

## Limits

- Several provider fields used for owner hints and signals are not documented exhaustively by the providers (for example the AgentCore `SessionCount` dimensions and Google engine audit-log method names); connectors parse them leniently and record a call as `unsupported_response` when a response no longer has the documented shape.
- OpenAI and Anthropic admin keys cannot be made read-only; set an expiry date. Agent objects, sessions and batches need project or workspace keys.
- Bedrock model invocation logging is off by default; without it, code-built agents on Bedrock show only plain model usage.
