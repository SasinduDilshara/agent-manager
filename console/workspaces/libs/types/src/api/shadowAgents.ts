/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Shadow Agent Discovery (Method 1: provider and cloud admin APIs). These
// mirror the agent-manager-service OpenAPI schemas named Shadow*.

export type ShadowProvider =
  | "openai"
  | "anthropic"
  | "bedrock"
  | "google"
  | "foundry"
  /** Source repository hosts: real connection test, source code analysis not available yet. */
  | "github"
  | "azure_devops";

export type ShadowFindingKind =
  | "platform_agent"
  | "runtime"
  | "api_key"
  | "principal"
  | "tool_infrastructure"
  /** An OpenAI project or Anthropic workspace holding evidence not tied to one key. */
  | "project";

export type ShadowVerdict = "agent" | "possible_agent" | "llm_consumer" | "tool_infrastructure";

export type ShadowFindingStatus = "new" | "reviewed" | "dismissed" | "onboarded" | "retired";

export type ShadowRetirementState =
  | ""
  | "monitoring"
  | "ready_to_retire"
  | "pending_verification"
  | "retired";

export type ShadowScanStatus = "queued" | "running" | "succeeded" | "partial" | "failed";

export type ShadowCallOutcome =
  | "ok"
  | "skipped"
  | "auth_failed"
  | "permission_denied"
  | "not_found"
  | "rate_limited"
  | "unsupported_response"
  | "failed";

export type ShadowFieldKind = "text" | "secret" | "textarea" | "list" | "checkbox" | "key_map";

export type ShadowSignalTier = "definitive" | "high" | "medium" | "low" | "info";

export interface ShadowEndpointSpec {
  key: string;
  label: string;
  default: string;
  placeholders: string[];
  option?: string;
}

export interface ShadowFieldSpec {
  key: string;
  label: string;
  kind: ShadowFieldKind;
  required: boolean;
  placeholder?: string;
  help?: string;
  defaultBool?: boolean;
  option?: string;
  /** Optional but recommended. */
  recommended?: boolean;
  /** A heading the field is shown under, for example "Services to scan". */
  section?: string;
}

/** At least one of these fields must hold a credential. */
export interface ShadowCredentialChoice {
  fields: string[];
  message: string;
}

/** One thing a scan can analyze, and the fields or options it needs. */
export interface ShadowCapabilitySpec {
  key: string;
  title: string;
  description: string;
  signals: string[];
  needs: string[];
}

export interface ShadowPermissionSpec {
  title: string;
  items: string[];
  policy?: string;
  note?: string;
}

export interface ShadowProviderSpec {
  provider: ShadowProvider;
  displayName: string;
  description: string;
  endpoints: ShadowEndpointSpec[];
  fields: ShadowFieldSpec[];
  permissions: ShadowPermissionSpec[];
  docs: string[];
  credentialChoice?: ShadowCredentialChoice;
  /** A source repository host (GitHub, Azure DevOps); its source code analysis is not available yet. */
  sourceHost?: boolean;
  capabilities: ShadowCapabilitySpec[];
}

export interface ShadowSignalDefinition {
  code: string;
  provider: string;
  name: string;
  group: string;
  tier: ShadowSignalTier;
  weight: number;
  condition: string;
}

export interface ShadowScoringRules {
  agentThreshold: number;
  possibleAgentThreshold: number;
  maxScore: number;
  retirementObservationDays: number;
  maxLookbackDays: number;
  defaultLookbackDays: number;
}

export interface ShadowProviderListResponse {
  providers: ShadowProviderSpec[];
  signals: ShadowSignalDefinition[];
  scoring: ShadowScoringRules;
}

export type ShadowSettingValue = string | boolean | string[] | Record<string, string>;

export interface ShadowConnectionRequest {
  name: string;
  provider: ShadowProvider;
  endpoints?: Record<string, string>;
  settings: Record<string, ShadowSettingValue>;
  /** On update: optional secret fields whose stored value is removed. */
  removeSecrets?: string[];
}

export interface ShadowConnectionCheck {
  name: string;
  outcome: ShadowCallOutcome | string;
  message?: string;
  unlocks?: string[];
}

export interface ShadowConnectionTest {
  ok: boolean;
  checks: ShadowConnectionCheck[];
}

export interface ShadowConnectionResponse {
  id: string;
  name: string;
  provider: ShadowProvider;
  endpoints: Record<string, string>;
  settings: Record<string, unknown>;
  secretHints: Record<string, string>;
  endpointWarnings: string[];
  lastTestedAt?: string;
  lastTest?: ShadowConnectionTest;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface ShadowConnectionListResponse {
  connections: ShadowConnectionResponse[];
}

export interface ShadowScanCallResult {
  call: string;
  outcome: ShadowCallOutcome;
  message?: string;
  items: number;
}

export interface ShadowScanConnectionResult {
  connectionId: string;
  connectionName: string;
  provider: string;
  outcome: string;
  message?: string;
  findingsCount: number;
  calls: ShadowScanCallResult[];
}

export interface ShadowScanRequest {
  connectionIds?: string[];
  lookbackDays?: number;
}

export interface ShadowScanResponse {
  id: string;
  status: ShadowScanStatus;
  lookbackDays: number;
  connectionIds: string[];
  results: ShadowScanConnectionResult[];
  findingsCount: number;
  requestedBy: string;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}

export interface ShadowScanListResponse {
  scans: ShadowScanResponse[];
}

export interface ShadowAgentSummary {
  totalFindings: number;
  byVerdict: Record<string, number>;
  byProvider: Record<string, number>;
  byStatus: Record<string, number>;
  connections: number;
  latestScan?: ShadowScanResponse;
}

export interface ShadowOwnerHint {
  name?: string;
  email?: string;
  username?: string;
  type?: string;
  source?: string;
  createdAt?: string;
}

export interface ShadowFindingSummary {
  id: string;
  connectionId: string;
  connectionName: string;
  provider: ShadowProvider;
  kind: ShadowFindingKind;
  externalId: string;
  displayName: string;
  scope: string;
  state: string;
  score: number;
  verdict: ShadowVerdict;
  status: ShadowFindingStatus;
  ownerHint: ShadowOwnerHint;
  providerCreatedAt?: string;
  firstUsedAt?: string;
  lastUsedAt?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  linkedProject: string;
  linkedAgent: string;
  retirementState: ShadowRetirementState;
  requestsInWindow: number;
}

export interface ShadowFindingListResponse {
  findings: ShadowFindingSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface ShadowFindingListQuery {
  provider?: string;
  verdict?: string;
  status?: string;
  kind?: string;
  connectionId?: string;
  /** Keep the findings this scan saw. */
  scanId?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface ShadowFindingSignal {
  code: string;
  name: string;
  group: string;
  tier: ShadowSignalTier;
  weight: number;
  counted?: boolean;
  source: string;
  condition: string;
  observed: Record<string, unknown>;
  detectedAt: string;
}

export interface ShadowAPIKey {
  keyId: string;
  name: string;
  redactedHint: string;
  status: string;
  scope: string;
  ownerHint: ShadowOwnerHint;
  createdAt?: string;
  lastUsedAt?: string;
  lastSeenAt?: string;
  present: boolean;
}

export interface ShadowUsageDay {
  day: string;
  keyId: string;
  model: string;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  costAmount?: number;
  currency?: string;
}

export interface ShadowFindingRelation {
  findingId: string;
  relation: string;
  reason?: string;
  displayName?: string;
  provider?: string;
}

export interface ShadowRetirementGuidance {
  title: string;
  steps: string[];
  docsUrl?: string;
}

export interface ShadowRetirement {
  state: ShadowRetirementState;
  observationDays: number;
  zeroUsageDays: number;
  lastDirectUseAt?: string;
  dataThrough?: string;
  markedAt?: string;
  markedBy?: string;
  verifiedAt?: string;
  verification?: string;
  guidance: ShadowRetirementGuidance;
}

export interface ShadowFindingDetail extends ShadowFindingSummary {
  attributes: Record<string, unknown>;
  related: ShadowFindingRelation[];
  signals: ShadowFindingSignal[];
  keys: ShadowAPIKey[];
  usage: ShadowUsageDay[];
  retirement: ShadowRetirement;
  onboardedAt?: string;
  onboardedBy?: string;
}

export interface ShadowFindingUpdateRequest {
  status: "new" | "reviewed" | "dismissed";
}

export interface ShadowOnboardingRequest {
  projectName: string;
  agentName: string;
}
