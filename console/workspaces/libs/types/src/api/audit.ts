/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import type { OrgPathParams } from "./common";

// Organization audit trail: GET /api/v1/orgs/{orgName}/audit/events.
// One normalised shape covers both sources — gateway traffic-log lines and
// agent-manager control-plane audit records.

export const AUDIT_CATEGORIES = [
  "OPERATIONAL",
  "LLM",
  "MCP",
  "A2A",
  "OTHER",
] as const;
export type AuditCategory = (typeof AUDIT_CATEGORIES)[number];

/**
 * STARTED is a control-plane intent record, written before a privileged
 * operation. Its result is a separate record whose `details.attemptEventId`
 * names it, so a STARTED record is neither a success nor a failure.
 */
export const AUDIT_OUTCOMES = ["SUCCESS", "DENIED", "FAILED", "STARTED"] as const;
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];

export type AuditSource = "GATEWAY" | "CONTROL_PLANE";

export type AuditActorType =
  | "USER"
  | "AGENT"
  | "SERVICE"
  | "GATEWAY"
  | "SYSTEM"
  | "ANONYMOUS";

export interface AuditActor {
  type: AuditActorType;
  id?: string;
  display?: string;
  authMethod?: string;
  clientId?: string;
  tokenId?: string;
}

export interface AuditOnBehalfOf {
  /** The principal the actor acts for (the end user of a delegated token). */
  subject?: string;
  /** Actor ids from the token's `act` claim, outermost (current actor) first. */
  chain?: string[];
}

export interface AuditAgentRef {
  name: string;
  project?: string;
  uuid?: string;
}

export interface AuditResource {
  type?: string;
  name?: string;
  id?: string;
}

export interface AuditDecision {
  terminalReason?: string;
  deniedBy?: {
    policy?: string;
    version?: string;
    phase?: string;
  } | null;
}

export interface AuditLlmInfo {
  provider?: string;
  requestModel?: string;
  model?: string;
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
  cost?: number | null;
}

export interface AuditMcpInfo {
  /** The MCP server (gateway API name). */
  server?: string;
  method?: string;
  tool?: string;
  sessionId?: string;
  jsonRpcId?: string;
  isError?: boolean;
}

/** The gateway's a2a block, as logged; only the commonly shown keys are typed. */
export interface AuditA2aInfo {
  operation?: string;
  requestType?: string;
  transport?: string;
  protocolVersion?: string;
  messageId?: string;
  taskState?: string;
  responseTaskId?: string;
  responseContextId?: string;
  isError?: boolean;
  isStreaming?: boolean;
  outcome?: string;
  [key: string]: unknown;
}

export interface AuditGuardrail {
  hit?: boolean;
  name?: string;
}

export interface AuditError {
  type?: string;
  code?: number | string;
  message?: string;
}

export interface AuditNetwork {
  clientIp?: string;
  userAgent?: string;
}

export interface AuditGatewayRef {
  id?: string;
  organization?: string;
  environment?: string;
}

export interface AuditEvent {
  id: string;
  /** RFC3339. */
  timestamp: string;
  source: AuditSource;
  category: AuditCategory;
  action: string;
  outcome: AuditOutcome;
  statusCode?: number | null;
  summary?: string;
  actor: AuditActor;
  onBehalfOf?: AuditOnBehalfOf | null;
  agent?: AuditAgentRef | null;
  project?: string;
  environment?: string;
  resource?: AuditResource | null;
  decision?: AuditDecision | null;
  llm?: AuditLlmInfo | null;
  mcp?: AuditMcpInfo | null;
  a2a?: AuditA2aInfo | null;
  guardrail?: AuditGuardrail | null;
  error?: AuditError | null;
  network?: AuditNetwork | null;
  correlationId?: string;
  gateway?: AuditGatewayRef | null;
  /** The original stored document. */
  raw?: Record<string, unknown>;
}

export type AuditCategoryCounts = Partial<Record<AuditCategory, number>>;

export interface AuditEventListResponse {
  events: AuditEvent[];
  nextCursor?: string | null;
  total?: number;
  totalRelation?: "eq" | "gte";
  categoryCounts?: AuditCategoryCounts;
}

export type AuditSortOrder = "asc" | "desc";

export interface ListAuditEventsQuery {
  /** RFC3339. */
  startTime?: string;
  /** RFC3339. */
  endTime?: string;
  category?: AuditCategory[];
  /** `project/agent` or bare `agent`. */
  agent?: string[];
  project?: string;
  environment?: string;
  outcome?: AuditOutcome[];
  actor?: string;
  search?: string;
  limit?: number;
  cursor?: string;
  sort?: AuditSortOrder;
}

export type ListAuditEventsPathParams = OrgPathParams;

/**
 * Scope the audit API requires (permission audit:read). Separate from
 * observability:log-read: the org audit trail is held by administrators only.
 */
export const AUDIT_READ_SCOPE = "amp:audit:read";
