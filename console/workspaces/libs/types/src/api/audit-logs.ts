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

export type AuditLogResult = "success" | "failure" | "denied" | "unknown";

export type AuditLogCategory = "management" | "authorization" | "access";

/**
 * Where a record came from: an operation performed through Agent Manager, or
 * agent activity relayed from the AI gateways by one of the two gateway feeds
 * (the OTel analytics publisher, or the traffic log).
 */
export type AuditLogSource = "platform" | "gateway-otel" | "gateway-traffic-log";

export type AuditLogActorType =
  | "user"
  | "service"
  | "agent"
  | "gateway"
  | "system"
  | "anonymous";

/** Fields GET /audit-logs/filter-values can list the distinct values of. */
export type AuditLogFilterField =
  | "action"
  | "result"
  | "category"
  | "actorId"
  | "actorType"
  | "resourceType"
  | "resourceName"
  | "project"
  | "environment"
  | "agent"
  | "source";

export interface AuditLogActor {
  type: string;
  id: string;
  display?: string;
}

export interface AuditLogRequest {
  method?: string;
  /** Route pattern for control-plane records; requested path for gateway records. */
  path?: string;
}

export interface AuditLogResource {
  type?: string;
  id?: string;
  name?: string;
  project?: string;
  environment?: string;
  /** The agent the record concerns, when that is not the resource itself. */
  agent?: string;
}

export interface AuditLogRecord {
  eventId: string;
  occurredAt: string;
  action: string;
  category?: AuditLogCategory;
  result: AuditLogResult;
  actionClass?: string;
  /** 1 info · 2 notice · 3 warning · 4 critical. */
  severity?: number;
  actor: AuditLogActor;
  authMethod?: string;
  surface?: string;
  sourceIp?: string;
  userAgent?: string;
  requestId?: string;
  request?: AuditLogRequest;
  resource?: AuditLogResource;
  statusCode?: number;
  durationMs?: number;
  errorCode?: string;
  errorMessage?: string;
  requiredPermission?: string;
  producer: string;
  source: AuditLogSource;
  details?: Record<string, unknown>;
}

export interface AuditLogListResponse {
  records: AuditLogRecord[];
  /** Exact number of records matching the query, of which records is the first page. */
  total: number;
  tookMs?: number;
}

export interface AuditLogFilterValue {
  value: string;
  count: number;
}

export interface AuditLogFilterValuesResponse {
  filter: string;
  values: AuditLogFilterValue[];
  totalValues?: number;
}

/** The last line of an export. */
export interface AuditLogExportManifest {
  complete: boolean;
  reason?: string;
  exportedCount: number;
  storeCount: number;
  duplicatesSkipped?: number;
  startTime: string;
  endTime: string;
  generatedAt?: string;
  sha256: string;
}

/** Window and filters shared by query, filter-values and export. */
export interface AuditLogFilters {
  /** RFC3339, inclusive. */
  startTime: string;
  /** RFC3339, exclusive. At most 366 days after startTime. */
  endTime: string;
  action?: string[];
  result?: AuditLogResult[];
  category?: AuditLogCategory[];
  actorId?: string[];
  actorType?: AuditLogActorType[];
  resourceType?: string[];
  resourceName?: string[];
  project?: string[];
  environment?: string[];
  agent?: string[];
  requestId?: string[];
  eventId?: string[];
  source?: AuditLogSource[];
  /** Case-sensitive substring over the whole record. */
  search?: string;
}

export type QueryAuditLogsPathParams = OrgPathParams;

export interface QueryAuditLogsQuery extends AuditLogFilters {
  /** 1–1000, default 100. */
  limit?: number;
  sortOrder?: "asc" | "desc";
}

export type QueryAuditLogFilterValuesPathParams = OrgPathParams;

export interface QueryAuditLogFilterValuesQuery
  extends Omit<AuditLogFilters, "requestId" | "eventId"> {
  filter: AuditLogFilterField;
  valueSearch?: string;
  maxValues?: number;
}

export type ExportAuditLogsPathParams = OrgPathParams;

export type ExportAuditLogsQuery = AuditLogFilters;
