/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import type { AuditLogRecord, AuditLogSource } from "@agent-management-platform/types";

// The page's views. Each gateway feed has its own, so the two can be watched
// apart and compared; "compare" lines them up request by request.
export type AuditLogView = "all" | "platform" | "otel" | "traffic" | "compare";

export const VIEWS: Array<{ value: AuditLogView; label: string; sources?: AuditLogSource[] }> = [
  { value: "all", label: "All records" },
  { value: "platform", label: "Platform operations", sources: ["platform"] },
  { value: "otel", label: "Agent activity · OTel", sources: ["gateway-otel"] },
  { value: "traffic", label: "Agent activity · Traffic log", sources: ["gateway-traffic-log"] },
  { value: "compare", label: "Compare feeds" },
];

export const DEFAULT_VIEW: AuditLogView = "all";

export function isAuditLogView(value: string | null): value is AuditLogView {
  return VIEWS.some((v) => v.value === value);
}

export const SOURCE_LABEL: Record<AuditLogSource, string> = {
  platform: "Platform",
  "gateway-otel": "Gateway · OTel",
  "gateway-traffic-log": "Gateway · Traffic log",
};

export function isGatewayView(view: AuditLogView): boolean {
  return view === "otel" || view === "traffic";
}

function detail(record: AuditLogRecord, key: string): unknown {
  return record.details?.[key];
}

export function detailString(record: AuditLogRecord, key: string): string | undefined {
  const v = detail(record, key);
  return typeof v === "string" && v !== "" ? v : undefined;
}

export function detailNumber(record: AuditLogRecord, key: string): number | undefined {
  const v = detail(record, key);
  return typeof v === "number" ? v : undefined;
}

export function agentOf(record: AuditLogRecord): string | undefined {
  return (
    record.resource?.agent ||
    (record.resource?.type === "agent" ? record.resource.name : undefined) ||
    undefined
  );
}

export function modelOf(record: AuditLogRecord): string | undefined {
  return detailString(record, "responseModel") ?? detailString(record, "requestModel");
}

export function tokensOf(record: AuditLogRecord): string | undefined {
  const input = detailNumber(record, "inputTokens");
  const output = detailNumber(record, "outputTokens");
  if (input === undefined && output === undefined) return undefined;
  return `${input ?? "–"} in / ${output ?? "–"} out`;
}

export function mcpOf(record: AuditLogRecord): string | undefined {
  const method = detailString(record, "mcpMethod");
  const target =
    detailString(record, "toolName") ??
    detailString(record, "promptName") ??
    detailString(record, "resourceUri");
  if (!method && !target) return undefined;
  return [method, target].filter(Boolean).join(" · ");
}

/** A field the comparison measures, read the same way from both feeds. */
export interface FeedField {
  key: string;
  label: string;
  value: (record: AuditLogRecord) => string | undefined;
}

const present = (v: unknown) => (v === undefined || v === null || v === "" ? undefined : String(v));

export const FEED_FIELDS: FeedField[] = [
  { key: "agent", label: "Agent", value: (r) => agentOf(r) },
  { key: "resolution", label: "Agent resolved by", value: (r) => detailString(r, "resolution") },
  { key: "path", label: "Request path", value: (r) => r.request?.path },
  { key: "status", label: "Status code", value: (r) => present(r.statusCode) },
  {
    key: "upstreamStatus",
    label: "Upstream status",
    value: (r) => present(detailNumber(r, "upstreamStatus")),
  },
  { key: "duration", label: "Duration (ms)", value: (r) => present(r.durationMs) },
  {
    key: "backendLatency",
    label: "Backend latency (ms)",
    value: (r) => present(detailNumber(r, "backendLatencyMs")),
  },
  { key: "provider", label: "LLM provider", value: (r) => detailString(r, "provider") },
  { key: "model", label: "Model", value: (r) => modelOf(r) },
  { key: "tokens", label: "Token usage", value: (r) => tokensOf(r) },
  { key: "cost", label: "Cost (USD)", value: (r) => present(detailNumber(r, "costUsd")) },
  { key: "mcp", label: "MCP method / tool", value: (r) => mcpOf(r) },
  { key: "mcpError", label: "MCP error flagged", value: (r) => present(detail(r, "mcpError")) },
  {
    key: "guardrail",
    label: "Guardrail",
    // Only a hit is reported: guardrailHit=false means one ran and passed.
    value: (r) =>
      detail(r, "guardrailHit") === true ? (detailString(r, "guardrailName") ?? "hit") : undefined,
  },
  {
    key: "application",
    label: "Application",
    value: (r) => detailString(r, "applicationName") ?? detailString(r, "applicationId"),
  },
  {
    key: "requestBody",
    label: "Prompt (request body)",
    value: (r) => (detailString(r, "requestBodyExcerpt") ? "captured" : undefined),
  },
  {
    key: "responseBody",
    label: "Completion (response body)",
    value: (r) => (detailString(r, "responseBodyExcerpt") ? "captured" : undefined),
  },
];

/** One gateway request as each feed recorded it. */
export interface FeedPair {
  key: string;
  occurredAt: string;
  otel?: AuditLogRecord;
  traffic?: AuditLogRecord;
}

/**
 * Lines the two feeds' records up by request: both carry the gateway's
 * correlation id as requestId. A record without one stands alone. Newest first.
 */
export function pairFeeds(otel: AuditLogRecord[], traffic: AuditLogRecord[]): FeedPair[] {
  const pairs = new Map<string, FeedPair>();
  const add = (record: AuditLogRecord, side: "otel" | "traffic") => {
    const key = record.requestId ? `req:${record.requestId}` : `evt:${record.eventId}`;
    const pair = pairs.get(key) ?? { key, occurredAt: record.occurredAt };
    if (!pair[side]) pair[side] = record;
    if (record.occurredAt > pair.occurredAt) pair.occurredAt = record.occurredAt;
    pairs.set(key, pair);
  };
  otel.forEach((r) => add(r, "otel"));
  traffic.forEach((r) => add(r, "traffic"));
  return [...pairs.values()].sort((a, b) => b.occurredAt.localeCompare(a.occurredAt));
}

/**
 * The records of both feeds that fall in the span both cover. Each feed is
 * capped at its newest records, so when one is cut off its oldest record marks
 * where the comparison stops: older records of the other feed would otherwise
 * look like requests only that feed saw.
 */
export function overlappingSpan(
  otel: AuditLogRecord[],
  traffic: AuditLogRecord[],
  capped: { otel: boolean; traffic: boolean },
): { otel: AuditLogRecord[]; traffic: AuditLogRecord[]; since?: string } {
  const oldest = (records: AuditLogRecord[]) =>
    records.reduce<string | undefined>(
      (min, r) => (min === undefined || r.occurredAt < min ? r.occurredAt : min),
      undefined,
    );
  const bounds = [
    capped.otel ? oldest(otel) : undefined,
    capped.traffic ? oldest(traffic) : undefined,
  ].filter((b): b is string => b !== undefined);
  if (bounds.length === 0) return { otel, traffic };
  const since = bounds.reduce((a, b) => (a > b ? a : b));
  const keep = (r: AuditLogRecord) => r.occurredAt >= since;
  return { otel: otel.filter(keep), traffic: traffic.filter(keep), since };
}

/** How many records of a feed carry each field, out of how many. */
export function fieldCoverage(records: AuditLogRecord[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const field of FEED_FIELDS) {
    out[field.key] = records.filter((r) => field.value(r) !== undefined).length;
  }
  return out;
}
