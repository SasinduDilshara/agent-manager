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

import type {
  AuditLogActorType,
  AuditLogCategory,
  AuditLogRecord,
  AuditLogResult,
} from "@agent-management-platform/types";

export const DAY_MS = 24 * 60 * 60 * 1000;

/** The API accepts windows of at most 366 days. */
export const MAX_WINDOW_MS = 366 * DAY_MS;

export const TIME_RANGE_OPTIONS = [
  { value: "1h", label: "1 Hour", ms: 60 * 60 * 1000 },
  { value: "6h", label: "6 Hours", ms: 6 * 60 * 60 * 1000 },
  { value: "1d", label: "1 Day", ms: DAY_MS },
  { value: "7d", label: "7 Days", ms: 7 * DAY_MS },
  { value: "30d", label: "30 Days", ms: 30 * DAY_MS },
  { value: "90d", label: "90 Days", ms: 90 * DAY_MS },
] as const;

export const DEFAULT_TIME_RANGE = "1d";

export const PAGE_SIZE = 100;

export const RESULT_OPTIONS: AuditLogResult[] = ["success", "failure", "denied"];

export const CATEGORY_OPTIONS: AuditLogCategory[] = [
  "management",
  "authorization",
  "access",
];

export const ACTOR_TYPE_OPTIONS: AuditLogActorType[] = [
  "user",
  "service",
  "agent",
  "gateway",
  "system",
  "anonymous",
];

/**
 * The window a preset covers, ending at `anchor`. The anchor is fixed when the
 * filters change or the user refreshes, so a query key stays stable between
 * renders instead of moving with the clock.
 */
export function presetWindow(
  preset: string,
  anchor: number,
): { startTime: string; endTime: string } {
  const option =
    TIME_RANGE_OPTIONS.find((o) => o.value === preset) ??
    TIME_RANGE_OPTIONS.find((o) => o.value === DEFAULT_TIME_RANGE)!;
  return {
    startTime: new Date(anchor - option.ms).toISOString(),
    endTime: new Date(anchor).toISOString(),
  };
}

export function isTimeRangePreset(value: string | null): value is string {
  return TIME_RANGE_OPTIONS.some((o) => o.value === value);
}

export const RESULT_COLOR: Record<
  AuditLogResult,
  "success" | "error" | "warning" | "default"
> = {
  success: "success",
  failure: "error",
  denied: "warning",
  unknown: "default",
};

export const SEVERITY_LABEL: Record<number, string> = {
  1: "Info",
  2: "Notice",
  3: "Warning",
  4: "Critical",
};

/** Records the gateway observed (agent activity), as opposed to control-plane operations. */
export function isGatewayObserved(record: AuditLogRecord): boolean {
  return record.surface === "gateway";
}

export function formatResource(record: AuditLogRecord): string {
  const r = record.resource;
  if (!r) return "—";
  const name = r.name || r.id;
  if (r.type && name) return `${r.type}/${name}`;
  return r.type || name || "—";
}

export function formatActor(record: AuditLogRecord): string {
  return record.actor.display || record.actor.id;
}

export function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  // Milliseconds matter when ordering audit records, and the target lib has no
  // fractionalSecondDigits option, so they are appended by hand.
  const base = d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    // 24-hour, so the string ends with the seconds the milliseconds follow.
    hour12: false,
  });
  return `${base}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

function errorStatus(error: unknown): number | undefined {
  const status = (error as { status?: unknown } | null)?.status;
  return typeof status === "number" ? status : undefined;
}

/**
 * What a failed audit request means, by status. The read helpers do not carry
 * the response body, and each of these statuses has one meaning on this API.
 */
export function describeAuditError(
  error: unknown,
  operation: "read" | "export",
): { severity: "error" | "warning" | "info"; title: string; message: string } {
  switch (errorStatus(error)) {
    case 400:
      return operation === "export"
        ? {
            severity: "warning",
            title: "Export refused",
            message:
              "The query is invalid or matches more records than one export may hold. Narrow the time range or filters and try again.",
          }
        : {
            severity: "warning",
            title: "Invalid query",
            message: "Check the time range and filters, then try again.",
          };
    case 403:
      return {
        severity: "warning",
        title: "Not permitted",
        message:
          operation === "export"
            ? "Your role does not include exporting the audit trail (audit-log:export)."
            : "Your role does not include reading the audit trail (audit-log:read).",
      };
    case 501:
      return {
        severity: "info",
        title: "Audit trail not available",
        message:
          "This platform's observability backend has no audit store. Ask your platform administrator to enable audit logs in OpenChoreo.",
      };
    case 503:
      return operation === "export"
        ? {
            severity: "error",
            title: "Export not started",
            message:
              "The audit store is unavailable, or the export could not be recorded in the audit trail, so it was not started. Try again shortly.",
          }
        : {
            severity: "error",
            title: "Audit store unavailable",
            message:
              "The audit store is unavailable or the audit reader is not configured. Try again shortly, or ask your platform administrator.",
          };
    default:
      return {
        severity: "error",
        title: operation === "export" ? "Export failed" : "Failed to load the audit trail",
        message:
          error instanceof Error && error.message
            ? error.message
            : "Please try again.",
      };
  }
}
