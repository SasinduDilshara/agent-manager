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

import type {
  AuditLogExportManifest,
  AuditLogFilters,
  AuditLogFilterValuesResponse,
  AuditLogListResponse,
  ExportAuditLogsPathParams,
  ExportAuditLogsQuery,
  QueryAuditLogFilterValuesPathParams,
  QueryAuditLogFilterValuesQuery,
  QueryAuditLogsPathParams,
  QueryAuditLogsQuery,
} from "@agent-management-platform/types";
import { encodeRequired, httpGET, SERVICE_BASE } from "../utils";

const REPEATABLE_FILTERS = [
  "action",
  "result",
  "category",
  "actorId",
  "actorType",
  "resourceType",
  "resourceName",
  "project",
  "environment",
  "agent",
  "requestId",
  "eventId",
  "source",
] as const;

/**
 * Serialises the window and filters as the API expects them: each multi-valued
 * filter repeated once per value (`action=a&action=b`), empty ones left out.
 */
function auditFilterSearchParams(filters: Partial<AuditLogFilters>): string[][] {
  const pairs: string[][] = [];
  if (filters.startTime) pairs.push(["startTime", filters.startTime]);
  if (filters.endTime) pairs.push(["endTime", filters.endTime]);
  for (const key of REPEATABLE_FILTERS) {
    for (const value of filters[key] ?? []) {
      if (value) pairs.push([key, value]);
    }
  }
  if (filters.search) pairs.push(["search", filters.search]);
  return pairs;
}

export async function queryAuditLogs(
  params: QueryAuditLogsPathParams,
  query: QueryAuditLogsQuery,
  getToken?: () => Promise<string>,
): Promise<AuditLogListResponse> {
  const org = encodeRequired(params.orgName, "orgName");
  const token = getToken ? await getToken() : undefined;
  const searchParams = auditFilterSearchParams(query);
  if (query.limit !== undefined) searchParams.push(["limit", String(query.limit)]);
  if (query.sortOrder) searchParams.push(["sortOrder", query.sortOrder]);

  const res = await httpGET(`${SERVICE_BASE}/orgs/${org}/audit-logs`, {
    token,
    searchParams,
  });
  return res.json();
}

export async function queryAuditLogFilterValues(
  params: QueryAuditLogFilterValuesPathParams,
  query: QueryAuditLogFilterValuesQuery,
  getToken?: () => Promise<string>,
): Promise<AuditLogFilterValuesResponse> {
  const org = encodeRequired(params.orgName, "orgName");
  const token = getToken ? await getToken() : undefined;
  const searchParams = auditFilterSearchParams(query);
  searchParams.push(["filter", query.filter]);
  if (query.valueSearch) searchParams.push(["valueSearch", query.valueSearch]);
  if (query.maxValues !== undefined) {
    searchParams.push(["maxValues", String(query.maxValues)]);
  }

  const res = await httpGET(
    `${SERVICE_BASE}/orgs/${org}/audit-logs/filter-values`,
    { token, searchParams },
  );
  return res.json();
}

export interface AuditLogExportFile {
  blob: Blob;
  filename: string;
  /** The export's last line; undefined means the file was cut off. */
  manifest: AuditLogExportManifest | undefined;
}

/** Reads the manifest from the export's last non-empty line, if it is one. */
export function parseAuditExportManifest(
  text: string,
): AuditLogExportManifest | undefined {
  const lines = text.trimEnd().split("\n");
  const last = lines[lines.length - 1];
  if (!last) return undefined;
  try {
    const parsed = JSON.parse(last) as { manifest?: AuditLogExportManifest };
    return parsed.manifest;
  } catch {
    return undefined;
  }
}

/**
 * How much of an export's end is read to find the manifest. The manifest line
 * is a few hundred bytes; the rest of the file is never read into memory.
 */
const MANIFEST_TAIL_BYTES = 64 * 1024;

async function readExportManifest(blob: Blob): Promise<AuditLogExportManifest | undefined> {
  const tail = await blob.slice(Math.max(0, blob.size - MANIFEST_TAIL_BYTES)).text();
  return parseAuditExportManifest(tail);
}

function filenameFromDisposition(header: string | null): string | undefined {
  const match = header?.match(/filename="?([^";]+)"?/);
  return match?.[1];
}

export async function exportAuditLogs(
  params: ExportAuditLogsPathParams,
  query: ExportAuditLogsQuery,
  getToken?: () => Promise<string>,
): Promise<AuditLogExportFile> {
  const org = encodeRequired(params.orgName, "orgName");
  const token = getToken ? await getToken() : undefined;

  const res = await httpGET(`${SERVICE_BASE}/orgs/${org}/audit-logs/export`, {
    token,
    searchParams: auditFilterSearchParams(query),
  });
  // Kept as the Blob the response gave, never a string: a large export would
  // otherwise be held in memory twice over, and the browser can keep a large
  // Blob on disk. Its type is the server's application/x-ndjson.
  const blob = await res.blob();
  return {
    blob,
    filename:
      filenameFromDisposition(res.headers.get("Content-Disposition")) ??
      "audit-logs.ndjson",
    manifest: await readExportManifest(blob),
  };
}
