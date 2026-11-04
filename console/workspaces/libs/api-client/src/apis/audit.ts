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

import type {
  AuditEventListResponse,
  ListAuditEventsPathParams,
  ListAuditEventsQuery,
} from "@agent-management-platform/types";
import { encodeRequired, httpGET, SERVICE_BASE } from "../utils";

/**
 * Serialises an audit query to search params. `category`, `agent` and
 * `outcome` are repeatable on the API, so they go out as one pair per value
 * (`?outcome=DENIED&outcome=FAILED`), not comma-joined.
 */
export function buildAuditEventsSearchParams(
  query?: ListAuditEventsQuery,
): string[][] {
  const out: string[][] = [];
  if (!query) return out;
  const single = (key: string, value: string | number | undefined) => {
    if (value === undefined || value === "") return;
    out.push([key, String(value)]);
  };
  const repeated = (key: string, values: readonly string[] | undefined) => {
    for (const v of values ?? []) {
      if (v) out.push([key, v]);
    }
  };
  single("startTime", query.startTime);
  single("endTime", query.endTime);
  repeated("category", query.category);
  repeated("agent", query.agent);
  single("project", query.project);
  single("environment", query.environment);
  repeated("outcome", query.outcome);
  single("actor", query.actor?.trim());
  single("search", query.search?.trim());
  single("limit", query.limit);
  single("cursor", query.cursor);
  single("sort", query.sort);
  return out;
}

export async function listAuditEvents(
  params: ListAuditEventsPathParams,
  query?: ListAuditEventsQuery,
  getToken?: () => Promise<string>,
): Promise<AuditEventListResponse> {
  const org = encodeRequired(params.orgName, "orgName");
  const token = getToken ? await getToken() : undefined;
  const searchParams = buildAuditEventsSearchParams(query);
  const res = await httpGET(`${SERVICE_BASE}/orgs/${org}/audit/events`, {
    token,
    searchParams: searchParams.length ? searchParams : undefined,
  });
  return res.json();
}
