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

import { useCallback, useEffect, useRef, useState } from "react";
import { keepPreviousData, useQueryClient } from "@tanstack/react-query";
import { useAuthHooks } from "@agent-management-platform/auth";
import type {
  AuditLogFilterValuesResponse,
  AuditLogRecord,
  AuditLogListResponse,
  ExportAuditLogsPathParams,
  ExportAuditLogsQuery,
  QueryAuditLogFilterValuesPathParams,
  QueryAuditLogFilterValuesQuery,
  QueryAuditLogsPathParams,
  QueryAuditLogsQuery,
} from "@agent-management-platform/types";
import {
  exportAuditLogs,
  queryAuditLogFilterValues,
  queryAuditLogs,
  type AuditLogExportFile,
} from "../apis";
import { useApiMutation, useApiQuery } from "./react-query-notifications";

// The audit pages render their own error states (a 403, 501 or 503 says
// something specific about the deployment), so the queries are silent.

export function useQueryAuditLogs(
  params: QueryAuditLogsPathParams,
  query: QueryAuditLogsQuery | undefined,
) {
  const { getToken } = useAuthHooks();
  return useApiQuery<AuditLogListResponse>({
    queryKey: ["audit-logs", params, query],
    queryFn: () => queryAuditLogs(params, query!, getToken),
    enabled: !!params.orgName && !!query,
    placeholderData: keepPreviousData,
    retry: false,
    silent: true,
  });
}

/**
 * The audit trail as a list that grows by "load more".
 *
 * The API pages by narrowing the window, not by offset: the next page is the
 * same query with its far edge moved to the last record's occurredAt. That
 * edge is exclusive, so it is moved one millisecond past the last record and
 * the records seen again are dropped by eventId; otherwise records sharing
 * the boundary millisecond would be skipped. A page that brings nothing new
 * (more records in one millisecond than a page holds) ends the list.
 */
export function useAuditLogTrail(
  params: QueryAuditLogsPathParams,
  query: QueryAuditLogsQuery | undefined,
) {
  const { getToken } = useAuthHooks();
  const first = useQueryAuditLogs(params, query);
  const [extra, setExtra] = useState<AuditLogRecord[]>([]);
  const [exhausted, setExhausted] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadMoreError, setLoadMoreError] = useState<unknown>(null);
  // State updates land after a render, so a second click in the same frame
  // would still see isLoadingMore false; the ref closes that gap.
  const loadingRef = useRef(false);

  useEffect(() => {
    setExtra([]);
    setExhausted(false);
    setLoadMoreError(null);
  }, [first.data]);

  const records = first.data ? [...first.data.records, ...extra] : [];
  const total = first.data?.total ?? 0;
  const hasMore = !!first.data && !exhausted && records.length < total;

  const loadMore = useCallback(async () => {
    if (!query || !first.data || loadingRef.current) return;
    const loaded = [...first.data.records, ...extra];
    const last = loaded[loaded.length - 1];
    if (!last) return;
    const ascending = query.sortOrder === "asc";
    const edge = new Date(last.occurredAt).getTime();
    const next: QueryAuditLogsQuery = ascending
      ? { ...query, startTime: new Date(edge).toISOString() }
      : { ...query, endTime: new Date(edge + 1).toISOString() };
    loadingRef.current = true;
    setIsLoadingMore(true);
    setLoadMoreError(null);
    try {
      const page = await queryAuditLogs(params, next, getToken);
      const seen = new Set(loaded.map((r) => r.eventId));
      const fresh = page.records.filter((r) => !seen.has(r.eventId));
      if (fresh.length === 0) {
        setExhausted(true);
      } else {
        setExtra((prev) => [...prev, ...fresh]);
      }
    } catch (err) {
      setLoadMoreError(err);
    } finally {
      loadingRef.current = false;
      setIsLoadingMore(false);
    }
  }, [query, first.data, extra, params, getToken]);

  return {
    records,
    total,
    tookMs: first.data?.tookMs,
    isLoading: first.isLoading,
    isFetching: first.isFetching,
    error: first.error,
    refetch: first.refetch,
    hasMore,
    loadMore,
    isLoadingMore,
    loadMoreError,
  };
}

export function useQueryAuditLogFilterValues(
  params: QueryAuditLogFilterValuesPathParams,
  query: QueryAuditLogFilterValuesQuery | undefined,
) {
  const { getToken } = useAuthHooks();
  return useApiQuery<AuditLogFilterValuesResponse>({
    queryKey: ["audit-log-filter-values", params, query],
    queryFn: () => queryAuditLogFilterValues(params, query!, getToken),
    enabled: !!params.orgName && !!query,
    staleTime: 60_000,
    retry: false,
    silent: true,
  });
}

export function useExportAuditLogs() {
  const { getToken } = useAuthHooks();
  const queryClient = useQueryClient();
  return useApiMutation<
    AuditLogExportFile,
    unknown,
    { params: ExportAuditLogsPathParams; query: ExportAuditLogsQuery }
  >({
    mutationFn: ({ params, query }) => exportAuditLogs(params, query, getToken),
    showSuccess: false,
    showError: false,
    // Starting an export is itself an audit record.
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["audit-logs"] }),
  });
}
