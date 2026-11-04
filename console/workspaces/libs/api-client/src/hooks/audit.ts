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

import { useCallback, useMemo, useState } from "react";
import { useAuthHooks } from "@agent-management-platform/auth";
import type {
  AuditEvent,
  AuditEventListResponse,
  ListAuditEventsPathParams,
  ListAuditEventsQuery,
} from "@agent-management-platform/types";
import { listAuditEvents } from "../apis";
import { useApiQuery } from "./react-query-notifications";

interface ExtraPages {
  // Identifies the result set the pages were appended to; pages kept under an
  // older key are dropped, so a filter change or refresh starts from page one.
  key: string;
  pages: AuditEventListResponse[];
  error: unknown;
}

const EMPTY_EXTRA: ExtraPages = { key: "", pages: [], error: null };

/**
 * Organization audit events with cursor ("Load more") pagination.
 *
 * The first page is an ordinary query, so it caches, refetches and reports
 * errors like every other list; later pages are fetched on demand with the
 * previous page's nextCursor and appended. The API sorts by @timestamp with an
 * _id tie-break, so pages never overlap, but rows are still de-duplicated by
 * id in case an event was indexed between two requests.
 */
export function useAuditEvents(
  params: ListAuditEventsPathParams,
  query: ListAuditEventsQuery,
  options: { enabled?: boolean } = {},
) {
  const { getToken } = useAuthHooks();
  const first = useApiQuery<AuditEventListResponse>({
    queryKey: ["audit-events", params, query],
    queryFn: () => listAuditEvents(params, query, getToken),
    enabled: !!params.orgName && options.enabled !== false,
    // The page shows its own inline error state for this list.
    silent: true,
    // A background refetch would reset the pages the user already loaded.
    refetchOnWindowFocus: false,
  });

  const resultKey = JSON.stringify([params, query, first.dataUpdatedAt]);
  const [extra, setExtra] = useState<ExtraPages>(EMPTY_EXTRA);
  const [loadingKey, setLoadingKey] = useState<string | null>(null);
  const current = extra.key === resultKey ? extra : EMPTY_EXTRA;

  const lastPage = current.pages[current.pages.length - 1] ?? first.data;
  const nextCursor = lastPage?.nextCursor || null;

  const events = useMemo(() => {
    const seen = new Set<string>();
    const out: AuditEvent[] = [];
    for (const page of [first.data, ...current.pages]) {
      for (const event of page?.events ?? []) {
        if (seen.has(event.id)) continue;
        seen.add(event.id);
        out.push(event);
      }
    }
    return out;
  }, [first.data, current.pages]);

  const loadMore = useCallback(async () => {
    if (!nextCursor || loadingKey === resultKey) return;
    const key = resultKey;
    setLoadingKey(key);
    try {
      const page = await listAuditEvents(
        params,
        { ...query, cursor: nextCursor },
        getToken,
      );
      // Stored under the key it was requested for: if the filters changed
      // meanwhile, `current` no longer matches it and the page is ignored.
      setExtra((prev) => ({
        key,
        pages: [...(prev.key === key ? prev.pages : []), page],
        error: null,
      }));
    } catch (error) {
      setExtra((prev) => ({
        key,
        pages: prev.key === key ? prev.pages : [],
        error,
      }));
    } finally {
      setLoadingKey((k) => (k === key ? null : k));
    }
  }, [nextCursor, loadingKey, resultKey, params, query, getToken]);

  return {
    events,
    firstPage: first.data,
    total: first.data?.total,
    totalRelation: first.data?.totalRelation,
    categoryCounts: first.data?.categoryCounts,
    hasMore: !!nextCursor,
    isLoading: first.isLoading,
    isFetching: first.isFetching,
    isLoadingMore: loadingKey === resultKey,
    error: first.error,
    loadMoreError: current.error,
    loadMore,
    refetch: first.refetch,
  };
}
