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

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AuditLogListResponse,
  AuditLogRecord,
  QueryAuditLogsQuery,
} from "@agent-management-platform/types";
import type * as AuditApi from "../apis/audit-logs";
import { queryAuditLogs } from "../apis/audit-logs";
import { useAuditLogTrail } from "./audit-logs";

const { getToken } = vi.hoisted(() => ({ getToken: async () => "token" }));

vi.mock("../apis/audit-logs", async (importOriginal) => ({
  ...(await importOriginal<typeof AuditApi>()),
  queryAuditLogs: vi.fn(),
}));
vi.mock("@agent-management-platform/auth", () => ({ useAuthHooks: () => ({ getToken }) }));
vi.mock("./react-query-notifications", async () => {
  const rq = await import("@tanstack/react-query");
  return { useApiQuery: rq.useQuery, useApiMutation: rq.useMutation };
});

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mockQuery = vi.mocked(queryAuditLogs);

const QUERY: QueryAuditLogsQuery = {
  startTime: "2026-10-20T09:00:00.000Z",
  endTime: "2026-10-20T10:00:00.000Z",
  limit: 2,
  sortOrder: "desc",
};

function rec(id: string, occurredAt: string): AuditLogRecord {
  return {
    eventId: id,
    occurredAt,
    action: "llm:call",
    result: "success",
    actor: { type: "agent", id: "support-agent" },
    producer: "agent-manager-service",
  };
}

function page(records: AuditLogRecord[], total: number): AuditLogListResponse {
  return { records, total };
}

type HookResult = ReturnType<typeof useAuditLogTrail>;
let root: Root | undefined;

function renderTrail(query: QueryAuditLogsQuery) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const result = {} as { current: HookResult };
  function Probe() {
    result.current = useAuditLogTrail({ orgName: "acme" }, query);
    return null;
  }
  root = createRoot(document.createElement("div"));
  act(() => {
    root!.render(
      <QueryClientProvider client={client}>
        <Probe />
      </QueryClientProvider>,
    );
  });
  return result;
}

async function waitFor(check: () => boolean) {
  for (let i = 0; i < 50 && !check(); i += 1) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
  expect(check()).toBe(true);
}

beforeEach(() => mockQuery.mockReset());

afterEach(() => {
  act(() => root?.unmount());
  root = undefined;
});

describe("useAuditLogTrail paging", () => {
  it("moves the exclusive end one millisecond past the last record and drops records seen again", async () => {
    mockQuery
      .mockResolvedValueOnce(
        page([rec("a", "2026-10-20T09:50:00.000Z"), rec("b", "2026-10-20T09:40:00.005Z")], 4),
      )
      // The boundary millisecond is queried again, so "b" comes back.
      .mockResolvedValueOnce(
        page([rec("b", "2026-10-20T09:40:00.005Z"), rec("c", "2026-10-20T09:40:00.005Z")], 3),
      );

    const result = renderTrail(QUERY);
    await waitFor(() => result.current.records.length === 2);
    expect(result.current.hasMore).toBe(true);

    await act(() => result.current.loadMore());
    const next = mockQuery.mock.calls[1][1];
    expect(next.endTime).toBe("2026-10-20T09:40:00.006Z");
    expect(next.startTime).toBe(QUERY.startTime);
    expect(result.current.records.map((r) => r.eventId)).toEqual(["a", "b", "c"]);
    expect(result.current.total).toBe(4);
    expect(result.current.hasMore).toBe(true);
  });

  it("moves the start in ascending order", async () => {
    mockQuery
      .mockResolvedValueOnce(
        page([rec("a", "2026-10-20T09:10:00.000Z"), rec("b", "2026-10-20T09:20:00.000Z")], 3),
      )
      .mockResolvedValueOnce(page([rec("c", "2026-10-20T09:30:00.000Z")], 2));

    const result = renderTrail({ ...QUERY, sortOrder: "asc" });
    await waitFor(() => result.current.records.length === 2);
    await act(() => result.current.loadMore());
    const next = mockQuery.mock.calls[1][1];
    expect(next.startTime).toBe("2026-10-20T09:20:00.000Z");
    expect(next.endTime).toBe(QUERY.endTime);
    expect(result.current.records.map((r) => r.eventId)).toEqual(["a", "b", "c"]);
    expect(result.current.hasMore).toBe(false);
  });

  it("stops when a page brings nothing new", async () => {
    // More records share the boundary millisecond than a page holds.
    const same = "2026-10-20T09:40:00.000Z";
    mockQuery
      .mockResolvedValueOnce(page([rec("a", same), rec("b", same)], 5))
      .mockResolvedValueOnce(page([rec("a", same), rec("b", same)], 5));

    const result = renderTrail(QUERY);
    await waitFor(() => result.current.records.length === 2);
    await act(() => result.current.loadMore());
    expect(result.current.records).toHaveLength(2);
    expect(result.current.hasMore).toBe(false);
  });

  it("keeps the loaded records and reports a failed page", async () => {
    mockQuery
      .mockResolvedValueOnce(page([rec("a", "2026-10-20T09:50:00.000Z")], 2))
      .mockRejectedValueOnce(Object.assign(new Error("HTTP error! status: 503"), { status: 503 }));

    const result = renderTrail(QUERY);
    await waitFor(() => result.current.records.length === 1);
    await act(() => result.current.loadMore());
    expect(result.current.records).toHaveLength(1);
    expect((result.current.loadMoreError as { status?: number }).status).toBe(503);
    expect(result.current.hasMore).toBe(true);
  });
});

describe("useAuditLogTrail double load", () => {
  it("loads a page once when loadMore is called twice before it settles", async () => {
    let release: (value: AuditLogListResponse) => void = () => {};
    mockQuery
      .mockResolvedValueOnce(page([rec("a", "2026-10-20T09:50:00.000Z")], 3))
      .mockImplementationOnce(
        () => new Promise<AuditLogListResponse>((resolve) => (release = resolve)),
      );

    const result = renderTrail(QUERY);
    await waitFor(() => result.current.records.length === 1);
    let first: Promise<void> = Promise.resolve();
    act(() => {
      first = result.current.loadMore();
      void result.current.loadMore();
    });
    await act(async () => {
      release(page([rec("b", "2026-10-20T09:40:00.000Z")], 3));
      await first;
    });
    expect(mockQuery).toHaveBeenCalledTimes(2);
    expect(result.current.records.map((r) => r.eventId)).toEqual(["a", "b"]);
  });
});
