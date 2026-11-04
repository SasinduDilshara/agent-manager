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

import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { ThemeProvider, createTheme } from "@wso2/oxygen-ui";
import type { AuditEvent, ListAuditEventsQuery } from "@agent-management-platform/types";

// api-client needs a configured app shell at import time; stub it at the
// module boundary, as the other page packages do.
vi.mock("@agent-management-platform/api-client", () => ({
  useAuditEvents: vi.fn(),
  useTokenScopes: vi.fn(),
  useListOrgAgents: vi.fn(() => ({
    data: {
      agents: [
        { name: "ext-audit-agent", displayName: "Ext Audit Agent", projectName: "default", projectDisplayName: "Default" },
        { name: "a2a-notes-agent", displayName: "Notes", projectName: "default", projectDisplayName: "Default" },
      ],
    },
    isLoading: false,
  })),
  useListProjects: vi.fn(() => ({ data: { projects: [{ name: "default", displayName: "Default" }] } })),
  useListEnvironments: vi.fn(() => ({ data: [{ name: "default", displayName: "Development" }] })),
}));
vi.mock("@agent-management-platform/shared-component", () => ({
  formatRelativeTime: () => "5 minutes ago",
  copyToClipboard: vi.fn(() => Promise.resolve(true)),
}));

import { useAuditEvents, useTokenScopes } from "@agent-management-platform/api-client";
import { AuditLogsOrganization } from "../AuditLogs.Organization";
import {
  ALL_EVENTS,
  llmChatOk,
  mcpOboToolsCallDenied,
  PAGE_ONE,
} from "./fixtures";

const mockUseAuditEvents = vi.mocked(useAuditEvents);
const mockUseTokenScopes = vi.mocked(useTokenScopes);

type HookResult = ReturnType<typeof useAuditEvents>;

function hookResult(overrides: Partial<HookResult> = {}): HookResult {
  return {
    events: ALL_EVENTS,
    firstPage: PAGE_ONE,
    total: PAGE_ONE.total,
    totalRelation: PAGE_ONE.totalRelation,
    categoryCounts: PAGE_ONE.categoryCounts,
    hasMore: true,
    isLoading: false,
    isFetching: false,
    isLoadingMore: false,
    error: null,
    loadMoreError: null,
    loadMore: vi.fn(),
    refetch: vi.fn(),
    ...overrides,
  } as unknown as HookResult;
}

let currentSearch = "";
function LocationProbe() {
  currentSearch = useLocation().search;
  return null;
}

function renderPage(search = "") {
  return render(
    <ThemeProvider theme={createTheme()}>
      <MemoryRouter initialEntries={[`/org/default/audit${search}`]}>
        <Routes>
          <Route
            path="/org/:orgId/audit/*"
            element={
              <>
                <AuditLogsOrganization />
                <LocationProbe />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </ThemeProvider>,
  );
}

/** The query the main (non-count) list was last called with. */
function lastListQuery(): ListAuditEventsQuery {
  const calls = mockUseAuditEvents.mock.calls.filter(([, q]) => q.limit !== 1);
  return calls[calls.length - 1][1];
}

function rowFor(event: AuditEvent) {
  return screen.getByRole("row", { name: new RegExp(`^${event.action} by .*${event.outcome.toLowerCase()}`, "i") });
}

beforeEach(() => {
  mockUseAuditEvents.mockReset();
  mockUseAuditEvents.mockImplementation(() => hookResult());
  mockUseTokenScopes.mockReturnValue({
    enforced: true,
    resolved: true,
    scopes: new Set(["amp:observability:log-read"]),
  });
});

afterEach(() => {
  currentSearch = "";
});

describe("filters ↔ URL", () => {
  it("maps URL params to the API query", () => {
    renderPage(
      "?timeRange=7d&agent=default/ext-audit-agent&outcome=DENIED&outcome=FAILED&actor=admin",
    );
    const q = lastListQuery();
    expect(q.agent).toEqual(["default/ext-audit-agent"]);
    expect(q.outcome).toEqual(["DENIED", "FAILED"]);
    expect(q.actor).toBe("admin");
    expect(q.category).toBeUndefined();
    expect(Date.parse(q.endTime!) - Date.parse(q.startTime!)).toBe(7 * 24 * 60 * 60 * 1000);
    expect(screen.getByRole("button", { name: /clear filters \(4\)/i })).toBeInTheDocument();
  });

  it("writes outcome chip toggles to the URL", () => {
    renderPage();
    fireEvent.click(screen.getByTestId("outcome-filter-DENIED"));
    expect(new URLSearchParams(currentSearch).getAll("outcome")).toEqual(["DENIED"]);
    expect(lastListQuery().outcome).toEqual(["DENIED"]);
    expect(screen.getByTestId("outcome-filter-DENIED")).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(screen.getByTestId("outcome-filter-DENIED"));
    expect(new URLSearchParams(currentSearch).getAll("outcome")).toEqual([]);
  });

  it("clears filters but keeps the time range", () => {
    renderPage("?timeRange=1h&outcome=FAILED&search=echo");
    fireEvent.click(screen.getByRole("button", { name: /clear filters/i }));
    expect(currentSearch).toBe("?timeRange=1h");
  });

  it("does not query without the log-read scope", () => {
    mockUseTokenScopes.mockReturnValue({ enforced: true, resolved: true, scopes: new Set() });
    renderPage();
    expect(screen.getByText(/don't have permission to view audit logs/i)).toBeInTheDocument();
    for (const [, , opts] of mockUseAuditEvents.mock.calls) {
      expect(opts?.enabled).toBe(false);
    }
  });
});

describe("category tabs", () => {
  it("shows a count per category and the total on All", () => {
    renderPage();
    const tabs = screen.getByRole("tablist", { name: /audit event categories/i });
    expect(within(tabs).getByRole("tab", { name: /^all events, 11$/i })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(within(tabs).getByRole("tab", { name: /^llm events, 4$/i })).toBeInTheDocument();
    expect(within(tabs).getByRole("tab", { name: /^mcp events, 3$/i })).toBeInTheDocument();
    expect(within(tabs).getByRole("tab", { name: /^operational events, 1$/i })).toBeInTheDocument();
  });

  it("selecting a tab filters the list and fetches counts without the category", () => {
    renderPage();
    fireEvent.click(screen.getByRole("tab", { name: /^llm events/i }));
    expect(new URLSearchParams(currentSearch).get("category")).toBe("LLM");
    expect(lastListQuery().category).toEqual(["LLM"]);

    const countCalls = mockUseAuditEvents.mock.calls.filter(([, q]) => q.limit === 1);
    const [, countQuery, countOpts] = countCalls[countCalls.length - 1];
    expect(countQuery.category).toBeUndefined();
    expect(countOpts?.enabled).toBe(true);
  });
});

describe("results table", () => {
  it("renders outcome chips with their colour per outcome", () => {
    renderPage();
    const denied = within(rowFor(mcpOboToolsCallDenied)).getByTestId("outcome-DENIED");
    expect(denied).toHaveTextContent("Denied");
    expect(denied.className).toMatch(/colorWarning/);
    const ok = within(rowFor(llmChatOk)).getByTestId("outcome-SUCCESS");
    expect(ok.className).toMatch(/colorSuccess/);
    expect(screen.getAllByTestId("outcome-FAILED")[0].className).toMatch(/colorError/);
  });

  it("badges delegated calls", () => {
    renderPage();
    expect(within(rowFor(mcpOboToolsCallDenied)).getByText("on behalf of")).toBeInTheDocument();
    expect(within(rowFor(llmChatOk)).queryByText("on behalf of")).toBeNull();
  });

  it("loads more through the cursor", () => {
    const loadMore = vi.fn();
    mockUseAuditEvents.mockImplementation(() => hookResult({ loadMore }));
    renderPage();
    fireEvent.click(screen.getByRole("button", { name: /load more/i }));
    expect(loadMore).toHaveBeenCalled();
  });

  it("shows an empty state", () => {
    mockUseAuditEvents.mockImplementation(() =>
      hookResult({ events: [], hasMore: false, total: 0, categoryCounts: {} }),
    );
    renderPage("?outcome=DENIED");
    expect(screen.getByText("No audit events found")).toBeInTheDocument();
    expect(screen.getByText(/no events match these filters/i)).toBeInTheDocument();
  });

  it("explains an unreachable audit store", () => {
    mockUseAuditEvents.mockImplementation(() =>
      hookResult({ events: [], error: Object.assign(new Error("x"), { status: 502 }) }),
    );
    renderPage();
    expect(screen.getByText(/audit store is unreachable/i)).toBeInTheDocument();
  });
});

describe("detail drawer", () => {
  it("renders the delegation chain and the denial decision", async () => {
    renderPage();
    fireEvent.click(rowFor(mcpOboToolsCallDenied));

    const chain = await screen.findByTestId("delegation-chain");
    const hops = within(chain).getAllByRole("listitem");
    expect(hops).toHaveLength(2);
    expect(hops[0]).toHaveTextContent("User01900000-0000-7000-8000-000000000030");
    expect(hops[1]).toHaveTextContent("Agentext-audit-agent");

    expect(screen.getByTestId("denied-alert")).toHaveTextContent(
      "Denied by policy mcp-authz during request_headers.",
    );
    const decision = screen.getByTestId("decision-section");
    expect(decision).toHaveTextContent("policy_denied");
    expect(decision).toHaveTextContent("mcp-authz");
    expect(decision).toHaveTextContent("v1");

    const mcp = screen.getByTestId("mcp-section");
    expect(mcp).toHaveTextContent("tools/call");
    expect(mcp).toHaveTextContent(mcpOboToolsCallDenied.mcp!.sessionId!);

    expect(screen.getByTestId("raw-json")).toHaveTextContent('"terminalReason": "policy_denied"');
  });

  it("opens from the keyboard and shows LLM details", async () => {
    renderPage();
    fireEvent.keyDown(rowFor(llmChatOk), { key: "Enter" });
    const llm = await screen.findByTestId("llm-section");
    expect(llm).toHaveTextContent("gpt-4o-mini-2024-07-18");
    expect(llm).toHaveTextContent("17");
    expect(screen.queryByTestId("delegation-chain")).toBeNull();
    expect(screen.queryByTestId("denied-alert")).toBeNull();
  });
});
