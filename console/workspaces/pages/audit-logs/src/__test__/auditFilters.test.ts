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

import { describe, expect, it } from "vitest";
import {
  activeFilterCount,
  clearedFilters,
  DEFAULT_TIME_PRESET,
  PAGE_SIZE,
  parseAuditFilters,
  resolveTimeWindow,
  toAuditQuery,
  withAuditFilters,
} from "../auditFilters";

const sp = (s: string) => new URLSearchParams(s);
const NOW = Date.parse("2026-11-04T12:00:00.000Z");

describe("parseAuditFilters", () => {
  it("defaults to the last 24 hours, newest first, no filters", () => {
    expect(parseAuditFilters(sp(""))).toEqual({
      timeRange: DEFAULT_TIME_PRESET,
      startTime: undefined,
      endTime: undefined,
      category: undefined,
      agents: [],
      project: undefined,
      environment: undefined,
      outcomes: [],
      actor: undefined,
      search: undefined,
      sort: "desc",
    });
  });

  it("reads every filter, including repeated agent and outcome params", () => {
    const f = parseAuditFilters(
      sp(
        "timeRange=7d&category=MCP&agent=default/ext-audit-agent&agent=default/int-audit-agent" +
          "&project=default&environment=dev&outcome=DENIED&outcome=FAILED" +
          "&actor=01a1a364&search=echo&sort=asc",
      ),
    );
    expect(f).toMatchObject({
      timeRange: "7d",
      category: "MCP",
      agents: ["default/ext-audit-agent", "default/int-audit-agent"],
      project: "default",
      environment: "dev",
      outcomes: ["DENIED", "FAILED"],
      actor: "01a1a364",
      search: "echo",
      sort: "asc",
    });
  });

  it("reads and writes the STARTED outcome", () => {
    expect(parseAuditFilters(sp("outcome=STARTED&outcome=SUCCESS")).outcomes).toEqual(["STARTED", "SUCCESS"]);
    expect(withAuditFilters(sp(""), { outcomes: ["STARTED"] }).getAll("outcome")).toEqual(["STARTED"]);
  });

  it("drops unknown enum values, duplicates and malformed ranges", () => {
    const f = parseAuditFilters(
      sp(
        "timeRange=2y&category=BOGUS&outcome=MAYBE&outcome=DENIED&outcome=DENIED" +
          "&agent=a&agent=a&agent=%20&startTime=2026-11-04T12:00:00Z&endTime=2026-11-04T11:00:00Z",
      ),
    );
    expect(f.timeRange).toBe(DEFAULT_TIME_PRESET);
    expect(f.category).toBeUndefined();
    expect(f.outcomes).toEqual(["DENIED"]);
    expect(f.agents).toEqual(["a"]);
    expect(f.startTime).toBeUndefined();
  });

  it("uses a valid custom range", () => {
    const f = parseAuditFilters(
      sp("startTime=2026-10-01T00:00:00Z&endTime=2026-10-02T00:00:00Z&timeRange=1h"),
    );
    expect(f.startTime).toBe("2026-10-01T00:00:00Z");
    expect(f.endTime).toBe("2026-10-02T00:00:00Z");
  });
});

describe("withAuditFilters", () => {
  it("round-trips through the URL", () => {
    const patch = {
      timeRange: "1h" as const,
      category: "LLM" as const,
      agents: ["default/ext-audit-agent"],
      outcomes: ["DENIED" as const],
      actor: "admin",
      search: "gpt-4o",
    };
    const next = withAuditFilters(sp(""), patch);
    expect(parseAuditFilters(next)).toMatchObject(patch);
    expect(next.getAll("agent")).toEqual(["default/ext-audit-agent"]);
  });

  it("leaves defaults out of the URL and keeps unrelated params", () => {
    const next = withAuditFilters(sp("foo=bar&category=LLM&sort=asc"), {
      category: undefined,
      sort: "desc",
      timeRange: DEFAULT_TIME_PRESET,
    });
    expect(next.toString()).toBe("foo=bar");
  });

  it("switching to a preset clears the custom range", () => {
    const next = withAuditFilters(
      sp("startTime=2026-10-01T00:00:00Z&endTime=2026-10-02T00:00:00Z"),
      { timeRange: "15m", startTime: undefined, endTime: undefined },
    );
    expect(next.get("startTime")).toBeNull();
    expect(next.get("timeRange")).toBe("15m");
  });

  it("writes repeated outcome params in a stable order without duplicates", () => {
    const next = withAuditFilters(sp(""), { outcomes: ["FAILED", "DENIED", "FAILED"] });
    expect(next.getAll("outcome")).toEqual(["FAILED", "DENIED"]);
  });

  it("clearing keeps the time range, tab and sort", () => {
    const start = sp("timeRange=7d&category=MCP&outcome=DENIED&actor=x&sort=asc&agent=p/a");
    const f = parseAuditFilters(start);
    expect(activeFilterCount(f)).toBe(3);
    const next = withAuditFilters(start, clearedFilters(f));
    expect(next.toString()).toBe("timeRange=7d&category=MCP&sort=asc");
  });
});

describe("toAuditQuery", () => {
  it("maps filters to the API contract", () => {
    const f = parseAuditFilters(
      sp("timeRange=1h&category=A2A&agent=default/a2a-notes-agent&outcome=SUCCESS&project=default"),
    );
    expect(toAuditQuery(f, NOW)).toEqual({
      startTime: "2026-11-04T11:00:00.000Z",
      endTime: "2026-11-04T12:00:00.000Z",
      category: ["A2A"],
      agent: ["default/a2a-notes-agent"],
      project: "default",
      environment: undefined,
      outcome: ["SUCCESS"],
      actor: undefined,
      search: undefined,
      limit: PAGE_SIZE,
      sort: "desc",
    });
  });

  it("can leave the category out, for the tab counts", () => {
    const f = parseAuditFilters(sp("category=LLM"));
    expect(toAuditQuery(f, NOW, { includeCategory: false }).category).toBeUndefined();
  });

  it("passes a custom range through unchanged", () => {
    const f = parseAuditFilters(
      sp("startTime=2026-06-01T00:00:00Z&endTime=2026-11-01T00:00:00Z"),
    );
    expect(resolveTimeWindow(f, NOW)).toEqual({
      startTime: "2026-06-01T00:00:00Z",
      endTime: "2026-11-01T00:00:00Z",
    });
  });
});
