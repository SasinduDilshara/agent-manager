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

import { beforeEach, describe, expect, it, vi } from "vitest";
import { httpGET } from "../utils";
import { buildAuditEventsSearchParams, listAuditEvents } from "./audit";

vi.mock("../utils", () => ({
  httpGET: vi.fn(),
  SERVICE_BASE: "/api/v1",
  encodeRequired: (v: string | undefined, label: string) => {
    if (!v) throw new Error(`Missing required parameter: ${label}`);
    return encodeURIComponent(v);
  },
}));

const mockGET = vi.mocked(httpGET);

beforeEach(() => {
  mockGET.mockReset();
  mockGET.mockResolvedValue(
    new Response(JSON.stringify({ events: [], nextCursor: null }), { status: 200 }),
  );
});

describe("buildAuditEventsSearchParams", () => {
  it("returns nothing for an empty query", () => {
    expect(buildAuditEventsSearchParams()).toEqual([]);
    expect(buildAuditEventsSearchParams({})).toEqual([]);
  });

  it("repeats multi-valued params and trims text", () => {
    const sp = buildAuditEventsSearchParams({
      startTime: "2026-11-04T10:00:00Z",
      endTime: "2026-11-04T11:00:00Z",
      category: ["LLM", "MCP"],
      agent: ["default/ext-audit-agent", "int-audit-agent"],
      project: "default",
      environment: "default",
      outcome: ["DENIED", "FAILED"],
      actor: "  01a1a364  ",
      search: " echo ",
      limit: 50,
      cursor: "abc",
      sort: "desc",
    });
    expect(sp).toEqual([
      ["startTime", "2026-11-04T10:00:00Z"],
      ["endTime", "2026-11-04T11:00:00Z"],
      ["category", "LLM"],
      ["category", "MCP"],
      ["agent", "default/ext-audit-agent"],
      ["agent", "int-audit-agent"],
      ["project", "default"],
      ["environment", "default"],
      ["outcome", "DENIED"],
      ["outcome", "FAILED"],
      ["actor", "01a1a364"],
      ["search", "echo"],
      ["limit", "50"],
      ["cursor", "abc"],
      ["sort", "desc"],
    ]);
    // URLSearchParams keeps the repeated keys.
    expect(new URLSearchParams(sp).getAll("outcome")).toEqual(["DENIED", "FAILED"]);
  });

  it("sends the STARTED outcome like any other", () => {
    expect(buildAuditEventsSearchParams({ outcome: ["SUCCESS", "STARTED"] })).toEqual([
      ["outcome", "SUCCESS"],
      ["outcome", "STARTED"],
    ]);
  });

  it("drops blank text filters", () => {
    expect(buildAuditEventsSearchParams({ actor: "  ", search: "" })).toEqual([]);
  });
});

describe("listAuditEvents", () => {
  it("calls the org audit endpoint with the token", async () => {
    await listAuditEvents(
      { orgName: "my org" },
      { outcome: ["DENIED"] },
      async () => "tok",
    );
    const [path, opts] = mockGET.mock.calls[0];
    expect(path).toBe("/api/v1/orgs/my%20org/audit/events");
    expect(opts.token).toBe("tok");
    expect(opts.searchParams).toEqual([["outcome", "DENIED"]]);
  });

  it("requires an org", async () => {
    await expect(listAuditEvents({ orgName: undefined })).rejects.toThrow(/orgName/);
  });
});
