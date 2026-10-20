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

import { beforeEach, describe, expect, it, vi } from "vitest";
import { httpGET } from "../utils";
import {
  exportAuditLogs,
  parseAuditExportManifest,
  queryAuditLogFilterValues,
  queryAuditLogs,
} from "./audit-logs";

vi.mock("../utils", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../utils")>()),
  httpGET: vi.fn(),
}));

const mockGET = vi.mocked(httpGET);

const WINDOW = {
  startTime: "2026-10-20T09:00:00.000Z",
  endTime: "2026-10-20T10:00:00.000Z",
};

function sent(): { path: string; pairs: string[][] } {
  const [path, opts] = mockGET.mock.calls[0];
  return { path, pairs: opts.searchParams as string[][] };
}

beforeEach(() => {
  mockGET.mockReset();
  mockGET.mockImplementation(
    async () => new Response(JSON.stringify({ records: [], total: 0 })),
  );
});

describe("queryAuditLogs", () => {
  it("repeats multi-valued filters and leaves empty ones out", async () => {
    await queryAuditLogs(
      { orgName: "acme" },
      {
        ...WINDOW,
        action: ["llm:call", "mcp:tool-call"],
        result: [],
        agent: ["support-agent"],
        search: "",
        limit: 100,
        sortOrder: "desc",
      },
    );
    const { path, pairs } = sent();
    expect(path).toBe("/api/v1/orgs/acme/audit-logs");
    expect(pairs).toEqual([
      ["startTime", WINDOW.startTime],
      ["endTime", WINDOW.endTime],
      ["action", "llm:call"],
      ["action", "mcp:tool-call"],
      ["agent", "support-agent"],
      ["limit", "100"],
      ["sortOrder", "desc"],
    ]);
  });

  it("encodes the organization into the path", async () => {
    await queryAuditLogs({ orgName: "a/b" }, { ...WINDOW });
    expect(sent().path).toBe("/api/v1/orgs/a%2Fb/audit-logs");
  });

  it("refuses to send a request without an organization", async () => {
    await expect(queryAuditLogs({ orgName: undefined }, { ...WINDOW })).rejects.toThrow(
      "orgName",
    );
    expect(mockGET).not.toHaveBeenCalled();
  });
});

describe("queryAuditLogFilterValues", () => {
  it("sends the field, the window and the value search", async () => {
    await queryAuditLogFilterValues(
      { orgName: "acme" },
      { ...WINDOW, filter: "action", valueSearch: "llm", maxValues: 50 },
    );
    const { path, pairs } = sent();
    expect(path).toBe("/api/v1/orgs/acme/audit-logs/filter-values");
    expect(pairs).toEqual([
      ["startTime", WINDOW.startTime],
      ["endTime", WINDOW.endTime],
      ["filter", "action"],
      ["valueSearch", "llm"],
      ["maxValues", "50"],
    ]);
  });
});

const MANIFEST = {
  complete: true,
  exportedCount: 2,
  storeCount: 2,
  startTime: WINDOW.startTime,
  endTime: WINDOW.endTime,
  sha256: "ab12",
};

describe("parseAuditExportManifest", () => {
  it("reads the manifest from the last line", () => {
    const text = `{"eventId":"1"}\n{"eventId":"2"}\n${JSON.stringify({ manifest: MANIFEST })}\n`;
    expect(parseAuditExportManifest(text)).toEqual(MANIFEST);
  });

  it("reports a file whose last line is a record as cut off", () => {
    expect(parseAuditExportManifest(`{"eventId":"1"}\n`)).toBeUndefined();
  });

  it("reports a truncated last line as cut off", () => {
    expect(parseAuditExportManifest(`{"eventId":"1"}\n{"manif`)).toBeUndefined();
  });

  it("reports an empty file as cut off", () => {
    expect(parseAuditExportManifest("")).toBeUndefined();
  });
});

describe("exportAuditLogs", () => {
  it("returns the file, its server-given name and its manifest", async () => {
    const body = `{"eventId":"1"}\n${JSON.stringify({ manifest: MANIFEST })}\n`;
    mockGET.mockImplementation(
      async () =>
        new Response(body, {
          headers: {
            "Content-Disposition":
              'attachment; filename="audit-logs-20261020T090000Z-20261020T100000Z.ndjson"',
          },
        }),
    );
    const file = await exportAuditLogs({ orgName: "acme" }, { ...WINDOW });
    expect(sent().path).toBe("/api/v1/orgs/acme/audit-logs/export");
    expect(file.filename).toBe("audit-logs-20261020T090000Z-20261020T100000Z.ndjson");
    expect(file.manifest).toEqual(MANIFEST);
    expect(await file.blob.text()).toBe(body);
  });

  it("falls back to a generic name when the server sends none", async () => {
    mockGET.mockImplementation(async () => new Response(""));
    const file = await exportAuditLogs({ orgName: "acme" }, { ...WINDOW });
    expect(file.filename).toBe("audit-logs.ndjson");
    expect(file.manifest).toBeUndefined();
  });
});

describe("exportAuditLogs on a large file", () => {
  it("finds the manifest at the end without reading the records", async () => {
    const records = Array.from({ length: 2000 }, (_, i) =>
      JSON.stringify({ eventId: `e${i}`, details: { pad: "x".repeat(64) } }),
    ).join("\n");
    const body = `${records}\n${JSON.stringify({ manifest: MANIFEST })}\n`;
    expect(body.length).toBeGreaterThan(64 * 1024);
    mockGET.mockImplementation(async () => new Response(body));
    const file = await exportAuditLogs({ orgName: "acme" }, { ...WINDOW });
    expect(file.manifest).toEqual(MANIFEST);
  });
});
