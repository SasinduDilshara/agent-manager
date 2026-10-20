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

import { describe, expect, it } from "vitest";
import type { AuditLogRecord } from "@agent-management-platform/types";
import {
  DAY_MS,
  describeAuditError,
  formatResource,
  formatTimestamp,
  isTimeRangePreset,
  presetWindow,
} from "./utils";

const httpError = (status: number) =>
  Object.assign(new Error(`HTTP error! status: ${status}`), { status });

function rec(partial: Partial<AuditLogRecord> = {}): AuditLogRecord {
  return {
    eventId: "e1",
    occurredAt: "2026-10-20T09:15:02.481Z",
    action: "agent:deploy",
    result: "success",
    actor: { type: "user", id: "u1" },
    producer: "agent-manager-service",
    ...partial,
  };
}

describe("presetWindow", () => {
  const anchor = Date.parse("2026-10-20T10:00:00.000Z");

  it("ends at the anchor and spans the preset", () => {
    expect(presetWindow("7d", anchor)).toEqual({
      startTime: new Date(anchor - 7 * DAY_MS).toISOString(),
      endTime: "2026-10-20T10:00:00.000Z",
    });
  });

  it("falls back to the default preset for an unknown value", () => {
    expect(presetWindow("forever", anchor).startTime).toBe(
      new Date(anchor - DAY_MS).toISOString(),
    );
  });

  it("recognises only the offered presets", () => {
    expect(isTimeRangePreset("90d")).toBe(true);
    expect(isTimeRangePreset("10m")).toBe(false);
    expect(isTimeRangePreset(null)).toBe(false);
  });
});

describe("formatResource", () => {
  it("prefers the name over the id", () => {
    expect(formatResource(rec({ resource: { type: "agent", id: "a-1", name: "support" } }))).toBe(
      "agent/support",
    );
  });

  it("falls back to whatever is present", () => {
    expect(formatResource(rec({ resource: { id: "a-1" } }))).toBe("a-1");
    expect(formatResource(rec())).toBe("—");
  });
});

describe("formatTimestamp", () => {
  it("keeps the milliseconds", () => {
    expect(formatTimestamp("2026-10-20T09:15:02.481Z")).toMatch(/\.481$/);
  });

  it("returns an unparseable value as it came", () => {
    expect(formatTimestamp("not-a-time")).toBe("not-a-time");
  });
});

describe("describeAuditError", () => {
  it("names the missing permission on 403", () => {
    expect(describeAuditError(httpError(403), "read").message).toContain("audit-log:read");
    expect(describeAuditError(httpError(403), "export").message).toContain("audit-log:export");
  });

  it("explains a backend without an audit store on 501", () => {
    expect(describeAuditError(httpError(501), "read").title).toBe("Audit trail not available");
  });

  it("says an export refused on 503 was not started", () => {
    expect(describeAuditError(httpError(503), "export").title).toBe("Export not started");
  });

  it("falls back to the error's message", () => {
    expect(describeAuditError(new Error("Failed to fetch"), "read").message).toBe(
      "Failed to fetch",
    );
  });
});
