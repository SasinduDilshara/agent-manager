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
  FEED_FIELDS,
  fieldCoverage,
  isAuditLogView,
  mcpOf,
  modelOf,
  overlappingSpan,
  pairFeeds,
  tokensOf,
} from "./feeds";

function rec(partial: Partial<AuditLogRecord>): AuditLogRecord {
  return {
    eventId: "e",
    occurredAt: "2026-10-20T09:00:00.000Z",
    action: "llm:call",
    result: "success",
    actor: { type: "agent", id: "support-agent" },
    producer: "agent-manager-service.gateway-otel",
    source: "gateway-otel",
    ...partial,
  };
}

describe("pairFeeds", () => {
  it("lines the feeds up by request id, newest first", () => {
    const otel = [
      rec({ eventId: "o1", requestId: "r1", occurredAt: "2026-10-20T09:00:01.000Z" }),
      rec({ eventId: "o2", requestId: "r2", occurredAt: "2026-10-20T09:00:05.000Z" }),
    ];
    const traffic = [
      rec({ eventId: "t1", requestId: "r1", source: "gateway-traffic-log" }),
      rec({
        eventId: "t3",
        requestId: "r3",
        source: "gateway-traffic-log",
        occurredAt: "2026-10-20T09:00:09.000Z",
      }),
    ];
    const pairs = pairFeeds(otel, traffic);
    expect(pairs.map((p) => p.key)).toEqual(["req:r3", "req:r2", "req:r1"]);
    const r1 = pairs.find((p) => p.key === "req:r1")!;
    expect(r1.otel?.eventId).toBe("o1");
    expect(r1.traffic?.eventId).toBe("t1");
    expect(pairs.find((p) => p.key === "req:r2")!.traffic).toBeUndefined();
    expect(pairs.find((p) => p.key === "req:r3")!.otel).toBeUndefined();
  });

  it("keeps a record without a request id on its own", () => {
    const pairs = pairFeeds(
      [rec({ eventId: "o1" })],
      [rec({ eventId: "t1", source: "gateway-traffic-log" })],
    );
    expect(pairs).toHaveLength(2);
  });

  it("keeps the first copy when a feed stored a request twice", () => {
    const pairs = pairFeeds(
      [rec({ eventId: "o1", requestId: "r1" }), rec({ eventId: "o1b", requestId: "r1" })],
      [],
    );
    expect(pairs).toHaveLength(1);
    expect(pairs[0].otel?.eventId).toBe("o1");
  });
});

describe("field readers", () => {
  it("prefers the response model", () => {
    expect(
      modelOf(rec({ details: { requestModel: "gpt-4o", responseModel: "gpt-4o-2024-08-06" } })),
    ).toBe("gpt-4o-2024-08-06");
    expect(modelOf(rec({ details: { requestModel: "gpt-4o" } }))).toBe("gpt-4o");
    expect(modelOf(rec({}))).toBeUndefined();
  });

  it("formats token usage, even when one side is missing", () => {
    expect(tokensOf(rec({ details: { inputTokens: 10, outputTokens: 3 } }))).toBe("10 in / 3 out");
    expect(tokensOf(rec({ details: { inputTokens: 10 } }))).toBe("10 in / – out");
    expect(tokensOf(rec({}))).toBeUndefined();
  });

  it("names the MCP method and its target", () => {
    expect(mcpOf(rec({ details: { mcpMethod: "tools/call", toolName: "create_issue" } }))).toBe(
      "tools/call · create_issue",
    );
    expect(mcpOf(rec({ details: { mcpMethod: "tools/list" } }))).toBe("tools/list");
    expect(mcpOf(rec({}))).toBeUndefined();
  });
});

describe("fieldCoverage", () => {
  it("counts the records carrying each field", () => {
    const records = [
      rec({
        details: {
          responseModel: "gpt-4o",
          inputTokens: 1,
          outputTokens: 2,
          requestBodyExcerpt: "{}",
        },
      }),
      rec({ details: { responseModel: "gpt-4o" } }),
      rec({}),
    ];
    const coverage = fieldCoverage(records);
    expect(coverage.model).toBe(2);
    expect(coverage.tokens).toBe(1);
    expect(coverage.requestBody).toBe(1);
    expect(coverage.guardrail).toBe(0);
    expect(Object.keys(coverage).sort()).toEqual(FEED_FIELDS.map((f) => f.key).sort());
  });

  it("reports a guardrail only when it was hit", () => {
    expect(
      fieldCoverage([rec({ details: { guardrailHit: true, guardrailName: "pii" } })]).guardrail,
    ).toBe(1);
    expect(
      FEED_FIELDS.find((f) => f.key === "guardrail")!.value(
        rec({ details: { guardrailHit: true } }),
      ),
    ).toBe("hit");
  });
});

describe("isAuditLogView", () => {
  it("accepts only the page's views", () => {
    expect(isAuditLogView("compare")).toBe(true);
    expect(isAuditLogView("traffic")).toBe(true);
    expect(isAuditLogView("everything")).toBe(false);
    expect(isAuditLogView(null)).toBe(false);
  });
});

describe("overlappingSpan", () => {
  const at = (sec: number) => `2026-10-20T09:00:${String(sec).padStart(2, "0")}.000Z`;
  it("trims both feeds to the span the capped one covers", () => {
    const otel = [
      rec({ eventId: "o1", occurredAt: at(50) }),
      rec({ eventId: "o2", occurredAt: at(30) }),
    ];
    const traffic = [
      rec({ eventId: "t1", occurredAt: at(50) }),
      rec({ eventId: "t2", occurredAt: at(10) }),
    ];
    const span = overlappingSpan(otel, traffic, { otel: true, traffic: false });
    expect(span.since).toBe(at(30));
    expect(span.otel.map((r) => r.eventId)).toEqual(["o1", "o2"]);
    expect(span.traffic.map((r) => r.eventId)).toEqual(["t1"]);
  });

  it("leaves both feeds whole when neither is capped", () => {
    const span = overlappingSpan([rec({ occurredAt: at(1) })], [rec({ occurredAt: at(2) })], {
      otel: false,
      traffic: false,
    });
    expect(span.since).toBeUndefined();
    expect(span.otel).toHaveLength(1);
    expect(span.traffic).toHaveLength(1);
  });
});

describe("guardrail field", () => {
  it("does not report a guardrail that passed", () => {
    const field = FEED_FIELDS.find((f) => f.key === "guardrail")!;
    expect(field.value(rec({ details: { guardrailHit: false } }))).toBeUndefined();
  });
});
