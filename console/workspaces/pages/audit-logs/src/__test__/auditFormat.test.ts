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
import type { AuditEvent } from "@agent-management-platform/types";
import {
  actorLabel,
  agentLabel,
  delegationPath,
  hasDelegation,
  toCsv,
  toJson,
} from "../auditFormat";
import {
  ALL_EVENTS,
  cpAgentCreate,
  llmChatOk,
  mcpOboToolsCallDenied,
  mcpToolsCallOk,
} from "./fixtures";

const USER = "01900000-0000-7000-8000-000000000030";
const AGENT = "01a1a364-bef0-7b63-bad3-f7f002d3e771";

describe("delegationPath", () => {
  it("renders the act chain as user → agent", () => {
    expect(hasDelegation(mcpOboToolsCallDenied)).toBe(true);
    expect(delegationPath(mcpOboToolsCallDenied)).toEqual([
      { id: USER, role: "subject" },
      { id: AGENT, role: "actor", display: "ext-audit-agent" },
    ]);
  });

  it("reverses a nested chain so the current actor comes last", () => {
    const event: AuditEvent = {
      ...mcpOboToolsCallDenied,
      actor: { type: "AGENT", id: "agent-b", display: "planner" },
      // Outermost (current actor) first, as in the token's nested act claim.
      onBehalfOf: { subject: "user-1", chain: ["agent-b", "agent-a"] },
    };
    expect(delegationPath(event).map((h) => h.display ?? h.id)).toEqual([
      "user-1",
      "agent-a",
      "planner",
    ]);
  });

  it("closes the path with the actor when the chain is empty", () => {
    const event: AuditEvent = {
      ...mcpToolsCallOk,
      onBehalfOf: { subject: "user-1", chain: [] },
    };
    expect(delegationPath(event).map((h) => h.id)).toEqual(["user-1", AGENT]);
  });

  it("is empty without delegation", () => {
    expect(hasDelegation(mcpToolsCallOk)).toBe(false);
    expect(delegationPath(mcpToolsCallOk)).toEqual([]);
  });
});

describe("labels", () => {
  it("prefers the resolved display name", () => {
    expect(actorLabel(mcpToolsCallOk.actor)).toBe("ext-audit-agent");
    expect(actorLabel(cpAgentCreate.actor)).toBe("admin");
    expect(actorLabel(llmChatOk.actor)).toBe("API key");
    expect(agentLabel(llmChatOk)).toBe("default/ext-audit-agent");
    expect(agentLabel(cpAgentCreate)).toBeUndefined();
  });
});

describe("export", () => {
  it("writes one CSV row per event with a header", () => {
    const lines = toCsv(ALL_EVENTS).trimEnd().split("\r\n");
    expect(lines).toHaveLength(ALL_EVENTS.length + 1);
    expect(lines[0].startsWith("timestamp,id,source,category,action,outcome")).toBe(true);
    const denied = lines.find((l) => l.includes(mcpOboToolsCallDenied.id))!;
    expect(denied).toContain("DENIED");
    expect(denied).toContain("mcp-authz");
    expect(denied).toContain(`${USER} > ${AGENT}`);
  });

  it("quotes commas and quotes, and neutralises formulas", () => {
    const event: AuditEvent = {
      ...llmChatOk,
      summary: 'said "hi", then left',
      action: "=HYPERLINK(\"x\")",
    };
    const row = toCsv([event]).split("\r\n")[1];
    expect(row).toContain('"said ""hi"", then left"');
    expect(row).toContain("\"'=HYPERLINK(\"\"x\"\")\"");
  });

  it("exports JSON as the events array", () => {
    expect(JSON.parse(toJson([llmChatOk]))).toEqual([llmChatOk]);
  });
});
