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

import { describe, expect, it } from "vitest";
import type { ShadowProviderSpec } from "@agent-management-platform/types";
import {
  directCredentialHint,
  INSTRUMENTATION_OTHER,
  INSTRUMENTATION_SHELL,
  moveOffDirectShell,
  OPENAI_CLIENT_PYTHON,
} from "./onboardingHints";
import {
  credentialChoiceError,
  credentialMode,
  evaluateCapabilities,
  hasValue,
} from "./capabilities";
import {
  AGENT_NAME_PATTERN,
  formatCount,
  itemCount,
  kindLabel,
  ownerLabel,
  suggestAgentName,
  unlockLabels,
} from "./shadowUi";
import {
  endpointVisible,
  fieldVisible,
  initialDraft,
  toSettings,
  validateDraft,
} from "./subComponents/ConnectionEditor";
import { dailyTotals } from "./subComponents/UsageCard";
import { getSourceRepoScanData } from "../sourceRepoScan/dummyData";

const openai: ShadowProviderSpec = {
  provider: "openai",
  displayName: "OpenAI",
  description: "",
  endpoints: [
    { key: "api", label: "OpenAI API", default: "https://api.openai.com/v1", placeholders: [] },
  ],
  fields: [
    { key: "apiKey", label: "Admin API key", kind: "secret", required: false, recommended: true },
    { key: "scopedKeys", label: "Project keys", kind: "key_map", required: false },
    {
      key: "deepInspection",
      label: "Deep inspection",
      kind: "checkbox",
      required: false,
      defaultBool: false,
    },
  ],
  permissions: [],
  docs: [],
  credentialChoice: {
    fields: ["apiKey", "scopedKeys"],
    message: "Add an Admin API key (recommended) or at least one project key.",
  },
  // The shape of the service's catalog (capabilities.go), cut down.
  capabilities: [
    {
      key: "openai.usage",
      title: "Usage and cost per API key",
      description: "",
      signals: ["openai.plain_usage"],
      needs: ["apiKey"],
    },
    {
      key: "openai.agents",
      title: "Agent objects and their sessions",
      description: "",
      signals: ["openai.agent_object"],
      needs: ["scopedKeys"],
    },
    {
      key: "openai.toolCalls",
      title: "Tool calls in stored chat completions and batches",
      description: "",
      signals: ["openai.tool_call_batch"],
      needs: ["scopedKeys", "deepInspection"],
    },
  ],
};

const anthropic: ShadowProviderSpec = {
  ...openai,
  provider: "anthropic",
  endpoints: [
    { key: "api", label: "API", default: "https://api.anthropic.com", placeholders: [] },
    {
      key: "awsVariant",
      label: "AWS",
      default: "https://aws-external-anthropic.{region}.api.aws",
      placeholders: ["region"],
      option: "includeCloudVariants",
    },
  ],
  fields: [
    { key: "apiKey", label: "Admin API key", kind: "secret", required: false, recommended: true },
    {
      key: "includeCloudVariants",
      label: "Cloud variants",
      kind: "checkbox",
      required: false,
      defaultBool: true,
    },
    {
      key: "regions",
      label: "AWS regions",
      kind: "list",
      required: false,
      option: "includeCloudVariants",
    },
  ],
};

describe("agent names", () => {
  it("suggests a valid name from a display name", () => {
    for (const name of ["Support Bot", "  123 Orders/Agent!!", "A", "x".repeat(60), "—"]) {
      const s = suggestAgentName(name);
      expect(s.length).toBeLessThanOrEqual(25);
      expect(AGENT_NAME_PATTERN.test(s)).toBe(true);
    }
    expect(suggestAgentName("Support Bot")).toBe("support-bot");
  });
});

describe("labels", () => {
  it("picks the most useful owner line", () => {
    expect(ownerLabel({ name: "Alice", email: "alice@acme.com" })).toBe("alice@acme.com");
    expect(ownerLabel({ username: "arn:aws:iam::1:user/bob" })).toBe("arn:aws:iam::1:user/bob");
    expect(ownerLabel(undefined)).toBe("");
    expect(formatCount(undefined)).toBe("0");
  });

  it("counts items in the singular and plural", () => {
    expect(itemCount(1)).toBe("1 item");
    expect(itemCount(0)).toBe("0 items");
    expect(itemCount(2500)).toBe(`${(2500).toLocaleString()} items`);
  });

  it("names unlocked signals and keeps other capabilities as given", () => {
    const names = new Map([["openai.agent_object", "Agent object"]]);
    expect(
      unlockLabels(["openai.agent_object", "Owner hints", "openai.agent_object"], names),
    ).toEqual(["Agent object", "Owner hints"]);
  });
});

const stored = {
  id: "1",
  name: "x",
  provider: "openai" as const,
  endpoints: {},
  settings: {},
  secretHints: { apiKey: "sk-a…wxyz" } as Record<string, string>,
  endpointWarnings: [],
  createdBy: "",
  createdAt: "",
  updatedAt: "",
};

describe("what Agent Manager can analyze", () => {
  const available = (d: ReturnType<typeof initialDraft>, existing?: typeof stored) =>
    evaluateCapabilities(openai, d, existing)
      .filter((c) => c.available)
      .map((c) => c.capability.key);

  it("follows the credentials: Admin key only, project keys only, both", () => {
    const d = initialDraft(openai, undefined);
    expect(available(d)).toEqual([]);
    d.values.apiKey = "sk-admin";
    expect(available(d)).toEqual(["openai.usage"]);
    d.values.apiKey = "";
    d.keyMaps.scopedKeys = [{ id: "proj_a", key: "sk-proj" }];
    expect(available(d)).toEqual(["openai.agents"]);
    d.values.deepInspection = true;
    expect(available(d)).toEqual(["openai.agents", "openai.toolCalls"]);
    d.values.apiKey = "sk-admin";
    expect(available(d)).toEqual(["openai.usage", "openai.agents", "openai.toolCalls"]);
  });

  it("names what is missing, and counts stored keys until they are removed", () => {
    const d = initialDraft(openai, stored);
    const usage = () => evaluateCapabilities(openai, d, stored)[0];
    expect(usage().available).toBe(true);
    d.removed = ["apiKey"];
    expect(usage()).toMatchObject({ available: false, missing: ["Admin API key"] });
    const tools = evaluateCapabilities(openai, d, stored)[2];
    expect(tools.missing).toEqual(["Project keys", "Deep inspection"]);
  });

  it("checks a key map row's stored key and ignores fields of an unticked option", () => {
    const d = initialDraft(openai, undefined);
    d.keyMaps.scopedKeys = [{ id: "proj_a", key: "" }];
    expect(hasValue(openai, d, undefined, "scopedKeys")).toBe(false);
    const withKey = { ...stored, secretHints: { "scopedKeys.proj_a": "sk-p…aaaa" } };
    expect(hasValue(openai, d, withKey, "scopedKeys")).toBe(true);
    const a = initialDraft(anthropic, undefined);
    a.values.regions = "us-east-1";
    expect(hasValue(anthropic, a, undefined, "regions")).toBe(true);
    a.values.includeCloudVariants = false;
    expect(hasValue(anthropic, a, undefined, "regions")).toBe(false);
    expect(hasValue(openai, d, undefined, "nope")).toBe(false);
  });

  it("gives the credential mode of OpenAI and Anthropic connections only", () => {
    expect(credentialMode("openai", { apiKey: "sk-a…" })).toBe("admin");
    expect(credentialMode("anthropic", {})).toBe("scoped");
    expect(credentialMode("bedrock", {})).toBeUndefined();
    const noChoice = { ...anthropic, credentialChoice: undefined };
    expect(credentialChoiceError(noChoice, initialDraft(noChoice, undefined), undefined)).toBe(
      undefined,
    );
    expect(
      credentialChoiceError(anthropic, initialDraft(anthropic, undefined), undefined),
    ).toBeDefined();
  });

  it("labels an Anthropic project finding as a workspace", () => {
    expect(kindLabel("project", "openai")).toBe("Project");
    expect(kindLabel("project", "anthropic")).toBe("Workspace");
    expect(kindLabel("api_key", "anthropic")).toBe("API key");
  });
});

describe("pluggable services", () => {
  const bedrock: ShadowProviderSpec = {
    ...openai,
    provider: "bedrock",
    credentialChoice: {
      fields: ["scanAgentCore", "readCloudTrail"],
      message: "Select at least one Bedrock service to scan.",
    },
    endpoints: [
      {
        key: "sts",
        label: "AWS STS",
        default: "https://sts.{region}.amazonaws.com",
        placeholders: ["region"],
        option: "roleArn",
      },
      {
        key: "agentcoreControl",
        label: "AgentCore",
        default: "https://x",
        placeholders: [],
        option: "scanAgentCore",
      },
      {
        key: "cloudtrail",
        label: "CloudTrail",
        default: "https://y",
        placeholders: [],
        option: "readCloudTrail",
      },
    ],
    fields: [
      { key: "roleArn", label: "Role to assume", kind: "text", required: false },
      {
        key: "scanAgentCore",
        label: "Scan AgentCore",
        kind: "checkbox",
        required: false,
        defaultBool: true,
        section: "Services to scan",
      },
      {
        key: "readCloudTrail",
        label: "Read CloudTrail",
        kind: "checkbox",
        required: false,
        defaultBool: true,
        section: "Services to scan",
      },
    ],
    capabilities: [
      {
        key: "bedrock.agentcore",
        title: "AgentCore",
        description: "",
        signals: [],
        needs: ["scanAgentCore"],
      },
      {
        key: "bedrock.modelCalls",
        title: "Model calls",
        description: "",
        signals: [],
        needs: ["readCloudTrail"],
      },
    ],
  };

  it("shows a service's endpoint only when it is ticked, and STS only with a role", () => {
    const d = initialDraft(bedrock, undefined);
    const shown = () =>
      bedrock.endpoints
        .filter((e) => endpointVisible(bedrock, d, undefined, e.option))
        .map((e) => e.key);
    expect(shown()).toEqual(["agentcoreControl", "cloudtrail"]);
    d.values.roleArn = "arn:aws:iam::123456789012:role/AmpShadowDiscovery";
    expect(shown()).toEqual(["sts", "agentcoreControl", "cloudtrail"]);
    d.values.readCloudTrail = false;
    expect(shown()).toEqual(["sts", "agentcoreControl"]);
  });

  it("drops a service's capability when it is unticked, and needs one service", () => {
    const d = initialDraft(bedrock, undefined);
    d.name = "x";
    const keys = () =>
      evaluateCapabilities(bedrock, d, undefined)
        .filter((c) => c.available)
        .map((c) => c.capability.key);
    expect(keys()).toEqual(["bedrock.agentcore", "bedrock.modelCalls"]);
    d.values.scanAgentCore = false;
    expect(keys()).toEqual(["bedrock.modelCalls"]);
    expect(validateDraft(bedrock, d, undefined).credentialChoice).toBeUndefined();
    d.values.readCloudTrail = false;
    expect(validateDraft(bedrock, d, undefined).credentialChoice).toBe(
      "Select at least one Bedrock service to scan.",
    );
  });
});

describe("onboarding hints", () => {
  it("names each provider's direct credential", () => {
    expect(directCredentialHint("openai").envVar).toBe("OPENAI_API_KEY");
    expect(directCredentialHint("anthropic").envVar).toBe("ANTHROPIC_API_KEY");
    for (const p of ["bedrock", "google", "foundry"]) {
      expect(directCredentialHint(p).envVar).toBeUndefined();
    }
    expect(moveOffDirectShell("openai").split("\n")[0]).toMatch(/^unset OPENAI_API_KEY/);
    expect(moveOffDirectShell("bedrock")).toBe("amp-instrument python main.py");
  });

  it("uses the documented variable names and the API-Key header", () => {
    expect(INSTRUMENTATION_SHELL).toContain("AMP_OTEL_ENDPOINT");
    expect(INSTRUMENTATION_SHELL).toContain("AMP_AGENT_API_KEY");
    expect(INSTRUMENTATION_OTHER).toContain("/v1/traces");
    expect(INSTRUMENTATION_OTHER).toContain("x-amp-api-key");
    expect(OPENAI_CLIENT_PYTHON).toContain('"API-Key"');
    expect(OPENAI_CLIENT_PYTHON).toContain('"Authorization": ""');
  });
});

describe("connection form", () => {
  it("prefills official endpoints and checkbox defaults", () => {
    const d = initialDraft(anthropic, undefined);
    expect(d.endpoints.awsVariant).toBe("https://aws-external-anthropic.{region}.api.aws");
    expect(d.values.includeCloudVariants).toBe(true);
    expect(fieldVisible(anthropic.fields[2], d)).toBe(true);
    d.values.includeCloudVariants = false;
    expect(fieldVisible(anthropic.fields[2], d)).toBe(false);
  });

  it("needs an Admin API key or a project key, typed or stored", () => {
    const d = initialDraft(openai, undefined);
    d.name = "OpenAI prod";
    expect(validateDraft(openai, d, undefined).credentialChoice).toBe(
      "Add an Admin API key (recommended) or at least one project key.",
    );
    expect(validateDraft(openai, d, undefined).apiKey).toBeUndefined();
    // A project key alone is enough.
    d.keyMaps.scopedKeys = [{ id: "proj_a", key: "sk-proj-a" }];
    expect(validateDraft(openai, d, undefined).credentialChoice).toBeUndefined();
    // A stored Admin key is enough, until the user removes it.
    const e = initialDraft(openai, stored);
    e.name = "x";
    expect(validateDraft(openai, e, stored).credentialChoice).toBeUndefined();
    e.removed = ["apiKey"];
    expect(validateDraft(openai, e, stored).credentialChoice).toBeDefined();
  });

  it("asks for the key of a new project key row, and the ID of a key", () => {
    const d = initialDraft(openai, undefined);
    d.name = "x";
    d.values.apiKey = "k";
    d.keyMaps.scopedKeys = [{ id: "proj_new", key: "" }];
    expect(validateDraft(openai, d, undefined).scopedKeys).toBe("Enter the key for proj_new");
    d.keyMaps.scopedKeys = [{ id: " ", key: "sk" }];
    expect(validateDraft(openai, d, undefined).scopedKeys).toBe(
      "Enter the ID for each key in Project keys",
    );
    // A stored key for the ID is kept.
    const withKey = { ...stored, secretHints: { "scopedKeys.proj_new": "sk-p…aaaa" } };
    d.keyMaps.scopedKeys = [{ id: "proj_new", key: "" }];
    expect(validateDraft(openai, d, withKey).scopedKeys).toBeUndefined();
  });

  it("rejects endpoints with a query", () => {
    const d = initialDraft(openai, undefined);
    d.name = "x";
    d.values.apiKey = "k";
    d.endpoints.api = "https://api.openai.com/v1?key=1";
    expect(validateDraft(openai, d, undefined)["endpoint:api"]).toBeDefined();
  });

  it("never sends an empty secret, and sends lists, maps and checkboxes typed", () => {
    const d = initialDraft(anthropic, undefined);
    d.values.regions = "us-east-1\n eu-west-1 ,";
    const s = toSettings(anthropic, d);
    expect(s).not.toHaveProperty("apiKey");
    expect(s.regions).toEqual(["us-east-1", "eu-west-1"]);
    expect(s.includeCloudVariants).toBe(true);
    const o = initialDraft(openai, undefined);
    o.keyMaps.scopedKeys = [
      { id: "proj_a", key: "" },
      { id: " ", key: "x" },
    ];
    expect(toSettings(openai, o).scopedKeys).toEqual({ proj_a: "" });
  });
});

describe("usage", () => {
  it("sums keys and models into one total per day, oldest first", () => {
    const totals = dailyTotals([
      { day: "2026-11-02", keyId: "k1", model: "a", requests: 2, inputTokens: 10, outputTokens: 1 },
      {
        day: "2026-11-01",
        keyId: "k1",
        model: "a",
        requests: 1,
        inputTokens: 5,
        outputTokens: 1,
        costAmount: 0.5,
        currency: "usd",
      },
      {
        day: "2026-11-02",
        keyId: "k2",
        model: "b",
        requests: 3,
        inputTokens: 1,
        outputTokens: 1,
        costAmount: 1,
      },
    ]);
    expect(totals.map((t) => t.day)).toEqual(["2026-11-01", "2026-11-02"]);
    expect(totals[1].requests).toBe(5);
    expect(totals[1].cost).toBe(1);
    expect(totals[0].currency).toBe("usd");
  });

  it("fills quiet days with zeros through the last scanned day", () => {
    const row = { keyId: "k", model: "m", inputTokens: 1, outputTokens: 1 };
    const totals = dailyTotals(
      [
        { ...row, day: "2026-10-30", requests: 1 },
        { ...row, day: "2026-11-02", requests: 2 },
      ],
      "2026-11-04",
    );
    expect(totals.map((t) => [t.day, t.requests])).toEqual([
      ["2026-10-30", 1],
      ["2026-10-31", 0],
      ["2026-11-01", 0],
      ["2026-11-02", 2],
      ["2026-11-03", 0],
      ["2026-11-04", 0],
    ]);
    expect(dailyTotals([])).toEqual([]);
  });
});

describe("source repository preview data", () => {
  it("is consistent with the design's detector weights and verdict rule", () => {
    const data = getSourceRepoScanData();
    const weight = new Map(data.detectors.map((d) => [d.id, d]));
    for (const s of data.suspects) {
      const ids = [...new Set(s.hits.map((h) => h.detectorId))];
      const score = ids.reduce((n, id) => n + (weight.get(id)?.weight ?? 0), 0);
      expect(s.score).toBe(score);
      const strong = ids.some((id) => weight.get(id)?.tier === "High" || id === "D7");
      const verdict =
        score >= 60 && strong ? "Agent" : score >= 30 && strong ? "Possible agent" : "LLM consumer";
      expect(s.verdict).toBe(verdict);
    }
  });
});
