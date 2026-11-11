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

import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { ShadowFindingDetail, ShadowFindingSummary } from "@agent-management-platform/types";

const finding = (over: Partial<ShadowFindingSummary> = {}): ShadowFindingSummary => ({
  id: "f1",
  connectionId: "c1",
  connectionName: "OpenAI prod",
  provider: "openai",
  kind: "api_key",
  externalId: "key_abc",
  displayName: "Support Bot",
  scope: "proj_1",
  state: "",
  score: 75,
  verdict: "agent",
  status: "new",
  ownerHint: { email: "alice@acme.com" },
  firstSeenAt: "2026-11-01T00:00:00Z",
  lastSeenAt: "2026-11-10T00:00:00Z",
  linkedProject: "",
  linkedAgent: "",
  retirementState: "",
  requestsInWindow: 12,
  ...over,
});

const detail = (over: Partial<ShadowFindingDetail> = {}): ShadowFindingDetail => ({
  ...finding(),
  attributes: { model: "gpt-4.1" },
  related: [],
  signals: [],
  keys: [],
  usage: [],
  retirement: {
    state: "",
    observationDays: 7,
    zeroUsageDays: 0,
    guidance: { title: "Delete the OpenAI project API key", steps: ["Step one", "Step two"] },
  },
  ...over,
});

const hoisted = vi.hoisted(() => ({
  findings: [] as ShadowFindingSummary[],
  findingsError: null as unknown,
  scopes: new Set<string>(),
  enforced: true,
  createAgent: vi.fn(),
  onboard: vi.fn(),
  confirm: vi.fn(),
  addConfirmation: vi.fn(),
  detail: null as ShadowFindingDetail | null,
}));

vi.mock("@agent-management-platform/api-client", () => ({
  useShadowFindings: () => ({
    data: { findings: hoisted.findings, total: hoisted.findings.length, limit: 50, offset: 0 },
    isLoading: false,
    error: hoisted.findingsError,
  }),
  useShadowFinding: () => ({ data: hoisted.detail, isLoading: false, error: null }),
  useUpdateShadowFinding: () => ({ mutate: vi.fn() }),
  useConfirmShadowRetirement: () => ({ mutate: hoisted.confirm, isPending: false }),
  useOnboardShadowFinding: () => ({ mutate: hoisted.onboard, isPending: false }),
  useCreateAgent: () => ({ mutate: hoisted.createAgent, isPending: false }),
  useListProjects: () => ({ data: { projects: [{ name: "default", displayName: "Default" }] } }),
  useListAgents: () => ({ data: { agents: [] } }),
  useTokenScopes: () => ({ enforced: hoisted.enforced, resolved: true, scopes: hoisted.scopes }),
  useShadowSummary: () => ({ data: undefined, isLoading: true }),
  useShadowProviders: () => ({ data: undefined }),
  useShadowConnections: () => ({ data: { connections: [] } }),
  useStartShadowScan: () => ({ mutate: vi.fn(), isPending: false }),
  isShadowScanActive: () => false,
  useTrack: () => ({ track: vi.fn() }),
  ConsoleAction: {},
}));

vi.mock("@agent-management-platform/shared-component", async () => {
  const React = await import("react");
  return {
    ResourceListShell: ({
      isEmpty,
      error,
      emptyState,
      children,
    }: {
      isEmpty?: boolean;
      error?: Error;
      emptyState: { title: string };
      children: React.ReactNode;
    }) =>
      React.createElement(
        "div",
        null,
        error ? error.message : isEmpty ? emptyState.title : children,
      ),
    isListEmpty: ({ isLoading, count }: { isLoading: boolean; count: number }) =>
      !isLoading && count === 0,
    formatRelativeTime: () => "2 days ago",
    useConfirmationDialog: () => ({ addConfirmation: hoisted.addConfirmation }),
    useUnsavedChangesGuard: () => ({ allowNavigation: (fn: () => void) => fn() }),
  };
});

import { FindingsTab } from "./subComponents/FindingsTab";
import { RetirementCard } from "./subComponents/RetirementCard";
import { OnboardFinding } from "./subComponents/OnboardFinding";
import { ShadowAgentDiscovery } from "./ShadowAgentDiscovery";
import { SourceRepoPreview } from "../sourceRepoScan/SourceRepoPreview";
import { AnalyzeSection } from "./subComponents/AnalyzeSection";
import { CredentialModeChip } from "./subComponents/ConnectionsTab";
import { ProjectFindingNote, relationLabel } from "./subComponents/FindingDetail";

const router = (ui: React.ReactNode, path = "/org/acme/shadow-agent-discovery") =>
  render(
    <MemoryRouter
      initialEntries={[path]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      {ui}
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.clearAllMocks();
  hoisted.findings = [];
  hoisted.findingsError = null;
  hoisted.scopes = new Set();
  hoisted.enforced = true;
  hoisted.detail = null;
});

describe("FindingsTab", () => {
  it("lists findings with score, verdict and owner hint", () => {
    hoisted.findings = [
      finding(),
      finding({ id: "f2", displayName: "Nightly job", verdict: "llm_consumer", score: 5 }),
    ];
    router(<FindingsTab orgName="acme" />);
    expect(screen.getByText("Support Bot")).toBeInTheDocument();
    expect(screen.getByText("Agent")).toBeInTheDocument();
    expect(screen.getByText("LLM consumer")).toBeInTheDocument();
    expect(screen.getAllByText("alice@acme.com").length).toBeGreaterThan(0);
    expect(screen.getByLabelText("Score 75 of 100")).toBeInTheDocument();
  });

  it("shows the empty state, not an error, when there are no findings", () => {
    router(<FindingsTab orgName="acme" />);
    expect(screen.getByText("No findings yet")).toBeInTheDocument();
  });

  it("shows only the error when loading fails", () => {
    hoisted.findingsError = new Error("boom");
    router(<FindingsTab orgName="acme" />);
    expect(screen.getByText(/Couldn't load findings/)).toBeInTheDocument();
    expect(screen.queryByText("No findings yet")).not.toBeInTheDocument();
  });
});

describe("RetirementCard", () => {
  it("renders nothing before onboarding", () => {
    const { container } = router(<RetirementCard orgName="acme" finding={detail()} canManage />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the zero-usage progress while monitoring, without the revoke steps", () => {
    const f = detail({
      linkedAgent: "support-bot",
      linkedProject: "default",
      retirement: { ...detail().retirement, state: "monitoring", zeroUsageDays: 3 },
    });
    router(<RetirementCard orgName="acme" finding={f} canManage />);
    expect(screen.getByText(/3 of\s*7/)).toBeInTheDocument();
    expect(screen.queryByText("Step one")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /revoked/ })).not.toBeInTheDocument();
  });

  it("guides the revocation once ready and asks for confirmation", () => {
    const f = detail({
      linkedAgent: "support-bot",
      linkedProject: "default",
      retirement: { ...detail().retirement, state: "ready_to_retire", zeroUsageDays: 8 },
    });
    router(<RetirementCard orgName="acme" finding={f} canManage />);
    expect(screen.getByText("Delete the OpenAI project API key")).toBeInTheDocument();
    expect(screen.getByText("Step one")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /revoked it/ }));
    expect(hoisted.addConfirmation).toHaveBeenCalledTimes(1);
    hoisted.addConfirmation.mock.calls[0][0].onConfirm();
    expect(hoisted.confirm).toHaveBeenCalledTimes(1);
  });

  it("shows the verified retirement", () => {
    const f = detail({
      linkedAgent: "a",
      retirement: {
        ...detail().retirement,
        state: "retired",
        verification: "The provider no longer lists the key.",
      },
    });
    router(<RetirementCard orgName="acme" finding={f} canManage />);
    expect(screen.getByText(/no longer lists the key/)).toBeInTheDocument();
  });
});

describe("OnboardFinding", () => {
  it("registers an external agent with the console's request, then links the finding", async () => {
    hoisted.detail = detail();
    hoisted.createAgent.mockImplementation((_vars, opts) => opts.onSuccess());
    router(
      <Routes>
        <Route
          path="/org/:orgId/shadow-agent-discovery/findings/:findingId/onboard"
          element={<OnboardFinding orgName="acme" listPath="/org/acme/shadow-agent-discovery" />}
        />
      </Routes>,
      "/org/acme/shadow-agent-discovery/findings/f1/onboard",
    );
    expect(screen.getByText("Externally-hosted agent")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByDisplayValue("support-bot")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Register agent" }));
    expect(hoisted.createAgent).toHaveBeenCalledTimes(1);
    const vars = hoisted.createAgent.mock.calls[0][0];
    expect(vars.params).toEqual({ orgName: "acme", projName: "default" });
    expect(vars.body).toMatchObject({
      name: "support-bot",
      displayName: "Support Bot",
      provisioning: { type: "external" },
      agentType: { type: "external-agent-api" },
    });
    expect(hoisted.onboard).toHaveBeenCalledWith(
      { projectName: "default", agentName: "support-bot" },
      expect.anything(),
    );
  });
});

describe("OnboardFinding next steps", () => {
  const renderLinked = (provider: string) => {
    hoisted.detail = detail({
      provider: provider as ShadowFindingDetail["provider"],
      linkedProject: "default",
      linkedAgent: "support-bot",
      status: "onboarded",
    });
    router(
      <Routes>
        <Route
          path="/org/:orgId/shadow-agent-discovery/findings/:findingId/onboard"
          element={<OnboardFinding orgName="acme" listPath="/org/acme/shadow-agent-discovery" />}
        />
      </Routes>,
      "/org/acme/shadow-agent-discovery/findings/f1/onboard",
    );
  };

  it("gives the instrumentation variables, the gateway variables and the OpenAI client example", async () => {
    renderLinked("openai");
    const instr = await screen.findByLabelText("instrumentation commands");
    expect(instr).toHaveTextContent("pip install amp-instrumentation");
    expect(instr).toHaveTextContent(
      'export AMP_OTEL_ENDPOINT="<OTel endpoint from the Setup Agent panel>"',
    );
    expect(instr).toHaveTextContent("export AMP_AGENT_API_KEY=");
    expect(instr).toHaveTextContent("amp-instrument python main.py");
    expect(screen.getByText(/x-amp-api-key/)).toBeInTheDocument();
    expect(screen.getByLabelText("LLM gateway variables")).toHaveTextContent("LLM_PROVIDER_URL");
    const client = screen.getByLabelText("OpenAI client example");
    expect(client).toHaveTextContent('"API-Key": os.environ["LLM_PROVIDER_KEY"]');
    expect(screen.getByLabelText("commands to move off the direct credential")).toHaveTextContent(
      "unset OPENAI_API_KEY",
    );
    expect(screen.getByText(/no direct usage for 7 days/)).toBeInTheDocument();
  });

  it("names the provider's own credential and shows no OpenAI snippet for other providers", async () => {
    renderLinked("anthropic");
    const move = await screen.findByLabelText("commands to move off the direct credential");
    expect(move).toHaveTextContent("unset ANTHROPIC_API_KEY");
    expect(screen.queryByLabelText("OpenAI client example")).not.toBeInTheDocument();
    expect(screen.getByText(/example cURL request/)).toBeInTheDocument();
  });

  it("has no environment variable to unset for a cloud identity", async () => {
    renderLinked("bedrock");
    const move = await screen.findByLabelText("commands to move off the direct credential");
    expect(move).not.toHaveTextContent("unset");
    expect(screen.getByText(/the AWS credentials it uses to call Bedrock/)).toBeInTheDocument();
  });
});

describe("ShadowAgentDiscovery access", () => {
  it("explains the access needed instead of showing the page", () => {
    router(
      <Routes>
        <Route path="/org/:orgId/shadow-agent-discovery/*" element={<ShadowAgentDiscovery />} />
      </Routes>,
    );
    expect(screen.getByText("You don't have access to Shadow Agent Discovery")).toBeInTheDocument();
  });

  it("shows the page with its tabs to an organization admin", () => {
    hoisted.scopes = new Set(["amp:shadow-agent:read", "amp:shadow-agent:manage"]);
    router(
      <Routes>
        <Route path="/org/:orgId/shadow-agent-discovery/*" element={<ShadowAgentDiscovery />} />
      </Routes>,
    );
    expect(screen.getByRole("heading", { name: "Shadow Agent Discovery" })).toBeInTheDocument();
    for (const tab of ["Overview", "Findings", "Connections", "Scans"]) {
      expect(screen.getByRole("tab", { name: tab })).toBeInTheDocument();
    }
    expect(screen.getByRole("tab", { name: /Source repositories/ })).toBeInTheDocument();
  });
});

describe("SourceRepoPreview", () => {
  it("labels the sample data and lists suspects of the scanned hosts", () => {
    router(<SourceRepoPreview hosts={[{ connectionName: "gh", provider: "github" }]} />);
    expect(screen.getByText("Sample data")).toBeInTheDocument();
    expect(screen.getByText("acme-corp/support-assistant")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: /Show hits for acme-corp\/support-assistant/ }),
    );
    expect(screen.getByText(/value not stored/)).toBeInTheDocument();
  });
});

describe("AnalyzeSection", () => {
  const statuses = [
    {
      capability: {
        key: "openai.usage",
        title: "Usage and cost per API key",
        description: "Daily requests per key.",
        signals: [],
        needs: ["apiKey"],
      },
      available: false,
      missing: ["Admin API key"],
    },
    {
      capability: {
        key: "openai.agents",
        title: "Agent objects and their sessions",
        description: "Agents per project.",
        signals: [],
        needs: ["scopedKeys"],
      },
      available: true,
      missing: [],
    },
  ];

  it("counts what is available and lists both groups with what is missing", () => {
    render(<AnalyzeSection providerName="OpenAI" statuses={statuses} />);
    expect(screen.getByText("What can Agent Manager analyze?")).toBeInTheDocument();
    expect(
      screen.getByText("1 of 2 available with these credentials and options."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "See what it can analyze" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("Available (1)");
    expect(dialog).toHaveTextContent("Agent objects and their sessions");
    expect(dialog).toHaveTextContent("Not available (1)");
    expect(dialog).toHaveTextContent("Needs: Admin API key");
  });

  it("renders nothing for a provider without capabilities", () => {
    const { container } = render(<AnalyzeSection providerName="X" statuses={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("CredentialModeChip", () => {
  it("shows the mode of OpenAI and Anthropic connections only", () => {
    const { rerender, container } = render(
      <CredentialModeChip provider="openai" secretHints={{ apiKey: "sk-a…" }} />,
    );
    expect(screen.getByText("Admin key")).toBeInTheDocument();
    rerender(<CredentialModeChip provider="anthropic" secretHints={{}} />);
    expect(screen.getByText("Workspace keys only (limited)")).toBeInTheDocument();
    rerender(<CredentialModeChip provider="openai" secretHints={{ "scopedKeys.p": "x" }} />);
    expect(screen.getByText("Project keys only (limited)")).toBeInTheDocument();
    rerender(<CredentialModeChip provider="bedrock" secretHints={{}} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ProjectFindingNote", () => {
  it("explains a project finding without candidate keys, and that nothing is retired", () => {
    render(<ProjectFindingNote finding={detail({ kind: "project" })} />);
    expect(screen.getByText(/Evidence that is not tied to one API key/)).toBeInTheDocument();
    expect(screen.getByText(/Add an Admin API key to the connection/)).toBeInTheDocument();
    expect(screen.getByText(/nothing to retire here/)).toBeInTheDocument();
  });

  it("points to the candidate keys when the Admin key listed them", () => {
    render(
      <ProjectFindingNote
        finding={detail({
          kind: "project",
          provider: "anthropic",
          related: [
            {
              findingId: "k1",
              relation: "candidate_key",
              displayName: "Key 1",
              provider: "anthropic",
            },
            {
              findingId: "k2",
              relation: "candidate_key",
              displayName: "Key 2",
              provider: "anthropic",
            },
          ],
        })}
      />,
    );
    expect(screen.getByText(/one of the 2 candidate keys/)).toBeInTheDocument();
    expect(screen.getByText(/message batches/)).toBeInTheDocument();
    expect(relationLabel("agent_in_project", "anthropic")).toBe("Agent in this workspace");
    expect(relationLabel("candidate_key", "openai")).toBe("Candidate key");
  });
});
