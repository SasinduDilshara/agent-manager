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

import { useState } from "react";
import { Box, Chip, IconButton, LinearProgress, Stack, Tooltip, Typography } from "@wso2/oxygen-ui";
import { Check, Copy } from "@wso2/oxygen-ui-icons-react";
import type {
  ShadowCallOutcome,
  ShadowFindingKind,
  ShadowFindingStatus,
  ShadowOwnerHint,
  ShadowProvider,
  ShadowRetirementState,
  ShadowScanStatus,
  ShadowVerdict,
} from "@agent-management-platform/types";

export const PROVIDER_LABELS: Record<ShadowProvider, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  bedrock: "Amazon Bedrock",
  google: "Google Agent Platform",
  foundry: "Microsoft Foundry",
  github: "GitHub",
  azure_devops: "Azure DevOps",
};

/** Source repository hosts: connection test only until source code analysis is added. */
export const SOURCE_HOSTS: string[] = ["github", "azure_devops"];

export function providerLabel(p: string): string {
  return PROVIDER_LABELS[p as ShadowProvider] ?? p;
}

export const KIND_LABELS: Record<ShadowFindingKind, string> = {
  platform_agent: "Platform agent",
  runtime: "Agent runtime",
  api_key: "API key",
  principal: "Cloud identity",
  tool_infrastructure: "Tool infrastructure",
  project: "Project",
};

/** The kind's label; an Anthropic project finding is a workspace. */
export function kindLabel(k: string, provider?: string): string {
  if (k === "project" && provider === "anthropic") return "Workspace";
  return KIND_LABELS[k as ShadowFindingKind] ?? k;
}

export const VERDICT_LABELS: Record<ShadowVerdict, string> = {
  agent: "Agent",
  possible_agent: "Possible agent",
  llm_consumer: "LLM consumer",
  tool_infrastructure: "Tool infrastructure",
};

const VERDICT_COLORS: Record<ShadowVerdict, "error" | "warning" | "default" | "info"> = {
  agent: "error",
  possible_agent: "warning",
  llm_consumer: "default",
  tool_infrastructure: "info",
};

export function VerdictChip({ verdict }: { verdict: ShadowVerdict }) {
  return (
    <Chip
      size="small"
      variant="outlined"
      color={VERDICT_COLORS[verdict] ?? "default"}
      label={VERDICT_LABELS[verdict] ?? verdict}
    />
  );
}

export const STATUS_LABELS: Record<ShadowFindingStatus, string> = {
  new: "New",
  reviewed: "Reviewed",
  dismissed: "Dismissed",
  onboarded: "Onboarded",
  retired: "Retired",
};

export function StatusChip({ status }: { status: ShadowFindingStatus }) {
  const color =
    status === "onboarded" || status === "retired"
      ? "success"
      : status === "new"
        ? "info"
        : "default";
  return <Chip size="small" color={color} label={STATUS_LABELS[status] ?? status} />;
}

export const RETIREMENT_LABELS: Record<ShadowRetirementState, string> = {
  "": "Not onboarded",
  monitoring: "Watching direct usage",
  ready_to_retire: "Ready to retire",
  pending_verification: "Waiting for verification",
  retired: "Retired",
};

const SCAN_STATUS_LABELS: Record<ShadowScanStatus, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  partial: "Partly failed",
  failed: "Failed",
};

export function ScanStatusChip({ status }: { status: ShadowScanStatus }) {
  const color =
    status === "succeeded"
      ? "success"
      : status === "failed"
        ? "error"
        : status === "partial"
          ? "warning"
          : "info";
  return <Chip size="small" color={color} label={SCAN_STATUS_LABELS[status] ?? status} />;
}

const OUTCOME_LABELS: Record<ShadowCallOutcome, string> = {
  ok: "OK",
  skipped: "Skipped",
  auth_failed: "Sign-in failed",
  permission_denied: "Permission denied",
  not_found: "Not found",
  rate_limited: "Rate limited",
  unsupported_response: "Unexpected response",
  failed: "Failed",
};

export function OutcomeChip({ outcome }: { outcome: string }) {
  const color =
    outcome === "ok"
      ? "success"
      : outcome === "skipped"
        ? "default"
        : outcome === "partial" || outcome === "rate_limited" || outcome === "not_found"
          ? "warning"
          : "error";
  const label =
    outcome === "partial"
      ? "Partly failed"
      : (OUTCOME_LABELS[outcome as ShadowCallOutcome] ?? outcome);
  return <Chip size="small" variant="outlined" color={color} label={label} />;
}

/** A score as a number and a thin bar against the 100 maximum. */
export function ScoreBar({ score }: { score: number }) {
  return (
    <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 120 }}>
      <Typography variant="body2" sx={{ width: 28, textAlign: "right" }}>
        {score}
      </Typography>
      <Box sx={{ flex: 1 }}>
        <LinearProgress
          variant="determinate"
          value={Math.max(0, Math.min(100, score))}
          aria-label={`Score ${score} of 100`}
          sx={{ height: 6, borderRadius: 3 }}
        />
      </Box>
    </Stack>
  );
}

/** The best single line to name who is behind a finding. */
export function ownerLabel(h: ShadowOwnerHint | undefined): string {
  if (!h) return "";
  return h.email || h.name || h.username || "";
}

/** A short date, or a dash. */
export function shortDate(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/**
 * Selection-card styles for a CardActionArea that fills its card: content is
 * top-aligned, so titles line up across a row of cards with different text.
 */
export const selectCardSx = {
  height: "100%",
  display: "flex",
  flexDirection: "column",
  alignItems: "stretch",
  justifyContent: "flex-start",
} as const;

/** A whole number with thousands separators. */
export function formatCount(n: number | undefined): string {
  return (n ?? 0).toLocaleString();
}

/** "1 item" / "3 items", with thousands separators. */
export function itemCount(n: number | undefined): string {
  return `${formatCount(n)} ${n === 1 ? "item" : "items"}`;
}

/**
 * The readable names of what a connection check unlocks: a signal code
 * (e.g. "openai.agent_object") becomes its catalog name; anything else (a
 * capability such as "Owner hints") is shown as given.
 */
export function unlockLabels(unlocks: string[], signalNames: Map<string, string>): string[] {
  return [...new Set(unlocks.map((u) => signalNames.get(u) ?? u))];
}

/**
 * A suggested agent name from a display name: lowercase letters, digits and
 * "-", starting with a letter, at most 25 characters (the service's limit).
 */
export function suggestAgentName(displayName: string): string {
  let s = displayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^[^a-z]+/, "")
    .replace(/-+/g, "-");
  s = s.slice(0, 25).replace(/-+$/, "");
  return s || "agent";
}

export const AGENT_NAME_PATTERN = /^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$/;
export const AGENT_NAME_MAX_LENGTH = 25;

/** A copyable code block: commands, environment variables or a snippet. */
export function CodeHint({ code, label }: { code: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard
      ?.writeText(code)
      .then(() => setCopied(true))
      .catch(() => setCopied(false));
  };
  return (
    <Box
      sx={{
        position: "relative",
        border: 1,
        borderColor: "divider",
        borderRadius: 1,
        bgcolor: "action.hover",
        my: 1,
      }}
    >
      <Box
        component="pre"
        aria-label={label}
        sx={{ m: 0, p: 1.5, pr: 5, overflowX: "auto", fontSize: 12, fontFamily: "monospace" }}
      >
        {code}
      </Box>
      <Tooltip title={copied ? "Copied" : "Copy"}>
        <IconButton
          size="small"
          aria-label={`Copy ${label}`}
          sx={{ position: "absolute", top: 4, right: 4 }}
          onClick={copy}
        >
          {copied ? <Check size={16} /> : <Copy size={16} />}
        </IconButton>
      </Tooltip>
    </Box>
  );
}
