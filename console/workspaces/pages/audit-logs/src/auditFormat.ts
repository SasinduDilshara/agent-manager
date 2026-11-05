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

import type {
  AuditActor,
  AuditCategory,
  AuditEvent,
  AuditOutcome,
} from "@agent-management-platform/types";

export const CATEGORY_LABEL: Record<AuditCategory, string> = {
  OPERATIONAL: "Operational",
  LLM: "LLM",
  MCP: "MCP",
  A2A: "A2A",
  OTHER: "Other",
};

export const CATEGORY_DESCRIPTION: Record<AuditCategory, string> = {
  OPERATIONAL: "Control-plane changes made through the console, CLI or API",
  LLM: "Calls through LLM proxies and providers",
  MCP: "Calls to MCP servers through the gateway",
  A2A: "Agent-to-agent requests",
  OTHER: "Agent endpoint calls and telemetry export",
};

export const OUTCOME_LABEL: Record<AuditOutcome, string> = {
  SUCCESS: "Success",
  DENIED: "Denied",
  FAILED: "Failed",
  STARTED: "Started",
};

/** Green / amber / red; neutral for an intent record, which has no result yet. */
export const OUTCOME_COLOR: Record<AuditOutcome, "success" | "warning" | "error" | "default"> = {
  SUCCESS: "success",
  DENIED: "warning",
  FAILED: "error",
  STARTED: "default",
};

export const OUTCOME_DESCRIPTION: Record<AuditOutcome, string> = {
  SUCCESS: "The operation or request succeeded",
  DENIED: "Refused by an authorization or policy check",
  FAILED: "The operation or request failed",
  STARTED: "Intent record written before a privileged operation; its result is a separate record",
};

const ACTOR_TYPE_LABEL: Record<AuditActor["type"], string> = {
  USER: "User",
  AGENT: "Agent",
  SERVICE: "Service",
  GATEWAY: "Gateway",
  SYSTEM: "System",
  ANONYMOUS: "Anonymous",
};

export function actorTypeLabel(type: AuditActor["type"] | undefined): string {
  return (type && ACTOR_TYPE_LABEL[type]) || "Unknown";
}

/** The best human-readable name for the actor. */
export function actorLabel(actor: AuditActor | undefined): string {
  if (!actor) return "Unknown";
  return actor.display || actor.id || actor.clientId || actorTypeLabel(actor.type);
}

export function agentLabel(event: AuditEvent): string | undefined {
  if (!event.agent?.name) return undefined;
  return event.agent.project
    ? `${event.agent.project}/${event.agent.name}`
    : event.agent.name;
}

export function hasDelegation(event: AuditEvent): boolean {
  return !!event.onBehalfOf?.subject || !!event.onBehalfOf?.chain?.length;
}

export interface DelegationHop {
  id: string;
  role: "subject" | "actor";
  /** Display name when the hop is the event's resolved actor. */
  display?: string;
}

/**
 * The delegation path in the order authority flowed: the end user first, then
 * each agent it was delegated to, ending with the actor that made the call.
 *
 * `onBehalfOf.chain` is the token's nested `act` claim, outermost (the current
 * actor) first, so it is reversed here. When the chain is empty but a subject
 * is present, the event's actor closes the path.
 */
export function delegationPath(event: AuditEvent): DelegationHop[] {
  const obo = event.onBehalfOf;
  if (!obo) return [];
  const hops: DelegationHop[] = [];
  if (obo.subject) hops.push({ id: obo.subject, role: "subject" });
  const chain = [...(obo.chain ?? [])].reverse();
  if (chain.length === 0 && event.actor?.id && event.actor.id !== obo.subject) {
    chain.push(event.actor.id);
  }
  for (const id of chain) {
    hops.push({
      id,
      role: "actor",
      display: id === event.actor?.id ? event.actor.display : undefined,
    });
  }
  return hops;
}

export function formatAbsoluteTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatNumber(n: number | null | undefined): string {
  return typeof n === "number" ? n.toLocaleString() : "-";
}

// --- Export ---------------------------------------------------------------

const CSV_COLUMNS: Array<[string, (e: AuditEvent) => unknown]> = [
  ["timestamp", (e) => e.timestamp],
  ["id", (e) => e.id],
  ["source", (e) => e.source],
  ["category", (e) => e.category],
  ["action", (e) => e.action],
  ["outcome", (e) => e.outcome],
  ["statusCode", (e) => e.statusCode],
  ["agent", (e) => agentLabel(e)],
  ["project", (e) => e.project],
  ["environment", (e) => e.environment],
  ["actorType", (e) => e.actor?.type],
  ["actorId", (e) => e.actor?.id],
  ["actor", (e) => actorLabel(e.actor)],
  ["onBehalfOf", (e) => e.onBehalfOf?.subject],
  ["delegationChain", (e) => delegationPath(e).map((h) => h.id).join(" > ")],
  ["resourceType", (e) => e.resource?.type],
  ["resourceName", (e) => e.resource?.name],
  ["deniedByPolicy", (e) => e.decision?.deniedBy?.policy],
  ["deniedByPhase", (e) => e.decision?.deniedBy?.phase],
  ["summary", (e) => e.summary],
  ["clientIp", (e) => e.network?.clientIp],
  ["correlationId", (e) => e.correlationId],
];

function csvCell(value: unknown): string {
  if (value === undefined || value === null) return "";
  let s = String(value);
  // Neutralise spreadsheet formula injection from logged, user-controlled text.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(events: AuditEvent[]): string {
  const header = CSV_COLUMNS.map(([name]) => name).join(",");
  const rows = events.map((e) => CSV_COLUMNS.map(([, get]) => csvCell(get(e))).join(","));
  return [header, ...rows].join("\r\n") + "\r\n";
}

/** Kubernetes metadata the raw view may show; anything else describes the platform. */
const RAW_KUBERNETES_FIELDS = ["namespace_name", "pod_name", "container_name"];

/**
 * The record's raw document as the console shows and exports it. The API
 * already returns an allow-listed view; this also reduces any Kubernetes block
 * to the namespace, pod and container names, so a console running against an
 * older API never shows node hosts, pod IPs, images, labels or annotations.
 */
export function displayRaw(raw: AuditEvent["raw"]): Record<string, unknown> | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const out: Record<string, unknown> = { ...raw };
  const k8s = out.kubernetes;
  if (k8s && typeof k8s === "object" && !Array.isArray(k8s)) {
    const kept = Object.fromEntries(
      RAW_KUBERNETES_FIELDS.filter((k) => k in k8s).map((k) => [k, (k8s as Record<string, unknown>)[k]]),
    );
    if (Object.keys(kept).length) out.kubernetes = kept;
    else delete out.kubernetes;
  }
  return out;
}

export function toJson(events: AuditEvent[]): string {
  return JSON.stringify(
    events.map((e) => (e.raw ? { ...e, raw: displayRaw(e.raw) } : e)),
    null,
    2,
  );
}

export function exportFileName(orgName: string, ext: "csv" | "json", now = new Date()) {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  return `audit-events-${orgName}-${stamp}.${ext}`;
}

/** Saves `content` as a file through a temporary object URL. */
export function downloadFile(name: string, content: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
