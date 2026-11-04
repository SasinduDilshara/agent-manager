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

import {
  AUDIT_CATEGORIES,
  AUDIT_OUTCOMES,
  type AuditCategory,
  type AuditOutcome,
  type AuditSortOrder,
  type ListAuditEventsQuery,
} from "@agent-management-platform/types";

// The page's filters live in the URL so a view can be shared or bookmarked.
// This module is the single mapping between the two; the page reads with
// parseAuditFilters and writes with withAuditFilters, never param by param.

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const TIME_PRESETS = [
  { value: "15m", label: "Last 15 minutes", ms: 15 * MINUTE },
  { value: "1h", label: "Last 1 hour", ms: HOUR },
  { value: "24h", label: "Last 24 hours", ms: DAY },
  { value: "7d", label: "Last 7 days", ms: 7 * DAY },
  { value: "30d", label: "Last 30 days", ms: 30 * DAY },
] as const;
export type AuditTimePreset = (typeof TIME_PRESETS)[number]["value"];
export const DEFAULT_TIME_PRESET: AuditTimePreset = "24h";
/** The API's maximum query window. */
export const MAX_RANGE_DAYS = 186;
export const PAGE_SIZE = 50;
/** Client-side export cap. */
export const MAX_EXPORT_ROWS = 1000;

/** URL parameter names. Repeated keys carry multi-valued filters. */
export const PARAM = {
  timeRange: "timeRange",
  startTime: "startTime",
  endTime: "endTime",
  category: "category",
  agent: "agent",
  project: "project",
  environment: "environment",
  outcome: "outcome",
  actor: "actor",
  search: "search",
  sort: "sort",
} as const;

export interface AuditFilters {
  timeRange: AuditTimePreset;
  /** A valid custom range overrides timeRange. */
  startTime?: string;
  endTime?: string;
  /** Undefined is the "All" tab. */
  category?: AuditCategory;
  /** `project/agent` keys. */
  agents: string[];
  project?: string;
  environment?: string;
  outcomes: AuditOutcome[];
  actor?: string;
  search?: string;
  sort: AuditSortOrder;
}

const isPreset = (v: string | null): v is AuditTimePreset =>
  TIME_PRESETS.some((p) => p.value === v);
const isCategory = (v: string | null): v is AuditCategory =>
  (AUDIT_CATEGORIES as readonly string[]).includes(v ?? "");
const isOutcome = (v: string): v is AuditOutcome =>
  (AUDIT_OUTCOMES as readonly string[]).includes(v);
const unique = <T>(values: T[]) => Array.from(new Set(values));

function validCustomRange(start: string | null, end: string | null) {
  if (!start || !end) return undefined;
  const s = Date.parse(start);
  const e = Date.parse(end);
  if (Number.isNaN(s) || Number.isNaN(e) || s >= e) return undefined;
  return { startTime: start, endTime: end };
}

/** Reads the filters from the URL, dropping anything unknown or malformed. */
export function parseAuditFilters(sp: URLSearchParams): AuditFilters {
  const rawPreset = sp.get(PARAM.timeRange);
  const rawCategory = sp.get(PARAM.category);
  const custom = validCustomRange(sp.get(PARAM.startTime), sp.get(PARAM.endTime));
  const text = (key: string) => sp.get(key)?.trim() || undefined;
  return {
    timeRange: isPreset(rawPreset) ? rawPreset : DEFAULT_TIME_PRESET,
    startTime: custom?.startTime,
    endTime: custom?.endTime,
    category: isCategory(rawCategory) ? rawCategory : undefined,
    agents: unique(sp.getAll(PARAM.agent).map((a) => a.trim()).filter(Boolean)),
    project: text(PARAM.project),
    environment: text(PARAM.environment),
    outcomes: unique(sp.getAll(PARAM.outcome).filter(isOutcome)),
    actor: text(PARAM.actor),
    search: text(PARAM.search),
    sort: sp.get(PARAM.sort) === "asc" ? "asc" : "desc",
  };
}

/**
 * Returns a copy of `sp` with `patch` applied. Defaults are left out of the
 * URL so a plain link stays plain; params the page does not own are kept.
 */
export function withAuditFilters(
  sp: URLSearchParams,
  patch: Partial<AuditFilters>,
): URLSearchParams {
  const next = { ...parseAuditFilters(sp), ...patch };
  const out = new URLSearchParams(sp);
  for (const key of Object.values(PARAM)) out.delete(key);

  const custom = validCustomRange(next.startTime ?? null, next.endTime ?? null);
  if (custom) {
    out.set(PARAM.startTime, custom.startTime);
    out.set(PARAM.endTime, custom.endTime);
  } else if (next.timeRange !== DEFAULT_TIME_PRESET) {
    out.set(PARAM.timeRange, next.timeRange);
  }
  if (next.category) out.set(PARAM.category, next.category);
  for (const a of unique(next.agents)) out.append(PARAM.agent, a);
  if (next.project) out.set(PARAM.project, next.project);
  if (next.environment) out.set(PARAM.environment, next.environment);
  for (const o of unique(next.outcomes)) out.append(PARAM.outcome, o);
  if (next.actor?.trim()) out.set(PARAM.actor, next.actor.trim());
  if (next.search?.trim()) out.set(PARAM.search, next.search.trim());
  if (next.sort === "asc") out.set(PARAM.sort, "asc");
  return out;
}

/** Filters cleared, keeping the time window, category tab and sort. */
export function clearedFilters(f: AuditFilters): Partial<AuditFilters> {
  return {
    agents: [],
    project: undefined,
    environment: undefined,
    outcomes: [],
    actor: undefined,
    search: undefined,
    sort: f.sort,
  };
}

/** Number of narrowing filters set (time range, tab and sort excluded). */
export function activeFilterCount(f: AuditFilters): number {
  return (
    f.agents.length +
    f.outcomes.length +
    (f.project ? 1 : 0) +
    (f.environment ? 1 : 0) +
    (f.actor ? 1 : 0) +
    (f.search ? 1 : 0)
  );
}

/** Absolute window for the filters; presets are measured back from `now`. */
export function resolveTimeWindow(
  f: AuditFilters,
  now: number,
): { startTime: string; endTime: string } {
  if (f.startTime && f.endTime) {
    return { startTime: f.startTime, endTime: f.endTime };
  }
  const preset = TIME_PRESETS.find((p) => p.value === f.timeRange) ?? TIME_PRESETS[2];
  return {
    startTime: new Date(now - preset.ms).toISOString(),
    endTime: new Date(now).toISOString(),
  };
}

/**
 * The API query for the filters. Category counts are requested without the
 * category filter applied, so the tab badges show what each tab would hold;
 * pass `includeCategory: false` for that.
 */
export function toAuditQuery(
  f: AuditFilters,
  now: number,
  { includeCategory = true }: { includeCategory?: boolean } = {},
): ListAuditEventsQuery {
  return {
    ...resolveTimeWindow(f, now),
    category: includeCategory && f.category ? [f.category] : undefined,
    agent: f.agents.length ? f.agents : undefined,
    project: f.project,
    environment: f.environment,
    outcome: f.outcomes.length ? f.outcomes : undefined,
    actor: f.actor,
    search: f.search,
    limit: PAGE_SIZE,
    sort: f.sort,
  };
}
