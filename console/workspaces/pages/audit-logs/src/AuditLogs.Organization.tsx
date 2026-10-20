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

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import {
  Alert,
  AlertTitle,
  Box,
  Button,
  CircularProgress,
  IconButton,
  InputAdornment,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@wso2/oxygen-ui";
import {
  RefreshCcw,
  ScrollText,
  Search,
  SortAsc,
  SortDesc,
} from "@wso2/oxygen-ui-icons-react";
import {
  PageLayout,
  TimeRangeSelector,
  useTimeRangeParams,
} from "@agent-management-platform/views";
import {
  isAuditTrailEnabled,
  useAuditLogTrail,
  useQueryAuditLogFilterValues,
  useTokenScopes,
} from "@agent-management-platform/api-client";
import type {
  AuditLogActorType,
  AuditLogCategory,
  AuditLogFilterField,
  AuditLogRecord,
  AuditLogResult,
  QueryAuditLogsQuery,
} from "@agent-management-platform/types";
import { AuditLogTable } from "./subComponents/AuditLogTable";
import { AuditLogDetailDrawer } from "./subComponents/AuditLogDetailDrawer";
import {
  MultiSelectFilter,
  type MultiSelectFilterOption,
} from "./subComponents/MultiSelectFilter";
import {
  ExportAuditLogsButton,
  type ExportOutcome,
} from "./subComponents/ExportAuditLogsButton";
import {
  ACTOR_TYPE_OPTIONS,
  CATEGORY_OPTIONS,
  DEFAULT_TIME_RANGE,
  describeAuditError,
  isTimeRangePreset,
  MAX_WINDOW_MS,
  PAGE_SIZE,
  presetWindow,
  RESULT_OPTIONS,
  TIME_RANGE_OPTIONS,
} from "./utils";

const SEARCH_DEBOUNCE_MS = 600;

/** Filters kept in the URL, so a filtered view can be shared as a link. */
const URL_FILTERS = [
  "action",
  "result",
  "category",
  "actorType",
  "agent",
  "project",
] as const;
type UrlFilter = (typeof URL_FILTERS)[number];

function useFilterValueOptions(
  orgName: string | undefined,
  filter: AuditLogFilterField,
  timeWindow: { startTime: string; endTime: string } | undefined,
): MultiSelectFilterOption[] {
  const { data } = useQueryAuditLogFilterValues(
    { orgName },
    timeWindow ? { filter, ...timeWindow } : undefined,
  );
  return useMemo(
    () => (data?.values ?? []).map((v) => ({ value: v.value, count: v.count })),
    [data],
  );
}

function ExportOutcomeAlert({
  outcome,
  onClose,
}: {
  outcome: ExportOutcome;
  onClose: () => void;
}) {
  if (outcome.kind === "error") {
    const { severity, title, message } = describeAuditError(outcome.error, "export");
    return (
      <Alert severity={severity} onClose={onClose}>
        <AlertTitle>{title}</AlertTitle>
        {message}
      </Alert>
    );
  }
  const { manifest, filename } = outcome.file;
  if (!manifest) {
    return (
      <Alert severity="error" onClose={onClose}>
        <AlertTitle>Export cut off</AlertTitle>
        {filename} has no manifest line, so the export ended early and the file is
        incomplete. Export again.
      </Alert>
    );
  }
  if (!manifest.complete) {
    return (
      <Alert severity="warning" onClose={onClose}>
        <AlertTitle>Export incomplete</AlertTitle>
        {filename} holds {manifest.exportedCount} of {manifest.storeCount} matching
        records{manifest.reason ? `: ${manifest.reason}` : "."} Narrow the filters
        and export again.
      </Alert>
    );
  }
  return (
    <Alert severity="success" onClose={onClose}>
      <AlertTitle>Export complete</AlertTitle>
      {filename}: {manifest.exportedCount} records, matching the audit store&apos;s
      count. The window ends at {new Date(manifest.endTime).toLocaleString()} so
      records still in transit are not counted. SHA-256{" "}
      <Box component="span" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
        {manifest.sha256}
      </Box>
    </Alert>
  );
}

const PAGE_TITLE = "Audit Logs";
const PAGE_DESCRIPTION =
  "What people did in Agent Manager, and what agents did through the organization's AI gateways.";

const AuditLogsPage: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { enforced, scopes } = useTokenScopes();
  const canExport = !enforced || scopes.has("amp:audit-log:export");

  const { customStartTime, customEndTime, hasCustomRange, handleCustomRangeApply } =
    useTimeRangeParams(searchParams, setSearchParams);
  const preset = useMemo(() => {
    const raw = searchParams.get("timeRange");
    return isTimeRangePreset(raw) ? raw : DEFAULT_TIME_RANGE;
  }, [searchParams]);

  // A preset window ends at the anchor, which moves only on refresh or when the
  // preset changes, so the query key does not move with the clock.
  const [anchor, setAnchor] = useState(() => Date.now());
  const timeWindow = useMemo(
    () =>
      hasCustomRange
        ? { startTime: customStartTime!, endTime: customEndTime! }
        : presetWindow(preset, anchor),
    [hasCustomRange, customStartTime, customEndTime, preset, anchor],
  );

  const selected = useMemo(() => {
    const out = {} as Record<UrlFilter, string[]>;
    for (const key of URL_FILTERS) out[key] = searchParams.getAll(key);
    return out;
  }, [searchParams]);
  const search = searchParams.get("search") ?? "";
  const sortOrder = searchParams.get("sortOrder") === "asc" ? "asc" : "desc";

  const [searchDraft, setSearchDraft] = useState(search);
  useEffect(() => setSearchDraft(search), [search]);

  const updateParams = useCallback(
    (mutate: (next: URLSearchParams) => void) => {
      const next = new URLSearchParams(searchParams);
      mutate(next);
      setSearchParams(next);
    },
    [searchParams, setSearchParams],
  );

  useEffect(() => {
    if (searchDraft === search) return;
    const timer = setTimeout(() => {
      updateParams((next) => {
        if (searchDraft) next.set("search", searchDraft);
        else next.delete("search");
      });
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchDraft, search, updateParams]);

  const setFilter = (key: UrlFilter, values: string[]) =>
    updateParams((next) => {
      next.delete(key);
      values.forEach((v) => next.append(key, v));
    });

  const query = useMemo<QueryAuditLogsQuery>(
    () => ({
      ...timeWindow,
      action: selected.action,
      result: selected.result as AuditLogResult[],
      category: selected.category as AuditLogCategory[],
      actorType: selected.actorType as AuditLogActorType[],
      agent: selected.agent,
      project: selected.project,
      search: search || undefined,
      limit: PAGE_SIZE,
      sortOrder,
    }),
    [timeWindow, selected, search, sortOrder],
  );
  const exportQuery = useMemo(() => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { limit: _limit, sortOrder: _sort, ...filters } = query;
    return filters;
  }, [query]);

  const {
    records,
    total,
    isLoading,
    isFetching,
    error,
    refetch,
    hasMore,
    loadMore,
    isLoadingMore,
    loadMoreError,
  } = useAuditLogTrail({ orgName: orgId }, query);

  const actionOptions = useFilterValueOptions(orgId, "action", timeWindow);
  const agentOptions = useFilterValueOptions(orgId, "agent", timeWindow);
  const projectOptions = useFilterValueOptions(orgId, "project", timeWindow);

  const [selectedRecord, setSelectedRecord] = useState<AuditLogRecord | null>(null);
  const [exportOutcome, setExportOutcome] = useState<ExportOutcome | null>(null);

  const handleRefresh = () => {
    if (hasCustomRange) refetch();
    else setAnchor(Date.now());
  };

  const filtersActive =
    URL_FILTERS.some((k) => selected[k].length > 0) || !!search;
  const readError = error ? describeAuditError(error, "read") : null;

  return (
    <PageLayout
      title={PAGE_TITLE}
      description={PAGE_DESCRIPTION}
      disableIcon
      actions={
        <Stack direction="row" spacing={1} alignItems="center">
          <ExportAuditLogsButton
            orgName={orgId}
            query={exportQuery}
            permitted={canExport}
            onOutcome={setExportOutcome}
          />
          <Tooltip title="Refresh">
            <span>
              <IconButton
                size="small"
                onClick={handleRefresh}
                disabled={isFetching}
                aria-label="Refresh"
              >
                {isFetching ? <CircularProgress size={16} /> : <RefreshCcw size={16} />}
              </IconButton>
            </span>
          </Tooltip>
        </Stack>
      }
    >
      <Stack spacing={2}>
        <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
          <TimeRangeSelector
            preset={preset}
            customStart={customStartTime}
            customEnd={customEndTime}
            options={TIME_RANGE_OPTIONS.map(({ value, label }) => ({ value, label }))}
            maxRangeMs={MAX_WINDOW_MS}
            onPresetChange={(value) => {
              setAnchor(Date.now());
              updateParams((next) => {
                next.set("timeRange", value);
                next.delete("startTime");
                next.delete("endTime");
              });
            }}
            onCustomRangeApply={handleCustomRangeApply}
          />
          <TextField
            size="small"
            placeholder="Search records…"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
            inputProps={{ maxLength: 256, "aria-label": "Search audit records" }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search size={16} />
                </InputAdornment>
              ),
            }}
            sx={{ minWidth: 220 }}
          />
          <MultiSelectFilter
            label="Actions"
            options={actionOptions}
            selected={selected.action}
            onChange={(v) => setFilter("action", v)}
            minWidth={170}
          />
          <MultiSelectFilter
            label="Agents"
            options={agentOptions}
            selected={selected.agent}
            onChange={(v) => setFilter("agent", v)}
          />
          <MultiSelectFilter
            label="Projects"
            options={projectOptions}
            selected={selected.project}
            onChange={(v) => setFilter("project", v)}
          />
          <MultiSelectFilter
            label="Actor types"
            options={ACTOR_TYPE_OPTIONS.map((value) => ({ value }))}
            selected={selected.actorType}
            onChange={(v) => setFilter("actorType", v)}
          />
          <MultiSelectFilter
            label="Results"
            options={RESULT_OPTIONS.map((value) => ({ value }))}
            selected={selected.result}
            onChange={(v) => setFilter("result", v)}
            minWidth={130}
          />
          <MultiSelectFilter
            label="Categories"
            options={CATEGORY_OPTIONS.map((value) => ({ value }))}
            selected={selected.category}
            onChange={(v) => setFilter("category", v)}
          />
          <Tooltip title={sortOrder === "desc" ? "Newest first" : "Oldest first"}>
            <IconButton
              size="small"
              onClick={() =>
                updateParams((next) =>
                  next.set("sortOrder", sortOrder === "desc" ? "asc" : "desc"),
                )
              }
              aria-label={sortOrder === "desc" ? "Sort oldest first" : "Sort newest first"}
            >
              {sortOrder === "desc" ? <SortDesc size={16} /> : <SortAsc size={16} />}
            </IconButton>
          </Tooltip>
          {filtersActive && (
            <Button
              size="small"
              variant="text"
              onClick={() =>
                updateParams((next) => {
                  URL_FILTERS.forEach((k) => next.delete(k));
                  next.delete("search");
                })
              }
            >
              Clear filters
            </Button>
          )}
        </Stack>

        {exportOutcome && (
          <ExportOutcomeAlert
            outcome={exportOutcome}
            onClose={() => setExportOutcome(null)}
          />
        )}

        {readError ? (
          <Alert severity={readError.severity}>
            <AlertTitle>{readError.title}</AlertTitle>
            {readError.message}
          </Alert>
        ) : !isLoading && records.length === 0 ? (
          <Stack alignItems="center" spacing={1} sx={{ py: 8, color: "text.secondary" }}>
            <ScrollText size={56} />
            <Typography variant="h6">No audit records</Typography>
            <Typography variant="body2">
              {filtersActive
                ? "No records match these filters in this time range."
                : "Nothing was recorded in this time range."}
            </Typography>
          </Stack>
        ) : (
          <>
            <AuditLogTable
              records={records}
              isLoading={isLoading}
              onSelect={setSelectedRecord}
            />
            {!isLoading && (
              <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
                <Typography variant="caption" color="text.secondary">
                  Showing {records.length} of {total} records
                </Typography>
                {hasMore && (
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={loadMore}
                    disabled={isLoadingMore}
                    startIcon={isLoadingMore ? <CircularProgress size={14} /> : undefined}
                  >
                    Load {sortOrder === "desc" ? "older" : "newer"} records
                  </Button>
                )}
              </Stack>
            )}
            {loadMoreError !== null && (
              <Alert severity="error">
                {describeAuditError(loadMoreError, "read").message}
              </Alert>
            )}
          </>
        )}
      </Stack>

      <AuditLogDetailDrawer
        record={selectedRecord}
        onClose={() => setSelectedRecord(null)}
      />
    </PageLayout>
  );
};

export const AuditLogsOrganization: React.FC = () => {
  // Fixed at boot from GET /api/v1/config, like the observer URL; the nav item
  // is hidden on the same condition, so this is reached only by a direct link.
  if (!isAuditTrailEnabled()) {
    return (
      <PageLayout title={PAGE_TITLE} description={PAGE_DESCRIPTION} disableIcon>
        <Alert severity="info">
          <AlertTitle>Audit trail not enabled</AlertTitle>
          This deployment does not read the audit trail back. Ask your platform
          administrator to set <code>AUDIT_OBSERVER_URL</code> on the agent-manager
          service (Helm: <code>agentManagerService.config.audit.reader</code>).
        </Alert>
      </PageLayout>
    );
  }
  return <AuditLogsPage />;
};

export default AuditLogsOrganization;
