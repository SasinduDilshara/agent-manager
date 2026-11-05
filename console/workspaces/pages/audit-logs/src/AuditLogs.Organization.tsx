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

import { useCallback, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import {
  Alert,
  Button,
  CircularProgress,
  IconButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Stack,
  Tooltip,
  Typography,
} from "@wso2/oxygen-ui";
import {
  Download,
  FileSpreadsheet,
  FileText,
  RefreshCcw,
  ScrollText,
} from "@wso2/oxygen-ui-icons-react";
import { NoDataFound, PageLayout, TimeRangeSelector } from "@agent-management-platform/views";
import {
  useAuditEvents,
  useListEnvironments,
  useListOrgAgents,
  useListProjects,
  useTokenScopes,
} from "@agent-management-platform/api-client";
import { AUDIT_READ_SCOPE, type AuditEvent } from "@agent-management-platform/types";
import {
  activeFilterCount,
  clearedFilters,
  MAX_EXPORT_ROWS,
  MAX_RANGE_DAYS,
  parseAuditFilters,
  TIME_PRESETS,
  toAuditQuery,
  withAuditFilters,
  type AuditFilters,
} from "./auditFilters";
import { downloadFile, exportFileName, toCsv, toJson } from "./auditFormat";
import { AuditCategoryTabs } from "./subComponents/AuditCategoryTabs";
import { AuditEventDrawer } from "./subComponents/AuditEventDrawer";
import { AuditEventsTable } from "./subComponents/AuditEventsTable";
import { AuditFilterBar, type FilterOption } from "./subComponents/AuditFilterBar";

const TITLE = "Audit Logs";
const DESCRIPTION =
  "Who did what, to which resource, and with what outcome: control-plane changes " +
  "and agent traffic through the gateway (LLM, MCP, A2A).";
const TIME_OPTIONS = TIME_PRESETS.map(({ value, label }) => ({ value, label }));

function errorStatus(error: unknown): number | undefined {
  const s = (error as { status?: unknown } | null)?.status;
  return typeof s === "number" ? s : undefined;
}

/** The server's own error message, which the audit API keeps safe to show. */
function serverMessage(error: unknown): string | undefined {
  const body = (error as { body?: unknown } | null)?.body;
  const message = (body as { message?: unknown } | null | undefined)?.message;
  return typeof message === "string" && message.trim() ? message.trim() : undefined;
}

function errorMessage(error: unknown): { title: string; detail: string } {
  switch (errorStatus(error)) {
    case 403:
      return {
        title: "You don't have access to audit logs.",
        detail: "Ask an organization administrator for the audit read permission.",
      };
    // The backend answers 503 when the audit query API is switched off on
    // this deployment (the page flag can be on while the API is off).
    case 404:
    case 503:
      return {
        title: "Audit logs aren't available on this deployment.",
        detail: "The audit query API is not enabled. Ask your platform administrator.",
      };
    case 429:
      return {
        title: "Too many audit searches right now.",
        detail: "Your organization's search limit was reached. Wait a few seconds and try again.",
      };
    case 502:
    case 504:
      return {
        title: "The audit store is unreachable right now.",
        detail: "Events are still being recorded. Try again in a moment.",
      };
    case 400:
      return {
        title: "These filters can't be used.",
        detail: serverMessage(error) ?? "Check the filters and the time range, then try again.",
      };
    default:
      return { title: "Couldn't load audit events.", detail: "Try again in a moment." };
  }
}

export function AuditLogsOrganization() {
  const { orgId } = useParams<{ orgId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useMemo(() => parseAuditFilters(searchParams), [searchParams]);
  const filterKey = searchParams.toString();

  const { enforced, resolved, scopes } = useTokenScopes();
  const canRead = !enforced || scopes.has(AUDIT_READ_SCOPE);
  const ready = !enforced || resolved;

  // Presets ("last 24 hours") are measured from the moment the filters were
  // last set or Refresh was pressed, so the query key stays stable between.
  const [anchor, setAnchor] = useState(() => ({ key: filterKey, at: Date.now() }));
  if (anchor.key !== filterKey) {
    setAnchor({ key: filterKey, at: Date.now() });
  }

  const params = useMemo(() => ({ orgName: orgId }), [orgId]);
  const query = useMemo(() => toAuditQuery(filters, anchor.at), [filters, anchor.at]);
  // With a category tab selected the main response is narrowed to it, so the
  // other tabs' counts come from a one-row request without that filter.
  const countsQuery = useMemo(
    () => ({ ...toAuditQuery(filters, anchor.at, { includeCategory: false }), limit: 1 }),
    [filters, anchor.at],
  );

  const enabled = ready && canRead;
  const result = useAuditEvents(params, query, { enabled });
  const counts = useAuditEvents(params, countsQuery, {
    enabled: enabled && !!filters.category,
  });
  const categoryCounts = filters.category
    ? counts.categoryCounts
    : result.categoryCounts;

  const { data: orgAgents, isLoading: agentsLoading } = useListOrgAgents(params);
  const { data: projectsData } = useListProjects(params);
  const { data: environmentsData } = useListEnvironments(params);

  const agentOptions = useMemo<FilterOption[]>(
    () =>
      (orgAgents?.agents ?? [])
        .filter((a) => !filters.project || a.projectName === filters.project)
        .map((a) => ({
          value: `${a.projectName}/${a.name}`,
          label: a.displayName || a.name,
          group: a.projectDisplayName || a.projectName,
        }))
        .sort((a, b) => (a.group ?? "").localeCompare(b.group ?? "") || a.label.localeCompare(b.label)),
    [orgAgents, filters.project],
  );
  const projectOptions = useMemo<FilterOption[]>(
    () =>
      (projectsData?.projects ?? []).map((p) => ({
        value: p.name,
        label: p.displayName || p.name,
      })),
    [projectsData],
  );
  const environmentOptions = useMemo<FilterOption[]>(
    () =>
      (environmentsData ?? []).map((e) => ({
        value: e.name,
        label: e.displayName || e.name,
      })),
    [environmentsData],
  );

  const update = useCallback(
    (patch: Partial<AuditFilters>) => setSearchParams(withAuditFilters(searchParams, patch)),
    [searchParams, setSearchParams],
  );

  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [exportAnchor, setExportAnchor] = useState<HTMLElement | null>(null);

  const refresh = () => {
    setAnchor({ key: filterKey, at: Date.now() });
  };

  const exportRows = result.events.slice(0, MAX_EXPORT_ROWS);
  const doExport = (kind: "csv" | "json") => {
    setExportAnchor(null);
    if (kind === "csv") {
      downloadFile(exportFileName(orgId ?? "org", "csv"), toCsv(exportRows), "text/csv;charset=utf-8");
    } else {
      downloadFile(exportFileName(orgId ?? "org", "json"), toJson(exportRows), "application/json");
    }
  };

  const activeCount = activeFilterCount(filters);
  const totalText =
    result.total === undefined
      ? undefined
      : `${result.totalRelation === "gte" ? "more than " : ""}${result.total.toLocaleString()}`;

  const actions = (
    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
      <TimeRangeSelector
        preset={filters.timeRange}
        customStart={filters.startTime}
        customEnd={filters.endTime}
        options={TIME_OPTIONS}
        maxRangeDays={MAX_RANGE_DAYS}
        onPresetChange={(v) =>
          update({ timeRange: v as AuditFilters["timeRange"], startTime: undefined, endTime: undefined })
        }
        onCustomRangeApply={(startTime, endTime) => update({ startTime, endTime })}
      />
      <Tooltip title="Refresh">
        <span>
          <IconButton
            size="small"
            aria-label="Refresh audit events"
            onClick={refresh}
            disabled={!enabled || result.isFetching}
          >
            {result.isFetching && !result.isLoading ? (
              <CircularProgress size={16} />
            ) : (
              <RefreshCcw size={16} />
            )}
          </IconButton>
        </span>
      </Tooltip>
      <Button
        size="small"
        variant="outlined"
        startIcon={<Download size={16} />}
        disabled={exportRows.length === 0}
        aria-haspopup="menu"
        aria-expanded={!!exportAnchor}
        aria-controls={exportAnchor ? "audit-export-menu" : undefined}
        onClick={(e) => setExportAnchor(e.currentTarget)}
      >
        Export
      </Button>
      <Menu
        id="audit-export-menu"
        anchorEl={exportAnchor}
        open={!!exportAnchor}
        onClose={() => setExportAnchor(null)}
      >
        <Typography variant="caption" color="text.secondary" sx={{ px: 2, display: "block" }}>
          {exportRows.length.toLocaleString()} loaded event{exportRows.length === 1 ? "" : "s"}
          {result.events.length > MAX_EXPORT_ROWS ? ` (first ${MAX_EXPORT_ROWS})` : ""}
        </Typography>
        <MenuItem onClick={() => doExport("csv")}>
          <ListItemIcon><FileSpreadsheet size={16} /></ListItemIcon>
          <ListItemText>CSV</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => doExport("json")}>
          <ListItemIcon><FileText size={16} /></ListItemIcon>
          <ListItemText>JSON</ListItemText>
        </MenuItem>
      </Menu>
    </Stack>
  );

  if (ready && !canRead) {
    return (
      <PageLayout title={TITLE} description={DESCRIPTION} disableIcon>
        <Alert severity="info">
          You don&apos;t have permission to view audit logs. Ask an organization
          administrator for the audit read permission (audit:read).
        </Alert>
      </PageLayout>
    );
  }

  const err = result.error ? errorMessage(result.error) : null;
  const loading = !ready || result.isLoading;
  const isEmpty = !loading && !result.error && result.events.length === 0;

  return (
    <PageLayout title={TITLE} description={DESCRIPTION} disableIcon actions={actions}>
      <Stack spacing={2}>
        <AuditFilterBar
          filters={filters}
          agentOptions={agentOptions}
          projectOptions={projectOptions}
          environmentOptions={environmentOptions}
          agentsLoading={agentsLoading}
          activeCount={activeCount}
          onChange={update}
          onClear={() => update(clearedFilters(filters))}
        />
        <AuditCategoryTabs
          value={filters.category}
          counts={categoryCounts}
          onChange={(category) => update({ category })}
        />
        <Typography variant="caption" color="text.secondary" role="status" aria-live="polite">
          {loading
            ? "Loading events…"
            : totalText !== undefined
              ? `Showing ${result.events.length.toLocaleString()} of ${totalText} events`
              : ""}
        </Typography>

        {err ? (
          <Alert
            severity={errorStatus(result.error) === 403 ? "info" : "error"}
            action={
              <Button color="inherit" size="small" onClick={() => result.refetch()}>
                Retry
              </Button>
            }
          >
            <strong>{err.title}</strong> {err.detail}
          </Alert>
        ) : isEmpty ? (
          <NoDataFound
            iconElement={ScrollText}
            message="No audit events found"
            subtitle={
              activeCount > 0 || filters.category
                ? "No events match these filters in the selected time range."
                : "Nothing was recorded in the selected time range. Try a wider range."
            }
            action={
              activeCount > 0 || filters.category ? (
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => update({ ...clearedFilters(filters), category: undefined })}
                >
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        ) : (
          <AuditEventsTable
            events={result.events}
            isLoading={loading}
            selectedId={selected?.id}
            onSelect={setSelected}
            hasMore={result.hasMore}
            isLoadingMore={result.isLoadingMore}
            loadMoreError={result.loadMoreError}
            onLoadMore={result.loadMore}
            sort={filters.sort}
            onSortChange={(sort) => update({ sort })}
          />
        )}
      </Stack>
      <AuditEventDrawer event={selected} onClose={() => setSelected(null)} />
    </PageLayout>
  );
}

export default AuditLogsOrganization;
