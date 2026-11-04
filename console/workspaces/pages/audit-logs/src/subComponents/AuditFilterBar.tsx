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

import { useEffect, useState, type ReactNode } from "react";
import {
  Autocomplete,
  Button,
  Checkbox,
  Chip,
  InputAdornment,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from "@wso2/oxygen-ui";
import { Bot, Search, User, X } from "@wso2/oxygen-ui-icons-react";
import { AUDIT_OUTCOMES, type AuditOutcome } from "@agent-management-platform/types";
import type { AuditFilters } from "../auditFilters";
import { OUTCOME_COLOR, OUTCOME_LABEL } from "../auditFormat";

export interface FilterOption {
  value: string;
  label: string;
  /** Group heading in the list, e.g. the agent's project. */
  group?: string;
}

export interface AuditFilterBarProps {
  filters: AuditFilters;
  agentOptions: FilterOption[];
  projectOptions: FilterOption[];
  environmentOptions: FilterOption[];
  agentsLoading?: boolean;
  activeCount: number;
  onChange: (patch: Partial<AuditFilters>) => void;
  onClear: () => void;
}

const TEXT_DEBOUNCE_MS = 400;
const ANY = "__any__";

/**
 * A text field that edits a URL-backed value: typing updates a local draft and
 * the value is committed after a short pause, so each keystroke is not a
 * request. A change made elsewhere (Clear filters, back button) resets it.
 */
function DebouncedTextFilter({
  value,
  onCommit,
  placeholder,
  ariaLabel,
  icon,
  width,
}: {
  value?: string;
  onCommit: (v: string | undefined) => void;
  placeholder: string;
  ariaLabel: string;
  icon: ReactNode;
  width: number;
}) {
  const [draft, setDraft] = useState(value ?? "");
  const [committed, setCommitted] = useState(value ?? "");
  if ((value ?? "") !== committed) {
    setCommitted(value ?? "");
    setDraft(value ?? "");
  }
  useEffect(() => {
    if (draft.trim() === committed) return undefined;
    const t = setTimeout(() => onCommit(draft.trim() || undefined), TEXT_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [draft, committed, onCommit]);

  return (
    <TextField
      size="small"
      value={draft}
      placeholder={placeholder}
      onChange={(e) => setDraft(e.target.value)}
      onKeyDown={(e) => {
        if (e.key === "Enter") onCommit(draft.trim() || undefined);
      }}
      slotProps={{
        htmlInput: { "aria-label": ariaLabel },
        input: {
          startAdornment: <InputAdornment position="start">{icon}</InputAdornment>,
          endAdornment: draft ? (
            <InputAdornment position="end">
              <X
                size={14}
                role="button"
                aria-label={`Clear ${ariaLabel.toLowerCase()}`}
                style={{ cursor: "pointer" }}
                onClick={() => {
                  setDraft("");
                  onCommit(undefined);
                }}
              />
            </InputAdornment>
          ) : undefined,
        },
      }}
      sx={{ width }}
    />
  );
}

function SingleSelect({
  value,
  options,
  anyLabel,
  ariaLabel,
  onChange,
}: {
  value?: string;
  options: FilterOption[];
  anyLabel: string;
  ariaLabel: string;
  onChange: (v: string | undefined) => void;
}) {
  // Keep a value from a shared link selectable even if it is not listed.
  const all =
    value && !options.some((o) => o.value === value)
      ? [...options, { value, label: value }]
      : options;
  return (
    <Select
      size="small"
      value={value ?? ANY}
      onChange={(e) => onChange(e.target.value === ANY ? undefined : String(e.target.value))}
      inputProps={{ "aria-label": ariaLabel }}
      sx={{ minWidth: 150 }}
    >
      <MenuItem value={ANY}>{anyLabel}</MenuItem>
      {all.map((o) => (
        <MenuItem key={o.value} value={o.value}>
          {o.label}
        </MenuItem>
      ))}
    </Select>
  );
}

/** Agent, project, environment, outcome, actor and free-text filters. */
export function AuditFilterBar({
  filters,
  agentOptions,
  projectOptions,
  environmentOptions,
  agentsLoading,
  activeCount,
  onChange,
  onClear,
}: AuditFilterBarProps) {
  const selectedAgents: FilterOption[] = filters.agents.map(
    (v) => agentOptions.find((o) => o.value === v) ?? { value: v, label: v },
  );

  const toggleOutcome = (o: AuditOutcome) => {
    const set = new Set(filters.outcomes);
    if (set.has(o)) set.delete(o);
    else set.add(o);
    onChange({ outcomes: AUDIT_OUTCOMES.filter((x) => set.has(x)) });
  };

  return (
    <Stack spacing={1.5} role="search" aria-label="Audit event filters">
      <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
        <Autocomplete
          multiple
          size="small"
          limitTags={2}
          loading={agentsLoading}
          options={agentOptions}
          value={selectedAgents}
          groupBy={(o) => o.group ?? ""}
          getOptionLabel={(o) => o.label}
          isOptionEqualToValue={(a, b) => a.value === b.value}
          disableCloseOnSelect
          onChange={(_, v) => onChange({ agents: v.map((o) => o.value) })}
          renderOption={(props, option, { selected }) => {
            const { key, ...rest } = props as typeof props & { key: string };
            return (
              <li key={key} {...rest}>
                <Checkbox size="small" checked={selected} sx={{ mr: 1, p: 0.5 }} />
                {option.label}
              </li>
            );
          }}
          renderInput={(params) => (
            <TextField
              {...params}
              placeholder={filters.agents.length ? "" : "All agents"}
              slotProps={{
                htmlInput: { ...params.inputProps, "aria-label": "Filter by agent" },
                input: {
                  ...params.InputProps,
                  startAdornment: (
                    <>
                      <InputAdornment position="start">
                        <Bot size={16} aria-hidden />
                      </InputAdornment>
                      {params.InputProps.startAdornment}
                    </>
                  ),
                },
              }}
            />
          )}
          sx={{ minWidth: 240, maxWidth: 420, flex: "1 1 240px" }}
        />
        <SingleSelect
          value={filters.project}
          options={projectOptions}
          anyLabel="All projects"
          ariaLabel="Filter by project"
          onChange={(project) => onChange({ project })}
        />
        <SingleSelect
          value={filters.environment}
          options={environmentOptions}
          anyLabel="All environments"
          ariaLabel="Filter by environment"
          onChange={(environment) => onChange({ environment })}
        />
        <DebouncedTextFilter
          value={filters.actor}
          onCommit={(actor) => onChange({ actor })}
          placeholder="Actor, subject or client ID"
          ariaLabel="Filter by actor"
          icon={<User size={16} aria-hidden />}
          width={220}
        />
        <DebouncedTextFilter
          value={filters.search}
          onCommit={(search) => onChange({ search })}
          placeholder="Search action, resource, model, policy…"
          ariaLabel="Search audit events"
          icon={<Search size={16} aria-hidden />}
          width={300}
        />
      </Stack>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Typography variant="caption" color="text.secondary" id="audit-outcome-label">
          Outcome
        </Typography>
        <Stack direction="row" spacing={1} role="group" aria-labelledby="audit-outcome-label">
          {AUDIT_OUTCOMES.map((o) => {
            const on = filters.outcomes.includes(o);
            return (
              <Chip
                key={o}
                size="small"
                clickable
                label={OUTCOME_LABEL[o]}
                color={on ? OUTCOME_COLOR[o] : "default"}
                variant={on ? "filled" : "outlined"}
                aria-pressed={on}
                onClick={() => toggleOutcome(o)}
                data-testid={`outcome-filter-${o}`}
              />
            );
          })}
        </Stack>
        {activeCount > 0 && (
          <Button
            size="small"
            variant="text"
            startIcon={<X size={14} />}
            onClick={onClear}
            sx={{ ml: "auto" }}
          >
            Clear filters ({activeCount})
          </Button>
        )}
      </Stack>
    </Stack>
  );
}
