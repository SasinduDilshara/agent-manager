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

import { useDeferredValue, useMemo, useState } from "react";
import { Box, Button, ListingTable, MenuItem, SearchBar, Stack, Typography } from "@wso2/oxygen-ui";
import { ScanSearch } from "@wso2/oxygen-ui-icons-react";
import { generatePath, useLocation, useNavigate } from "react-router-dom";
import { returnToState, TextInput } from "@agent-management-platform/views";
import { useShadowFindings } from "@agent-management-platform/api-client";
import {
  formatRelativeTime,
  isListEmpty,
  ResourceListShell,
} from "@agent-management-platform/shared-component";
import { absoluteRouteMap, type ShadowFindingListQuery } from "@agent-management-platform/types";
import {
  kindLabel,
  ownerLabel,
  PROVIDER_LABELS,
  providerLabel,
  ScoreBar,
  SOURCE_HOSTS,
  StatusChip,
  VERDICT_LABELS,
  VerdictChip,
} from "../shadowUi";

const PAGE_SIZE = 50;

interface FindingsTabProps {
  orgName: string | undefined;
  /** Only the findings this scan saw. */
  scanId?: string;
  /** Replaces the empty state's text (e.g. a scan from before findings were recorded per scan). */
  emptyText?: { title: string; description: string };
  /** Shown in the empty state when there is nothing to scan yet. */
  emptyAction?: React.ReactNode;
}

/** The findings list: potential agents, highest score first. */
export function FindingsTab({ orgName, scanId, emptyText, emptyAction }: FindingsTabProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [search, setSearch] = useState("");
  const [verdict, setVerdict] = useState("");
  const [provider, setProvider] = useState("");
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const deferredSearch = useDeferredValue(search.trim());
  const query = useMemo<ShadowFindingListQuery>(
    () => ({
      scanId,
      search: deferredSearch,
      verdict,
      provider,
      status,
      limit: PAGE_SIZE,
      offset,
    }),
    [scanId, deferredSearch, verdict, provider, status, offset],
  );
  const { data, isLoading, error } = useShadowFindings(orgName, query);
  const findings = data?.findings ?? [];
  const total = data?.total ?? 0;
  const isFiltered = !!(deferredSearch || verdict || provider || status);

  const setFilter = (set: (v: string) => void) => (v: string) => {
    set(v);
    setOffset(0);
  };

  const toolbar = (
    <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} alignItems={{ md: "center" }}>
      <Box sx={{ width: { xs: "100%", md: 400 } }}>
        <SearchBar
          placeholder="Search by name, ID or owner"
          size="small"
          value={search}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
            setFilter(setSearch)(e.target.value)
          }
          fullWidth
        />
      </Box>
      <Box sx={{ flex: 1 }} />
      <Box sx={{ minWidth: 170 }}>
        <TextInput
          select
          aria-label="Verdict"
          value={verdict}
          onChange={(e) => setFilter(setVerdict)(e.target.value)}
          size="small"
          slotProps={{ select: { displayEmpty: true } }}
        >
          <MenuItem value="">All verdicts</MenuItem>
          {Object.entries(VERDICT_LABELS).map(([k, v]) => (
            <MenuItem key={k} value={k}>
              {v}
            </MenuItem>
          ))}
        </TextInput>
      </Box>
      <Box sx={{ minWidth: 190 }}>
        <TextInput
          select
          aria-label="Provider"
          value={provider}
          onChange={(e) => setFilter(setProvider)(e.target.value)}
          size="small"
          slotProps={{ select: { displayEmpty: true } }}
        >
          <MenuItem value="">All providers</MenuItem>
          {Object.entries(PROVIDER_LABELS)
            .filter(([k]) => !SOURCE_HOSTS.includes(k))
            .map(([k, v]) => (
              <MenuItem key={k} value={k}>
                {v}
              </MenuItem>
            ))}
        </TextInput>
      </Box>
      <Box sx={{ minWidth: 150 }}>
        <TextInput
          select
          aria-label="Status"
          value={status}
          onChange={(e) => setFilter(setStatus)(e.target.value)}
          size="small"
          slotProps={{ select: { displayEmpty: true } }}
        >
          <MenuItem value="">All statuses</MenuItem>
          <MenuItem value="new">New</MenuItem>
          <MenuItem value="reviewed">Reviewed</MenuItem>
          <MenuItem value="onboarded">Onboarded</MenuItem>
          <MenuItem value="retired">Retired</MenuItem>
          <MenuItem value="dismissed">Dismissed</MenuItem>
        </TextInput>
      </Box>
    </Stack>
  );

  return (
    <ResourceListShell
      resourceName="shadow-agent-findings"
      disablePaper
      searchValue={search}
      onSearchChange={setFilter(setSearch)}
      toolbar={toolbar}
      error={error ? new Error("Couldn't load findings. Reload the page to try again.") : undefined}
      isLoading={isLoading}
      isEmpty={isListEmpty({ isLoading, count: findings.length, isFiltered })}
      isSearchEmpty={!isLoading && isFiltered && findings.length === 0}
      emptyState={{
        illustration: <ScanSearch size={64} />,
        title: emptyText?.title ?? (scanId ? "This scan found nothing" : "No findings yet"),
        description: emptyText
          ? emptyText.description
          : scanId
            ? "No connection of this scan returned an agent or an LLM workload. Open the scan details to see each provider call."
            : "Connect a provider and run a scan. Agents and LLM workloads that call providers directly show up here.",
        action: emptyAction,
      }}
      searchEmptyState={{
        illustration: <ScanSearch size={64} />,
        title: "No findings match your filters",
        description: "Try other search keywords or clear the filters.",
      }}
    >
      <ListingTable>
        <ListingTable.Head>
          <ListingTable.Row>
            <ListingTable.Cell>Finding</ListingTable.Cell>
            <ListingTable.Cell>Provider</ListingTable.Cell>
            <ListingTable.Cell>Score</ListingTable.Cell>
            <ListingTable.Cell>Verdict</ListingTable.Cell>
            <ListingTable.Cell>Owner hint</ListingTable.Cell>
            <ListingTable.Cell>Last used</ListingTable.Cell>
            <ListingTable.Cell>Status</ListingTable.Cell>
          </ListingTable.Row>
        </ListingTable.Head>
        <ListingTable.Body>
          {findings.map((f) => (
            <ListingTable.Row
              key={f.id}
              hover
              sx={{ cursor: "pointer" }}
              onClick={() =>
                navigate(
                  generatePath(
                    absoluteRouteMap.children.org.children.shadowAgentDiscovery.children.finding
                      .path,
                    { orgId: orgName ?? "", findingId: f.id },
                  ),
                  { state: returnToState(location) },
                )
              }
            >
              <ListingTable.Cell>
                <Typography variant="body2" fontWeight={500}>
                  {f.displayName}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {kindLabel(f.kind, f.provider)}
                  {f.scope ? ` · ${f.scope}` : ""}
                </Typography>
              </ListingTable.Cell>
              <ListingTable.Cell>
                <Typography variant="body2">{providerLabel(f.provider)}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {f.connectionName}
                </Typography>
              </ListingTable.Cell>
              <ListingTable.Cell>
                <ScoreBar score={f.score} />
              </ListingTable.Cell>
              <ListingTable.Cell>
                <VerdictChip verdict={f.verdict} />
              </ListingTable.Cell>
              <ListingTable.Cell>
                <Typography
                  variant="body2"
                  color={ownerLabel(f.ownerHint) ? "text.primary" : "text.secondary"}
                >
                  {ownerLabel(f.ownerHint) || "Unknown"}
                </Typography>
              </ListingTable.Cell>
              <ListingTable.Cell>
                <Typography variant="body2" color="text.secondary">
                  {f.lastUsedAt ? formatRelativeTime(f.lastUsedAt) : "—"}
                </Typography>
              </ListingTable.Cell>
              <ListingTable.Cell>
                <StatusChip status={f.status} />
              </ListingTable.Cell>
            </ListingTable.Row>
          ))}
        </ListingTable.Body>
      </ListingTable>
      {total > PAGE_SIZE && (
        <Stack direction="row" spacing={1} alignItems="center" sx={{ pt: 2 }}>
          <Button
            variant="outlined"
            size="small"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            Previous
          </Button>
          <Button
            variant="outlined"
            size="small"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Next
          </Button>
          <Typography variant="body2" color="text.secondary">
            {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </Typography>
        </Stack>
      )}
    </ResourceListShell>
  );
}

export default FindingsTab;
