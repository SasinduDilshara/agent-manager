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
import {
  Box,
  Button,
  Divider,
  Drawer,
  IconButton,
  ListingTable,
  Stack,
  Typography,
} from "@wso2/oxygen-ui";
import { History, X } from "@wso2/oxygen-ui-icons-react";
import { generatePath, useLocation, useNavigate } from "react-router-dom";
import { returnToState } from "@agent-management-platform/views";
import { useShadowScans } from "@agent-management-platform/api-client";
import {
  formatRelativeTime,
  isListEmpty,
  ResourceListShell,
} from "@agent-management-platform/shared-component";
import { absoluteRouteMap, type ShadowScanResponse } from "@agent-management-platform/types";
import { itemCount, OutcomeChip, providerLabel, ScanStatusChip } from "../shadowUi";

/** The path of a scan's findings page. */
export function scanFindingsPath(orgName: string, scanId: string): string {
  return generatePath(
    absoluteRouteMap.children.org.children.shadowAgentDiscovery.children.scan.path,
    {
      orgId: orgName,
      scanId,
    },
  );
}

/** The outcome of every provider call of a scan, per connection. */
export function ScanDetailsDrawer({
  scan,
  onClose,
}: {
  scan: ShadowScanResponse | null;
  onClose: () => void;
}) {
  return (
    <Drawer anchor="right" open={!!scan} onClose={onClose}>
      <Box sx={{ width: { xs: "100vw", sm: 560 }, p: 3 }} role="dialog" aria-label="Scan details">
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Typography variant="h6">Scan details</Typography>
          <IconButton aria-label="Close" onClick={onClose}>
            <X size={18} />
          </IconButton>
        </Stack>
        {scan && (
          <Stack spacing={2} sx={{ mt: 2 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <ScanStatusChip status={scan.status} />
              <Typography variant="body2" color="text.secondary">
                {scan.findingsCount} findings · {scan.lookbackDays} days of history
              </Typography>
            </Stack>
            {scan.results.length === 0 && (
              <Typography variant="body2" color="text.secondary">
                The scan has not finished any connection yet.
              </Typography>
            )}
            {scan.results.map((r) => (
              <Box key={r.connectionId} sx={{ border: 1, borderColor: "divider", borderRadius: 1 }}>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ p: 1.5 }}>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography variant="body2" fontWeight={500} noWrap>
                      {r.connectionName || r.connectionId}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {providerLabel(r.provider)} · {r.findingsCount} findings
                    </Typography>
                  </Box>
                  <OutcomeChip outcome={r.outcome} />
                </Stack>
                {r.message && (
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    component="p"
                    sx={{ px: 1.5, pb: 1 }}
                  >
                    {r.message}
                  </Typography>
                )}
                <Divider />
                <Stack divider={<Divider />}>
                  {r.calls.map((c) => (
                    <Box key={c.call} sx={{ px: 1.5, py: 1 }}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography
                          variant="caption"
                          sx={{
                            flex: 1,
                            minWidth: 0,
                            fontFamily: "monospace",
                            wordBreak: "break-all",
                          }}
                        >
                          {c.call}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {itemCount(c.items)}
                        </Typography>
                        <OutcomeChip outcome={c.outcome} />
                      </Stack>
                      {c.message && (
                        <Typography variant="caption" color="text.secondary" component="p">
                          {c.message}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Stack>
              </Box>
            ))}
          </Stack>
        )}
      </Box>
    </Drawer>
  );
}

/**
 * The scan history, newest first. A row opens the outcome of every provider
 * call; View findings opens the findings the scan saw.
 */
export function ScansTab({ orgName }: { orgName: string | undefined }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { data, isLoading, error } = useShadowScans(orgName);
  const [open, setOpen] = useState<ShadowScanResponse | null>(null);
  const scans = data?.scans ?? [];
  const current = open ? (scans.find((s) => s.id === open.id) ?? open) : null;

  return (
    <>
      <ResourceListShell
        resourceName="shadow-agent-scans"
        disablePaper
        searchValue=""
        onSearchChange={() => undefined}
        toolbar={<span />}
        error={error ? new Error("Couldn't load scans. Reload the page to try again.") : undefined}
        isLoading={isLoading}
        isEmpty={isListEmpty({ isLoading, count: scans.length, isFiltered: false })}
        emptyState={{
          illustration: <History size={64} />,
          title: "No scans yet",
          description: "Run a scan from the top of this page once a provider is connected.",
        }}
      >
        <ListingTable>
          <ListingTable.Head>
            <ListingTable.Row>
              <ListingTable.Cell>Started</ListingTable.Cell>
              <ListingTable.Cell>Status</ListingTable.Cell>
              <ListingTable.Cell>History read</ListingTable.Cell>
              <ListingTable.Cell>Connections</ListingTable.Cell>
              <ListingTable.Cell>Findings</ListingTable.Cell>
              <ListingTable.Cell align="right" />
            </ListingTable.Row>
          </ListingTable.Head>
          <ListingTable.Body>
            {scans.map((s) => (
              <ListingTable.Row
                key={s.id}
                hover
                sx={{ cursor: "pointer" }}
                onClick={() => setOpen(s)}
              >
                <ListingTable.Cell>
                  <Typography variant="body2">
                    {formatRelativeTime(s.startedAt ?? s.createdAt)}
                  </Typography>
                </ListingTable.Cell>
                <ListingTable.Cell>
                  <ScanStatusChip status={s.status} />
                </ListingTable.Cell>
                <ListingTable.Cell>
                  <Typography variant="body2">{s.lookbackDays} days</Typography>
                </ListingTable.Cell>
                <ListingTable.Cell>
                  <Typography variant="body2">{s.connectionIds.length}</Typography>
                </ListingTable.Cell>
                <ListingTable.Cell>
                  <Typography variant="body2">{s.findingsCount}</Typography>
                </ListingTable.Cell>
                <ListingTable.Cell align="right">
                  <Button
                    variant="outlined"
                    size="small"
                    aria-label={`View findings of the scan started ${formatRelativeTime(
                      s.startedAt ?? s.createdAt,
                    )}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      navigate(scanFindingsPath(orgName ?? "", s.id), {
                        state: returnToState(location),
                      });
                    }}
                  >
                    View findings
                  </Button>
                </ListingTable.Cell>
              </ListingTable.Row>
            ))}
          </ListingTable.Body>
        </ListingTable>
      </ResourceListShell>

      <ScanDetailsDrawer scan={current} onClose={() => setOpen(null)} />
    </>
  );
}

export default ScansTab;
