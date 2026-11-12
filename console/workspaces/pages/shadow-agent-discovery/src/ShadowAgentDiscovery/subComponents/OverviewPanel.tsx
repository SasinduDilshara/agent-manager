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

import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Card,
  CardContent,
  Grid,
  ListingTable,
  Skeleton,
  Stack,
  Typography,
} from "@wso2/oxygen-ui";
import { ChevronDown, ChevronRight, CircleCheck, PlugZap } from "@wso2/oxygen-ui-icons-react";
import { useLocation, useNavigate } from "react-router-dom";
import { returnToState, StateNotice } from "@agent-management-platform/views";
import { useShadowProviders, useShadowSummary } from "@agent-management-platform/api-client";
import { formatRelativeTime } from "@agent-management-platform/shared-component";
import { formatCount, providerLabel, ScanStatusChip } from "../shadowUi";
import { RunScanButton } from "./RunScanButton";
import { scanFindingsPath } from "./ScansTab";

interface OverviewPanelProps {
  orgName: string | undefined;
  canManage: boolean;
  onConnect: () => void;
  onOpenScans: () => void;
  onOpenConnections: () => void;
}

interface Step {
  title: string;
  description: string;
  done: boolean;
  action?: React.ReactNode;
}

/** The order to work in: connect, test, scan, review, onboard. */
function GettingStarted({ steps }: { steps: Step[] }) {
  return (
    <Box>
      <Typography variant="subtitle1" sx={{ mb: 1.5 }}>
        How to find and onboard shadow agents
      </Typography>
      <Stack
        direction={{ xs: "column", lg: "row" }}
        spacing={1}
        alignItems={{ lg: "stretch" }}
        component="ol"
        sx={{ listStyle: "none", m: 0, p: 0 }}
      >
        {steps.map((s, i) => (
          <Stack
            key={s.title}
            component="li"
            direction={{ xs: "column", lg: "row" }}
            spacing={1}
            alignItems={{ lg: "center" }}
            sx={{ flex: 1, minWidth: 0 }}
          >
            <Card variant="outlined" sx={{ flex: 1, height: "100%" }}>
              <CardContent>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
                  {s.done ? (
                    <Box sx={{ color: "success.main", display: "flex" }} aria-label="Done">
                      <CircleCheck size={18} />
                    </Box>
                  ) : (
                    <Typography variant="body2" color="text.secondary" fontWeight={500}>
                      {i + 1}.
                    </Typography>
                  )}
                  <Typography variant="body2" fontWeight={500}>
                    {s.title}
                  </Typography>
                </Stack>
                <Typography variant="caption" color="text.secondary" component="p">
                  {s.description}
                </Typography>
                {s.action && <Box sx={{ mt: 1.5 }}>{s.action}</Box>}
              </CardContent>
            </Card>
            {i < steps.length - 1 && (
              <Box sx={{ display: { xs: "none", lg: "flex" }, color: "text.disabled" }} aria-hidden>
                <ChevronRight size={18} />
              </Box>
            )}
          </Stack>
        ))}
      </Stack>
    </Box>
  );
}

function StatTile({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <Card variant="outlined" sx={{ height: "100%" }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
        <Typography variant="h4" sx={{ my: 0.5 }}>
          {value}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {hint}
        </Typography>
      </CardContent>
    </Card>
  );
}

/** Counts by verdict, the latest scan and how a score is made. */
export function OverviewPanel({
  orgName,
  canManage,
  onConnect,
  onOpenScans,
  onOpenConnections,
}: OverviewPanelProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const summary = useShadowSummary(orgName);
  const providers = useShadowProviders(orgName);
  const connected = (summary.data?.connections ?? 0) > 0;
  const scanned = !!summary.data?.latestScan;
  const steps: Step[] = [
    {
      title: "Add a connection",
      description:
        "Connect a model provider, a cloud agent platform or a source repository host with a read-only credential.",
      done: connected,
      action: canManage ? (
        <Button size="small" variant="outlined" onClick={onConnect}>
          Add connection
        </Button>
      ) : undefined,
    },
    {
      title: "Test the connection",
      description: "Test connection makes one read-only call per capability and shows what works.",
      done: false,
      action: connected ? (
        <Button size="small" variant="outlined" onClick={onOpenConnections}>
          Open connections
        </Button>
      ) : undefined,
    },
    {
      title: "Run a scan",
      description: "A scan reads the chosen history from every connection, in the background.",
      done: scanned,
      action: canManage && connected ? <RunScanButton orgName={orgName} /> : undefined,
    },
    {
      title: "Review the findings",
      description:
        "In Scans, choose View findings on a scan to see what it found, with the evidence.",
      done: false,
      action: scanned ? (
        <Button size="small" variant="outlined" onClick={onOpenScans}>
          Open scans
        </Button>
      ) : undefined,
    },
    {
      title: "Onboard and retire",
      description:
        "Onboard an agent from its finding, then revoke its direct credential once its direct usage stops.",
      done: (summary.data?.byStatus?.onboarded ?? 0) > 0,
    },
  ];

  if (summary.isLoading) {
    return (
      <Grid container spacing={2}>
        {[0, 1, 2, 3].map((i) => (
          <Grid key={i} size={{ xs: 12, sm: 6, lg: 3 }}>
            <Skeleton variant="rounded" height={112} />
          </Grid>
        ))}
      </Grid>
    );
  }
  if (summary.error) {
    return (
      <Typography variant="body2" color="error">
        Couldn&apos;t load the summary. Reload the page to try again.
      </Typography>
    );
  }
  const s = summary.data;
  if (s && s.connections === 0) {
    return (
      <Stack spacing={3}>
        <StateNotice
          icon={PlugZap}
          title="Connect a provider to start"
          description="Shadow Agent Discovery reads provider admin and cloud management APIs with a read-only credential to find agents and LLM workloads that call providers directly."
          actions={
            canManage ? (
              <Button variant="contained" onClick={onConnect}>
                Connect provider
              </Button>
            ) : undefined
          }
        />
        <GettingStarted steps={steps} />
      </Stack>
    );
  }

  const v = s?.byVerdict ?? {};
  const scoring = providers.data?.scoring;
  return (
    <Stack spacing={3}>
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 6, lg: 3 }}>
          <StatTile
            label="Agents"
            value={formatCount(v.agent)}
            hint="Confidence score at or above the agent threshold"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, lg: 3 }}>
          <StatTile
            label="Possible agents"
            value={formatCount(v.possible_agent)}
            hint="Tool use seen, more evidence needed"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, lg: 3 }}>
          <StatTile
            label="LLM consumers"
            value={formatCount(v.llm_consumer)}
            hint="Direct model usage without agent signals"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, lg: 3 }}>
          <StatTile
            label="Tool infrastructure"
            value={formatCount(v.tool_infrastructure)}
            hint="MCP servers and gateways agents use"
          />
        </Grid>
      </Grid>

      <Card variant="outlined">
        <CardContent>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
            <Box sx={{ flex: 1 }}>
              <Typography variant="subtitle1">Latest scan</Typography>
              {s?.latestScan ? (
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 0.5 }}>
                  <ScanStatusChip status={s.latestScan.status} />
                  <Typography variant="body2" color="text.secondary">
                    {formatRelativeTime(s.latestScan.startedAt ?? s.latestScan.createdAt)} ·{" "}
                    {s.latestScan.findingsCount} findings · {s.connections} connected{" "}
                    {s.connections === 1 ? "provider" : "providers"}
                  </Typography>
                </Stack>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No scan yet. Use Run scan at the top of the page.
                </Typography>
              )}
            </Box>
            {s?.latestScan && (
              <Stack direction="row" spacing={1}>
                <Button
                  variant="outlined"
                  onClick={() =>
                    navigate(scanFindingsPath(orgName ?? "", s.latestScan?.id ?? ""), {
                      state: returnToState(location),
                    })
                  }
                >
                  View findings
                </Button>
                <Button variant="text" onClick={onOpenScans}>
                  All scans
                </Button>
              </Stack>
            )}
          </Stack>
          {s && Object.keys(s.byProvider).length > 0 && (
            <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1.5 }}>
              Findings by provider:{" "}
              {Object.entries(s.byProvider)
                .map(([p, n]) => `${providerLabel(p)} ${n}`)
                .join(" · ")}
            </Typography>
          )}
        </CardContent>
      </Card>

      {scoring && providers.data && (
        <Accordion variant="outlined" disableGutters>
          <AccordionSummary expandIcon={<ChevronDown size={18} />}>
            <Typography variant="subtitle1">How the confidence score works</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              A finding&apos;s confidence score adds the weight of the signals the provider APIs
              show, once per kind of evidence, up to {scoring.maxScore}. An agent object the
              provider itself lists is definitive and scores {scoring.maxScore} on its own. An agent
              scores {scoring.agentThreshold} or more with at least one definitive or high signal; a
              possible agent scores {scoring.possibleAgentThreshold} to {scoring.agentThreshold - 1}{" "}
              with a high signal; anything else is an LLM consumer. Prompts, completions and tool
              payloads are never stored. Open a connection type to see its signals.
            </Typography>
            <Stack spacing={1}>
              {providers.data.providers
                .map((p) => ({
                  p,
                  signals: providers.data?.signals.filter((d) => d.provider === p.provider) ?? [],
                }))
                .filter((x) => x.signals.length > 0)
                .map(({ p, signals }) => (
                  <Accordion key={p.provider} variant="outlined" disableGutters>
                    <AccordionSummary expandIcon={<ChevronDown size={16} />}>
                      <Typography variant="body2" fontWeight={500}>
                        {p.displayName}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                        · {signals.length} {signals.length === 1 ? "signal" : "signals"}
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ overflowX: "auto" }}>
                        <ListingTable>
                          <ListingTable.Head>
                            <ListingTable.Row>
                              <ListingTable.Cell>Signal</ListingTable.Cell>
                              <ListingTable.Cell>Weight</ListingTable.Cell>
                              <ListingTable.Cell>Exact condition</ListingTable.Cell>
                            </ListingTable.Row>
                          </ListingTable.Head>
                          <ListingTable.Body>
                            {signals.map((d) => (
                              <ListingTable.Row key={d.code}>
                                <ListingTable.Cell>{d.name}</ListingTable.Cell>
                                <ListingTable.Cell>{d.weight}</ListingTable.Cell>
                                <ListingTable.Cell>
                                  <Typography variant="caption" color="text.secondary">
                                    {d.condition}
                                  </Typography>
                                </ListingTable.Cell>
                              </ListingTable.Row>
                            ))}
                          </ListingTable.Body>
                        </ListingTable>
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                ))}
            </Stack>
          </AccordionDetails>
        </Accordion>
      )}

      <GettingStarted steps={steps} />
    </Stack>
  );
}

export default OverviewPanel;
