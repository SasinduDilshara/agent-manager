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
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Grid,
  ListingTable,
  Skeleton,
  Stack,
  Tooltip,
  Typography,
} from "@wso2/oxygen-ui";
import { ArrowRight, SearchX } from "@wso2/oxygen-ui-icons-react";
import {
  generatePath,
  Link as RouterLink,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";
import {
  PageLayout,
  returnToState,
  StateNotice,
  useReturnTo,
} from "@agent-management-platform/views";
import { useShadowFinding, useUpdateShadowFinding } from "@agent-management-platform/api-client";
import { absoluteRouteMap, type ShadowFindingDetail } from "@agent-management-platform/types";
import {
  kindLabel,
  ownerLabel,
  providerLabel,
  ScoreBar,
  shortDate,
  StatusChip,
  VerdictChip,
} from "../shadowUi";
import { RetirementCard } from "./RetirementCard";
import { UsageCard } from "./UsageCard";

/** A related finding's relation, as a short label. */
export function relationLabel(relation: string, provider: string): string {
  switch (relation) {
    case "agent_in_project":
      return provider === "anthropic" ? "Agent in this workspace" : "Agent in this project";
    case "candidate_key":
      return "Candidate key";
    case "used_by_agent":
      return "Used by agent";
    case "uses_deployment":
      return "Uses deployment";
    case "possible_duplicate":
      return "Possible duplicate";
    default:
      return relation.replace(/_/g, " ");
  }
}

/**
 * What a project (or workspace) finding is: evidence read with a project or
 * workspace key that cannot be tied to one API key. It has no credential of
 * its own to retire.
 */
export function ProjectFindingNote({ finding: f }: { finding: ShadowFindingDetail }) {
  const unit = f.provider === "anthropic" ? "workspace" : "project";
  const sources =
    f.provider === "anthropic" ? "message batches" : "stored chat completions or batches";
  const candidates = f.related.filter((r) => r.relation === "candidate_key").length;
  return (
    <Alert severity="info">
      <Typography variant="body2" fontWeight={500} gutterBottom>
        Evidence that is not tied to one API key
      </Typography>
      <Typography variant="body2" component="p">
        Tool calls were found in this {unit}&apos;s {sources}, read with its {unit} key. These
        records belong to the {unit}, not to a key.{" "}
        {candidates > 0
          ? `More than one key of the ${unit} was used in the scanned period: one of the ${candidates} candidate keys under Related findings made these calls.`
          : `The keys of this ${unit} are not known. Add an Admin API key to the connection: the next scan then ties the evidence to a key when only one key was used.`}
      </Typography>
      <Typography variant="body2" component="p" sx={{ mt: 1 }}>
        A {unit} has no credential of its own, so there is nothing to retire here. Retire the keys
        from their own findings.
      </Typography>
    </Alert>
  );
}

const ATTRIBUTE_LABELS: Record<string, string> = {
  model: "Model",
  models: "Models",
  modelVersion: "Model version",
  framework: "Framework",
  agentKind: "Agent kind",
  agentVersion: "Version",
  serverProtocol: "Server protocol",
  image: "Container image",
  repositoryUrl: "Source repository",
  region: "Region",
  location: "Location",
  project: "Project",
  workspace: "Workspace",
  deployment: "Deployment",
  roleArn: "Execution role",
  serviceAccount: "Service account",
  resourceId: "Resource ID",
  accountKind: "Account kind",
  sku: "SKU",
  orchestrationType: "Orchestration",
  principalType: "Identity type",
  protocolType: "Protocol",
  authorizerType: "Authorizer",
  recordType: "Record type",
  tools: "Tools",
  toolCount: "Tool count",
  mcpServers: "MCP servers",
  skills: "Skills",
  endpoint: "Endpoint",
  accountId: "Cloud account",
  capacity: "Capacity",
  apiSources: "API sources",
  products: "Products",
  archived: "Archived",
  state: "State",
  status: "Status",
  labels: "Labels",
  otelAgentId: "Telemetry agent ID",
  deepInspection: "Deep inspection",
  invocationLogging: "Model invocation logging",
  sessionCount: "Sessions",
  lastSessionAt: "Last session",
  description: "Description",
  displayName: "Display name",
  runtimeReference: "Runtime reference",
  agentEndpointURL: "Agent endpoint",
  agentCardURL: "Agent card",
  possibleDuplicates: "Possible duplicates",
};

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) {
    return v
      .map((x) =>
        typeof x === "object" && x !== null
          ? [
              (x as { type?: string; label?: string }).type ?? (x as { label?: string }).label,
              (x as { name?: string; origin?: string }).name ?? (x as { origin?: string }).origin,
            ]
              .filter(Boolean)
              .join(": ")
          : String(x),
      )
      .join(", ");
  }
  if (typeof v === "object") {
    return Object.entries(v as Record<string, unknown>)
      .map(([k, x]) => `${k}=${String(x)}`)
      .join(", ");
  }
  return String(v);
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <Box>
      <Typography variant="caption" color="text.secondary">
        {label}
      </Typography>
      <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
        {value || "—"}
      </Typography>
    </Box>
  );
}

function EvidenceCard({ finding }: { finding: ShadowFindingDetail }) {
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="subtitle1" gutterBottom>
          Evidence
        </Typography>
        {finding.signals.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            No signals in the scanned period.
          </Typography>
        ) : (
          <Box sx={{ overflowX: "auto" }}>
            <ListingTable>
              <ListingTable.Head>
                <ListingTable.Row>
                  <ListingTable.Cell>Signal</ListingTable.Cell>
                  <ListingTable.Cell>Weight</ListingTable.Cell>
                  <ListingTable.Cell>Exact condition</ListingTable.Cell>
                  <ListingTable.Cell>Observed</ListingTable.Cell>
                </ListingTable.Row>
              </ListingTable.Head>
              <ListingTable.Body>
                {finding.signals.map((s) => (
                  <ListingTable.Row key={`${s.code}|${s.source}`}>
                    <ListingTable.Cell>
                      <Typography variant="body2" fontWeight={500}>
                        {s.name || s.code}
                      </Typography>
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ fontFamily: "monospace" }}
                      >
                        {s.source}
                      </Typography>
                    </ListingTable.Cell>
                    <ListingTable.Cell>
                      {s.counted === false && s.weight > 0 ? (
                        <Tooltip title="Another signal of the same kind already counts">
                          <Typography variant="body2" color="text.secondary">
                            {s.weight} (not counted)
                          </Typography>
                        </Tooltip>
                      ) : (
                        <Typography variant="body2">{s.weight}</Typography>
                      )}
                    </ListingTable.Cell>
                    <ListingTable.Cell>
                      <Typography variant="caption" color="text.secondary">
                        {s.condition}
                      </Typography>
                    </ListingTable.Cell>
                    <ListingTable.Cell>
                      <Typography variant="caption">{formatValue(s.observed)}</Typography>
                    </ListingTable.Cell>
                  </ListingTable.Row>
                ))}
              </ListingTable.Body>
            </ListingTable>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

/** One finding: its score and the evidence behind it, owner hint, usage and onboarding. */
export function FindingDetail({
  orgName,
  canManage,
  listPath,
}: {
  orgName: string | undefined;
  canManage: boolean;
  listPath: string;
}) {
  const { findingId } = useParams<{ findingId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const returnTo = useReturnTo(`${listPath}?tab=scans`);
  const { data: f, isLoading, error } = useShadowFinding(orgName, findingId);
  const update = useUpdateShadowFinding(orgName, findingId);
  const back = { backHref: returnTo, backLabel: "Back to findings" };

  if (isLoading) {
    return (
      <PageLayout title="Finding" disableIcon {...back}>
        <Skeleton variant="rounded" height={360} />
      </PageLayout>
    );
  }
  if (error || !f) {
    return (
      <PageLayout title="Finding" disableIcon {...back}>
        <StateNotice
          icon={SearchX}
          tone="error"
          title="Couldn't load this finding"
          description="It may have been deleted with its connection. Go back to the findings list."
        />
      </PageLayout>
    );
  }

  const canOnboard = canManage && !f.linkedAgent && f.kind !== "tool_infrastructure";
  const onboardHref = generatePath(
    absoluteRouteMap.children.org.children.shadowAgentDiscovery.children.finding.children.onboard
      .path,
    { orgId: orgName ?? "", findingId: f.id },
  );
  const attributes = Object.entries(f.attributes ?? {});
  const owner = ownerLabel(f.ownerHint);

  return (
    <PageLayout
      title={f.displayName}
      description={`${providerLabel(f.provider)} · ${kindLabel(f.kind, f.provider)} · ${f.connectionName}`}
      disableIcon
      {...back}
      actions={
        canOnboard ? (
          <Button
            variant="contained"
            endIcon={<ArrowRight size={16} />}
            onClick={() => navigate(onboardHref, { state: returnToState(location) })}
          >
            Onboard as a governed agent
          </Button>
        ) : undefined
      }
    >
      <Stack spacing={3}>
        <Card variant="outlined">
          <CardContent>
            <Grid container spacing={2} alignItems="center">
              <Grid size={{ xs: 12, md: 4 }}>
                <Typography variant="caption" color="text.secondary">
                  Score
                </Typography>
                <ScoreBar score={f.score} />
              </Grid>
              <Grid size={{ xs: 6, md: 2 }}>
                <Typography variant="caption" color="text.secondary" component="p">
                  Verdict
                </Typography>
                <VerdictChip verdict={f.verdict} />
              </Grid>
              <Grid size={{ xs: 6, md: 2 }}>
                <Typography variant="caption" color="text.secondary" component="p">
                  Status
                </Typography>
                <StatusChip status={f.status} />
              </Grid>
              <Grid size={{ xs: 12, md: 4 }}>
                {f.linkedAgent ? (
                  <Field
                    label="Governed agent"
                    value={
                      <RouterLink
                        to={generatePath(
                          absoluteRouteMap.children.org.children.projects.children.agents.path,
                          {
                            orgId: orgName ?? "",
                            projectId: f.linkedProject,
                            agentId: f.linkedAgent,
                          },
                        )}
                      >
                        {f.linkedProject} / {f.linkedAgent}
                      </RouterLink>
                    }
                  />
                ) : (
                  canManage &&
                  !f.linkedAgent && (
                    <Stack direction="row" spacing={1}>
                      {f.status !== "reviewed" && f.status !== "dismissed" && (
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => update.mutate({ status: "reviewed" })}
                        >
                          Mark reviewed
                        </Button>
                      )}
                      {f.status === "dismissed" ? (
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => update.mutate({ status: "new" })}
                        >
                          Reopen
                        </Button>
                      ) : (
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => update.mutate({ status: "dismissed" })}
                        >
                          Dismiss
                        </Button>
                      )}
                    </Stack>
                  )
                )}
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {f.kind === "project" ? (
          <ProjectFindingNote finding={f} />
        ) : (
          <RetirementCard orgName={orgName} finding={f} canManage={canManage} />
        )}

        <EvidenceCard finding={f} />

        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 6 }}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  Owner hint
                </Typography>
                <Stack spacing={1.5}>
                  <Field label="Who" value={owner || "Unknown"} />
                  {f.ownerHint?.name && f.ownerHint.name !== owner && (
                    <Field label="Name" value={f.ownerHint.name} />
                  )}
                  {f.ownerHint?.username && f.ownerHint.username !== owner && (
                    <Field label="Username / principal" value={f.ownerHint.username} />
                  )}
                  <Field label="Source" value={f.ownerHint?.source} />
                  <Grid container spacing={1.5}>
                    <Grid size={6}>
                      <Field
                        label="Created at provider"
                        value={shortDate(f.providerCreatedAt ?? f.ownerHint?.createdAt)}
                      />
                    </Grid>
                    <Grid size={6}>
                      <Field label="First seen by a scan" value={shortDate(f.firstSeenAt)} />
                    </Grid>
                    <Grid size={6}>
                      <Field label="First used" value={shortDate(f.firstUsedAt)} />
                    </Grid>
                    <Grid size={6}>
                      <Field label="Last used" value={shortDate(f.lastUsedAt)} />
                    </Grid>
                  </Grid>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  Details
                </Typography>
                <Stack spacing={1.5}>
                  <Field
                    label="Provider ID"
                    value={<span style={{ fontFamily: "monospace" }}>{f.externalId}</span>}
                  />
                  {f.scope && <Field label="Scope" value={f.scope} />}
                  {f.state && <Field label="State at the provider" value={f.state} />}
                  {attributes.map(([k, v]) => (
                    <Field key={k} label={ATTRIBUTE_LABELS[k] ?? k} value={formatValue(v)} />
                  ))}
                  <Typography variant="caption" color="text.secondary">
                    Prompts, instructions, completions, tool payloads and secrets are never stored.
                  </Typography>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        <UsageCard
          usage={f.usage}
          onboardedAt={f.onboardedAt}
          through={f.lastSeenAt?.slice(0, 10)}
        />

        {f.keys.length > 0 && (
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                API keys
              </Typography>
              <Box sx={{ overflowX: "auto" }}>
                <ListingTable>
                  <ListingTable.Head>
                    <ListingTable.Row>
                      <ListingTable.Cell>Key</ListingTable.Cell>
                      <ListingTable.Cell>Status</ListingTable.Cell>
                      <ListingTable.Cell>Owner</ListingTable.Cell>
                      <ListingTable.Cell>Created</ListingTable.Cell>
                      <ListingTable.Cell>Last used</ListingTable.Cell>
                    </ListingTable.Row>
                  </ListingTable.Head>
                  <ListingTable.Body>
                    {f.keys.map((k) => (
                      <ListingTable.Row key={k.keyId}>
                        <ListingTable.Cell>
                          <Typography variant="body2" fontWeight={500}>
                            {k.name || k.keyId}
                          </Typography>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ fontFamily: "monospace" }}
                          >
                            {k.redactedHint || k.keyId}
                          </Typography>
                        </ListingTable.Cell>
                        <ListingTable.Cell>
                          {k.present ? (
                            <Chip size="small" variant="outlined" label={k.status || "listed"} />
                          ) : (
                            <Chip size="small" color="success" label="No longer listed" />
                          )}
                        </ListingTable.Cell>
                        <ListingTable.Cell>{ownerLabel(k.ownerHint) || "—"}</ListingTable.Cell>
                        <ListingTable.Cell>{shortDate(k.createdAt)}</ListingTable.Cell>
                        <ListingTable.Cell>{shortDate(k.lastUsedAt)}</ListingTable.Cell>
                      </ListingTable.Row>
                    ))}
                  </ListingTable.Body>
                </ListingTable>
              </Box>
            </CardContent>
          </Card>
        )}

        {f.related.length > 0 && (
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Related findings
              </Typography>
              <Stack spacing={1}>
                {f.related.map((r) => (
                  <Stack
                    key={`${r.findingId}|${r.relation}`}
                    direction="row"
                    spacing={1}
                    alignItems="center"
                  >
                    <Chip
                      size="small"
                      variant="outlined"
                      color={r.relation === "possible_duplicate" ? "warning" : "default"}
                      label={relationLabel(r.relation, f.provider)}
                    />
                    <RouterLink
                      to={generatePath(
                        absoluteRouteMap.children.org.children.shadowAgentDiscovery.children.finding
                          .path,
                        { orgId: orgName ?? "", findingId: r.findingId },
                      )}
                    >
                      {r.displayName || r.findingId}
                    </RouterLink>
                    {r.provider && (
                      <Typography variant="caption" color="text.secondary">
                        {providerLabel(r.provider)}
                        {r.reason ? ` · ${r.reason}` : ""}
                      </Typography>
                    )}
                  </Stack>
                ))}
              </Stack>
            </CardContent>
          </Card>
        )}
      </Stack>
    </PageLayout>
  );
}

export default FindingDetail;
