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

import { useMemo, useState } from "react";
import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  ListingTable,
  SearchBar,
  Stack,
  Tooltip,
  Typography,
} from "@wso2/oxygen-ui";
import { Pencil, PlugZap, Plus, Trash2, TriangleAlert } from "@wso2/oxygen-ui-icons-react";
import {
  useDeleteShadowConnection,
  useShadowConnections,
  useShadowProviders,
  useTestShadowConnection,
} from "@agent-management-platform/api-client";
import {
  formatRelativeTime,
  isListEmpty,
  ResourceListShell,
  useConfirmationDialog,
} from "@agent-management-platform/shared-component";
import type {
  ShadowConnectionResponse,
  ShadowConnectionTest,
} from "@agent-management-platform/types";
import { OutcomeChip, providerLabel, unlockLabels } from "../shadowUi";
import { credentialMode } from "../capabilities";

/** "Admin key" or "Project keys only", for OpenAI and Anthropic connections. */
export function CredentialModeChip({
  provider,
  secretHints,
}: {
  provider: string;
  secretHints: Record<string, string> | undefined;
}) {
  const mode = credentialMode(provider, secretHints);
  if (!mode) return null;
  if (mode === "admin") return <Chip size="small" variant="outlined" label="Admin key" />;
  const scoped = provider === "anthropic" ? "Workspace keys only" : "Project keys only";
  return (
    <Tooltip
      title={`Limited: API keys, usage, costs and owners are not read, so workloads that call ${providerLabel(
        provider,
      )} without an agent object are not found. Add an Admin API key to scan the whole organization.`}
    >
      <Chip size="small" variant="outlined" color="warning" label={`${scoped} (limited)`} />
    </Tooltip>
  );
}

/** GitHub and Azure DevOps: the credential in use, and that the analysis is not available yet. */
export function SourceHostChips({ connection }: { connection: ShadowConnectionResponse }) {
  if (connection.provider !== "github" && connection.provider !== "azure_devops") return null;
  const entra = connection.provider === "azure_devops" && connection.settings?.useEntra === true;
  return (
    <>
      <Chip
        size="small"
        variant="outlined"
        label={entra ? "Entra service principal" : "Personal access token"}
      />
      <Tooltip title="Test connection checks the credential now. Scans list this connection as skipped until source code analysis is added.">
        <Chip size="small" variant="outlined" color="info" label="Analysis coming soon" />
      </Tooltip>
    </>
  );
}

interface ConnectionsTabProps {
  orgName: string | undefined;
  canManage: boolean;
  onAdd: () => void;
  onEdit: (c: ShadowConnectionResponse) => void;
}

/** The provider connections: which accounts are scanned and how their last test went. */
export function ConnectionsTab({ orgName, canManage, onAdd, onEdit }: ConnectionsTabProps) {
  const [search, setSearch] = useState("");
  const [testResult, setTestResult] = useState<{
    name: string;
    result: ShadowConnectionTest;
  } | null>(null);
  const { data, isLoading, error } = useShadowConnections(orgName);
  const remove = useDeleteShadowConnection(orgName);
  const test = useTestShadowConnection(orgName);
  const providers = useShadowProviders(orgName);
  const signalNames = useMemo(
    () => new Map((providers.data?.signals ?? []).map((d) => [d.code, d.name])),
    [providers.data],
  );
  const { addConfirmation } = useConfirmationDialog();
  const connections = useMemo(() => data?.connections ?? [], [data]);
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return connections;
    return connections.filter(
      (c) =>
        c.name.toLowerCase().includes(q) || providerLabel(c.provider).toLowerCase().includes(q),
    );
  }, [connections, search]);

  const addButton = canManage ? (
    <Button variant="outlined" startIcon={<Plus size={16} />} onClick={onAdd}>
      Connect provider
    </Button>
  ) : undefined;

  const handleDelete = (c: ShadowConnectionResponse) =>
    addConfirmation({
      title: `Delete ${c.name}?`,
      description:
        "The stored credential and every finding of this connection are deleted. The provider account is not changed.",
      confirmButtonText: "Delete",
      confirmButtonColor: "error",
      onConfirm: () => remove.mutate(c.id),
    });

  const handleTest = (c: ShadowConnectionResponse) =>
    test.mutate(c.id, { onSuccess: (result) => setTestResult({ name: c.name, result }) });

  const toolbar = (
    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
      <Box sx={{ width: { xs: "100%", sm: 400 } }}>
        <SearchBar
          placeholder="Search connections"
          size="small"
          fullWidth
          value={search}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearch(e.target.value)}
        />
      </Box>
      <Box sx={{ flex: 1 }} />
      {addButton}
    </Stack>
  );

  return (
    <>
      <ResourceListShell
        resourceName="shadow-agent-connections"
        disablePaper
        searchValue={search}
        onSearchChange={setSearch}
        toolbar={toolbar}
        error={
          error ? new Error("Couldn't load connections. Reload the page to try again.") : undefined
        }
        isLoading={isLoading}
        isEmpty={isListEmpty({ isLoading, count: connections.length, isFiltered: !!search })}
        isSearchEmpty={!isLoading && connections.length > 0 && filtered.length === 0}
        emptyState={{
          illustration: <PlugZap size={64} />,
          title: "No providers connected",
          description:
            "Connect OpenAI, Anthropic, Amazon Bedrock, Google Agent Platform, Microsoft Foundry, GitHub or Azure DevOps with a read-only credential.",
          action: addButton,
        }}
        searchEmptyState={{
          illustration: <PlugZap size={64} />,
          title: "No connections match your search",
          description: "Try another name or provider.",
        }}
      >
        <ListingTable>
          <ListingTable.Head>
            <ListingTable.Row>
              <ListingTable.Cell>Connection</ListingTable.Cell>
              <ListingTable.Cell>Provider</ListingTable.Cell>
              <ListingTable.Cell>Last test</ListingTable.Cell>
              <ListingTable.Cell>Created</ListingTable.Cell>
              <ListingTable.Cell align="right" />
            </ListingTable.Row>
          </ListingTable.Head>
          <ListingTable.Body>
            {filtered.map((c) => (
              <ListingTable.Row key={c.id}>
                <ListingTable.Cell>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="body2" fontWeight={500}>
                      {c.name}
                    </Typography>
                    {c.endpointWarnings.length > 0 && (
                      <Tooltip title={c.endpointWarnings.join(". ")}>
                        <Box
                          component="span"
                          aria-label="Custom endpoint"
                          sx={{ display: "inline-flex", color: "warning.main" }}
                        >
                          <TriangleAlert size={16} />
                        </Box>
                      </Tooltip>
                    )}
                  </Stack>
                </ListingTable.Cell>
                <ListingTable.Cell>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                    <Typography variant="body2">{providerLabel(c.provider)}</Typography>
                    <CredentialModeChip provider={c.provider} secretHints={c.secretHints} />
                    <SourceHostChips connection={c} />
                  </Stack>
                </ListingTable.Cell>
                <ListingTable.Cell>
                  {c.lastTest ? (
                    <Stack direction="row" spacing={1} alignItems="center">
                      <OutcomeChip outcome={c.lastTest.ok ? "ok" : "failed"} />
                      <Typography variant="caption" color="text.secondary">
                        {c.lastTestedAt ? formatRelativeTime(c.lastTestedAt) : ""}
                      </Typography>
                    </Stack>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      Not tested
                    </Typography>
                  )}
                </ListingTable.Cell>
                <ListingTable.Cell>
                  <Typography variant="body2" color="text.secondary">
                    {formatRelativeTime(c.createdAt)}
                  </Typography>
                </ListingTable.Cell>
                <ListingTable.Cell align="right">
                  {canManage && (
                    <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                      <Tooltip title="Test connection">
                        <span>
                          <IconButton
                            size="small"
                            aria-label={`Test ${c.name}`}
                            disabled={test.isPending}
                            onClick={() => handleTest(c)}
                          >
                            <PlugZap size={18} />
                          </IconButton>
                        </span>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton
                          size="small"
                          aria-label={`Edit ${c.name}`}
                          onClick={() => onEdit(c)}
                        >
                          <Pencil size={18} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton
                          size="small"
                          aria-label={`Delete ${c.name}`}
                          onClick={() => handleDelete(c)}
                        >
                          <Trash2 size={18} />
                        </IconButton>
                      </Tooltip>
                    </Stack>
                  )}
                </ListingTable.Cell>
              </ListingTable.Row>
            ))}
          </ListingTable.Body>
        </ListingTable>
      </ResourceListShell>

      <Dialog open={!!testResult} onClose={() => setTestResult(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Test of {testResult?.name}</DialogTitle>
        <DialogContent>
          <Stack spacing={1.5}>
            <Typography variant="body2" color="text.secondary">
              One read per capability. A failed check names the signals a scan will miss.
            </Typography>
            {testResult?.result.checks.map((ch) => (
              <Box
                key={ch.name}
                sx={{ border: 1, borderColor: "divider", borderRadius: 1, p: 1.5 }}
              >
                <Stack
                  direction="row"
                  spacing={1}
                  alignItems="center"
                  justifyContent="space-between"
                >
                  <Typography variant="body2" fontWeight={500}>
                    {ch.name}
                  </Typography>
                  <OutcomeChip outcome={ch.outcome} />
                </Stack>
                {ch.message && (
                  <Typography variant="caption" color="text.secondary" component="p">
                    {ch.message}
                  </Typography>
                )}
                {ch.unlocks && ch.unlocks.length > 0 && (
                  <Typography variant="caption" color="text.secondary" component="p">
                    Unlocks: {unlockLabels(ch.unlocks, signalNames).join(", ")}
                  </Typography>
                )}
              </Box>
            ))}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ justifyContent: "flex-start", px: 3, pb: 2 }}>
          <Button variant="outlined" onClick={() => setTestResult(null)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

export default ConnectionsTab;
