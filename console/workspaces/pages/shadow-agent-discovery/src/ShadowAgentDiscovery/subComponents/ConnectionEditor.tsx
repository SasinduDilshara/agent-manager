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

import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Checkbox,
  Chip,
  FormControlLabel,
  Grid,
  IconButton,
  Skeleton,
  Stack,
  Tooltip,
  Typography,
} from "@wso2/oxygen-ui";
import { Copy, Plus, Trash2 } from "@wso2/oxygen-ui-icons-react";
import { generatePath, useNavigate, useParams } from "react-router-dom";
import { PageLayout, TextInput, useReturnTo } from "@agent-management-platform/views";
import {
  useCreateShadowConnection,
  useShadowConnection,
  useShadowProviders,
  useUpdateShadowConnection,
} from "@agent-management-platform/api-client";
import { useUnsavedChangesGuard } from "@agent-management-platform/shared-component";
import {
  absoluteRouteMap,
  INPUT_LIMITS,
  type ShadowConnectionResponse,
  type ShadowFieldSpec,
  type ShadowProvider,
  type ShadowProviderSpec,
  type ShadowSettingValue,
} from "@agent-management-platform/types";
import { selectCardSx } from "../shadowUi";
import {
  credentialChoiceError,
  evaluateCapabilities,
  hasValue,
  optionActive,
} from "../capabilities";
import { AnalyzeSection } from "./AnalyzeSection";

type KeyMapRow = { id: string; key: string };

export interface ConnectionDraft {
  name: string;
  provider: ShadowProvider | "";
  endpoints: Record<string, string>;
  values: Record<string, string | boolean>;
  keyMaps: Record<string, KeyMapRow[]>;
  /** Stored optional secrets to remove on save. */
  removed: string[];
}

/** The form's initial state: defaults for a new connection, or the stored settings. */
export function initialDraft(
  spec: ShadowProviderSpec | undefined,
  existing: ShadowConnectionResponse | undefined,
): ConnectionDraft {
  const draft: ConnectionDraft = {
    name: existing?.name ?? "",
    provider: (existing?.provider ?? spec?.provider ?? "") as ShadowProvider | "",
    endpoints: {},
    values: {},
    keyMaps: {},
    removed: [],
  };
  if (!spec) return draft;
  for (const e of spec.endpoints) {
    draft.endpoints[e.key] = existing?.endpoints?.[e.key] ?? e.default;
  }
  for (const f of spec.fields) {
    const stored = existing?.settings?.[f.key];
    switch (f.kind) {
      case "checkbox":
        draft.values[f.key] = typeof stored === "boolean" ? stored : (f.defaultBool ?? false);
        break;
      case "list":
        draft.values[f.key] = Array.isArray(stored) ? (stored as string[]).join("\n") : "";
        break;
      case "key_map": {
        const ids = existing?.settings?.[`${f.key}Ids`];
        draft.keyMaps[f.key] = Array.isArray(ids)
          ? (ids as string[]).map((id) => ({ id, key: "" }))
          : [];
        break;
      }
      case "secret":
      case "textarea":
        draft.values[f.key] = "";
        break;
      default:
        draft.values[f.key] = typeof stored === "string" ? stored : "";
    }
  }
  return draft;
}

/** The request settings from the draft; empty secrets are omitted (kept on update). */
export function toSettings(
  spec: ShadowProviderSpec,
  draft: ConnectionDraft,
): Record<string, ShadowSettingValue> {
  const out: Record<string, ShadowSettingValue> = {};
  for (const f of spec.fields) {
    const v = draft.values[f.key];
    switch (f.kind) {
      case "checkbox":
        out[f.key] = v === true;
        break;
      case "list":
        out[f.key] = String(v ?? "")
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      case "key_map": {
        const rows = draft.keyMaps[f.key] ?? [];
        const m: Record<string, string> = {};
        for (const r of rows) {
          if (r.id.trim()) m[r.id.trim()] = r.key.trim();
        }
        out[f.key] = m;
        break;
      }
      case "secret":
      case "textarea":
        if (String(v ?? "").trim()) out[f.key] = String(v).trim();
        break;
      default:
        out[f.key] = String(v ?? "").trim();
    }
  }
  return out;
}

/**
 * Whether an endpoint is shown: one tied to an option shows only when the
 * option holds something (a ticked service, or a role to assume for STS).
 */
export function endpointVisible(
  spec: ShadowProviderSpec,
  draft: ConnectionDraft,
  existing: ShadowConnectionResponse | undefined,
  option: string | undefined,
): boolean {
  if (!option) return true;
  if (option.startsWith("!")) return !hasValue(spec, draft, existing, option.slice(1));
  return hasValue(spec, draft, existing, option);
}

/**
 * Whether a field is shown: a field tied to a checkbox shows while it is
 * ticked, or with "!key" while it is not (Azure DevOps: a PAT or Entra).
 */
export function fieldVisible(f: ShadowFieldSpec, draft: ConnectionDraft): boolean {
  return optionActive(f.option, draft.values);
}

/** Client checks that mirror the service's; the service has the final say. */
export function validateDraft(
  spec: ShadowProviderSpec,
  draft: ConnectionDraft,
  existing: ShadowConnectionResponse | undefined,
): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!draft.name.trim()) errors.name = "Name is required";
  if (draft.name.trim().length > 100) errors.name = "Name must be at most 100 characters";
  for (const f of spec.fields) {
    if (!f.required || !fieldVisible(f, draft)) continue;
    const v = draft.values[f.key];
    if (f.kind === "secret") {
      if (!String(v ?? "").trim() && !existing?.secretHints?.[f.key])
        errors[f.key] = `${f.label} is required`;
    } else if (f.kind === "list") {
      if (!String(v ?? "").trim()) errors[f.key] = `${f.label} needs at least one value`;
    } else if (f.kind === "text" && !String(v ?? "").trim()) {
      errors[f.key] = `${f.label} is required`;
    }
  }
  for (const f of spec.fields) {
    if (f.kind !== "key_map" || !fieldVisible(f, draft)) continue;
    for (const r of draft.keyMaps[f.key] ?? []) {
      const id = r.id.trim();
      if (!id && r.key.trim()) errors[f.key] = `Enter the ID for each key in ${f.label}`;
      else if (id && !r.key.trim() && !existing?.secretHints?.[`${f.key}.${id}`])
        errors[f.key] = `Enter the key for ${id}`;
    }
  }
  const choice = credentialChoiceError(spec, draft, existing);
  if (choice) errors.credentialChoice = choice;
  for (const e of spec.endpoints) {
    const v = (draft.endpoints[e.key] ?? "").trim();
    if (!endpointVisible(spec, draft, existing, e.option)) continue;
    if (!/^https?:\/\/[^\s/?#]+/.test(v)) errors[`endpoint:${e.key}`] = "Enter an http(s) URL";
    else if (/[?#]/.test(v)) errors[`endpoint:${e.key}`] = "Remove the query or fragment";
  }
  return errors;
}

function CopyBlock({ text }: { text: string }) {
  const pretty = useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      return text;
    }
  }, [text]);
  return (
    <Box
      sx={{
        position: "relative",
        border: 1,
        borderColor: "divider",
        borderRadius: 1,
        bgcolor: "action.hover",
      }}
    >
      <Box
        component="pre"
        sx={{ m: 0, p: 1.5, pr: 5, overflowX: "auto", fontSize: 12, maxHeight: 240 }}
      >
        {pretty}
      </Box>
      <Tooltip title="Copy">
        <IconButton
          size="small"
          aria-label="Copy policy"
          sx={{ position: "absolute", top: 4, right: 4 }}
          onClick={() => void navigator.clipboard?.writeText(pretty)}
        >
          <Copy size={16} />
        </IconButton>
      </Tooltip>
    </Box>
  );
}

/** The provider's least-privilege setup, shown next to the form. */
export function PermissionsPanel({ spec }: { spec: ShadowProviderSpec }) {
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="subtitle1" gutterBottom>
          Required permissions
        </Typography>
        <Stack spacing={2}>
          {spec.permissions.map((p) => (
            <Box key={p.title}>
              <Typography variant="body2" fontWeight={500}>
                {p.title}
              </Typography>
              <Box component="ul" sx={{ pl: 2.5, my: 0.5 }}>
                {p.items.map((it) => (
                  <Typography key={it} component="li" variant="body2" color="text.secondary">
                    {it}
                  </Typography>
                ))}
              </Box>
              {p.policy && <CopyBlock text={p.policy} />}
            </Box>
          ))}
          {spec.docs.length > 0 && (
            <Typography variant="caption" color="text.secondary">
              Official documentation:{" "}
              {spec.docs.map((d, i) => (
                <span key={d}>
                  {i > 0 && ", "}
                  <a href={d} target="_blank" rel="noreferrer noopener">
                    {new URL(d).hostname}
                  </a>
                </span>
              ))}
            </Typography>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

function FieldInput({
  field,
  draft,
  setDraft,
  error,
  storedHint,
  inChoice,
}: {
  field: ShadowFieldSpec;
  draft: ConnectionDraft;
  setDraft: (d: ConnectionDraft) => void;
  error?: string;
  storedHint?: string;
  /** The field is one of the provider's "one of these credentials". */
  inChoice?: boolean;
}) {
  const setValue = (v: string | boolean) =>
    setDraft({ ...draft, values: { ...draft.values, [field.key]: v } });
  // A recommended field or one of a credential choice is not plain optional.
  const optional = field.required || field.recommended || inChoice ? "" : " (optional)";
  const recommendedChip = field.recommended ? (
    <Chip size="small" color="primary" variant="outlined" label="Recommended" sx={{ ml: 1 }} />
  ) : null;
  if (field.kind === "checkbox") {
    return (
      <Box>
        <FormControlLabel
          control={
            <Checkbox
              checked={draft.values[field.key] === true}
              onChange={(e) => setValue(e.target.checked)}
            />
          }
          label={field.label}
        />
        {field.help && (
          <Typography variant="caption" color="text.secondary" component="p" sx={{ ml: 4 }}>
            {field.help}
          </Typography>
        )}
      </Box>
    );
  }
  if (field.kind === "key_map") {
    const rows = draft.keyMaps[field.key] ?? [];
    const setRows = (next: KeyMapRow[]) =>
      setDraft({ ...draft, keyMaps: { ...draft.keyMaps, [field.key]: next } });
    return (
      <Box>
        <Typography variant="body2" fontWeight={500}>
          {`${field.label}${optional}`}
          {recommendedChip}
        </Typography>
        {field.help && (
          <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 1 }}>
            {field.help}
          </Typography>
        )}
        {error && (
          <Typography variant="caption" color="error" component="p" sx={{ mb: 1 }}>
            {error}
          </Typography>
        )}
        <Stack spacing={1}>
          {rows.map((r, i) => (
            <Stack key={i} direction="row" spacing={1} alignItems="flex-start">
              <Box sx={{ flex: 1 }}>
                <TextInput
                  slotProps={{ htmlInput: { "aria-label": `${field.label} ID ${i + 1}` } }}
                  placeholder={field.placeholder}
                  value={r.id}
                  size="small"
                  maxLength={INPUT_LIMITS.SHORT_TEXT}
                  hideCharacterCount
                  onChange={(e) =>
                    setRows(rows.map((x, j) => (j === i ? { ...x, id: e.target.value } : x)))
                  }
                />
              </Box>
              <Box sx={{ flex: 2 }}>
                <TextInput
                  slotProps={{ htmlInput: { "aria-label": `${field.label} key ${i + 1}` } }}
                  type="password"
                  autoComplete="off"
                  placeholder={r.id && !r.key ? "Stored — leave empty to keep" : "Key"}
                  value={r.key}
                  size="small"
                  onChange={(e) =>
                    setRows(rows.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)))
                  }
                />
              </Box>
              <Tooltip title="Remove">
                <IconButton
                  aria-label={`Remove ${field.label} ${i + 1}`}
                  onClick={() => setRows(rows.filter((_, j) => j !== i))}
                >
                  <Trash2 size={16} />
                </IconButton>
              </Tooltip>
            </Stack>
          ))}
          <Box>
            <Button
              size="small"
              variant="text"
              startIcon={<Plus size={14} />}
              onClick={() => setRows([...rows, { id: "", key: "" }])}
            >
              Add
            </Button>
          </Box>
        </Stack>
      </Box>
    );
  }
  const isSecret = field.kind === "secret";
  const multiline = field.kind === "list" || field.key === "serviceAccountJson";
  // A stored optional secret can be removed (for example the Admin API key,
  // to scan with project keys only).
  const canRemove = isSecret && !!storedHint && !field.required;
  const removed = draft.removed.includes(field.key);
  const setRemoved = (on: boolean) =>
    setDraft({
      ...draft,
      values: on ? { ...draft.values, [field.key]: "" } : draft.values,
      removed: on
        ? [...draft.removed.filter((k) => k !== field.key), field.key]
        : draft.removed.filter((k) => k !== field.key),
    });
  const input = (
    <TextInput
      label={`${field.label}${optional}`}
      placeholder={
        removed
          ? "Removed when you save"
          : isSecret && storedHint
            ? `Stored (${storedHint}). Leave empty to keep it.`
            : field.kind === "list"
              ? `${field.placeholder ?? ""} (one per line)`
              : field.placeholder
      }
      type={isSecret && !multiline ? "password" : "text"}
      autoComplete="off"
      multiline={multiline}
      minRows={multiline ? 3 : undefined}
      value={String(draft.values[field.key] ?? "")}
      onChange={(e) => setValue(e.target.value)}
      disabled={removed}
      error={!!error}
      helperText={
        error ?? (removed ? `The stored ${field.label} is removed when you save.` : field.help)
      }
    />
  );
  if (!recommendedChip && !canRemove) return input;
  return (
    <Box>
      {recommendedChip && (
        <Box sx={{ mb: 1 }}>
          <Typography variant="body2" fontWeight={500} component="span">
            {field.label}
          </Typography>
          {recommendedChip}
        </Box>
      )}
      {input}
      {canRemove && (
        <Button
          size="small"
          variant="text"
          color={removed ? "primary" : "error"}
          sx={{ mt: 0.5 }}
          onClick={() => setRemoved(!removed)}
        >
          {removed ? `Keep the stored ${field.label}` : `Remove the stored ${field.label}`}
        </Button>
      )}
    </Box>
  );
}

/** Create (connections/new) or edit (connections/:connectionId/edit) a provider connection. */
export function ConnectionEditor({
  orgName,
  listPath,
}: {
  orgName: string | undefined;
  listPath: string;
}) {
  const { connectionId } = useParams<{ connectionId?: string }>();
  const navigate = useNavigate();
  const returnTo = useReturnTo(`${listPath}?tab=connections`);
  const providers = useShadowProviders(orgName);
  const existing = useShadowConnection(orgName, connectionId);
  const create = useCreateShadowConnection(orgName);
  const update = useUpdateShadowConnection(orgName, connectionId);
  const isEdit = !!connectionId;
  const [draft, setDraft] = useState<ConnectionDraft | null>(null);
  const [initial, setInitial] = useState<string>("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [serverError, setServerError] = useState<string | null>(null);

  const spec = useMemo(
    () =>
      providers.data?.providers.find(
        (p) => p.provider === (draft?.provider || existing.data?.provider),
      ),
    [providers.data, draft?.provider, existing.data?.provider],
  );

  // What the scan can analyze with the form as it is now.
  const statuses = useMemo(
    () => (spec && draft ? evaluateCapabilities(spec, draft, existing.data) : []),
    [spec, draft, existing.data],
  );

  useEffect(() => {
    if (draft || !providers.data) return;
    if (isEdit && !existing.data) return;
    const s = isEdit
      ? providers.data.providers.find((p) => p.provider === existing.data?.provider)
      : undefined;
    const d = initialDraft(s, existing.data);
    setDraft(d);
    setInitial(JSON.stringify(d));
  }, [draft, providers.data, existing.data, isEdit]);

  const isDirty = !!draft && JSON.stringify(draft) !== initial;
  const { allowNavigation } = useUnsavedChangesGuard(isDirty);

  const choose = (p: ShadowProviderSpec) => {
    const d = initialDraft(p, undefined);
    d.name = draft?.name || `${p.displayName} connection`;
    setDraft(d);
    setErrors({});
  };

  const save = () => {
    if (!draft || !spec) return;
    const found = validateDraft(spec, draft, existing.data);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    setServerError(null);
    const body = {
      name: draft.name.trim(),
      provider: spec.provider,
      endpoints: Object.fromEntries(Object.entries(draft.endpoints).map(([k, v]) => [k, v.trim()])),
      settings: toSettings(spec, draft),
      ...(isEdit && draft.removed.length > 0 ? { removeSecrets: draft.removed } : {}),
    };
    const onSuccess = () => allowNavigation(() => navigate(returnTo));
    const onError = (e: unknown) =>
      setServerError(
        (e as { message?: string })?.message ??
          "The connection could not be saved. Check the values and try again.",
      );
    if (isEdit) update.mutate(body, { onSuccess, onError });
    else create.mutate(body, { onSuccess, onError });
  };

  const title = isEdit ? `Edit ${existing.data?.name ?? "connection"}` : "Connect a provider";
  const back = { backHref: returnTo, backLabel: "Back to Shadow Agent Discovery" };

  if (providers.isLoading || (isEdit && existing.isLoading) || !draft) {
    return (
      <PageLayout title={title} disableIcon {...back}>
        <Skeleton variant="rounded" height={320} />
      </PageLayout>
    );
  }

  return (
    <PageLayout title={title} disableIcon {...back}>
      {!spec ? (
        <Stack spacing={2}>
          <Typography variant="body1">Choose the provider to connect.</Typography>
          {[
            {
              title: "Model providers and cloud agent platforms",
              list: (providers.data?.providers ?? []).filter((p) => !p.sourceHost),
            },
            {
              title: "Source repositories",
              list: (providers.data?.providers ?? []).filter((p) => p.sourceHost),
            },
          ]
            .filter((g) => g.list.length > 0)
            .map((g) => (
              <Stack key={g.title} spacing={1.5}>
                <Typography variant="subtitle1">{g.title}</Typography>
                <Grid container spacing={2}>
                  {g.list.map((p) => (
                    <Grid key={p.provider} size={{ xs: 12, sm: 6, lg: 4 }}>
                      <Card variant="outlined" sx={{ height: "100%" }}>
                        <CardActionArea
                          onClick={() => choose(p)}
                          sx={selectCardSx}
                          aria-label={`Connect ${p.displayName}`}
                        >
                          <CardContent>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <Typography variant="subtitle1">{p.displayName}</Typography>
                              {p.sourceHost && <Chip size="small" label="Analysis coming soon" />}
                            </Stack>
                            <Typography variant="body2" color="text.secondary">
                              {p.description}
                            </Typography>
                          </CardContent>
                        </CardActionArea>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Stack>
            ))}
        </Stack>
      ) : (
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, lg: 7 }}>
            <Stack spacing={2.5}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="subtitle1">{spec.displayName}</Typography>
                {!isEdit && (
                  <Button
                    size="small"
                    variant="text"
                    onClick={() => setDraft({ ...draft, provider: "" })}
                  >
                    Change provider
                  </Button>
                )}
              </Stack>
              <AnalyzeSection
                providerName={spec.displayName}
                statuses={statuses}
                preview={!!spec.sourceHost}
              />
              {spec.sourceHost && (
                <Alert severity="info">
                  Source code analysis is not available yet. Test connection checks the{" "}
                  {draft.values.useEntra === true ? "service principal" : "token"} now, with
                  read-only calls; scans list this connection as skipped until the analysis is
                  added.
                </Alert>
              )}
              <TextInput
                label="Connection name"
                placeholder="e.g. OpenAI production"
                value={draft.name}
                maxLength={INPUT_LIMITS.NAME}
                hideCharacterCount
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                error={!!errors.name}
                helperText={errors.name}
              />
              {spec.fields
                .filter((f) => fieldVisible(f, draft))
                .map((f, i, shown) => (
                  <Box key={f.key}>
                    {f.section && f.section !== shown[i - 1]?.section && (
                      <Typography variant="subtitle1" sx={{ mb: 1 }}>
                        {f.section}
                      </Typography>
                    )}
                    <FieldInput
                      field={f}
                      draft={draft}
                      setDraft={setDraft}
                      error={errors[f.key]}
                      storedHint={existing.data?.secretHints?.[f.key]}
                      inChoice={spec.credentialChoice?.fields.includes(f.key)}
                    />
                  </Box>
                ))}
              {errors.credentialChoice && <Alert severity="error">{errors.credentialChoice}</Alert>}

              <Box>
                <Typography variant="subtitle1">Endpoints</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                  The official endpoints are filled in. Change one only to reach the provider
                  through a host you trust: the credential is sent to it. Placeholders such as{" "}
                  {"{region}"} are filled in for each region or location you scan.
                </Typography>
                <Stack spacing={2}>
                  {spec.endpoints
                    .filter((e) => endpointVisible(spec, draft, existing.data, e.option))
                    .map((e) => {
                      const value = draft.endpoints[e.key] ?? "";
                      const custom = value.trim() !== e.default;
                      return (
                        <TextInput
                          key={e.key}
                          label={e.label}
                          placeholder={e.default}
                          value={value}
                          onChange={(ev) =>
                            setDraft({
                              ...draft,
                              endpoints: { ...draft.endpoints, [e.key]: ev.target.value },
                            })
                          }
                          error={!!errors[`endpoint:${e.key}`]}
                          helperText={
                            errors[`endpoint:${e.key}`] ??
                            (custom ? `Not the official endpoint (${e.default}).` : undefined)
                          }
                        />
                      );
                    })}
                </Stack>
              </Box>

              {serverError && <Alert severity="error">{serverError}</Alert>}
              <Stack direction="row" spacing={1.5} justifyContent="flex-start">
                <Button
                  variant="contained"
                  onClick={save}
                  disabled={create.isPending || update.isPending}
                >
                  {isEdit ? "Save" : "Connect provider"}
                </Button>
                <Button
                  variant="outlined"
                  onClick={() => allowNavigation(() => navigate(returnTo))}
                >
                  Cancel
                </Button>
              </Stack>
            </Stack>
          </Grid>
          <Grid size={{ xs: 12, lg: 5 }}>
            <PermissionsPanel spec={spec} />
          </Grid>
        </Grid>
      )}
    </PageLayout>
  );
}

/** Builds the edit route of a connection. */
export function editConnectionPath(orgId: string, connectionId: string): string {
  return generatePath(
    absoluteRouteMap.children.org.children.shadowAgentDiscovery.children.editConnection.path,
    { orgId, connectionId },
  );
}

export default ConnectionEditor;
