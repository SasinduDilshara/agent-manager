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
  Grid,
  MenuItem,
  Skeleton,
  Stack,
  Typography,
} from "@wso2/oxygen-ui";
import { ExternalLink } from "@wso2/oxygen-ui-icons-react";
import { generatePath, Link as RouterLink, useNavigate, useParams } from "react-router-dom";
import { PageLayout, TextInput, useReturnTo } from "@agent-management-platform/views";
import {
  useCreateAgent,
  useListAgents,
  useListProjects,
  useOnboardShadowFinding,
  useShadowFinding,
  useShadowProviders,
} from "@agent-management-platform/api-client";
import { useUnsavedChangesGuard } from "@agent-management-platform/shared-component";
import {
  absoluteRouteMap,
  INPUT_LIMITS,
  type ShadowFindingDetail,
} from "@agent-management-platform/types";
import {
  AGENT_NAME_MAX_LENGTH,
  AGENT_NAME_PATTERN,
  kindLabel,
  providerLabel,
  CodeHint,
  selectCardSx,
  suggestAgentName,
} from "../shadowUi";
import {
  directCredentialHint,
  INSTRUMENTATION_OTHER,
  INSTRUMENTATION_SHELL,
  LLM_GATEWAY_SHELL,
  moveOffDirectShell,
  OPENAI_CLIENT_PYTHON,
} from "../onboardingHints";

type Path = "external" | "internal";

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <Box sx={{ display: "flex", gap: 2 }}>
      <Box
        sx={{
          width: 28,
          height: 28,
          borderRadius: "50%",
          bgcolor: "action.selected",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        <Typography variant="body2" fontWeight={600}>
          {n}
        </Typography>
      </Box>
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography variant="subtitle1" gutterBottom>
          {title}
        </Typography>
        {children}
      </Box>
    </Box>
  );
}

function PathCard({
  selected,
  title,
  description,
  onClick,
}: {
  selected: boolean;
  title: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <Card
      variant="outlined"
      sx={{ height: "100%", borderColor: selected ? "primary.main" : "divider" }}
    >
      <CardActionArea onClick={onClick} sx={selectCardSx} aria-pressed={selected}>
        <CardContent>
          <Typography variant="subtitle1">{title}</Typography>
          <Typography variant="body2" color="text.secondary">
            {description}
          </Typography>
        </CardContent>
      </CardActionArea>
    </Card>
  );
}

/** The description an onboarded agent starts with: where it was found. */
export function discoveredDescription(f: ShadowFindingDetail): string {
  return `Discovered by Shadow Agent Discovery: ${providerLabel(f.provider)} ${kindLabel(f.kind, f.provider).toLowerCase()} ${f.externalId}`.slice(
    0,
    INPUT_LIMITS.DESCRIPTION,
  );
}

/**
 * Turns a finding into a governed agent, following the Agent Manager
 * documentation: register it as an externally-hosted agent (or create it as
 * a platform-hosted one), set it up, route its model calls through an
 * organization LLM provider, then move the workload off its direct key.
 */
export function OnboardFinding({
  orgName,
  listPath,
}: {
  orgName: string | undefined;
  listPath: string;
}) {
  const { findingId } = useParams<{ findingId: string }>();
  const navigate = useNavigate();
  const findingPath = generatePath(
    absoluteRouteMap.children.org.children.shadowAgentDiscovery.children.finding.path,
    { orgId: orgName ?? "", findingId: findingId ?? "" },
  );
  const returnTo = useReturnTo(findingPath || listPath);
  const { data: f, isLoading } = useShadowFinding(orgName, findingId);
  // The retirement observation window comes from the service.
  const providers = useShadowProviders(orgName);
  const observationDays = providers.data?.scoring.retirementObservationDays ?? 7;
  const projects = useListProjects({ orgName });
  const [path, setPath] = useState<Path>("external");
  const [project, setProject] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [agentName, setAgentName] = useState("");
  const [description, setDescription] = useState("");
  const [linkAgent, setLinkAgent] = useState("");
  const [registered, setRegistered] = useState<{ project: string; agent: string } | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const createAgent = useCreateAgent();
  const onboard = useOnboardShadowFinding(orgName, findingId);
  const agents = useListAgents({ orgName, projName: project || undefined });

  useEffect(() => {
    if (!f || displayName) return;
    setDisplayName(f.displayName.slice(0, INPUT_LIMITS.NAME));
    setAgentName(suggestAgentName(f.displayName));
    setDescription(discoveredDescription(f));
  }, [f, displayName]);
  useEffect(() => {
    if (!project && projects.data?.projects?.length) setProject(projects.data.projects[0].name);
  }, [project, projects.data]);
  useEffect(() => {
    if (f?.linkedAgent && !registered)
      setRegistered({ project: f.linkedProject, agent: f.linkedAgent });
  }, [f, registered]);

  const { allowNavigation } = useUnsavedChangesGuard(false);
  const nameError = useMemo(() => {
    if (!agentName) return "Name is required";
    if (agentName.length > AGENT_NAME_MAX_LENGTH)
      return `At most ${AGENT_NAME_MAX_LENGTH} characters`;
    if (!AGENT_NAME_PATTERN.test(agentName)) {
      return 'Lowercase letters, digits and "-", starting with a letter and ending with a letter or digit';
    }
    return undefined;
  }, [agentName]);

  const back = { backHref: returnTo, backLabel: "Back to the finding" };
  if (isLoading || !f) {
    return (
      <PageLayout title="Onboard" disableIcon {...back}>
        <Skeleton variant="rounded" height={360} />
      </PageLayout>
    );
  }

  const agentPath = (p: string, a: string) =>
    generatePath(absoluteRouteMap.children.org.children.projects.children.agents.path, {
      orgId: orgName ?? "",
      projectId: p,
      agentId: a,
    });
  const addLLMPath = (p: string, a: string) =>
    generatePath(
      absoluteRouteMap.children.org.children.projects.children.agents.children.configure.children
        .llmProviders.children.add.path,
      { orgId: orgName ?? "", projectId: p, agentId: a },
    );
  const createSourcePath = project
    ? generatePath(
        absoluteRouteMap.children.org.children.projects.children.newAgent.children.create.children
          .source.path,
        { orgId: orgName ?? "", projectId: project },
      )
    : "";

  const link = (p: string, a: string) =>
    onboard.mutate(
      { projectName: p, agentName: a },
      {
        onSuccess: () => setRegistered({ project: p, agent: a }),
        onError: () => setFormError("The finding could not be linked to the agent."),
      },
    );

  const register = () => {
    setFormError(null);
    if (!project) return setFormError("Choose a project.");
    if (nameError) return setFormError(nameError);
    if (displayName.trim().length < 3)
      return setFormError("Display name must be at least 3 characters.");
    // The same request the console's "Register an agent" page sends.
    createAgent.mutate(
      {
        params: { orgName, projName: project },
        body: {
          name: agentName,
          displayName: displayName.trim(),
          description: description.trim(),
          provisioning: { type: "external" },
          agentType: { type: "external-agent-api" },
        },
      },
      {
        onSuccess: () => link(project, agentName),
        onError: () =>
          setFormError("The agent could not be registered. The name may be taken in this project."),
      },
    );
  };

  const hints = [
    typeof f.attributes.repositoryUrl === "string"
      ? `Source repository: ${f.attributes.repositoryUrl}`
      : "",
    typeof f.attributes.image === "string" ? `Container image: ${f.attributes.image}` : "",
    typeof f.attributes.model === "string" ? `Model in use: ${f.attributes.model}` : "",
  ].filter(Boolean);

  const projectSelect = (
    <TextInput
      select
      label="Project"
      value={project}
      onChange={(e) => {
        setProject(e.target.value);
        setLinkAgent("");
      }}
      disabled={!!registered}
    >
      {(projects.data?.projects ?? []).map((p) => (
        <MenuItem key={p.name} value={p.name}>
          {p.displayName || p.name}
        </MenuItem>
      ))}
    </TextInput>
  );

  const linkExisting = (
    <Stack spacing={1.5}>
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>{projectSelect}</Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <TextInput
            select
            label="Agent"
            value={linkAgent}
            onChange={(e) => setLinkAgent(e.target.value)}
          >
            {(agents.data?.agents ?? []).map((a) => (
              <MenuItem key={a.name} value={a.name}>
                {a.displayName || a.name}
              </MenuItem>
            ))}
          </TextInput>
        </Grid>
      </Grid>
      <Box>
        <Button
          variant="outlined"
          disabled={!project || !linkAgent || onboard.isPending}
          onClick={() => link(project, linkAgent)}
        >
          Link finding to agent
        </Button>
      </Box>
    </Stack>
  );

  const nextSteps = registered && (
    <Stack spacing={3}>
      <Alert severity="success">
        The finding is linked to {registered.project} / {registered.agent}. Agent Manager now
        watches its direct provider usage on the finding page.
      </Alert>
      <Step n={2} title="Set up the agent">
        <Typography variant="body2" color="text.secondary" gutterBottom>
          In the agent&apos;s Setup Agent panel, choose a token duration and generate the key (it is
          shown once). Then, where the workload runs, set these two process environment variables
          (not a .env file) and start it with amp-instrument. No code changes are needed.
        </Typography>
        <CodeHint label="instrumentation commands" code={INSTRUMENTATION_SHELL} />
        <Typography variant="caption" color="text.secondary" component="p" gutterBottom>
          {INSTRUMENTATION_OTHER}
        </Typography>
        <Button
          component={RouterLink}
          to={`${agentPath(registered.project, registered.agent)}?setup=true`}
          variant="outlined"
          endIcon={<ExternalLink size={14} />}
        >
          Open the setup panel
        </Button>
      </Step>
      <Step n={3} title="Route model calls through Agent Manager">
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Under Configure, choose Add LLM Configuration, pick an organization LLM provider (add
          guardrails if you need them) and save. The Connect to LLM Provider panel then shows the
          Endpoint URL, the header name (API-Key) and an API key, which is shown once. Give them to
          the workload, for example as:
        </Typography>
        <CodeHint label="LLM gateway variables" code={LLM_GATEWAY_SHELL} />
        <Typography variant="caption" color="text.secondary" component="p" gutterBottom>
          The variable names are your choice; use the ones the workload&apos;s code reads.
        </Typography>
        <Button
          component={RouterLink}
          to={addLLMPath(registered.project, registered.agent)}
          variant="outlined"
          endIcon={<ExternalLink size={14} />}
        >
          Add LLM configuration
        </Button>
      </Step>
      <Step n={4} title="Move the workload off its direct credential">
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Point the workload&apos;s model client at the Endpoint URL and send the Agent Manager key
          in the API-Key header on every request (not as a bearer token). Then stop using{" "}
          {directCredentialHint(f.provider).credential}.
        </Typography>
        {f.provider === "openai" && (
          <>
            <Typography variant="caption" color="text.secondary" component="p">
              With the OpenAI Python SDK (example from the Agent Manager documentation):
            </Typography>
            <CodeHint label="OpenAI client example" code={OPENAI_CLIENT_PYTHON} />
          </>
        )}
        {f.provider !== "openai" && (
          <Typography variant="caption" color="text.secondary" component="p">
            The Connect to LLM Provider panel shows an example cURL request for the provider you
            picked.
          </Typography>
        )}
        <CodeHint
          label="commands to move off the direct credential"
          code={moveOffDirectShell(f.provider)}
        />
        <Typography variant="body2" color="text.secondary">
          Then run scans over the next days. Once the finding shows no direct usage for{" "}
          {observationDays} days, it lists the steps to revoke the direct credential.
        </Typography>
      </Step>
      <Box>
        <Button variant="contained" onClick={() => allowNavigation(() => navigate(findingPath))}>
          Go to the finding
        </Button>
      </Box>
    </Stack>
  );

  return (
    <PageLayout
      title={`Onboard ${f.displayName}`}
      description={`${providerLabel(f.provider)} · ${kindLabel(f.kind, f.provider)} · confidence score ${f.score}`}
      disableIcon
      {...back}
    >
      <Stack spacing={3}>
        {hints.length > 0 && (
          <Alert severity="info">
            What the scan knows about this workload: {hints.join(" · ")}
          </Alert>
        )}
        {registered ? (
          nextSteps
        ) : (
          <>
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 6 }}>
                <PathCard
                  selected={path === "external"}
                  title="Externally-hosted agent"
                  description="Register the workload where it runs today. It keeps running there; Agent Manager adds observability, an agent identity and governed model access."
                  onClick={() => setPath("external")}
                />
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <PathCard
                  selected={path === "internal"}
                  title="Platform-hosted agent"
                  description="Agent Manager builds the agent from its GitHub repository and runs it."
                  onClick={() => setPath("internal")}
                />
              </Grid>
            </Grid>

            {path === "external" ? (
              <Card variant="outlined">
                <CardContent>
                  <Step n={1} title="Register the agent">
                    <Stack spacing={2}>
                      <Grid container spacing={2}>
                        <Grid size={{ xs: 12, md: 6 }}>{projectSelect}</Grid>
                        <Grid size={{ xs: 12, md: 6 }}>
                          <TextInput
                            label="Display name"
                            placeholder="e.g. Support assistant"
                            value={displayName}
                            maxLength={INPUT_LIMITS.NAME}
                            hideCharacterCount
                            onChange={(e) => setDisplayName(e.target.value)}
                          />
                        </Grid>
                        <Grid size={{ xs: 12, md: 6 }}>
                          <TextInput
                            label="Name"
                            placeholder="e.g. support-assistant"
                            value={agentName}
                            maxLength={AGENT_NAME_MAX_LENGTH}
                            onChange={(e) => setAgentName(e.target.value.toLowerCase())}
                            error={!!nameError}
                            helperText={nameError ?? "Used in URLs; it cannot be changed later."}
                          />
                        </Grid>
                        <Grid size={{ xs: 12, xl: 8 }}>
                          <TextInput
                            label="Description (optional)"
                            placeholder="e.g. Answers customer questions"
                            value={description}
                            multiline
                            minRows={2}
                            maxLength={INPUT_LIMITS.DESCRIPTION}
                            hideCharacterCount
                            onChange={(e) => setDescription(e.target.value)}
                          />
                        </Grid>
                      </Grid>
                      {formError && <Alert severity="error">{formError}</Alert>}
                      <Stack direction="row" spacing={1.5}>
                        <Button
                          variant="contained"
                          disabled={createAgent.isPending || onboard.isPending}
                          onClick={register}
                        >
                          Register agent
                        </Button>
                        <Button
                          variant="outlined"
                          onClick={() => allowNavigation(() => navigate(returnTo))}
                        >
                          Cancel
                        </Button>
                      </Stack>
                      <Typography variant="caption" color="text.secondary">
                        Already registered it? Link the finding to the existing agent instead:
                      </Typography>
                      {linkExisting}
                    </Stack>
                  </Step>
                </CardContent>
              </Card>
            ) : (
              <Card variant="outlined">
                <CardContent>
                  <Stack spacing={3}>
                    <Step n={1} title="Create the agent from source">
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        In Add Agent, choose Platform-Hosted Agent and Source Code. Enter the GitHub
                        repository, branch and project path, pick the language (Python, Ballerina or
                        Docker) and keep auto instrumentation on, choose the agent type (Chat,
                        Custom API or A2A; it cannot be changed later), add environment variables
                        (mark secrets as Secret), and deploy. Add the LLM configuration from
                        Configure afterwards; the platform injects its URL and API key as read-only
                        environment variables.
                      </Typography>
                      <Stack direction="row" spacing={2} alignItems="center">
                        <Box sx={{ minWidth: 240 }}>{projectSelect}</Box>
                        <Button
                          component={RouterLink}
                          to={createSourcePath}
                          variant="outlined"
                          disabled={!project}
                          endIcon={<ExternalLink size={14} />}
                        >
                          Open the create page
                        </Button>
                      </Stack>
                    </Step>
                    <Step n={2} title="Link the finding to the new agent">
                      {linkExisting}
                      {formError && (
                        <Alert severity="error" sx={{ mt: 1 }}>
                          {formError}
                        </Alert>
                      )}
                    </Step>
                  </Stack>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </Stack>
    </PageLayout>
  );
}

export default OnboardFinding;
