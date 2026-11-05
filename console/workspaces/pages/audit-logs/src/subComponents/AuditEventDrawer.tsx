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

import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  Paper,
  Stack,
  Tooltip,
  Typography,
} from "@wso2/oxygen-ui";
import {
  ArrowRight,
  Bot,
  Braces,
  Check,
  ChevronDown,
  Copy,
  ScrollText,
  User,
} from "@wso2/oxygen-ui-icons-react";
import { DrawerContent, DrawerHeader, DrawerWrapper } from "@agent-management-platform/views";
import { copyToClipboard } from "@agent-management-platform/shared-component";
import type { AuditEvent } from "@agent-management-platform/types";
import {
  actorLabel,
  actorTypeLabel,
  agentLabel,
  delegationPath,
  displayRaw,
  formatAbsoluteTime,
  formatNumber,
} from "../auditFormat";
import { CategoryChip, OutcomeChip } from "./AuditChips";

type Value = ReactNode | string | number | boolean | null | undefined;

function isEmpty(v: Value) {
  return v === undefined || v === null || v === "";
}

function Section({ title, children, testId }: {
  title: string;
  children: ReactNode;
  testId?: string;
}) {
  const id = `audit-section-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  return (
    <Paper
      variant="outlined"
      component="section"
      aria-labelledby={id}
      data-testid={testId}
      sx={{ p: 2 }}
    >
      <Typography id={id} variant="subtitle2" component="h3" sx={{ mb: 1.5 }}>
        {title}
      </Typography>
      {children}
    </Paper>
  );
}

/** Label/value pairs; empty values are skipped. */
function Fields({ rows }: { rows: Array<[string, Value, { mono?: boolean }?]> }) {
  const shown = rows.filter(([, v]) => !isEmpty(v));
  if (shown.length === 0) {
    return <Typography variant="body2" color="text.secondary">No details recorded.</Typography>;
  }
  return (
    <Box
      component="dl"
      sx={{
        display: "grid",
        gridTemplateColumns: "minmax(120px, 34%) 1fr",
        columnGap: 2,
        rowGap: 1,
        m: 0,
      }}
    >
      {shown.map(([label, value, opts]) => (
        <Fragment key={label}>
          <Typography component="dt" variant="body2" color="text.secondary">
            {label}
          </Typography>
          <Typography
            component="dd"
            variant="body2"
            sx={{
              m: 0,
              wordBreak: "break-all",
              ...(opts?.mono ? { fontFamily: "monospace", fontSize: 13 } : {}),
            }}
          >
            {typeof value === "boolean" ? (value ? "Yes" : "No") : value}
          </Typography>
        </Fragment>
      ))}
    </Box>
  );
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <Button
      size="small"
      variant="text"
      startIcon={copied ? <Check size={14} /> : <Copy size={14} />}
      aria-label={label}
      onClick={async (e) => {
        e.stopPropagation();
        if (!(await copyToClipboard(text))) return;
        setCopied(true);
        clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

/** user → agent → agent, in the order authority was delegated. */
export function DelegationChain({ event }: { event: AuditEvent }) {
  const hops = delegationPath(event);
  if (hops.length === 0) return null;
  return (
    <Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        Delegation chain
      </Typography>
      <Stack
        component="ol"
        direction="row"
        alignItems="center"
        flexWrap="wrap"
        useFlexGap
        spacing={1}
        aria-label="Delegation chain"
        data-testid="delegation-chain"
        sx={{ listStyle: "none", p: 0, m: 0 }}
      >
        {hops.map((hop, i) => (
          <Stack component="li" key={`${hop.id}-${i}`} direction="row" alignItems="center" spacing={1}>
            {i > 0 && <ArrowRight size={14} aria-hidden />}
            <Tooltip title={hop.id}>
              <Chip
                size="small"
                variant="outlined"
                color={hop.role === "subject" ? "primary" : "secondary"}
                icon={hop.role === "subject" ? <User size={14} /> : <Bot size={14} />}
                label={
                  <span>
                    <Box component="span" sx={{ color: "text.secondary", mr: 0.5 }}>
                      {hop.role === "subject" ? "User" : "Agent"}
                    </Box>
                    {hop.display || hop.id}
                  </span>
                }
                aria-label={`${hop.role === "subject" ? "User" : "Agent"} ${hop.display || hop.id}`}
              />
            </Tooltip>
          </Stack>
        ))}
      </Stack>
    </Box>
  );
}

export interface AuditEventDrawerProps {
  event: AuditEvent | null;
  onClose: () => void;
}

export function AuditEventDrawer({ event, onClose }: AuditEventDrawerProps) {
  return (
    <DrawerWrapper open={!!event} onClose={onClose} minWidth={560} maxWidth={760}>
      {event && <AuditEventDetails event={event} onClose={onClose} />}
    </DrawerWrapper>
  );
}

export function AuditEventDetails({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  const denied = event.decision?.deniedBy;
  const raw = JSON.stringify(displayRaw(event.raw) ?? event, null, 2);
  const a2a = event.a2a;

  return (
    <Box role="dialog" aria-label={`Audit event ${event.action}`} sx={{ pb: 3 }}>
      <DrawerHeader icon={<ScrollText size={20} />} title="Audit event" onClose={onClose} />
      <DrawerContent>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          <Typography variant="h6" component="p" sx={{ fontFamily: "monospace", mr: 1 }}>
            {event.action}
          </Typography>
          <OutcomeChip outcome={event.outcome} />
          <CategoryChip category={event.category} />
        </Stack>
        {event.summary && (
          <Typography variant="body2" color="text.secondary">{event.summary}</Typography>
        )}

        {event.outcome === "STARTED" && (
          <Alert severity="info" data-testid="started-alert">
            Intent record, written before the operation ran. Its result is the
            record whose <code>attemptEventId</code> is <code>{event.id}</code>;
            with no such record, the result was never recorded.
          </Alert>
        )}

        {event.outcome === "DENIED" && denied?.policy && (
          <Alert severity="warning" data-testid="denied-alert">
            Denied by policy <strong>{denied.policy}</strong>
            {denied.phase ? ` during ${denied.phase}` : ""}.
          </Alert>
        )}

        <Section title="Overview">
          <Fields
            rows={[
              ["Time", formatAbsoluteTime(event.timestamp)],
              ["Timestamp (UTC)", event.timestamp, { mono: true }],
              ["Source", event.source === "GATEWAY" ? "Gateway" : "Control plane"],
              ["Status code", event.statusCode ?? undefined],
              ["Agent", agentLabel(event)],
              ["Project", event.project],
              ["Environment", event.environment],
              ["Resource type", event.resource?.type],
              ["Resource", event.resource?.name, { mono: true }],
              ["Resource ID", event.resource?.id, { mono: true }],
              ["Gateway", event.gateway?.id],
              ["Correlation ID", event.correlationId, { mono: true }],
              ["Event ID", event.id, { mono: true }],
            ]}
          />
        </Section>

        <Section title="Identity & delegation" testId="identity-section">
          <Stack spacing={2}>
            <Fields
              rows={[
                ["Actor", actorLabel(event.actor)],
                ["Actor type", actorTypeLabel(event.actor?.type)],
                ["Actor ID", event.actor?.id, { mono: true }],
                ["Auth method", event.actor?.authMethod],
                ["Client ID", event.actor?.clientId, { mono: true }],
                ["Token ID", event.actor?.tokenId, { mono: true }],
                ["On behalf of", event.onBehalfOf?.subject, { mono: true }],
              ]}
            />
            <DelegationChain event={event} />
          </Stack>
        </Section>

        {(event.decision || event.guardrail || event.error) && (
          <Section title="Decision" testId="decision-section">
            <Fields
              rows={[
                ["Terminal reason", event.decision?.terminalReason],
                ["Denied by policy", denied?.policy],
                ["Policy version", denied?.version],
                ["Phase", denied?.phase],
                ["Guardrail hit", event.guardrail?.hit],
                ["Guardrail", event.guardrail?.name],
                ["Error type", event.error?.type],
                ["Error code", event.error?.code],
                ["Error message", event.error?.message],
              ]}
            />
          </Section>
        )}

        {event.llm && (
          <Section title="LLM" testId="llm-section">
            <Fields
              rows={[
                ["Provider", event.llm.provider],
                ["Requested model", event.llm.requestModel],
                ["Model", event.llm.model],
                ["Prompt tokens", isEmpty(event.llm.promptTokens) ? undefined : formatNumber(event.llm.promptTokens)],
                ["Completion tokens", isEmpty(event.llm.completionTokens) ? undefined : formatNumber(event.llm.completionTokens)],
                ["Total tokens", isEmpty(event.llm.totalTokens) ? undefined : formatNumber(event.llm.totalTokens)],
                ["Cost", event.llm.cost ?? undefined],
              ]}
            />
          </Section>
        )}

        {event.mcp && (
          <Section title="MCP" testId="mcp-section">
            <Fields
              rows={[
                ["Server", event.mcp.server, { mono: true }],
                ["Method", event.mcp.method, { mono: true }],
                ["Tool", event.mcp.tool],
                ["Session ID", event.mcp.sessionId, { mono: true }],
                ["JSON-RPC ID", event.mcp.jsonRpcId, { mono: true }],
                ["Error result", event.mcp.isError],
              ]}
            />
          </Section>
        )}

        {a2a && (
          <Section title="A2A" testId="a2a-section">
            <Fields
              rows={[
                ["Operation", a2a.operation],
                ["Request type", a2a.requestType],
                ["Transport", a2a.transport],
                ["Protocol version", a2a.protocolVersion],
                ["Message ID", a2a.messageId, { mono: true }],
                ["Task ID", a2a.responseTaskId, { mono: true }],
                ["Context ID", a2a.responseContextId, { mono: true }],
                ["Task state", a2a.taskState],
                ["Streaming", a2a.isStreaming],
                ["Error", a2a.isError],
              ]}
            />
          </Section>
        )}

        <Section title="Network">
          <Fields
            rows={[
              ["Client IP", event.network?.clientIp, { mono: true }],
              ["User agent", event.network?.userAgent],
              ["Gateway organization", event.gateway?.organization],
              ["Gateway environment", event.gateway?.environment],
            ]}
          />
        </Section>

        <Accordion disableGutters variant="outlined" sx={{ "&:before": { display: "none" } }}>
          <AccordionSummary
            expandIcon={<ChevronDown size={16} />}
            aria-controls="audit-raw-json"
            id="audit-raw-json-header"
          >
            <Stack direction="row" spacing={1} alignItems="center" sx={{ flex: 1 }}>
              <Braces size={16} aria-hidden />
              <Typography variant="subtitle2">Raw JSON</Typography>
            </Stack>
          </AccordionSummary>
          <AccordionDetails id="audit-raw-json">
            <Stack direction="row" justifyContent="flex-end">
              <CopyButton text={raw} label="Copy raw JSON" />
            </Stack>
            <Divider sx={{ my: 1 }} />
            <Box
              component="pre"
              data-testid="raw-json"
              sx={{
                m: 0,
                maxHeight: 420,
                overflow: "auto",
                fontSize: 12,
                fontFamily: "monospace",
                whiteSpace: "pre",
              }}
            >
              {raw}
            </Box>
          </AccordionDetails>
        </Accordion>
      </DrawerContent>
    </Box>
  );
}
