/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import type { ReactNode } from "react";
import { Alert, Box, Chip, Divider, Stack, Typography } from "@wso2/oxygen-ui";
import { ScrollText } from "@wso2/oxygen-ui-icons-react";
import { DrawerContent, DrawerHeader, DrawerWrapper } from "@agent-management-platform/views";
import { CodeBlock } from "@agent-management-platform/shared-component";
import type { AuditLogRecord } from "@agent-management-platform/types";
import { formatTimestamp, isGatewayObserved, RESULT_COLOR, SEVERITY_LABEL } from "../utils";
import { SOURCE_LABEL } from "../feeds";

const EXCERPT_KEYS = [
  "requestBodyExcerpt",
  "responseBodyExcerpt",
  "bodyExcerptTruncated",
  "bodyExcerptsOmitted",
];

/** A body excerpt, pretty-printed when it is whole JSON. */
function formatExcerpt(text: string): { code: string; language: string } {
  try {
    return { code: JSON.stringify(JSON.parse(text), null, 2), language: "json" };
  } catch {
    return { code: text, language: "text" };
  }
}

interface AuditLogDetailDrawerProps {
  record: AuditLogRecord | null;
  onClose: () => void;
}

interface FieldProps {
  label: string;
  value: ReactNode;
}

function Field({ label, value }: FieldProps) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <Stack direction="row" spacing={2} alignItems="baseline">
      <Typography variant="caption" color="text.secondary" sx={{ width: 140, flexShrink: 0 }}>
        {label}
      </Typography>
      <Typography variant="body2" sx={{ wordBreak: "break-all" }}>
        {value}
      </Typography>
    </Stack>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Stack spacing={1}>
      <Typography variant="overline" color="text.secondary">
        {title}
      </Typography>
      {children}
    </Stack>
  );
}

export function AuditLogDetailDrawer({ record, onClose }: AuditLogDetailDrawerProps) {
  return (
    <DrawerWrapper open={!!record} onClose={onClose} minWidth={560} maxWidth={720}>
      <DrawerHeader icon={<ScrollText size={24} />} title="Audit Record" onClose={onClose} />
      <DrawerContent>
        {record && (
          <Stack spacing={3}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
              <Typography variant="h6" sx={{ fontFamily: "monospace" }}>
                {record.action}
              </Typography>
              <Chip
                size="small"
                variant="outlined"
                label={record.result}
                color={RESULT_COLOR[record.result] ?? "default"}
              />
              {record.severity !== undefined && (
                <Chip
                  size="small"
                  variant="outlined"
                  label={SEVERITY_LABEL[record.severity] ?? `Severity ${record.severity}`}
                />
              )}
            </Stack>

            {isGatewayObserved(record) && (
              <Alert severity="info">
                Observed by the AI gateway and delivered best effort: a record can be missing if the
                gateway could not deliver it.
              </Alert>
            )}

            <Section title="Event">
              <Field label="Occurred at" value={formatTimestamp(record.occurredAt)} />
              <Field label="Event ID" value={record.eventId} />
              <Field label="Category" value={record.category} />
              <Field label="Action class" value={record.actionClass} />
              <Field label="Source" value={SOURCE_LABEL[record.source] ?? record.source} />
              <Field label="Surface" value={record.surface} />
              <Field label="Producer" value={record.producer} />
            </Section>

            <Divider />

            <Section title="Actor">
              <Field label="Type" value={record.actor.type} />
              <Field label="ID" value={record.actor.id} />
              <Field label="Name" value={record.actor.display} />
              <Field label="Auth method" value={record.authMethod} />
              <Field label="Source IP" value={record.sourceIp} />
              <Field label="User agent" value={record.userAgent} />
            </Section>

            {(record.request || record.requestId || record.statusCode !== undefined) && (
              <>
                <Divider />
                <Section title="Request">
                  <Field label="Method" value={record.request?.method} />
                  <Field label="Path" value={record.request?.path} />
                  <Field label="Status code" value={record.statusCode} />
                  <Field
                    label="Duration"
                    value={record.durationMs !== undefined ? `${record.durationMs} ms` : undefined}
                  />
                  <Field label="Request ID" value={record.requestId} />
                </Section>
              </>
            )}

            {record.resource && (
              <>
                <Divider />
                <Section title="Resource">
                  <Field label="Type" value={record.resource.type} />
                  <Field label="Name" value={record.resource.name} />
                  <Field label="ID" value={record.resource.id} />
                  <Field label="Project" value={record.resource.project} />
                  <Field label="Environment" value={record.resource.environment} />
                  <Field label="Agent" value={record.resource.agent} />
                </Section>
              </>
            )}

            {(record.errorCode || record.errorMessage || record.requiredPermission) && (
              <>
                <Divider />
                <Section title="Error">
                  <Field label="Code" value={record.errorCode} />
                  <Field label="Message" value={record.errorMessage} />
                  <Field label="Required permission" value={record.requiredPermission} />
                </Section>
              </>
            )}

            {record.details?.bodyExcerptsOmitted === true && (
              <Alert severity="info">
                The request and response body excerpts were left out of this record: with them it
                exceeded the audit store&apos;s record size.
              </Alert>
            )}

            {(["requestBodyExcerpt", "responseBodyExcerpt"] as const).map((key) => {
              const text = record.details?.[key];
              if (typeof text !== "string" || text === "") return null;
              const { code, language } = formatExcerpt(text);
              return (
                <Box key={key}>
                  <Divider sx={{ mb: 3 }} />
                  <Section
                    title={
                      key === "requestBodyExcerpt"
                        ? "Request body (prompt)"
                        : "Response body (completion)"
                    }
                  >
                    {record.details?.bodyExcerptTruncated === true && (
                      <Typography variant="caption" color="text.secondary">
                        Excerpt — the body was longer and was cut.
                      </Typography>
                    )}
                    <CodeBlock
                      code={code}
                      language={language}
                      fieldId={`audit-${key}`}
                      analyticsId="audit-body-excerpt"
                    />
                  </Section>
                </Box>
              );
            })}

            {record.details &&
              Object.keys(record.details).some((k) => !EXCERPT_KEYS.includes(k)) && (
                <>
                  <Divider />
                  <Section title="Details">
                    <Box>
                      <CodeBlock
                        code={JSON.stringify(
                          Object.fromEntries(
                            Object.entries(record.details).filter(
                              ([k]) => !EXCERPT_KEYS.includes(k),
                            ),
                          ),
                          null,
                          2,
                        )}
                        language="json"
                        fieldId="audit-record-details"
                        analyticsId="audit-record-details"
                      />
                    </Box>
                  </Section>
                </>
              )}

            <Divider />
            <Section title="Raw record">
              <Box>
                <CodeBlock
                  code={JSON.stringify(record, null, 2)}
                  language="json"
                  fieldId="audit-record-raw"
                  analyticsId="audit-record-raw"
                />
              </Box>
            </Section>
          </Stack>
        )}
      </DrawerContent>
    </DrawerWrapper>
  );
}
