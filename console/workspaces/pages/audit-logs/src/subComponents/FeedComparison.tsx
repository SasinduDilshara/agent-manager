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

import { useMemo, useState } from "react";
import {
  Alert,
  AlertTitle,
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  ListingTable,
  Stack,
  Typography,
} from "@wso2/oxygen-ui";
import { GitCompare } from "@wso2/oxygen-ui-icons-react";
import { useQueryAuditLogs } from "@agent-management-platform/api-client";
import { DrawerContent, DrawerHeader, DrawerWrapper } from "@agent-management-platform/views";
import { CodeBlock } from "@agent-management-platform/shared-component";
import type { AuditLogFilters, AuditLogRecord } from "@agent-management-platform/types";
import { describeAuditError, formatTimestamp } from "../utils";
import {
  FEED_FIELDS,
  fieldCoverage,
  mcpOf,
  modelOf,
  overlappingSpan,
  pairFeeds,
  tokensOf,
  type FeedPair,
} from "../feeds";

const COMPARE_LIMIT = 1000;

interface FeedComparisonProps {
  orgName: string | undefined;
  filters: AuditLogFilters;
}

function summary(record?: AuditLogRecord): string {
  if (!record) return "";
  return (
    [modelOf(record), tokensOf(record), mcpOf(record)].filter(Boolean).join(" · ") || record.action
  );
}

function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: number | string;
  hint?: string;
}) {
  return (
    <Card variant="outlined" sx={{ flex: 1, minWidth: 160 }}>
      <CardContent>
        <Typography variant="caption" color="text.secondary">
          {label}
        </Typography>
        <Typography variant="h5">{value}</Typography>
        {hint && (
          <Typography variant="caption" color="text.secondary">
            {hint}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

function percent(count: number, total: number): string {
  if (total === 0) return "—";
  return `${Math.round((count / total) * 100)}% (${count}/${total})`;
}

function PairDrawer({ pair, onClose }: { pair: FeedPair | null; onClose: () => void }) {
  return (
    <DrawerWrapper open={!!pair} onClose={onClose} minWidth={720} maxWidth={1100}>
      <DrawerHeader
        icon={<GitCompare size={24} />}
        title="One request, two feeds"
        onClose={onClose}
      />
      <DrawerContent>
        {pair && (
          <Stack spacing={3}>
            <ListingTable density="compact">
              <ListingTable.Head>
                <ListingTable.Row>
                  <ListingTable.Cell width="200px">Field</ListingTable.Cell>
                  <ListingTable.Cell>OTel</ListingTable.Cell>
                  <ListingTable.Cell>Traffic log</ListingTable.Cell>
                </ListingTable.Row>
              </ListingTable.Head>
              <ListingTable.Body>
                {FEED_FIELDS.map((field) => {
                  const a = pair.otel ? field.value(pair.otel) : undefined;
                  const b = pair.traffic ? field.value(pair.traffic) : undefined;
                  return (
                    <ListingTable.Row key={field.key}>
                      <ListingTable.Cell>
                        <Typography variant="body2">{field.label}</Typography>
                      </ListingTable.Cell>
                      {[a, b].map((v, i) => (
                        <ListingTable.Cell key={i}>
                          <Typography
                            variant="body2"
                            color={v === undefined ? "text.disabled" : "text.primary"}
                            sx={{ wordBreak: "break-all" }}
                          >
                            {v ?? "not reported"}
                          </Typography>
                        </ListingTable.Cell>
                      ))}
                    </ListingTable.Row>
                  );
                })}
              </ListingTable.Body>
            </ListingTable>
            <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
              {(["otel", "traffic"] as const).map((side) => (
                <Box key={side} sx={{ flex: 1, minWidth: 0 }}>
                  <Typography variant="overline" color="text.secondary">
                    {side === "otel" ? "OTel record" : "Traffic-log record"}
                  </Typography>
                  {pair[side] ? (
                    <CodeBlock
                      code={JSON.stringify(pair[side], null, 2)}
                      language="json"
                      fieldId={`compare-raw-${side}`}
                      analyticsId="audit-compare-raw"
                    />
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      This feed has no record of the request.
                    </Typography>
                  )}
                </Box>
              ))}
            </Stack>
          </Stack>
        )}
      </DrawerContent>
    </DrawerWrapper>
  );
}

/**
 * The two gateway feeds side by side: what each reported for the same
 * requests, matched by the gateway's correlation id.
 */
export function FeedComparison({ orgName, filters }: FeedComparisonProps) {
  const otelQuery = useMemo(
    () => ({
      ...filters,
      source: ["gateway-otel" as const],
      limit: COMPARE_LIMIT,
      sortOrder: "desc" as const,
    }),
    [filters],
  );
  const trafficQuery = useMemo(
    () => ({
      ...filters,
      source: ["gateway-traffic-log" as const],
      limit: COMPARE_LIMIT,
      sortOrder: "desc" as const,
    }),
    [filters],
  );
  const otel = useQueryAuditLogs({ orgName }, otelQuery);
  const traffic = useQueryAuditLogs({ orgName }, trafficQuery);
  const [selected, setSelected] = useState<FeedPair | null>(null);

  // Both feeds over the span both cover, so a request missing from one feed
  // is missing, not merely past the other feed's cap.
  const span = useMemo(
    () =>
      overlappingSpan(otel.data?.records ?? [], traffic.data?.records ?? [], {
        otel: (otel.data?.total ?? 0) > (otel.data?.records.length ?? 0),
        traffic: (traffic.data?.total ?? 0) > (traffic.data?.records.length ?? 0),
      }),
    [otel.data, traffic.data],
  );
  const otelRecords = span.otel;
  const trafficRecords = span.traffic;
  const pairs = useMemo(
    () => pairFeeds(otelRecords, trafficRecords),
    [otelRecords, trafficRecords],
  );
  const otelCoverage = useMemo(() => fieldCoverage(otelRecords), [otelRecords]);
  const trafficCoverage = useMemo(() => fieldCoverage(trafficRecords), [trafficRecords]);

  const error = otel.error ?? traffic.error;
  if (error) {
    const { severity, title, message } = describeAuditError(error, "read");
    return (
      <Alert severity={severity}>
        <AlertTitle>{title}</AlertTitle>
        {message}
      </Alert>
    );
  }
  if (otel.isLoading || traffic.isLoading) {
    return (
      <Stack alignItems="center" sx={{ py: 8 }}>
        <CircularProgress />
      </Stack>
    );
  }

  const both = pairs.filter((p) => p.otel && p.traffic).length;
  const onlyOtel = pairs.filter((p) => p.otel && !p.traffic).length;
  const onlyTraffic = pairs.filter((p) => !p.otel && p.traffic).length;
  return (
    <Stack spacing={3}>
      {span.since && (
        <Alert severity="info">
          A feed holds more than {COMPARE_LIMIT} records in this time range, so the comparison
          covers what both feeds recorded since {formatTimestamp(span.since)}. Narrow the time range
          to compare all of it.
        </Alert>
      )}
      <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
        <StatCard label="OTel feed" value={otel.data?.total ?? 0} hint="records" />
        <StatCard label="Traffic-log feed" value={traffic.data?.total ?? 0} hint="records" />
        <StatCard label="Requests in both" value={both} />
        <StatCard label="Only in OTel" value={onlyOtel} />
        <StatCard label="Only in traffic log" value={onlyTraffic} />
      </Stack>

      <Box>
        <Typography variant="h6" gutterBottom>
          What each feed reports
        </Typography>
        <ListingTable density="compact">
          <ListingTable.Head>
            <ListingTable.Row>
              <ListingTable.Cell>Field</ListingTable.Cell>
              <ListingTable.Cell>OTel records carrying it</ListingTable.Cell>
              <ListingTable.Cell>Traffic-log records carrying it</ListingTable.Cell>
            </ListingTable.Row>
          </ListingTable.Head>
          <ListingTable.Body>
            {FEED_FIELDS.map((field) => (
              <ListingTable.Row key={field.key}>
                <ListingTable.Cell>
                  <Typography variant="body2">{field.label}</Typography>
                </ListingTable.Cell>
                <ListingTable.Cell>
                  <Typography variant="body2">
                    {percent(otelCoverage[field.key], otelRecords.length)}
                  </Typography>
                </ListingTable.Cell>
                <ListingTable.Cell>
                  <Typography variant="body2">
                    {percent(trafficCoverage[field.key], trafficRecords.length)}
                  </Typography>
                </ListingTable.Cell>
              </ListingTable.Row>
            ))}
          </ListingTable.Body>
        </ListingTable>
      </Box>

      <Box>
        <Typography variant="h6" gutterBottom>
          Request by request
        </Typography>
        {pairs.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            Neither feed recorded agent activity in this time range.
          </Typography>
        ) : (
          <ListingTable density="compact">
            <ListingTable.Head>
              <ListingTable.Row>
                <ListingTable.Cell width="200px">Time</ListingTable.Cell>
                <ListingTable.Cell>Action</ListingTable.Cell>
                <ListingTable.Cell>OTel reported</ListingTable.Cell>
                <ListingTable.Cell>Traffic log reported</ListingTable.Cell>
                <ListingTable.Cell width="120px">Seen by</ListingTable.Cell>
              </ListingTable.Row>
            </ListingTable.Head>
            <ListingTable.Body>
              {pairs.map((pair) => (
                <ListingTable.Row key={pair.key} hover clickable onClick={() => setSelected(pair)}>
                  <ListingTable.Cell>
                    <Typography variant="body2" sx={{ whiteSpace: "nowrap" }}>
                      {formatTimestamp(pair.occurredAt)}
                    </Typography>
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                      {(pair.otel ?? pair.traffic)?.action}
                    </Typography>
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Typography variant="body2">{summary(pair.otel) || "—"}</Typography>
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Typography variant="body2">{summary(pair.traffic) || "—"}</Typography>
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Chip
                      size="small"
                      variant="outlined"
                      color={pair.otel && pair.traffic ? "success" : "warning"}
                      label={
                        pair.otel && pair.traffic
                          ? "Both"
                          : pair.otel
                            ? "OTel only"
                            : "Traffic only"
                      }
                    />
                  </ListingTable.Cell>
                </ListingTable.Row>
              ))}
            </ListingTable.Body>
          </ListingTable>
        )}
      </Box>
      <PairDrawer pair={selected} onClose={() => setSelected(null)} />
    </Stack>
  );
}
