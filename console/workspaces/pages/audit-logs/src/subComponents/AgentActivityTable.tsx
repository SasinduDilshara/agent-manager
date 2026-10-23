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

import { Chip, ListingTable, Skeleton, Stack, Tooltip, Typography } from "@wso2/oxygen-ui";
import type { AuditLogRecord } from "@agent-management-platform/types";
import { formatTimestamp, RESULT_COLOR } from "../utils";
import { agentOf, detailString, mcpOf, modelOf, tokensOf } from "../feeds";

interface AgentActivityTableProps {
  records: AuditLogRecord[];
  isLoading: boolean;
  onSelect: (record: AuditLogRecord) => void;
}

const COLUMNS = ["Time", "Action", "Agent", "API", "Model", "Tokens", "MCP", "Status", "Duration"];

function Dash() {
  return (
    <Typography variant="body2" color="text.disabled">
      —
    </Typography>
  );
}

function Cell({ value, mono }: { value?: string; mono?: boolean }) {
  if (!value) return <Dash />;
  return (
    <Typography
      variant="body2"
      sx={{ wordBreak: "break-all", fontFamily: mono ? "monospace" : undefined }}
    >
      {value}
    </Typography>
  );
}

/** Agent activity from one gateway feed, with the fields that feed reports. */
export function AgentActivityTable({ records, isLoading, onSelect }: AgentActivityTableProps) {
  return (
    <ListingTable density="compact">
      <ListingTable.Head>
        <ListingTable.Row>
          {COLUMNS.map((c) => (
            <ListingTable.Cell key={c}>{c}</ListingTable.Cell>
          ))}
        </ListingTable.Row>
      </ListingTable.Head>
      <ListingTable.Body>
        {isLoading
          ? Array.from({ length: 8 }).map((_, i) => (
              <ListingTable.Row key={i}>
                {COLUMNS.map((c) => (
                  <ListingTable.Cell key={c}>
                    <Skeleton variant="text" height={20} />
                  </ListingTable.Cell>
                ))}
              </ListingTable.Row>
            ))
          : records.map((record) => {
              const fromBody = record.details?.derivedFromBody === true;
              return (
                <ListingTable.Row
                  key={record.eventId}
                  hover
                  clickable
                  onClick={() => onSelect(record)}
                >
                  <ListingTable.Cell>
                    <Typography variant="body2" sx={{ whiteSpace: "nowrap" }}>
                      {formatTimestamp(record.occurredAt)}
                    </Typography>
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Cell value={record.action} mono />
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Stack spacing={0}>
                      <Cell
                        value={
                          agentOf(record) ??
                          (record.actor.type === "anonymous" ? undefined : record.actor.id)
                        }
                      />
                      <Typography variant="caption" color="text.secondary">
                        {detailString(record, "resolution") ?? record.actor.type}
                      </Typography>
                    </Stack>
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Cell value={record.resource?.name} />
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Cell value={modelOf(record)} />
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Cell value={tokensOf(record)} />
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Cell value={mcpOf(record)} mono />
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      <Chip
                        size="small"
                        variant="outlined"
                        label={record.statusCode ?? record.result}
                        color={RESULT_COLOR[record.result] ?? "default"}
                      />
                      {fromBody && (
                        <Tooltip title="Model, tokens or MCP fields were read from the captured bodies">
                          <Chip size="small" variant="outlined" label="from body" />
                        </Tooltip>
                      )}
                    </Stack>
                  </ListingTable.Cell>
                  <ListingTable.Cell>
                    <Cell
                      value={
                        record.durationMs !== undefined ? `${record.durationMs} ms` : undefined
                      }
                    />
                  </ListingTable.Cell>
                </ListingTable.Row>
              );
            })}
      </ListingTable.Body>
    </ListingTable>
  );
}
