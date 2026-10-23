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

import {
  Chip,
  ListingTable,
  Skeleton,
  Stack,
  Tooltip,
  Typography,
} from "@wso2/oxygen-ui";
import type { AuditLogRecord } from "@agent-management-platform/types";
import {
  formatActor,
  formatResource,
  formatTimestamp,
  RESULT_COLOR,
} from "../utils";
import { SOURCE_LABEL } from "../feeds";

interface AuditLogTableProps {
  records: AuditLogRecord[];
  isLoading: boolean;
  onSelect: (record: AuditLogRecord) => void;
}

const COLUMN_COUNT = 7;

function LoadingRows() {
  return (
    <>
      {Array.from({ length: 8 }).map((_, i) => (
        <ListingTable.Row key={i}>
          {Array.from({ length: COLUMN_COUNT }).map((__, j) => (
            <ListingTable.Cell key={j}>
              <Skeleton variant="text" height={20} />
            </ListingTable.Cell>
          ))}
        </ListingTable.Row>
      ))}
    </>
  );
}

export function AuditLogTable({ records, isLoading, onSelect }: AuditLogTableProps) {
  return (
    <ListingTable density="compact">
      <ListingTable.Head>
        <ListingTable.Row>
          <ListingTable.Cell width="200px">Time</ListingTable.Cell>
          <ListingTable.Cell>Action</ListingTable.Cell>
          <ListingTable.Cell>Actor</ListingTable.Cell>
          <ListingTable.Cell>Resource</ListingTable.Cell>
          <ListingTable.Cell>Agent</ListingTable.Cell>
          <ListingTable.Cell width="160px">Source</ListingTable.Cell>
          <ListingTable.Cell align="center" width="100px">
            Result
          </ListingTable.Cell>
        </ListingTable.Row>
      </ListingTable.Head>
      <ListingTable.Body>
        {isLoading ? (
          <LoadingRows />
        ) : (
          records.map((record) => (
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
                <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                  {record.action}
                </Typography>
              </ListingTable.Cell>
              <ListingTable.Cell>
                <Stack spacing={0}>
                  <Typography variant="body2" sx={{ wordBreak: "break-all" }}>
                    {formatActor(record)}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {record.actor.type}
                  </Typography>
                </Stack>
              </ListingTable.Cell>
              <ListingTable.Cell>
                <Typography variant="body2" sx={{ wordBreak: "break-all" }}>
                  {formatResource(record)}
                </Typography>
              </ListingTable.Cell>
              <ListingTable.Cell>
                <Typography variant="body2">
                  {record.resource?.agent ||
                    (record.resource?.type === "agent" ? record.resource.name : "") ||
                    "—"}
                </Typography>
              </ListingTable.Cell>
              <ListingTable.Cell>
                {record.source === "platform" ? (
                  <Typography variant="body2" color="text.secondary">
                    {SOURCE_LABEL.platform}
                    {record.surface ? ` · ${record.surface}` : ""}
                  </Typography>
                ) : (
                  <Tooltip title="Agent activity observed by the AI gateway, relayed by this feed">
                    <Chip size="small" variant="outlined" label={SOURCE_LABEL[record.source] ?? record.source} />
                  </Tooltip>
                )}
              </ListingTable.Cell>
              <ListingTable.Cell align="center">
                <Chip
                  size="small"
                  variant="outlined"
                  label={record.result}
                  color={RESULT_COLOR[record.result] ?? "default"}
                />
              </ListingTable.Cell>
            </ListingTable.Row>
          ))
        )}
      </ListingTable.Body>
    </ListingTable>
  );
}
