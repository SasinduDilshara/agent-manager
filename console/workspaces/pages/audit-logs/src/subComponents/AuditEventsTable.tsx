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

import type { KeyboardEvent } from "react";
import {
  Box,
  Button,
  CircularProgress,
  ListingTable,
  Skeleton,
  Stack,
  Tooltip,
  Typography,
} from "@wso2/oxygen-ui";
import { ArrowDown } from "@wso2/oxygen-ui-icons-react";
import { formatRelativeTime } from "@agent-management-platform/shared-component";
import type { AuditEvent, AuditSortOrder } from "@agent-management-platform/types";
import {
  actorLabel,
  actorTypeLabel,
  agentLabel,
  formatAbsoluteTime,
  hasDelegation,
} from "../auditFormat";
import { CategoryChip, OnBehalfOfBadge, OutcomeChip } from "./AuditChips";

export interface AuditEventsTableProps {
  events: AuditEvent[];
  isLoading?: boolean;
  selectedId?: string | null;
  onSelect: (event: AuditEvent) => void;
  hasMore?: boolean;
  isLoadingMore?: boolean;
  loadMoreError?: unknown;
  onLoadMore?: () => void;
  sort: AuditSortOrder;
  onSortChange: (sort: AuditSortOrder) => void;
}

const ellipsis = {
  display: "block",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  maxWidth: "100%",
} as const;

const COLUMNS = [
  { key: "time", label: "Time", width: "11%" },
  { key: "category", label: "Category", width: "9%" },
  { key: "action", label: "Action", width: "14%" },
  { key: "agent", label: "Agent", width: "13%" },
  { key: "actor", label: "Actor", width: "16%" },
  { key: "outcome", label: "Outcome", width: "9%" },
  { key: "summary", label: "Summary", width: "20%" },
  { key: "environment", label: "Environment", width: "8%" },
] as const;

function SortArrow({ className }: { className?: string }) {
  return <ArrowDown size={14} className={className} />;
}

export function AuditEventsTable({
  events,
  isLoading,
  selectedId,
  onSelect,
  hasMore,
  isLoadingMore,
  loadMoreError,
  onLoadMore,
  sort,
  onSortChange,
}: AuditEventsTableProps) {
  const head = (
    <ListingTable.Head>
      <ListingTable.Row>
        {COLUMNS.map((c) => (
          <ListingTable.Cell key={c.key} width={c.width} sx={{ whiteSpace: "nowrap" }}>
            {c.key === "time" ? (
              <ListingTable.SortLabel
                active
                direction={sort}
                IconComponent={SortArrow}
                onClick={() => onSortChange(sort === "desc" ? "asc" : "desc")}
                aria-label={sort === "desc" ? "Newest first; sort oldest first" : "Oldest first; sort newest first"}
              >
                {c.label}
              </ListingTable.SortLabel>
            ) : (
              c.label
            )}
          </ListingTable.Cell>
        ))}
      </ListingTable.Row>
    </ListingTable.Head>
  );

  const onRowKeyDown = (e: KeyboardEvent<HTMLTableRowElement>, event: AuditEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onSelect(event);
    }
  };

  return (
    <ListingTable.Container>
      <ListingTable aria-label="Audit events" aria-busy={isLoading || undefined}>
        {head}
        <ListingTable.Body>
          {isLoading
            ? Array.from({ length: 8 }, (_, i) => (
                <ListingTable.Row key={i}>
                  {COLUMNS.map((c) => (
                    <ListingTable.Cell key={c.key}>
                      <Skeleton variant="text" />
                    </ListingTable.Cell>
                  ))}
                </ListingTable.Row>
              ))
            : events.map((event) => {
                const agent = agentLabel(event);
                const actor = actorLabel(event.actor);
                return (
                  <ListingTable.Row
                    key={event.id}
                    hover
                    clickable
                    tabIndex={0}
                    selected={selectedId === event.id}
                    aria-selected={selectedId === event.id}
                    aria-label={`${event.action} by ${actor}, ${event.outcome.toLowerCase()}, ${formatAbsoluteTime(event.timestamp)}. Open details.`}
                    onClick={() => onSelect(event)}
                    onKeyDown={(e: KeyboardEvent<HTMLTableRowElement>) => onRowKeyDown(e, event)}
                    sx={{ cursor: "pointer" }}
                  >
                    <ListingTable.Cell>
                      <Tooltip title={formatAbsoluteTime(event.timestamp)}>
                        <Typography variant="body2" component="span" sx={ellipsis}>
                          {formatRelativeTime(event.timestamp)}
                        </Typography>
                      </Tooltip>
                    </ListingTable.Cell>
                    <ListingTable.Cell>
                      <CategoryChip category={event.category} />
                    </ListingTable.Cell>
                    <ListingTable.Cell sx={{ maxWidth: 200 }}>
                      <Tooltip title={event.action}>
                        <Typography
                          variant="body2"
                          component="span"
                          sx={{ ...ellipsis, fontFamily: "monospace", fontSize: 13 }}
                        >
                          {event.action}
                        </Typography>
                      </Tooltip>
                    </ListingTable.Cell>
                    <ListingTable.Cell sx={{ maxWidth: 180 }}>
                      {agent ? (
                        <Tooltip title={agent}>
                          <Typography variant="body2" component="span" sx={ellipsis}>
                            {event.agent?.name}
                          </Typography>
                        </Tooltip>
                      ) : (
                        <Typography variant="body2" color="text.disabled">-</Typography>
                      )}
                    </ListingTable.Cell>
                    <ListingTable.Cell sx={{ maxWidth: 220 }}>
                      <Stack spacing={0.25} alignItems="flex-start">
                        <Tooltip title={`${actorTypeLabel(event.actor?.type)}: ${event.actor?.id ?? actor}`}>
                          <Typography variant="body2" component="span" sx={ellipsis}>
                            {actor}
                          </Typography>
                        </Tooltip>
                        {hasDelegation(event) && (
                          <OnBehalfOfBadge subject={event.onBehalfOf?.subject} />
                        )}
                      </Stack>
                    </ListingTable.Cell>
                    <ListingTable.Cell>
                      <OutcomeChip outcome={event.outcome} />
                    </ListingTable.Cell>
                    <ListingTable.Cell sx={{ maxWidth: 300 }}>
                      <Tooltip title={event.summary ?? ""} disableHoverListener={!event.summary}>
                        <Typography
                          variant="body2"
                          component="span"
                          color="text.secondary"
                          sx={ellipsis}
                        >
                          {event.summary || "-"}
                        </Typography>
                      </Tooltip>
                    </ListingTable.Cell>
                    <ListingTable.Cell>
                      <Typography variant="body2" component="span" sx={ellipsis}>
                        {event.environment || "-"}
                      </Typography>
                    </ListingTable.Cell>
                  </ListingTable.Row>
                );
              })}
        </ListingTable.Body>
      </ListingTable>
      {!isLoading && (hasMore || isLoadingMore) && (
        <Box display="flex" justifyContent="center" py={1.5}>
          {isLoadingMore ? (
            <CircularProgress size={18} aria-label="Loading more events" />
          ) : loadMoreError ? (
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="caption" color="error">
                Couldn&apos;t load more events.
              </Typography>
              <Button size="small" variant="text" onClick={onLoadMore}>
                Retry
              </Button>
            </Stack>
          ) : (
            <Button
              size="small"
              variant="outlined"
              startIcon={<ArrowDown size={16} />}
              onClick={onLoadMore}
            >
              Load more
            </Button>
          )}
        </Box>
      )}
    </ListingTable.Container>
  );
}
