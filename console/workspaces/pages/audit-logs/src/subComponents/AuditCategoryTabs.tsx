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

import { Box, Stack, Tab, Tabs, Tooltip, Typography } from "@wso2/oxygen-ui";
import {
  AUDIT_CATEGORIES,
  type AuditCategory,
  type AuditCategoryCounts,
} from "@agent-management-platform/types";
import { CATEGORY_DESCRIPTION, CATEGORY_LABEL } from "../auditFormat";

const ALL = "ALL";

export interface AuditCategoryTabsProps {
  value?: AuditCategory;
  counts?: AuditCategoryCounts;
  /** Undefined while counts are loading. */
  totalLabelSuffix?: string;
  onChange: (category: AuditCategory | undefined) => void;
}

function CountBadge({ count }: { count?: number }) {
  return (
    <Box
      component="span"
      sx={{
        ml: 1,
        px: 0.75,
        minWidth: 20,
        borderRadius: 10,
        fontSize: 11,
        lineHeight: "18px",
        textAlign: "center",
        bgcolor: "action.selected",
        color: "text.secondary",
      }}
    >
      {count === undefined ? "–" : count.toLocaleString()}
    </Box>
  );
}

/** All / Operational / LLM / MCP / A2A / Other, each with its event count. */
export function AuditCategoryTabs({
  value,
  counts,
  totalLabelSuffix = "",
  onChange,
}: AuditCategoryTabsProps) {
  const total = counts
    ? AUDIT_CATEGORIES.reduce((sum, c) => sum + (counts[c] ?? 0), 0)
    : undefined;
  return (
    <Tabs
      value={value ?? ALL}
      onChange={(_, v: string) =>
        onChange(v === ALL ? undefined : (v as AuditCategory))
      }
      variant="scrollable"
      scrollButtons="auto"
      aria-label="Audit event categories"
      sx={{ borderBottom: 1, borderColor: "divider", minHeight: 40 }}
    >
      <Tab
        value={ALL}
        sx={{ minHeight: 40 }}
        aria-label={`All events${total === undefined ? "" : `, ${total}${totalLabelSuffix}`}`}
        label={
          <Stack direction="row" alignItems="center">
            <Typography variant="body2" component="span">All</Typography>
            <CountBadge count={total} />
          </Stack>
        }
      />
      {AUDIT_CATEGORIES.map((c) => (
        <Tab
          key={c}
          value={c}
          sx={{ minHeight: 40 }}
          aria-label={`${CATEGORY_LABEL[c]} events${
            counts ? `, ${counts[c] ?? 0}${totalLabelSuffix}` : ""
          }`}
          label={
            <Tooltip title={CATEGORY_DESCRIPTION[c]} placement="top">
              <Stack direction="row" alignItems="center">
                <Typography variant="body2" component="span">
                  {CATEGORY_LABEL[c]}
                </Typography>
                <CountBadge count={counts ? (counts[c] ?? 0) : undefined} />
              </Stack>
            </Tooltip>
          }
        />
      ))}
    </Tabs>
  );
}
