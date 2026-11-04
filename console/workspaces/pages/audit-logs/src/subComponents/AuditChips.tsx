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

import { Chip, Tooltip } from "@wso2/oxygen-ui";
import {
  CircleCheck,
  CircleX,
  ShieldX,
  Users,
} from "@wso2/oxygen-ui-icons-react";
import type { AuditCategory, AuditOutcome } from "@agent-management-platform/types";
import {
  CATEGORY_DESCRIPTION,
  CATEGORY_LABEL,
  OUTCOME_COLOR,
  OUTCOME_LABEL,
} from "../auditFormat";

const OUTCOME_ICON = {
  SUCCESS: CircleCheck,
  DENIED: ShieldX,
  FAILED: CircleX,
} as const;

export function OutcomeChip({ outcome }: { outcome: AuditOutcome }) {
  const Icon = OUTCOME_ICON[outcome] ?? CircleX;
  return (
    <Chip
      size="small"
      variant="outlined"
      color={OUTCOME_COLOR[outcome] ?? "default"}
      icon={<Icon size={14} aria-hidden />}
      label={OUTCOME_LABEL[outcome] ?? outcome}
      data-testid={`outcome-${outcome}`}
    />
  );
}

export function CategoryChip({ category }: { category: AuditCategory }) {
  return (
    <Tooltip title={CATEGORY_DESCRIPTION[category] ?? ""}>
      <Chip
        size="small"
        variant="filled"
        label={CATEGORY_LABEL[category] ?? category}
        sx={{ fontWeight: 500 }}
      />
    </Tooltip>
  );
}

/** Marks an event made with a delegated (on-behalf-of) token. */
export function OnBehalfOfBadge({ subject }: { subject?: string }) {
  return (
    <Tooltip title={subject ? `On behalf of ${subject}` : "Delegated access"}>
      <Chip
        size="small"
        variant="outlined"
        color="info"
        icon={<Users size={12} aria-hidden />}
        label="on behalf of"
        sx={{ height: 20, "& .MuiChip-label": { px: 0.75, fontSize: 11 } }}
      />
    </Tooltip>
  );
}
