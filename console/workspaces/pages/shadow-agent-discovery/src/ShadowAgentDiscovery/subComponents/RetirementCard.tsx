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

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  LinearProgress,
  Stack,
  Typography,
} from "@wso2/oxygen-ui";
import { useConfirmShadowRetirement } from "@agent-management-platform/api-client";
import { useConfirmationDialog } from "@agent-management-platform/shared-component";
import type { ShadowFindingDetail } from "@agent-management-platform/types";
import { RETIREMENT_LABELS, shortDate } from "../shadowUi";

interface RetirementCardProps {
  orgName: string | undefined;
  finding: ShadowFindingDetail;
  canManage: boolean;
}

/**
 * The last step of onboarding: watch the direct usage stay at zero for the
 * observation window, then revoke the direct credential at the provider.
 * Agent Manager only guides and verifies; it never revokes anything.
 */
export function RetirementCard({ orgName, finding, canManage }: RetirementCardProps) {
  const r = finding.retirement;
  const confirm = useConfirmShadowRetirement(orgName, finding.id);
  const { addConfirmation } = useConfirmationDialog();
  if (!finding.linkedAgent) return null;
  const progress = Math.min(100, (r.zeroUsageDays / Math.max(1, r.observationDays)) * 100);

  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
          <Typography variant="subtitle1" sx={{ flex: 1 }}>
            Retire the direct credential
          </Typography>
          <Chip
            size="small"
            color={
              r.state === "retired" ? "success" : r.state === "ready_to_retire" ? "warning" : "info"
            }
            label={RETIREMENT_LABELS[r.state] ?? r.state}
          />
        </Stack>

        {(r.state === "monitoring" || r.state === "ready_to_retire") && (
          <Box sx={{ mb: 2 }}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Days without direct usage since the agent was onboarded: {r.zeroUsageDays} of{" "}
              {r.observationDays}
              {r.dataThrough ? ` (data through ${shortDate(r.dataThrough)})` : ""}.
              {r.lastDirectUseAt ? ` Last direct use: ${shortDate(r.lastDirectUseAt)}.` : ""}
            </Typography>
            <LinearProgress
              variant="determinate"
              value={progress}
              aria-label={`${r.zeroUsageDays} of ${r.observationDays} days without direct usage`}
              sx={{ height: 6, borderRadius: 3 }}
            />
            {r.state === "monitoring" && (
              <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1 }}>
                Run a scan each day or two. Once the workload has made no direct calls for{" "}
                {r.observationDays} days, the steps to revoke the credential appear here.
              </Typography>
            )}
          </Box>
        )}

        {(r.state === "ready_to_retire" || r.state === "pending_verification") && (
          <Box sx={{ mb: 2 }}>
            <Typography variant="body2" fontWeight={500} gutterBottom>
              {r.guidance.title}
            </Typography>
            <Box component="ol" sx={{ pl: 2.5, my: 0 }}>
              {r.guidance.steps.map((s) => (
                <Typography
                  key={s}
                  component="li"
                  variant="body2"
                  color="text.secondary"
                  sx={{ mb: 0.5 }}
                >
                  {s}
                </Typography>
              ))}
            </Box>
            {r.guidance.docsUrl && (
              <Typography variant="caption" component="p">
                <a href={r.guidance.docsUrl} target="_blank" rel="noreferrer noopener">
                  Official documentation
                </a>
              </Typography>
            )}
          </Box>
        )}

        {r.state === "pending_verification" && (
          <Alert severity="info" sx={{ mb: 2 }}>
            You confirmed the revocation {r.markedAt ? `on ${shortDate(r.markedAt)}` : ""}.{" "}
            {r.verification}
          </Alert>
        )}
        {r.state === "retired" && (
          <Alert severity="success">
            Retired{r.verifiedAt ? ` on ${shortDate(r.verifiedAt)}` : ""}. {r.verification}
          </Alert>
        )}

        {r.state === "ready_to_retire" && canManage && (
          <Button
            variant="contained"
            disabled={confirm.isPending}
            onClick={() =>
              addConfirmation({
                title: "Did you revoke the credential?",
                description:
                  "Confirm only after you followed the steps at the provider. The next scan checks the provider and marks the credential retired.",
                confirmButtonText: "I've revoked it",
                onConfirm: () => confirm.mutate(),
              })
            }
          >
            I&apos;ve revoked it
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

export default RetirementCard;
