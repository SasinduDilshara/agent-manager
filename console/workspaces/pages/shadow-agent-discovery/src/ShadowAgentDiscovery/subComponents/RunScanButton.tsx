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

import { useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Stack,
  Typography,
} from "@wso2/oxygen-ui";
import { Radar } from "@wso2/oxygen-ui-icons-react";
import { TextInput } from "@agent-management-platform/views";
import {
  isShadowScanActive,
  useShadowConnections,
  useShadowSummary,
  useStartShadowScan,
} from "@agent-management-platform/api-client";

const LOOKBACK_OPTIONS = [7, 30, 60, 90];

/** The page's primary action: queue a scan of every connection. */
export function RunScanButton({ orgName }: { orgName: string | undefined }) {
  const [open, setOpen] = useState(false);
  const [lookbackDays, setLookbackDays] = useState(30);
  const summary = useShadowSummary(orgName);
  const connections = useShadowConnections(orgName);
  const start = useStartShadowScan(orgName);
  const active = isShadowScanActive(summary.data?.latestScan?.status);
  const none = (connections.data?.connections.length ?? 0) === 0;

  return (
    <>
      <Button
        variant="contained"
        startIcon={<Radar size={16} />}
        disabled={active || none || start.isPending}
        onClick={() => setOpen(true)}
      >
        {active ? "Scan running…" : "Run scan"}
      </Button>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Run a scan</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Scans every connected provider with read-only calls. Provider usage history is read
              for the period you choose; some providers keep less (for example 90 days of CloudTrail
              and Activity Log events).
            </Typography>
            <TextInput
              select
              label="History to read"
              value={String(lookbackDays)}
              onChange={(e) => setLookbackDays(Number(e.target.value))}
            >
              {LOOKBACK_OPTIONS.map((d) => (
                <MenuItem key={d} value={String(d)}>
                  Last {d} days
                </MenuItem>
              ))}
            </TextInput>
          </Stack>
        </DialogContent>
        <DialogActions sx={{ justifyContent: "flex-start", px: 3, pb: 2 }}>
          <Button
            variant="contained"
            disabled={start.isPending}
            onClick={() => start.mutate({ lookbackDays }, { onSuccess: () => setOpen(false) })}
          >
            Start scan
          </Button>
          <Button variant="outlined" onClick={() => setOpen(false)}>
            Cancel
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
