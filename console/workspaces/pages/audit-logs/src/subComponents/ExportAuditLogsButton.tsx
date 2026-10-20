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

import { Button, CircularProgress, Tooltip } from "@wso2/oxygen-ui";
import { Download } from "@wso2/oxygen-ui-icons-react";
import {
  useExportAuditLogs,
  type AuditLogExportFile,
} from "@agent-management-platform/api-client";
import type { ExportAuditLogsQuery } from "@agent-management-platform/types";

export type ExportOutcome =
  | { kind: "done"; file: AuditLogExportFile }
  | { kind: "error"; error: unknown };

interface ExportAuditLogsButtonProps {
  orgName: string | undefined;
  query: ExportAuditLogsQuery | undefined;
  /** False when the caller's token lacks audit-log:export. */
  permitted: boolean;
  onOutcome: (outcome: ExportOutcome) => void;
}

function saveFile(file: AuditLogExportFile) {
  const url = URL.createObjectURL(file.blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = file.filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function ExportAuditLogsButton({
  orgName,
  query,
  permitted,
  onOutcome,
}: ExportAuditLogsButtonProps) {
  const { mutate, isPending } = useExportAuditLogs();

  const button = (
    <Button
      size="small"
      variant="outlined"
      startIcon={isPending ? <CircularProgress size={14} /> : <Download size={16} />}
      disabled={!permitted || !query || !orgName || isPending}
      onClick={() => {
        if (!query) return;
        mutate(
          { params: { orgName }, query },
          {
            onSuccess: (file) => {
              saveFile(file);
              onOutcome({ kind: "done", file });
            },
            onError: (error) => onOutcome({ kind: "error", error }),
          },
        );
      }}
    >
      {isPending ? "Exporting…" : "Export"}
    </Button>
  );

  if (permitted) return button;
  return (
    <Tooltip title="Your role does not include exporting the audit trail (audit-log:export)">
      {/* A disabled button fires no events; the span carries the tooltip. */}
      <span>{button}</span>
    </Tooltip>
  );
}
