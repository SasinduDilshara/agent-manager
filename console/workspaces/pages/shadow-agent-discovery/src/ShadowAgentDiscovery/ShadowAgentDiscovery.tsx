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

import { Box, Divider, ListingTable, Skeleton, Stack, Tab, Tabs } from "@wso2/oxygen-ui";
import { Lock } from "@wso2/oxygen-ui-icons-react";
import {
  generatePath,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
  useResolvedPath,
  useSearchParams,
} from "react-router-dom";
import { PageLayout, returnToState, StateNotice } from "@agent-management-platform/views";
import { absoluteRouteMap } from "@agent-management-platform/types";
import { ConnectionEditor, editConnectionPath } from "./subComponents/ConnectionEditor";
import { ConnectionsTab } from "./subComponents/ConnectionsTab";
import { FindingDetail } from "./subComponents/FindingDetail";
import { OnboardFinding } from "./subComponents/OnboardFinding";
import { OverviewPanel } from "./subComponents/OverviewPanel";
import { RunScanButton } from "./subComponents/RunScanButton";
import { ScanFindings } from "./subComponents/ScanFindings";
import { ScansTab } from "./subComponents/ScansTab";
import { useShadowAccess } from "./useShadowAccess";

export type ShadowTab = "overview" | "scans" | "connections";
const TABS: ShadowTab[] = ["overview", "scans", "connections"];

const PAGE_TITLE = "Shadow Agent Discovery";
const PAGE_DESCRIPTION =
  "Find agents and LLM workloads that call model providers directly, bypassing Agent Manager, and bring them under governance.";

function ShadowOverview({
  orgName,
  canManage,
}: {
  orgName: string | undefined;
  canManage: boolean;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("tab") as ShadowTab | null;
  const tab: ShadowTab = requested && TABS.includes(requested) ? requested : "overview";
  const setTab = (t: ShadowTab) => setSearchParams({ tab: t }, { replace: true });
  const newConnection = () =>
    navigate(
      generatePath(
        absoluteRouteMap.children.org.children.shadowAgentDiscovery.children.newConnection.path,
        {
          orgId: orgName ?? "",
        },
      ),
      { state: returnToState(location) },
    );

  return (
    <PageLayout
      title={PAGE_TITLE}
      description={PAGE_DESCRIPTION}
      disableIcon
      actions={canManage ? <RunScanButton orgName={orgName} /> : undefined}
    >
      <ListingTable.Container>
        <Stack spacing={2.5}>
          <Box>
            <Tabs
              value={tab}
              onChange={(_, v: ShadowTab) => setTab(v)}
              variant="scrollable"
              allowScrollButtonsMobile
            >
              <Tab value="overview" label="Overview" />
              <Tab value="scans" label="Scans" />
              <Tab value="connections" label="Connections" />
            </Tabs>
            <Divider />
          </Box>
          <Box sx={{ px: 2, pb: 2 }}>
            {tab === "overview" && (
              <OverviewPanel
                orgName={orgName}
                canManage={canManage}
                onConnect={newConnection}
                onOpenScans={() => setTab("scans")}
                onOpenConnections={() => setTab("connections")}
              />
            )}
            {tab === "scans" && <ScansTab orgName={orgName} />}
            {tab === "connections" && (
              <ConnectionsTab
                orgName={orgName}
                canManage={canManage}
                onAdd={newConnection}
                onEdit={(c) =>
                  navigate(editConnectionPath(orgName ?? "", c.id), {
                    state: returnToState(location),
                  })
                }
              />
            )}
          </Box>
        </Stack>
      </ListingTable.Container>
    </PageLayout>
  );
}

/**
 * Shadow Agent Discovery (org level): overview, scans (each with the
 * findings it saw) and provider connections, with the scan findings,
 * finding, onboarding and connection pages below it. Mount it on a "/*"
 * route.
 */
export function ShadowAgentDiscovery() {
  const { orgId } = useParams<{ orgId: string }>();
  const listPath = useResolvedPath(".").pathname;
  const access = useShadowAccess();

  if (!access.resolved) {
    return (
      <PageLayout title={PAGE_TITLE} disableIcon>
        <Skeleton variant="rounded" height={240} />
      </PageLayout>
    );
  }
  if (!access.canRead) {
    return (
      <PageLayout title={PAGE_TITLE} disableIcon>
        <StateNotice
          icon={Lock}
          title="You don't have access to Shadow Agent Discovery"
          description="It shows provider credentials, usage and owners, so it is available to organization administrators."
        />
      </PageLayout>
    );
  }
  return (
    <Routes>
      <Route index element={<ShadowOverview orgName={orgId} canManage={access.canManage} />} />
      <Route path="scans/:scanId" element={<ScanFindings orgName={orgId} listPath={listPath} />} />
      <Route
        path="findings/:findingId"
        element={<FindingDetail orgName={orgId} canManage={access.canManage} listPath={listPath} />}
      />
      {access.canManage && (
        <>
          <Route
            path="findings/:findingId/onboard"
            element={<OnboardFinding orgName={orgId} listPath={listPath} />}
          />
          <Route
            path="connections/new"
            element={<ConnectionEditor orgName={orgId} listPath={listPath} />}
          />
          <Route
            path="connections/:connectionId/edit"
            element={<ConnectionEditor orgName={orgId} listPath={listPath} />}
          />
        </>
      )}
    </Routes>
  );
}

export default ShadowAgentDiscovery;
