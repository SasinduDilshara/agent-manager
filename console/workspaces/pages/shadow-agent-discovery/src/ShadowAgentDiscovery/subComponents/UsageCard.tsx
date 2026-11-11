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

import { useMemo, useState } from "react";
import {
  Box,
  Button,
  Card,
  CardContent,
  ListingTable,
  Stack,
  Typography,
  useTheme,
} from "@wso2/oxygen-ui";
import { BarChart } from "@wso2/oxygen-ui-charts-react";
import type { ShadowUsageDay } from "@agent-management-platform/types";
import { formatCount } from "../shadowUi";

export interface DailyTotal {
  day: string;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  cost: number | null;
  currency: string;
}

/** The UTC day (YYYY-MM-DD) after the given one. */
function nextDay(day: string): string {
  const d = new Date(`${day}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

/**
 * Sums usage rows (per key and model) into one total per day, oldest first.
 * Days without usage between the first used day and `through` (or the last
 * used day) are filled in with zeros, so quiet days stay visible.
 */
export function dailyTotals(usage: ShadowUsageDay[], through?: string): DailyTotal[] {
  const byDay = new Map<string, DailyTotal>();
  for (const u of usage) {
    const t = byDay.get(u.day) ?? {
      day: u.day,
      requests: 0,
      inputTokens: 0,
      outputTokens: 0,
      cost: null,
      currency: "",
    };
    t.requests += u.requests;
    t.inputTokens += u.inputTokens;
    t.outputTokens += u.outputTokens;
    if (u.costAmount !== undefined && u.costAmount !== null) {
      t.cost = (t.cost ?? 0) + u.costAmount;
      t.currency = t.currency || (u.currency ?? "");
    }
    byDay.set(u.day, t);
  }
  const days = [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day));
  if (days.length === 0) return days;
  const last = through && through > days[days.length - 1].day ? through : days[days.length - 1].day;
  const filled: DailyTotal[] = [];
  // Bounded by the 90-day maximum history (plus the days since the last scan).
  for (let day = days[0].day, i = 0; day <= last && filled.length < 400; day = nextDay(day)) {
    if (days[i]?.day === day) {
      filled.push(days[i]);
      i++;
    } else {
      filled.push({ day, requests: 0, inputTokens: 0, outputTokens: 0, cost: null, currency: "" });
    }
  }
  return filled;
}

/**
 * Daily direct usage of the workload. One series (requests per day), so no
 * legend; the table below is the accessible view of the same numbers.
 */
export function UsageCard({
  usage,
  onboardedAt,
  through,
}: {
  usage: ShadowUsageDay[];
  onboardedAt?: string;
  /** The last day the provider data covers (the day of the latest scan). */
  through?: string;
}) {
  const theme = useTheme();
  const [showTable, setShowTable] = useState(false);
  const days = useMemo(() => dailyTotals(usage, through), [usage, through]);
  const models = useMemo(() => [...new Set(usage.map((u) => u.model).filter(Boolean))], [usage]);
  const total = days.reduce((n, d) => n + d.requests, 0);

  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
          <Box>
            <Typography variant="subtitle1">Direct requests per day</Typography>
            <Typography variant="caption" color="text.secondary">
              {formatCount(total)} requests in the stored history
              {models.length > 0 ? ` · ${models.join(", ")}` : ""}
              {onboardedAt ? ` · onboarded ${onboardedAt.slice(0, 10)}` : ""}
            </Typography>
          </Box>
          {days.length > 0 && (
            <Button size="small" variant="text" onClick={() => setShowTable(!showTable)}>
              {showTable ? "Show chart" : "Show table"}
            </Button>
          )}
        </Stack>
        {days.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            The provider reported no usage for this finding in the scanned period.
          </Typography>
        ) : showTable ? (
          <Box sx={{ overflowX: "auto" }}>
            <ListingTable>
              <ListingTable.Head>
                <ListingTable.Row>
                  <ListingTable.Cell>Day</ListingTable.Cell>
                  <ListingTable.Cell align="right">Requests</ListingTable.Cell>
                  <ListingTable.Cell align="right">Input tokens</ListingTable.Cell>
                  <ListingTable.Cell align="right">Output tokens</ListingTable.Cell>
                  <ListingTable.Cell align="right">Cost</ListingTable.Cell>
                </ListingTable.Row>
              </ListingTable.Head>
              <ListingTable.Body>
                {days.map((d) => (
                  <ListingTable.Row key={d.day}>
                    <ListingTable.Cell>{d.day}</ListingTable.Cell>
                    <ListingTable.Cell align="right">{formatCount(d.requests)}</ListingTable.Cell>
                    <ListingTable.Cell align="right">
                      {formatCount(d.inputTokens)}
                    </ListingTable.Cell>
                    <ListingTable.Cell align="right">
                      {formatCount(d.outputTokens)}
                    </ListingTable.Cell>
                    <ListingTable.Cell align="right">
                      {d.cost === null ? "—" : `${d.cost.toFixed(2)} ${d.currency.toUpperCase()}`}
                    </ListingTable.Cell>
                  </ListingTable.Row>
                ))}
              </ListingTable.Body>
            </ListingTable>
          </Box>
        ) : (
          <Box aria-label="Direct requests per day chart">
            <BarChart
              data={days}
              xAxisDataKey="day"
              height={220}
              legend={{ show: false }}
              grid={{ show: true, strokeDasharray: "3 3" }}
              tooltip={{ show: true }}
              xAxis={{ show: true }}
              yAxis={{ show: true }}
              maxBarSize={24}
              bars={[
                {
                  dataKey: "requests",
                  name: "Requests",
                  fill: theme.palette.primary.main,
                  radius: [4, 4, 0, 0],
                  isAnimationActive: false,
                },
              ]}
            />
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

export default UsageCard;
