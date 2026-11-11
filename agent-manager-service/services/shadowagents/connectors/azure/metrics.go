// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package azure

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Metric names (supported-metrics page for Microsoft.CognitiveServices/
// accounts, evidence/azure_openai.md §2.3). Both request metrics and both
// token families are requested; they are combined either-or per day, never
// summed, because whether one call increments both is unverified.
const (
	metricAOAIRequests  = "AzureOpenAIRequests"
	metricModelRequests = "ModelRequests"
	metricPromptTokens  = "ProcessedPromptTokens"
	metricGenTokens     = "GeneratedTokens"
	metricInputTokens   = "InputTokens"
	metricOutputTokens  = "OutputTokens"
	dimDeployment       = "ModelDeploymentName"
	metricsNamespace    = "Microsoft.CognitiveServices/accounts"
)

var metricNames = []string{metricAOAIRequests, metricModelRequests, metricPromptTokens, metricGenTokens, metricInputTokens, metricOutputTokens}

// metricsResponse is the Metrics_List response (2023-10-01), with only the
// fields used.
type metricsResponse struct {
	Value []struct {
		Name struct {
			Value string `json:"value"`
		} `json:"name"`
		ErrorCode  string `json:"errorCode"`
		Timeseries []struct {
			Metadatavalues []struct {
				Name struct {
					Value string `json:"value"`
				} `json:"name"`
				Value string `json:"value"`
			} `json:"metadatavalues"`
			Data []struct {
				TimeStamp string   `json:"timeStamp"`
				Total     *float64 `json:"total"`
			} `json:"data"`
		} `json:"timeseries"`
	} `json:"value"`
}

// dayMetrics is one deployment's metric totals on one day.
type dayMetrics struct {
	aoaiRequests, modelRequests float64
	promptTokens, genTokens     float64
	inputTokens, outputTokens   float64
}

// requests is AzureOpenAIRequests or ModelRequests, whichever is larger:
// either-or, so a call counted by both is never counted twice.
func (d *dayMetrics) requests() int64 {
	return int64(math.Round(math.Max(d.aoaiRequests, d.modelRequests)))
}

func (d *dayMetrics) input() int64 {
	return int64(math.Round(math.Max(d.promptTokens, d.inputTokens)))
}

func (d *dayMetrics) output() int64 {
	return int64(math.Round(math.Max(d.genTokens, d.outputTokens)))
}

// deploymentUsage is one deployment's daily metrics, keyed by UTC day.
type deploymentUsage map[time.Time]*dayMetrics

// usageDay is one day of a deployment's usage.
type usageDay struct {
	day                   time.Time
	requests, input, outp int64
}

// days returns the days with any requests or tokens, oldest first.
func (u deploymentUsage) days() []usageDay {
	out := make([]usageDay, 0, len(u))
	for day, m := range u {
		d := usageDay{day: day, requests: m.requests(), input: m.input(), outp: m.output()}
		if d.requests == 0 && d.input == 0 && d.outp == 0 {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].day.Before(out[j].day) })
	return out
}

// totals returns the request total and the number of days with requests.
func (u deploymentUsage) totals() (int64, int) {
	var total int64
	active := 0
	for _, m := range u {
		if r := m.requests(); r > 0 {
			total += r
			active++
		}
	}
	return total, active
}

// accountUsage is an account's usage per deployment name (lower-cased; the
// dimension value is matched case-insensitively).
type accountUsage map[string]deploymentUsage

// metrics reads an account's per-deployment request and token metrics over
// the window at daily grain. A per-metric errorCode inside the 200 is
// recorded as its own call entry; the other metrics are still used.
func (a *armClient) metrics(ctx context.Context, accountID string, w sa.Window, calls *sa.Calls) (accountUsage, error) {
	u := a.url(accountID+"/providers/Microsoft.Insights/metrics",
		qp{"api-version", apiMetrics},
		qp{"metricnamespace", metricsNamespace},
		qp{"metricnames", strings.Join(metricNames, ",")},
		qp{"aggregation", "Total"},
		qp{"interval", "P1D"},
		qp{"timespan", timespan(w.Start, w.End)},
		qp{"$filter", dimDeployment + " eq '*'"},
		qp{"top", strconv.Itoa(metricsTop)},
		qp{"AutoAdjustTimegrain", "true"},
	)
	var resp metricsResponse
	if err := a.getWith529Retry(ctx, u, &resp); err != nil {
		calls.Record(callMetrics, 0, err)
		return nil, err
	}
	out := accountUsage{}
	series := 0
	for _, m := range resp.Value {
		name := m.Name.Value
		if m.ErrorCode != "" && !strings.EqualFold(m.ErrorCode, "Success") {
			calls.Record(callMetrics+" ("+sa.Truncate(name, 40)+")", 0, &sa.CallError{
				Outcome: models.ShadowCallFailed,
				Message: sa.ScrubText("the metric returned errorCode " + sa.Truncate(m.ErrorCode, 64)),
			})
			continue
		}
		for _, ts := range m.Timeseries {
			dep := ""
			for _, md := range ts.Metadatavalues {
				if strings.EqualFold(md.Name.Value, dimDeployment) {
					dep = strings.ToLower(strings.TrimSpace(md.Value))
				}
			}
			if dep == "" {
				continue
			}
			series++
			for _, d := range ts.Data {
				if d.Total == nil || *d.Total <= 0 {
					continue
				}
				t := parseTime(d.TimeStamp)
				if t == nil {
					continue
				}
				day := sa.DayOf(*t)
				du := out[dep]
				if du == nil {
					du = deploymentUsage{}
					out[dep] = du
				}
				dm := du[day]
				if dm == nil {
					dm = &dayMetrics{}
					du[day] = dm
				}
				addMetric(dm, name, *d.Total)
			}
		}
	}
	calls.Record(callMetrics, series, nil)
	return out, nil
}

func addMetric(dm *dayMetrics, name string, v float64) {
	switch {
	case strings.EqualFold(name, metricAOAIRequests):
		dm.aoaiRequests += v
	case strings.EqualFold(name, metricModelRequests):
		dm.modelRequests += v
	case strings.EqualFold(name, metricPromptTokens):
		dm.promptTokens += v
	case strings.EqualFold(name, metricGenTokens):
		dm.genTokens += v
	case strings.EqualFold(name, metricInputTokens):
		dm.inputTokens += v
	case strings.EqualFold(name, metricOutputTokens):
		dm.outputTokens += v
	}
}

// getWith529Retry GETs u, retrying the metrics backend's HTTP 529 ("the
// metrics backend is currently throttling your requests… implement an
// exponential backoff"), which the SDK pipeline does not retry.
func (a *armClient) getWith529Retry(ctx context.Context, u string, out any) error {
	var err error
	for attempt := 1; attempt <= metricsMaxAttempts; attempt++ {
		err = a.client.GetJSON(ctx, u, out)
		if err == nil || statusOf(err) != 529 || attempt == metricsMaxAttempts {
			return err
		}
		if werr := a.sleep(ctx, time.Duration(1<<(attempt-1))*time.Second); werr != nil {
			return err
		}
	}
	return err
}

func timespan(start, end time.Time) string {
	return start.UTC().Format(time.RFC3339) + "/" + end.UTC().Format(time.RFC3339)
}
