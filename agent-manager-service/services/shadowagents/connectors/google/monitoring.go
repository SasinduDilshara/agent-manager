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

package google

import (
	"context"
	"encoding/json"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// listTimeSeriesResponse is the v3 ListTimeSeriesResponse.
type listTimeSeriesResponse struct {
	TimeSeries    []timeSeries `json:"timeSeries"`
	NextPageToken string       `json:"nextPageToken"`
}

type timeSeries struct {
	Metric struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"metric"`
	Resource struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	Points []struct {
		Interval struct {
			StartTime string `json:"startTime"`
			EndTime   string `json:"endTime"`
		} `json:"interval"`
		Value typedValue `json:"value"`
	} `json:"points"`
}

// typedValue is a TypedValue. int64Value is a JSON string ("25") per the
// Discovery document; a bare number is accepted too.
type typedValue struct {
	Int64Value  json.RawMessage `json:"int64Value"`
	DoubleValue *float64        `json:"doubleValue"`
}

func (v typedValue) count() (int64, bool) {
	if len(v.Int64Value) > 0 {
		raw := strings.Trim(string(v.Int64Value), `"`)
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return n, true
		}
		return 0, false
	}
	if v.DoubleValue != nil && !math.IsNaN(*v.DoubleValue) && !math.IsInf(*v.DoubleValue, 0) {
		return int64(math.Round(*v.DoubleValue)), true
	}
	return 0, false
}

// monitoringInterval is the scan window capped to Cloud Monitoring's 6
// week retention of aiplatform metrics.
func monitoringInterval(w sa.Window) (time.Time, time.Time) {
	start, end := w.Start.UTC(), w.End.UTC()
	if end.Sub(start) > monitoringRetention {
		start = end.Add(-monitoringRetention)
	}
	return start, end
}

// pointDay is the UTC day an aligned point counts for: the day holding the
// middle of its alignment period (points are aligned to the interval end,
// so a 24-hour period can straddle midnight).
func pointDay(startTime, endTime string) (time.Time, bool) {
	end := parseTime(endTime)
	if end == nil {
		return time.Time{}, false
	}
	if start := parseTime(startTime); start != nil && start.Before(*end) {
		return sa.DayOf(start.Add(end.Sub(*start) / 2)), true
	}
	return sa.DayOf(*end), true
}

// requestCounts reads reasoning_engine/request_count for a project, sums it
// per engine and day across response codes, and marks engines in use.
func (s *scanner) requestCounts(ctx context.Context, project string) {
	if !s.hasEngines(project) {
		s.deferSkip(callTimeSeries, "no Agent Runtime engine was found to match metrics to")
		return
	}
	if !s.proceed(ctx, callTimeSeries) {
		return
	}
	base, err := baseURL(s.conn, sa.EPGoogleMonitoring)
	if err != nil {
		s.record(callTimeSeries, 0, &sa.CallError{Outcome: models.ShadowCallFailed, Message: err.Error()})
		return
	}
	u := base + "/v3/projects/" + url.PathEscape(project) + "/timeSeries"
	start, end := monitoringInterval(s.w)
	daily := map[*engine]map[time.Time]int64{}
	var order []*engine
	seen := map[string]bool{}
	unmatched := 0
	s.paginate(ctx, callTimeSeries, maxSeriesPages, func(token string) (string, int, error) {
		q := url.Values{
			"filter":                       {`metric.type="` + requestCountMetric + `"`},
			"interval.startTime":           {start.Format(time.RFC3339)},
			"interval.endTime":             {end.Format(time.RFC3339)},
			"aggregation.alignmentPeriod":  {alignmentPeriod},
			"aggregation.perSeriesAligner": {"ALIGN_SUM"},
			"view":                         {"FULL"},
		}
		if token != "" {
			q.Set("pageToken", token)
		}
		var resp listTimeSeriesResponse
		if err := s.api.GetJSON(ctx, u, q, &resp); err != nil {
			return "", 0, err
		}
		for i := range resp.TimeSeries {
			ts := &resp.TimeSeries[i]
			e := s.seriesEngine(project, ts)
			if e == nil {
				unmatched++
				continue
			}
			key := e.finding.ExternalID + "\x00" + labelKey(ts.Metric.Labels)
			for _, p := range ts.Points {
				n, ok := p.Value.count()
				if !ok {
					continue
				}
				day, ok := pointDay(p.Interval.StartTime, p.Interval.EndTime)
				if !ok {
					continue
				}
				// A point seen twice (a metrics scope covering another
				// scanned project, or a repeated page) is counted once.
				pk := key + "\x00" + p.Interval.StartTime + "\x00" + p.Interval.EndTime
				if seen[pk] {
					continue
				}
				seen[pk] = true
				if daily[e] == nil {
					daily[e] = map[time.Time]int64{}
					order = append(order, e)
				}
				daily[e][day] += n
			}
		}
		return resp.NextPageToken, len(resp.TimeSeries), nil
	})
	for _, e := range order {
		s.applyUsage(e, daily[e])
	}
	if unmatched > 0 {
		s.c.logger.Debug("Shadow agent discovery Google metrics for engines not in the scan", "series", unmatched)
	}
}

// seriesEngine finds the engine a series belongs to from its resource
// labels (reasoning_engine_id, location, resource_container or project_id).
func (s *scanner) seriesEngine(project string, ts *timeSeries) *engine {
	l := ts.Resource.Labels
	id := l["reasoning_engine_id"]
	if id == "" {
		return nil
	}
	proj := l["resource_container"]
	if proj == "" {
		proj = l["project_id"]
	}
	if proj == "" {
		proj = project
	}
	return s.findEngine(engineRef{project: proj, location: strings.ToLower(l["location"]), id: id})
}

func (s *scanner) applyUsage(e *engine, days map[time.Time]int64) {
	keys := make([]time.Time, 0, len(days))
	for d := range days {
		keys = append(keys, d)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
	var total int64
	activeDays := 0
	for _, d := range keys {
		n := days[d]
		if n <= 0 {
			continue
		}
		total += n
		activeDays++
		e.finding.AddUsage(sa.UsageDay{Day: d, Requests: n})
		e.finding.ObserveUse(d)
	}
	if total > 0 {
		e.finding.AddSignal(sa.Signal{Code: sa.SigGoogleEngineInUse, Source: callTimeSeries, Observed: map[string]any{
			"requests": total, "activeDays": activeDays,
		}})
	}
}

func labelKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
		b.WriteByte(';')
	}
	return b.String()
}
