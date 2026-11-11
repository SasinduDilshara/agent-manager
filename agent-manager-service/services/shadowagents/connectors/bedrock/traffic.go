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

package bedrock

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

const (
	agentCoreNamespace = "AWS/Bedrock-AgentCore"
	sessionCountMetric = "SessionCount"
	bedrockEventSource = "bedrock.amazonaws.com"
	relUsedByAgent     = "used_by_agent"
)

// modelEvents are the Bedrock Runtime model calls CloudTrail logs as
// management events (evidence §2.11).
var modelEvents = map[string]bool{
	"InvokeModel":                   true,
	"InvokeModelWithResponseStream": true,
	"Converse":                      true,
	"ConverseStream":                true,
}

// ---- principals -----------------------------------------------------------

// normalizePrincipal turns an identity ARN into the principal it stands for.
// An STS assumed-role session ARN becomes its role's IAM ARN (the session
// ARN does not carry the role path, so role ARNs are normalised without
// path), and key is "account|roleName" for matching an execution role
// (evidence §3, "Note on matching identity.arn to a runtime roleArn").
func normalizePrincipal(arn string) (norm, key, kind string) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return arn, "", ""
	}
	partition, service, account, resource := parts[1], parts[2], parts[4], parts[5]
	switch {
	case service == "sts" && strings.HasPrefix(resource, "assumed-role/"):
		name := strings.SplitN(strings.TrimPrefix(resource, "assumed-role/"), "/", 2)[0]
		if name == "" {
			return arn, "", ""
		}
		return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, account, name), account + "|" + name, "AssumedRole"
	case service == "iam" && strings.HasPrefix(resource, "role/"):
		segs := strings.Split(resource, "/")
		name := segs[len(segs)-1]
		return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, account, name), account + "|" + name, "AssumedRole"
	case service == "iam" && strings.HasPrefix(resource, "user/"):
		return arn, "", "IAMUser"
	case service == "iam" && resource == "root":
		return arn, "", "Root"
	case service == "sts" && strings.HasPrefix(resource, "federated-user/"):
		return arn, "", "FederatedUser"
	}
	return arn, "", ""
}

// roleKey returns the "account|roleName" key of a role or session ARN.
func roleKey(arn string) string {
	_, key, _ := normalizePrincipal(arn)
	return key
}

// principalName is the resource part of a principal ARN ("role/Name").
func principalName(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[5] != "" {
		return parts[5]
	}
	return arn
}

// trafficTarget returns the finding model traffic from identityARN belongs
// to: the runtime that runs as that role when exactly one does (dedup rule:
// traffic of a runtime's execution role is the runtime's), otherwise the
// principal's own finding, linked to the runtimes and classic agents that
// share the role.
func (s *scan) trafficTarget(region, identityARN, identityType string) *sa.Finding {
	norm, key, kind := normalizePrincipal(identityARN)
	if key != "" {
		if rts := s.runtimesByRole[key]; len(rts) == 1 {
			return rts[0]
		}
	}
	f := s.fs.Get(models.ShadowKindPrincipal, norm)
	if f.DisplayName == "" {
		f.DisplayName = sa.SanitizeName(principalName(norm))
		parts := strings.SplitN(norm, ":", 6)
		if len(parts) == 6 {
			f.Scope = parts[4]
			f.Attributes["accountId"] = parts[4]
		}
		f.Attributes["resourceId"] = norm
	}
	if identityType == "" {
		identityType = kind
	}
	if identityType != "" {
		f.Attributes["principalType"] = identityType
	}
	if key != "" {
		for _, rt := range s.runtimesByRole[key] {
			addRelation(f, rt, "the AgentCore runtimes share this execution role")
		}
		for _, ag := range s.agentsByRole[key] {
			addRelation(f, ag, "a classic Bedrock agent runs as this role")
		}
	}
	if s.principalRegions[f] == nil {
		s.principalRegions[f] = map[string]bool{}
	}
	s.principalRegions[f][region] = true
	return f
}

func addRelation(f, to *sa.Finding, reason string) {
	for _, r := range f.Related {
		if r.ExternalID == to.ExternalID && r.Kind == to.Kind {
			return
		}
	}
	f.Related = append(f.Related, sa.Relation{ExternalID: to.ExternalID, Kind: to.Kind, Relation: relUsedByAgent, Reason: reason})
}

// modelName reduces a model ARN (foundation model, inference profile) to
// its ID; a plain model ID is kept.
func modelName(id string) string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, "arn:") {
		parts := strings.SplitN(id, ":", 6)
		if len(parts) == 6 {
			res := parts[5]
			if i := strings.IndexByte(res, '/'); i >= 0 {
				res = res[i+1:]
			}
			return sa.Truncate(res, 200)
		}
	}
	return sa.Truncate(id, 200)
}

// ---- CloudTrail -------------------------------------------------------------

// trailEvent is the part of a CloudTrailEvent document the connector reads.
// requestParameters of InvokeModel/Converse hold the model ID only (the
// body is not logged); nothing else of the event is decoded.
type trailEvent struct {
	EventType    string `json:"eventType"`
	EventName    string `json:"eventName"`
	EventSource  string `json:"eventSource"`
	EventTime    string `json:"eventTime"`
	UserIdentity struct {
		Type string `json:"type"`
		ARN  string `json:"arn"`
	} `json:"userIdentity"`
	RequestParameters json.RawMessage `json:"requestParameters"`
	Resources         []struct {
		Type string `json:"type"`
		ARN  string `json:"ARN"`
	} `json:"resources"`
}

type usageKey struct {
	f     *sa.Finding
	day   time.Time
	model string
}

// scanCloudTrail reads the region's CloudTrail event history for Bedrock
// model calls (evidence §2.11): one lookup attribute (EventSource), a window
// capped at 90 days, 50 events per page, at most 2 requests per second.
func (s *scan) scanCloudTrail(ctx context.Context, rc *regionClients) {
	end := s.w.End.UTC()
	start := s.w.Start.UTC()
	if earliest := end.Add(-trailMaxDays * 24 * time.Hour); start.Before(earliest) {
		start = earliest
	}
	p := cloudtrail.NewLookupEventsPaginator(rc.cloudTrail, &cloudtrail.LookupEventsInput{
		LookupAttributes: []cttypes.LookupAttribute{{AttributeKey: cttypes.LookupAttributeKeyEventSource, AttributeValue: aws.String(bedrockEventSource)}},
		StartTime:        aws.Time(start),
		EndTime:          aws.Time(end),
		MaxResults:       aws.Int32(trailPageSize),
		EventCategory:    "",
		NextToken:        nil,
	})
	usage := map[usageKey]int64{}
	seen := map[string]bool{}
	var last time.Time
	parsed, bad := 0, 0
	n, err := paginate(ctx, maxTrailPages, p.HasMorePages, func(ctx context.Context) (int, error) {
		if err := s.c.pace(ctx, &last); err != nil {
			return 0, err
		}
		out, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, ev := range out.Events {
			if id := str(ev.EventId); id != "" {
				if seen[id] {
					continue
				}
				seen[id] = true
			}
			switch s.trailModelCall(rc.region, ev, start, end, usage) {
			case trailParsed:
				parsed++
			case trailBad:
				bad++
			}
		}
		return len(out.Events), nil
	})
	if err == nil && bad > 0 && parsed == 0 {
		err = sa.Unsupported("CloudTrailEvent did not match the documented shape (%d events)", bad)
	}
	s.calls.Record(callLookupEvents, n, err)
	totals := map[*sa.Finding]int64{}
	for k, v := range usage {
		k.f.AddUsage(sa.UsageDay{Day: k.day, Model: k.model, Requests: v})
		totals[k.f] += v
	}
	for f, v := range totals {
		f.AddSignal(sa.Signal{Code: sa.SigBedrockPlainModelUsage, Source: callLookupEvents, Observed: map[string]any{"requests": v}})
	}
	s.log.Debug("Shadow agent discovery Bedrock CloudTrail lookup", "region", rc.region, "events", n, "modelCalls", parsed, "unparsed", bad)
}

type trailOutcome int

const (
	trailIgnored trailOutcome = iota
	trailParsed
	trailBad
)

// trailModelCall counts one event when it is a model call made by a
// principal (eventType AwsApiCall: streaming calls add an AwsServiceEvent
// that must not be counted twice).
func (s *scan) trailModelCall(region string, ev cttypes.Event, start, end time.Time, usage map[usageKey]int64) trailOutcome {
	if name := str(ev.EventName); name != "" && !modelEvents[name] {
		return trailIgnored
	}
	if src := str(ev.EventSource); src != "" && src != bedrockEventSource {
		return trailIgnored
	}
	var te trailEvent
	if err := json.Unmarshal([]byte(str(ev.CloudTrailEvent)), &te); err != nil {
		return trailBad
	}
	if te.EventType != "AwsApiCall" || !modelEvents[te.EventName] || (te.EventSource != "" && te.EventSource != bedrockEventSource) {
		return trailIgnored
	}
	if te.UserIdentity.ARN == "" {
		return trailIgnored
	}
	t := time.Time{}
	if ev.EventTime != nil {
		t = ev.EventTime.UTC()
	} else if pt, err := time.Parse(time.RFC3339, te.EventTime); err == nil {
		t = pt.UTC()
	}
	if t.IsZero() || t.Before(start) || t.After(end) {
		return trailIgnored
	}
	model := trailModel(te)
	f := s.trafficTarget(region, te.UserIdentity.ARN, te.UserIdentity.Type)
	if f.Kind == models.ShadowKindPrincipal && f.OwnerHint.Username == "" {
		f.OwnerHint = sa.MinimiseOwnerHint(models.ShadowOwnerHint{
			Username: f.ExternalID, Type: te.UserIdentity.Type, Source: callLookupEvents,
		})
	}
	f.ObserveUse(t)
	addModel(f, model)
	usage[usageKey{f: f, day: sa.DayOf(t), model: model}]++
	return trailParsed
}

// trailModel is requestParameters.modelId, or the Bedrock model resource
// (requestParameters of Converse events is not documented; evidence §2.11).
func trailModel(te trailEvent) string {
	if len(te.RequestParameters) > 0 && te.RequestParameters[0] == '{' {
		var rp struct {
			ModelID string `json:"modelId"`
		}
		if json.Unmarshal(te.RequestParameters, &rp) == nil && rp.ModelID != "" {
			return modelName(rp.ModelID)
		}
	}
	for _, r := range te.Resources {
		if strings.HasPrefix(r.Type, "AWS::Bedrock::") && r.ARN != "" {
			return modelName(r.ARN)
		}
	}
	return ""
}

// pace waits until interval has passed since *last, then records now.
func (c *Connector) pace(ctx context.Context, last *time.Time) error {
	if !last.IsZero() && c.trailInterval > 0 {
		if wait := c.trailInterval - time.Since(*last); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	*last = time.Now()
	return nil
}

// ---- CloudWatch -------------------------------------------------------------

type metricMatch struct {
	f       *sa.Finding
	dims    int
	metrics []cwtypes.Metric
}

// scanRuntimeMetrics reads AgentCore SessionCount per runtime (evidence
// §2.10). The metric's dimensions are not documented, so ListMetrics finds
// the dimension sets that name each runtime first; GetMetricData then sums
// one-day periods. Session counts are kept as observations, not as usage.
func (s *scan) scanRuntimeMetrics(ctx context.Context, rc *regionClients) {
	rts := s.regionRuntimes[rc.region]
	if len(rts) == 0 {
		s.skipLater(callListMetrics, "no AgentCore runtimes to look up")
		s.skipLater(callGetMetricData, "no AgentCore runtimes to look up")
		return
	}
	lp := cloudwatch.NewListMetricsPaginator(rc.cloudWatch, &cloudwatch.ListMetricsInput{
		Namespace: aws.String(agentCoreNamespace), MetricName: aws.String(sessionCountMetric),
		Dimensions: nil, IncludeLinkedAccounts: nil, NextToken: nil, OwningAccount: nil, RecentlyActive: "",
	})
	var metrics []cwtypes.Metric
	n, err := paginate(ctx, maxPages, lp.HasMorePages, func(ctx context.Context) (int, error) {
		out, err := lp.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		metrics = append(metrics, out.Metrics...)
		return len(out.Metrics), nil
	})
	s.calls.Record(callListMetrics, n, err)

	matches := map[*sa.Finding]*metricMatch{}
	var order []*sa.Finding
	for _, m := range metrics {
		f := s.metricRuntime(rc.region, m)
		if f == nil {
			continue
		}
		mm := matches[f]
		switch {
		case mm == nil:
			matches[f] = &metricMatch{f: f, dims: len(m.Dimensions), metrics: []cwtypes.Metric{m}}
			order = append(order, f)
		case len(m.Dimensions) < mm.dims:
			// The least specific dimension set is the runtime total; the
			// more specific ones (per endpoint) are parts of it.
			mm.dims, mm.metrics = len(m.Dimensions), []cwtypes.Metric{m}
		case len(m.Dimensions) == mm.dims:
			mm.metrics = append(mm.metrics, m)
		}
	}
	if len(order) == 0 {
		if err == nil {
			s.skipLater(callGetMetricData, "no SessionCount metric names a runtime")
		}
		return
	}

	type query struct {
		id string
		f  *sa.Finding
		q  cwtypes.MetricDataQuery
	}
	var queries []query
	for _, f := range order {
		for _, m := range matches[f].metrics {
			id := fmt.Sprintf("m%d", len(queries))
			queries = append(queries, query{id: id, f: f, q: cwtypes.MetricDataQuery{
				Id: aws.String(id),
				MetricStat: &cwtypes.MetricStat{
					Metric: &cwtypes.Metric{Namespace: m.Namespace, MetricName: m.MetricName, Dimensions: m.Dimensions},
					Period: aws.Int32(metricPeriod), Stat: aws.String("Sum"), Unit: "",
				},
				ReturnData: aws.Bool(true), AccountId: nil, Expression: nil, Label: nil, Period: nil,
			}})
		}
	}
	byID := map[string]*sa.Finding{}
	for _, q := range queries {
		byID[q.id] = q.f
	}
	sessions := map[*sa.Finding]float64{}
	days := map[*sa.Finding]map[time.Time]bool{}
	total := 0
	var gerr error
	for i := 0; i < len(queries) && gerr == nil; i += maxMetricQueries {
		batch := queries[i:min(i+maxMetricQueries, len(queries))]
		in := &cloudwatch.GetMetricDataInput{
			StartTime: aws.Time(s.w.Start.UTC()), EndTime: aws.Time(s.w.End.UTC()),
			LabelOptions: nil, MaxDatapoints: nil, NextToken: nil, ScanBy: "",
		}
		for _, q := range batch {
			in.MetricDataQueries = append(in.MetricDataQueries, q.q)
		}
		gp := cloudwatch.NewGetMetricDataPaginator(rc.cloudWatch, in)
		var got int
		got, gerr = paginate(ctx, maxPages, gp.HasMorePages, func(ctx context.Context) (int, error) {
			out, err := gp.NextPage(ctx)
			if err != nil {
				return 0, err
			}
			for _, r := range out.MetricDataResults {
				f := byID[str(r.Id)]
				if f == nil {
					continue
				}
				for j, v := range r.Values {
					if v <= 0 || math.IsNaN(v) {
						continue
					}
					sessions[f] += v
					if j < len(r.Timestamps) {
						if days[f] == nil {
							days[f] = map[time.Time]bool{}
						}
						days[f][sa.DayOf(r.Timestamps[j])] = true
					}
				}
			}
			return len(out.MetricDataResults), nil
		})
		total += got
	}
	s.calls.Record(callGetMetricData, total, gerr)
	if gerr != nil && total == 0 {
		return
	}
	for _, f := range order {
		count := int64(math.Round(sessions[f]))
		f.Attributes["sessionCount"] = count
		if count <= 0 {
			continue
		}
		var lastDay time.Time
		for d := range days[f] {
			f.ObserveUse(d)
			if d.After(lastDay) {
				lastDay = d
			}
		}
		if !lastDay.IsZero() {
			f.Attributes["lastSessionAt"] = lastDay.Format("2006-01-02")
		}
		f.AddSignal(sa.Signal{Code: sa.SigBedrockRuntimeInUse, Source: callGetMetricData, Observed: map[string]any{
			"sessionCount": count, "activeDays": int64(len(days[f])),
		}})
	}
}

// metricRuntime returns the runtime a SessionCount metric names through
// any of its dimensions: the runtime ARN (Resource), an endpoint ARN under
// it, the runtime ID, or "AgentName::EndpointName" (Name).
func (s *scan) metricRuntime(region string, m cwtypes.Metric) *sa.Finding {
	for _, d := range m.Dimensions {
		v := str(d.Value)
		if v == "" {
			continue
		}
		if f := s.runtimeByARN[v]; f != nil {
			return f
		}
		if strings.Contains(v, ":runtime/") {
			if id := arnResourceID(v, "runtime/"); id != "" {
				if f := s.runtimeByID[arnRegion(v, region)+"|"+id]; f != nil {
					return f
				}
			}
		}
		if f := s.runtimeByID[region+"|"+v]; f != nil {
			return f
		}
		if str(d.Name) == "Name" {
			if name, _, ok := strings.Cut(v, "::"); ok {
				for _, f := range s.regionRuntimes[region] {
					if f.DisplayName == name {
						return f
					}
				}
			}
		}
	}
	return nil
}
