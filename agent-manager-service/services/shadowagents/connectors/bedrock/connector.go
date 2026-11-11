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

// Package bedrock is the Amazon Bedrock / AgentCore connector of Shadow
// Agent Discovery (Method 1). Per region it lists AgentCore runtimes and
// gateways, AWS Agent Registry records and classic Bedrock agents, reads
// AgentCore session metrics from CloudWatch, model calls from CloudTrail
// event history and, with deep inspection, tool use from model invocation
// logs. It uses the vendored aws-sdk-go-v2 clients; see
// evidence/impl_notes_bedrock.md for the wire protocol each one speaks.
package bedrock

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Call names, as recorded in scan results and signal sources.
const (
	callListRuntimes   = "AgentCore ListAgentRuntimes"
	callGetRuntime     = "AgentCore GetAgentRuntime"
	callListGateways   = "AgentCore ListGateways"
	callGetGateway     = "AgentCore GetGateway"
	callListTargets    = "AgentCore ListGatewayTargets"
	callListRegistries = "Agent Registry ListRegistries"
	callListRecords    = "Agent Registry ListRegistryRecords"
	callListAgents     = "Bedrock Agents ListAgents"
	callGetAgent       = "Bedrock Agents GetAgent"
	callListActions    = "Bedrock Agents ListAgentActionGroups"
	callLoggingConfig  = "Bedrock GetModelInvocationLoggingConfiguration"
	callFilterLogs     = "CloudWatch Logs FilterLogEvents"
	callListMetrics    = "CloudWatch ListMetrics"
	callGetMetricData  = "CloudWatch GetMetricData"
	callLookupEvents   = "CloudTrail LookupEvents"
	callConfigure      = "AWS client configuration"
)

// Bounds.
const (
	// maxPages bounds every listing (per region and parent resource).
	maxPages = 50
	// pageSize is the maxResults sent to the list APIs (all accept 100).
	pageSize = 100
	// maxTrailPages bounds CloudTrail LookupEvents per region: 100 pages of
	// 50 events at 2 TPS is under a minute.
	maxTrailPages = 100
	// trailPageSize is LookupEvents' maximum MaxResults.
	trailPageSize = 50
	// trailMaxDays is how far back CloudTrail event history reaches.
	trailMaxDays = 90
	// defaultTrailInterval keeps LookupEvents at 2 TPS per account and
	// region, the documented limit.
	defaultTrailInterval = 500 * time.Millisecond
	// maxLogEvents and maxLogBytes bound the invocation log records read in
	// memory per region (deep inspection only).
	maxLogEvents = 1000
	maxLogBytes  = 16 << 20
	// logPageSize is the FilterLogEvents limit per page.
	logPageSize = 100
	// maxMetricQueries is GetMetricData's maximum queries per request.
	maxMetricQueries = 500
	// metricPeriod is one day, in seconds.
	metricPeriod = 86400
)

// Connector scans Amazon Bedrock and AgentCore in the connection's regions.
type Connector struct {
	http   *http.Client
	logger *slog.Logger
	// trailInterval is the minimum time between LookupEvents requests in a
	// region.
	trailInterval time.Duration
	// retryer, when set, replaces the SDK's standard retryer.
	retryer func() aws.Retryer
}

// New returns the Bedrock connector. httpClient is the redirect-guarded
// client every SDK client uses.
func New(httpClient *http.Client, logger *slog.Logger) sa.Connector {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Connector{http: httpClient, logger: logger, trailInterval: defaultTrailInterval, retryer: nil}
}

// Provider implements sa.Connector.
func (c *Connector) Provider() string { return models.ShadowProviderBedrock }

// Scan implements sa.Connector.
func (c *Connector) Scan(ctx context.Context, conn sa.Connection, w sa.Window) *sa.Result {
	s := newScan(c, conn, w)
	s.run(ctx)
	res := &sa.Result{Findings: s.fs.All(), Keys: nil, Calls: s.calls.Results(), KeysListed: false}
	c.logger.Info("Shadow agent discovery Bedrock scan finished",
		"connectionId", conn.ID.String(), "regions", len(conn.Config.Regions),
		"findings", len(res.Findings), "calls", len(res.Calls))
	return res
}

// scan is the state of one Scan.
type scan struct {
	c     *Connector
	conn  sa.Connection
	w     sa.Window
	calls *sa.Calls
	fs    *sa.Findings
	log   *slog.Logger

	regions []*regionClients

	// runtimeByARN and runtimeByID (region + "|" + id) find a runtime
	// finding from a registry record's provenance.
	runtimeByARN map[string]*sa.Finding
	runtimeByID  map[string]*sa.Finding
	// gatewayByID (region + "|" + gatewayId) finds a gateway finding.
	gatewayByID map[string]*sa.Finding
	// runtimesByRole and agentsByRole map an execution role (account + "|"
	// + role name) to the runtimes and classic agents that run as it.
	runtimesByRole map[string][]*sa.Finding
	agentsByRole   map[string][]*sa.Finding
	// regionRuntimes are the runtime findings of each region.
	regionRuntimes map[string][]*sa.Finding
	// principalRegions are the regions where a principal finding had
	// model traffic.
	principalRegions map[*sa.Finding]map[string]bool
	// logsOff are the regions without a model invocation logging config.
	logsOff map[string]bool
	// pendingSkips are calls not made in a region, recorded as skipped at
	// the end only if no region made them.
	pendingSkips []skip
}

type skip struct{ call, reason string }

func newScan(c *Connector, conn sa.Connection, w sa.Window) *scan {
	return &scan{
		c: c, conn: conn, w: w,
		calls: sa.NewCalls(), fs: sa.NewFindings(), log: c.logger,
		runtimeByARN: map[string]*sa.Finding{}, runtimeByID: map[string]*sa.Finding{},
		gatewayByID: map[string]*sa.Finding{}, runtimesByRole: map[string][]*sa.Finding{},
		agentsByRole: map[string][]*sa.Finding{}, regionRuntimes: map[string][]*sa.Finding{},
		principalRegions: map[*sa.Finding]map[string]bool{}, logsOff: map[string]bool{},
	}
}

func (s *scan) skipLater(call, reason string) {
	s.pendingSkips = append(s.pendingSkips, skip{call: call, reason: reason})
}

func (s *scan) run(ctx context.Context) {
	regions := cleanRegions(s.conn.Config.Regions)
	if len(regions) == 0 {
		s.calls.Record(callConfigure, 0, &sa.CallError{Outcome: models.ShadowCallFailed, Message: "no regions are configured"})
		return
	}
	for _, region := range regions {
		rc, err := newRegionClients(s.conn, s.c.http, region, s.c.retryer)
		if err != nil {
			s.calls.Record(callConfigure, 0, &sa.CallError{Outcome: models.ShadowCallFailed, Message: sa.ScrubText(region + ": " + err.Error())})
			continue
		}
		s.regions = append(s.regions, rc)
	}
	if len(s.regions) == 0 {
		return
	}

	on := func(opt string) bool { return sa.ServiceEnabled(s.conn.Config, opt) }
	s.skipUnselected()

	// Inventory first, in every region, so the registry and the traffic
	// phase can attribute evidence to the workloads they belong to.
	for i, rc := range s.regions {
		if ctx.Err() != nil {
			break
		}
		if on(sa.OptBedrockAgentCore) {
			err := s.scanRuntimes(ctx, rc)
			if i == 0 && isAuthFailure(err) {
				// Authentication failed on the very first call: every other
				// call would fail the same way.
				s.log.Warn("Shadow agent discovery Bedrock authentication failed; stopping the scan",
					"connectionId", s.conn.ID.String(), "region", rc.region)
				return
			}
			s.scanGateways(ctx, rc)
		}
		if on(sa.OptBedrockClassicAgents) {
			s.scanClassicAgents(ctx, rc)
		}
	}
	if on(sa.OptBedrockRegistry) {
		for _, rc := range s.regions {
			if ctx.Err() != nil {
				break
			}
			s.scanRegistry(ctx, rc)
		}
	}
	for _, rc := range s.regions {
		if ctx.Err() != nil {
			break
		}
		if on(sa.OptBedrockMetrics) {
			s.scanRuntimeMetrics(ctx, rc)
		}
		if on(sa.OptBedrockCloudTrail) {
			s.scanCloudTrail(ctx, rc)
		}
		if on(sa.OptBedrockInvocationLogs) {
			s.scanInvocationLogs(ctx, rc)
		}
	}
	s.finish()
}

// serviceCalls are the calls of each optional service.
var serviceCalls = []struct {
	option string
	calls  []string
}{
	{sa.OptBedrockAgentCore, []string{callListRuntimes, callGetRuntime, callListGateways, callGetGateway, callListTargets}},
	{sa.OptBedrockClassicAgents, []string{callListAgents, callGetAgent, callListActions}},
	{sa.OptBedrockRegistry, []string{callListRegistries, callListRecords}},
	{sa.OptBedrockMetrics, []string{callListMetrics, callGetMetricData}},
	{sa.OptBedrockCloudTrail, []string{callLookupEvents}},
	{sa.OptBedrockInvocationLogs, []string{callLoggingConfig, callFilterLogs}},
}

// skipUnselected records the calls of the services the user unticked.
func (s *scan) skipUnselected() {
	for _, sc := range serviceCalls {
		if sa.ServiceEnabled(s.conn.Config, sc.option) {
			continue
		}
		for _, call := range sc.calls {
			s.calls.Skip(call, sa.ReasonServiceOff)
		}
	}
}

// finish applies the region-level signals and records the skipped calls.
func (s *scan) finish() {
	for region := range s.logsOff {
		sig := sa.Signal{Code: sa.SigBedrockInvocationLogsOff, Source: callLoggingConfig, Observed: map[string]any{"loggingConfigured": false}}
		for _, f := range s.regionRuntimes[region] {
			f.AddSignal(sig)
		}
		for p, regions := range s.principalRegions {
			if regions[region] {
				p.AddSignal(sig)
			}
		}
	}
	for _, f := range s.fs.All() {
		if ms, ok := f.Attributes["models"].([]string); ok {
			sort.Strings(ms)
		}
	}
	for _, sk := range s.pendingSkips {
		s.calls.Skip(sk.call, sk.reason)
	}
}

func cleanRegions(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// paginate drives an SDK paginator: next fetches one page and returns its
// item count. It stops at the first error or after limit pages.
func paginate(ctx context.Context, limit int, hasMore func() bool, next func(context.Context) (int, error)) (int, error) {
	items, pages := 0, 0
	for hasMore() {
		if pages == limit {
			return items, truncatedError(limit)
		}
		if err := ctx.Err(); err != nil {
			return items, awsError(err)
		}
		n, err := next(ctx)
		pages++
		if err != nil {
			return items, awsError(err)
		}
		items += n
	}
	return items, nil
}

// addModel adds a model to a finding's "models" attribute.
func addModel(f *sa.Finding, model string) {
	if model == "" {
		return
	}
	ms, _ := f.Attributes["models"].([]string)
	for _, m := range ms {
		if m == model {
			return
		}
	}
	f.Attributes["models"] = append(ms, model)
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func timePtr(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
