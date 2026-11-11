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

package openai

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// usageQuery is the window and grouping of a daily usage or costs read.
func (s *scan) usageQuery(groupBy ...string) url.Values {
	q := url.Values{
		"start_time":   []string{strconv.FormatInt(s.w.Start.Unix(), 10)},
		"end_time":     []string{strconv.FormatInt(s.w.End.Unix(), 10)},
		"bucket_width": []string{"1d"},
	}
	if len(groupBy) > 0 {
		q["group_by[]"] = groupBy
	}
	return q
}

// readCompletionsUsage reads usage/completions grouped by project, key,
// model and api_source. Each row goes to exactly one finding: Agents API
// rows to the project's agent when the project has exactly one, every
// other row to its key, so usage is never counted twice.
func (s *scan) readCompletionsUsage(ctx context.Context) {
	q := s.usageQuery("project_id", "api_key_id", "model", "api_source")
	rows, truncated, err := readBuckets(ctx, s.admin, s.base+"/organization/usage/completions", q, usageDailyLimit,
		func(day time.Time, r completionsResult) { s.addCompletions(day, r) })
	s.calls.Record(callUsage, rows, err)
	if truncated {
		s.pageLimit(callUsage, maxUsagePages)
	}
}

func (s *scan) addCompletions(day time.Time, r completionsResult) {
	if r.NumModelRequests <= 0 && r.InputTokens == 0 && r.OutputTokens == 0 {
		return
	}
	if r.APIKeyID == "" {
		// Usage no key is named for cannot be attributed to a workload.
		s.skippedRows[callUsage]++
		return
	}
	pid := s.projectOf(r.ProjectID, r.APIKeyID)
	if r.NumModelRequests > 0 {
		if s.keysWithUsage[pid] == nil {
			s.keysWithUsage[pid] = map[string]bool{}
		}
		s.keysWithUsage[pid][r.APIKeyID] = true
	}
	var target *sa.Finding
	agentsAPI := r.APISource == apiSourceAgents
	if agentsAPI {
		if ag, ok := s.soleAgent(pid); ok {
			target = s.toAgent(ag, r.APIKeyID)
		}
	}
	if target == nil {
		target = s.keyFinding(r.APIKeyID, pid)
	}
	target.AddUsage(sa.UsageDay{
		Day: day, KeyID: r.APIKeyID, Model: r.Model,
		Requests: r.NumModelRequests, InputTokens: r.InputTokens, OutputTokens: r.OutputTokens,
	})
	addAttrValue(target, "models", r.Model)
	addAttrValue(target, "apiSources", r.APISource)
	if r.NumModelRequests <= 0 {
		return
	}
	target.ObserveUse(day)
	counts := map[string]int64{"numModelRequests": r.NumModelRequests}
	// Plain usage is a key's signal ("num_model_requests > 0 for the
	// key"); rows routed to an agent carry only the Agents API signal.
	if target.Kind == models.ShadowKindAPIKey {
		s.tally(target, sa.SigOpenAIPlainUsage, callUsage, day, counts)
	}
	if agentsAPI {
		s.tally(target, sa.SigOpenAIAgentsAPIUsage, callUsage, day, counts)
	}
}

// readCosts reads daily costs grouped by project, key and api_source. Cost
// is added per key and day (model left empty: costs have no model group),
// to the same finding the key's usage of that api_source went to.
func (s *scan) readCosts(ctx context.Context) {
	q := s.usageQuery("project_id", "api_key_id", "api_source")
	rows, truncated, err := readBuckets(ctx, s.admin, s.base+"/organization/costs", q, costsDailyLimit,
		func(day time.Time, r costsResult) { s.addCost(day, r) })
	s.calls.Record(callCosts, rows, err)
	if truncated {
		s.pageLimit(callCosts, maxUsagePages)
	}
}

func (s *scan) addCost(day time.Time, r costsResult) {
	if r.Amount == nil || r.Amount.Value == 0 {
		return
	}
	if r.APIKeyID == "" {
		s.skippedRows[callCosts]++
		return
	}
	pid := s.projectOf(r.ProjectID, r.APIKeyID)
	var target *sa.Finding
	agentsAPI := r.APISource == apiSourceAgents && r.Amount.Value > 0
	if agentsAPI {
		if ag, ok := s.soleAgent(pid); ok {
			target = s.toAgent(ag, r.APIKeyID)
		}
	}
	if target == nil {
		target = s.keyFinding(r.APIKeyID, pid)
	}
	amount := r.Amount.Value
	target.AddUsage(sa.UsageDay{Day: day, KeyID: r.APIKeyID, CostAmount: &amount, Currency: r.Amount.Currency})
	addAttrValue(target, "apiSources", r.APISource)
	if agentsAPI {
		s.tally(target, sa.SigOpenAIAgentsAPIUsage, callCosts, day, map[string]int64{})
	}
}

// readWebSearch reads web search calls grouped by key, project and
// api_source. Agents API rows follow the same routing as completions.
func (s *scan) readWebSearch(ctx context.Context) {
	q := s.usageQuery("api_key_id", "project_id", "api_source")
	rows, truncated, err := readBuckets(ctx, s.admin, s.base+"/organization/usage/web_search_calls", q, usageDailyLimit,
		func(day time.Time, r searchResult) { s.addSearch(day, r, callWebSearch, true) })
	s.calls.Record(callWebSearch, rows, err)
	if truncated {
		s.pageLimit(callWebSearch, maxUsagePages)
	}
}

// readFileSearch reads file search calls grouped by key and project (the
// endpoint cannot group by api_source or model).
func (s *scan) readFileSearch(ctx context.Context) {
	q := s.usageQuery("api_key_id", "project_id")
	rows, truncated, err := readBuckets(ctx, s.admin, s.base+"/organization/usage/file_search_calls", q, usageDailyLimit,
		func(day time.Time, r searchResult) { s.addSearch(day, r, callFileSearch, false) })
	s.calls.Record(callFileSearch, rows, err)
	if truncated {
		s.pageLimit(callFileSearch, maxUsagePages)
	}
}

func (s *scan) addSearch(day time.Time, r searchResult, source string, bySource bool) {
	if r.NumRequests <= 0 {
		return
	}
	if r.APIKeyID == "" {
		s.skippedRows[source]++
		return
	}
	pid := s.projectOf(r.ProjectID, r.APIKeyID)
	var target *sa.Finding
	if bySource && r.APISource == apiSourceAgents {
		if ag, ok := s.soleAgent(pid); ok {
			target = s.toAgent(ag, r.APIKeyID)
		}
	}
	if target == nil {
		target = s.keyFinding(r.APIKeyID, pid)
	}
	target.ObserveUse(day)
	s.tally(target, sa.SigOpenAIHostedSearch, source, day, map[string]int64{"numRequests": r.NumRequests})
}

// readCodeInterpreter reads code interpreter sessions, which can only be
// grouped by project. A project's sessions go to its key when exactly one
// key of the project had usage in the window; otherwise the keys get the
// project-level info signal.
func (s *scan) readCodeInterpreter(ctx context.Context) {
	sessions := map[string]int64{}
	q := s.usageQuery("project_id")
	rows, truncated, err := readBuckets(ctx, s.admin, s.base+"/organization/usage/code_interpreter_sessions", q, usageDailyLimit,
		func(_ time.Time, r codeInterpreterResult) {
			if r.ProjectID != "" && r.NumSessions > 0 {
				sessions[r.ProjectID] += r.NumSessions
			}
		})
	s.calls.Record(callCodeInterpreter, rows, err)
	if truncated {
		s.pageLimit(callCodeInterpreter, maxUsagePages)
	}
	for _, pid := range sortedKeys(sessions) {
		n := sessions[pid]
		withUsage := sortedKeys(s.keysWithUsage[pid])
		if len(withUsage) == 1 {
			s.keyFinding(withUsage[0], pid).AddSignal(sa.Signal{
				Code: sa.SigOpenAICodeInterpreter, Source: callCodeInterpreter,
				Observed: map[string]any{"numSessions": n, "keysWithUsage": int64(1)},
			})
			continue
		}
		targets := withUsage
		if len(targets) == 0 {
			targets = s.listedKeysOf(pid)
		}
		if len(targets) == 0 {
			s.unattributed[callCodeInterpreter] = append(s.unattributed[callCodeInterpreter], pid+": no keys")
			continue
		}
		for _, id := range targets {
			s.keyFinding(id, pid).AddSignal(sa.Signal{
				Code: sa.SigOpenAICodeInterpreterPrj, Source: callCodeInterpreter,
				Observed: map[string]any{"numSessions": n, "keysWithUsage": int64(len(withUsage))},
			})
		}
	}
}

// listedKeysOf returns the IDs of the listed keys of a project, sorted.
func (s *scan) listedKeysOf(projectID string) []string {
	out := []string{}
	for _, k := range s.keys {
		if k.Scope == projectID {
			if _, ok := s.fs.Lookup(models.ShadowKindAPIKey, k.KeyID); ok {
				out = append(out, k.KeyID)
			}
		}
	}
	sort.Strings(out)
	return out
}
