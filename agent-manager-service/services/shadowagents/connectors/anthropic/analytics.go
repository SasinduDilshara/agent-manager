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

package anthropic

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// span is one analytics request range: [start, end), at most 31 days.
type span struct {
	start, end time.Time
}

// analyticsSpans splits the scan window into the ranges the analytics API
// accepts (anthropic.md §2.3): starting_at no earlier than 2026-01-01 and
// within the last 365 days, at most 31 days a request, whole UTC days
// (time_bucket_width=1d rounds the bounds down to midnight, so the current
// partial day is left out; its data lags 4 to 24 hours anyway). floor is
// the earliest day the API accepts; clamped says the window started before.
func analyticsSpans(w sa.Window, now time.Time) (spans []span, floor time.Time, clamped bool) {
	end := sa.DayOf(w.End)
	if n := sa.DayOf(now); n.Before(end) {
		end = n
	}
	floor = analyticsEpoch
	if lb := sa.DayOf(now).AddDate(0, 0, -analyticsLookbackDays+1); lb.After(floor) {
		floor = lb
	}
	start := sa.DayOf(w.Start)
	if start.Before(floor) {
		start, clamped = floor, true
	}
	for st := start; st.Before(end); {
		e := st.Add(analyticsMaxSpan)
		if e.After(end) {
			e = end
		}
		spans = append(spans, span{start: st, end: e})
		st = e
	}
	return spans, floor, clamped
}

// pace keeps analytics requests at most one a second.
func (s *scan) pace(ctx context.Context) error {
	if s.analyticsSent > 0 {
		if err := s.c.sleep(ctx, analyticsInterval); err != nil {
			return err
		}
	}
	s.analyticsSent++
	return nil
}

func analyticsQuery(sp span, groupBy []string) url.Values {
	return url.Values{
		"starting_at":       {sp.start.Format(time.RFC3339)},
		"ending_at":         {sp.end.Format(time.RFC3339)},
		"time_bucket_width": {"1d"},
		"group_by[]":        groupBy,
		"limit":             {"1000"},
	}
}

// analytics reads the usage and cost analytics of the window and attributes
// each row: to the Managed Agent when group.agent_id is set (and only
// there), else to the API key, else (cloud variants) to the federated cloud
// principal. It returns the error of the first request, so a caller can
// stop when the credential is rejected.
func (s *scan) analytics(ctx context.Context, p *platform) error {
	usageCall, costCall := p.call(callUsage), p.call(callCost)
	spans, floor, clamped := analyticsSpans(s.w, s.now)
	if len(spans) == 0 {
		reason := "the scan window has no complete day the analytics API covers (from 2026-01-01, last 365 days)"
		s.calls.Skip(usageCall, reason)
		s.calls.Skip(costCall, reason)
		return nil
	}
	if clamped {
		s.calls.Skip(p.call("analytics before "+floor.Format(time.DateOnly)),
			"window clamped to start "+floor.Format(time.RFC3339)+": the analytics API has no data before 2026-01-01 and keeps 365 days")
	}
	hdr := http.Header{headerBeta: {betaAnalytics}}
	var first error
	firstSet := false
	for _, sp := range spans {
		n, refreshed, err := listByCursor(ctx, p.orgAPI, p.orgURL("/v1/organizations/analytics/usage"),
			analyticsQuery(sp, p.analyticsGroupBy), hdr, maxAnalyticsPages, s.pace, func(rows []usageRow) bool {
				for i := range rows {
					s.usageRow(p, &rows[i], usageCall)
				}
				return true
			})
		s.calls.Record(usageCall, n, err)
		if !firstSet {
			first, firstSet = err, true
			if sa.OutcomeOf(err) == models.ShadowCallAuthFailed {
				s.calls.Skip(costCall, "not called: the credential was rejected")
				return err
			}
		}
		if refreshed != "" {
			s.c.logger.Debug("Anthropic analytics freshness", "call", usageCall, "dataRefreshedAt", refreshed)
		}
	}
	costGroupBy := append(append([]string{}, p.analyticsGroupBy...), "cost_type")
	for _, sp := range spans {
		n, _, err := listByCursor(ctx, p.orgAPI, p.orgURL("/v1/organizations/analytics/cost"),
			analyticsQuery(sp, costGroupBy), hdr, maxAnalyticsPages, s.pace, func(rows []costRow) bool {
				for i := range rows {
					s.costRow(p, &rows[i], costCall)
				}
				return true
			})
		s.calls.Record(costCall, n, err)
	}
	return first
}

// attribute returns the finding an analytics row belongs to: the Managed
// Agent (agent_id set; the key it used is linked to it), else the API key,
// else a federated cloud principal. nil means the row cannot be tied to a
// workload (Console, workload identity or Anthropic-managed usage).
func (s *scan) attribute(p *platform, g *analyticGroup) (f *sa.Finding, isAgent bool) {
	keyID, agentID := deref(g.APIKeyID), deref(g.AgentID)
	switch {
	case agentID != "":
		f = s.agentFinding(p, agentID)
		s.linkKeyToAgent(p, keyID, agentID)
		return f, true
	case keyID != "":
		return s.keyFinding(p, keyID), false
	case g.Actor != nil && g.Actor.Type == "federated_actor" && strings.TrimSpace(g.Actor.Subject) != "":
		return s.principalFinding(p, g.Actor), false
	default:
		return nil, false
	}
}

// principalFinding returns the finding of a federated cloud principal (an
// AWS IAM principal ARN or a Google principal) seen in the analytics of a
// cloud variant, where calls are made with cloud credentials, not API keys.
func (s *scan) principalFinding(p *platform, a *analyticActor) *sa.Finding {
	subject := strings.TrimSpace(a.Subject)
	f := s.findings.Get(models.ShadowKindPrincipal, p.kind+":"+subject)
	if f.DisplayName != "" {
		return f
	}
	f.DisplayName = subject
	f.Scope = p.orgScope()
	p.attrs(f)
	f.Attributes["principalType"] = "federated_actor"
	if a.Provider != nil && a.Provider.AccountID != "" {
		f.Attributes["accountId"] = a.Provider.AccountID
	}
	f.OwnerHint = models.ShadowOwnerHint{Username: subject, Type: "federated_actor", Source: p.call(callUsage) + " (group.actor)"}
	return f
}

// usageRow applies one usage row.
func (s *scan) usageRow(p *platform, r *usageRow, source string) {
	day, ok := parseTime(r.StartingAt)
	if !ok {
		return
	}
	u := &r.Usage
	keyID := deref(r.Group.APIKeyID)
	req := u.Requests
	in := u.UncachedInputTokens + u.CacheCreation.Ephemeral1h + u.CacheCreation.Ephemeral5m + u.CacheReadInputTokens
	out := u.OutputTokens
	var web int64
	if u.ServerToolUse != nil {
		web = u.ServerToolUse.WebSearchRequests
	}
	if req == 0 && in == 0 && out == 0 && web == 0 {
		return
	}
	if keyID != "" && req > 0 {
		if t, seen := s.keyLastUsed[keyID]; !seen || day.After(t) {
			s.keyLastUsed[keyID] = day
		}
	}
	f, isAgent := s.attribute(p, &r.Group)
	if f == nil {
		if req > 0 {
			s.unattributed++
		}
		return
	}
	if req > 0 || in > 0 || out > 0 {
		f.AddUsage(sa.UsageDay{Day: day, KeyID: keyID, Model: deref(r.Group.Model), Requests: req, InputTokens: in, OutputTokens: out})
	}
	if req > 0 {
		f.ObserveUse(day)
		s.addToSet(f, "models", deref(r.Group.Model))
		s.addToSet(f, "products", deref(r.Group.Product))
		code := sa.SigAnthropicPlainUsage
		if isAgent {
			code = sa.SigAnthropicManagedAgentUsage
		}
		f.AddSignal(sa.Signal{Code: code, Source: source, Observed: map[string]any{"requests": req}})
	}
	if web > 0 {
		f.AddSignal(sa.Signal{Code: sa.SigAnthropicServerWebSearch, Source: source, Observed: map[string]any{"webSearchRequests": web}})
	}
}

// costRow applies one cost row. Amounts are decimal strings in cents with
// six decimals ("41280.000000" is 412.80 USD, anthropic.md §2.4); the
// usage records them in currency units. amount (post-discount) is used, not
// list_amount.
func (s *scan) costRow(p *platform, r *costRow, source string) {
	day, ok := parseTime(r.StartingAt)
	if !ok {
		return
	}
	cents, err := strconv.ParseFloat(strings.TrimSpace(r.Cost.Amount), 64)
	if err != nil {
		return
	}
	f, _ := s.attribute(p, &r.Group)
	if f == nil {
		return
	}
	if cents != 0 {
		amount := cents / 100
		currency := strings.TrimSpace(r.Cost.Currency)
		if currency == "" {
			currency = "USD"
		}
		f.AddUsage(sa.UsageDay{Day: day, KeyID: deref(r.Group.APIKeyID), Model: deref(r.Group.Model), CostAmount: &amount, Currency: currency})
	}
	if deref(r.Group.CostType) == "code_execution" && cents > 0 {
		f.ObserveUse(day)
		f.AddSignal(sa.Signal{Code: sa.SigAnthropicServerCodeExec, Source: source, Observed: map[string]any{"costRows": 1}})
	}
}
