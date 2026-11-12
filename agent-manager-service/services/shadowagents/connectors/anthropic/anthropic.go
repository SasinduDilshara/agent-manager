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

// Package anthropic is the Shadow Agent Discovery connector for Anthropic:
// the Claude Developer Platform (first party, Admin API key plus optional
// workspace keys) and, optionally, the Anthropic-operated cloud variants
// Claude Platform on AWS and Claude Models on Google Cloud (Anthropic
// managed). See evidence/anthropic.md and anthropic_cloud_variants.md.
package anthropic

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Headers and pinned versions (anthropic.md §2.0, §2.1, §2.3).
// reasonNeedsAdminKey is recorded for the organization routes when the
// connection has workspace keys only.
const reasonNeedsAdminKey = "needs the Admin API key, which this connection does not have"

const (
	headerVersion   = "anthropic-version"
	headerBeta      = "anthropic-beta"
	headerWorkspace = "anthropic-workspace-id"
	headerAPIKey    = "x-api-key"

	// apiVersion is pinned: API keys return scope only under 2026-10-21.
	apiVersion          = "2026-10-21"
	betaManagedAgents   = "managed-agents-2026-04-01"
	betaAnalytics       = "analytics-usage-cost-2026-08-24"
	awsSigV4ServiceName = "aws-external-anthropic"
)

// Call names (one per route; variants add a prefix).
const (
	callWorkspaces   = "GET /v1/organizations/workspaces"
	callUsers        = "GET /v1/organizations/users"
	callAPIKeys      = "GET /v1/organizations/api_keys"
	callUsage        = "GET /v1/organizations/analytics/usage"
	callCost         = "GET /v1/organizations/analytics/cost"
	callAgents       = "GET /v1/agents"
	callSessions     = "GET /v1/sessions"
	callEvents       = "GET /v1/sessions/{session_id}/events"
	callBatches      = "GET /v1/messages/batches"
	callBatchResults = "GET /v1/messages/batches/{id}/results"
)

// Bounds.
const (
	// maxAdminPages bounds the Admin API lists (1000 items a page).
	maxAdminPages = 50
	// maxAnalyticsPages bounds one analytics window (1000 rows a page).
	maxAnalyticsPages = 100
	// maxAgentPages bounds the agents list (100 a page).
	maxAgentPages = 50
	// maxSessionsPerAgent bounds the sessions read per agent (newest first).
	maxSessionsPerAgent = 100
	// maxSessionPages bounds the session list pages per agent.
	maxSessionPages = 20
	// maxEventSessionsPerAgent and maxEventSessionsPerWorkspace bound the
	// sessions whose events are read (deep inspection).
	maxEventSessionsPerAgent     = 10
	maxEventSessionsPerWorkspace = 50
	// maxEventsPerSession bounds the tool-use events read per session.
	maxEventsPerSession = 1000
	maxEventPages       = 20
	// maxBatchesPerWorkspace bounds the batch results read (deep inspection).
	maxBatchesPerWorkspace = 20
	maxBatchListPages      = 10
	// maxBatchResultBytes bounds one results file read in memory.
	maxBatchResultBytes = 5 << 20
	// batchRetention is how long batch results stay downloadable.
	batchRetention = 29 * 24 * time.Hour
	// analyticsInterval paces analytics requests at the 60 requests a minute
	// documented for the analytics endpoints (anthropic.md §2.3).
	analyticsInterval = time.Second
	// analyticsMaxSpan is the longest range one analytics request may cover.
	analyticsMaxSpan = 31 * 24 * time.Hour
	// analyticsLookback is how far back the analytics API reaches.
	analyticsLookbackDays = 365
)

// analyticsEpoch is the earliest starting_at the analytics API accepts.
var analyticsEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Connector scans Anthropic.
type Connector struct {
	http   *http.Client
	logger *slog.Logger
	now    func() time.Time
	// sleep waits between paced or retried requests (tests replace it).
	sleep func(ctx context.Context, d time.Duration) error
}

// New returns the Anthropic connector. httpClient is the redirect-guarded
// client of sa.NewHTTPClient.
func New(httpClient *http.Client, logger *slog.Logger) sa.Connector {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Connector{http: httpClient, logger: logger, now: time.Now, sleep: sleepCtx}
}

// Provider implements sa.Connector.
func (c *Connector) Provider() string { return models.ShadowProviderAnthropic }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// scan is the state of one connection's scan.
type scan struct {
	c        *Connector
	conn     sa.Connection
	w        sa.Window
	now      time.Time
	calls    *sa.Calls
	findings *sa.Findings
	keys     []sa.Key
	keyIndex map[string]int
	// keyWorkspace is the workspace a listed key is bound to ("" for an
	// organization-scoped key).
	keyWorkspace map[string]string
	// keyLastUsed is the last daily bucket with requests, per key.
	keyLastUsed map[string]time.Time
	users       map[string]user
	// sets collects list attributes (models, products) per finding.
	sets map[*sa.Finding]map[string]map[string]bool
	// analyticsSent counts analytics requests, for pacing.
	analyticsSent int
	unattributed  int
	// wsAgents holds the agent finding IDs of each workspace, by its scope.
	wsAgents map[string][]string
}

// Scan implements sa.Connector.
func (c *Connector) Scan(ctx context.Context, conn sa.Connection, w sa.Window) *sa.Result {
	s := c.newScan(conn, w)
	s.firstParty(ctx)
	res := s.result()
	c.logger.Info("Anthropic shadow agent scan finished",
		"connectionId", conn.ID.String(), "findings", len(res.Findings), "keys", len(res.Keys),
		"calls", len(res.Calls), "unattributedUsageRows", s.unattributed)
	return res
}

func (c *Connector) newScan(conn sa.Connection, w sa.Window) *scan {
	return &scan{
		c: c, conn: conn, w: w, now: c.now().UTC(),
		calls: sa.NewCalls(), findings: sa.NewFindings(),
		keyIndex: map[string]int{}, keyWorkspace: map[string]string{}, keyLastUsed: map[string]time.Time{},
		users: map[string]user{}, sets: map[*sa.Finding]map[string]map[string]bool{},
		wsAgents: map[string][]string{},
	}
}

func (s *scan) newAPI(header func(http.Header), authorize func(context.Context, *http.Request, []byte) error) *sa.API {
	return &sa.API{HTTP: s.c.http, Header: header, Authorize: authorize, Logger: s.c.logger, Sleep: s.c.sleep}
}

// firstPartyPlatform builds the first-party platform: the Admin API key in
// x-api-key for the organization routes (anthropic.md §4 A), and each
// workspace's key as a bearer token for its workspace routes (§4 C).
func (s *scan) firstPartyPlatform() (*platform, error) {
	base, err := sa.Expand(sa.EndpointOf(s.conn, sa.EPAnthropicAPI), nil)
	if err != nil {
		return nil, err
	}
	p := &platform{
		base:             base,
		analyticsGroupBy: []string{"api_key_id", "model", "product", "agent_id"},
	}
	adminKey := strings.TrimSpace(s.conn.Secret.APIKey)
	p.orgAPI = s.newAPI(func(h http.Header) {
		h.Set(headerAPIKey, adminKey)
		h.Set(headerVersion, apiVersion)
	}, nil)
	p.wsAPI = func(ws string) (*sa.API, bool) {
		key := strings.TrimSpace(s.conn.Secret.ScopedKeys[ws])
		if key == "" {
			return nil, false
		}
		return s.newAPI(func(h http.Header) {
			h.Set("Authorization", "Bearer "+key)
			h.Set(headerVersion, apiVersion)
		}, nil), true
	}
	return p, nil
}

// firstParty scans the Claude Developer Platform.
func (s *scan) firstParty(ctx context.Context) {
	p, err := s.firstPartyPlatform()
	if err != nil {
		for _, call := range []string{callWorkspaces, callUsers, callAPIKeys, callUsage, callCost, callAgents} {
			s.calls.Record(call, 0, err)
		}
		return
	}
	var listed []workspace
	if strings.TrimSpace(s.conn.Secret.APIKey) == "" {
		for _, call := range []string{callWorkspaces, callUsers, callAPIKeys, callUsage, callCost} {
			s.calls.Skip(call, reasonNeedsAdminKey)
		}
	} else {
		listed = s.admin(ctx, p)
	}
	s.noteWorkspacesWithoutKey(listed)
	s.workspaces(ctx, p, sortedKeys(s.conn.Secret.ScopedKeys), "no workspace keys")
}

// admin runs the Admin API calls and returns the listed workspaces. The
// first call checks the key: when it is rejected, the other Admin calls are
// not made.
func (s *scan) admin(ctx context.Context, p *platform) []workspace {
	listed, err := s.listWorkspaces(ctx, p)
	if sa.OutcomeOf(err) == models.ShadowCallAuthFailed {
		for _, call := range []string{callUsers, callAPIKeys, callUsage, callCost} {
			s.calls.Skip(p.call(call), "not called: the Admin API key was rejected")
		}
		return nil
	}
	s.listUsers(ctx, p)
	s.listKeys(ctx, p)
	_ = s.analytics(ctx, p) // the outcome is recorded in the calls
	return listed
}

// noteWorkspacesWithoutKey records the active workspaces whose Managed
// Agents, sessions and batches cannot be read because the connection has
// no workspace key for them.
func (s *scan) noteWorkspacesWithoutKey(listed []workspace) {
	var missing []string
	active := 0
	for _, w := range listed {
		if w.ArchivedAt != nil && *w.ArchivedAt != "" {
			continue
		}
		active++
		if strings.TrimSpace(s.conn.Secret.ScopedKeys[w.ID]) == "" {
			missing = append(missing, w.ID)
		}
	}
	if len(missing) == 0 {
		return
	}
	shown := missing
	if len(shown) > 5 {
		shown = shown[:5]
	}
	msg := fmt.Sprintf("no workspace key for %d of %d workspaces (%s", len(missing), active, strings.Join(shown, ", "))
	if len(missing) > len(shown) {
		msg += ", ..."
	}
	s.calls.Skip(callAgents+" (workspaces without a key)", msg+"); their Managed Agents, sessions and batches are not read")
}

// result builds the scan result.
func (s *scan) result() *sa.Result {
	for f, sets := range s.sets {
		for attr, set := range sets {
			f.Attributes[attr] = sortedSet(set)
		}
	}
	for i := range s.keys {
		if t, ok := s.keyLastUsed[s.keys[i].KeyID]; ok {
			t := t
			s.keys[i].LastUsedAt = &t
		}
	}
	all := s.findings.All()
	for _, f := range all {
		f.Attributes = sa.SanitizeAttributes(f.Attributes)
		f.OwnerHint = sa.MinimiseOwnerHint(f.OwnerHint)
		f.DisplayName = sa.SanitizeName(f.DisplayName)
		sort.SliceStable(f.Usage, func(i, j int) bool {
			a, b := f.Usage[i], f.Usage[j]
			if !a.Day.Equal(b.Day) {
				return a.Day.Before(b.Day)
			}
			if a.KeyID != b.KeyID {
				return a.KeyID < b.KeyID
			}
			return a.Model < b.Model
		})
	}
	return &sa.Result{
		Findings:   all,
		Keys:       s.keys,
		Calls:      s.calls.Results(),
		KeysListed: s.calls.OK(callAPIKeys),
	}
}

// addToSet records value under a list attribute of f.
func (s *scan) addToSet(f *sa.Finding, attr, value string) {
	if value == "" {
		return
	}
	m, ok := s.sets[f]
	if !ok {
		m = map[string]map[string]bool{}
		s.sets[f] = m
	}
	if m[attr] == nil {
		m[attr] = map[string]bool{}
	}
	m[attr][value] = true
}

// keyFinding returns the finding of an API key, creating a minimal one for
// a key the listing did not return (or on a platform without key listing).
func (s *scan) keyFinding(p *platform, id string) *sa.Finding {
	f := s.findings.Get(models.ShadowKindAPIKey, id)
	if f.DisplayName == "" {
		f.DisplayName = id
		f.Scope = p.orgScope()
		f.AddKeyID(id)
	}
	return f
}

// agentFinding returns the finding of a Managed Agent; the agents listing
// fills in its name and workspace when it has them.
func (s *scan) agentFinding(p *platform, id string) *sa.Finding {
	f := s.findings.Get(models.ShadowKindPlatformAgent, id)
	if f.DisplayName == "" {
		f.DisplayName = id
		f.Scope = p.orgScope()
	}
	return f
}

// linkKeyToAgent records that an agent's usage was made with a key.
func (s *scan) linkKeyToAgent(p *platform, keyID, agentID string) {
	if keyID == "" || agentID == "" {
		return
	}
	s.agentFinding(p, agentID).AddKeyID(keyID)
	kf := s.keyFinding(p, keyID)
	for _, r := range kf.Related {
		if r.ExternalID == agentID && r.Kind == models.ShadowKindPlatformAgent {
			return
		}
	}
	kf.Related = append(kf.Related, sa.Relation{
		ExternalID: agentID, Kind: models.ShadowKindPlatformAgent, Relation: "used_by_agent",
		Reason: "analytics usage rows of this Managed Agent carry this API key",
	})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if strings.TrimSpace(k) != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func (s *scan) inWindow(t time.Time) bool {
	return !t.Before(s.w.Start) && !t.After(s.w.End)
}
