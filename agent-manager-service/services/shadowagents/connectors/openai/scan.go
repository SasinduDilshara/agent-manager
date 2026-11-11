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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// scan is the state of one connection's scan.
type scan struct {
	c     *Connector
	conn  sa.Connection
	w     sa.Window
	base  string
	admin *sa.API
	calls *sa.Calls
	fs    *sa.Findings

	projects   []project
	projectIdx map[string]int
	keys       []sa.Key
	keyIdx     map[string]int
	keyProject map[string]string
	keysListed bool
	// keyScopesListed are the projects whose keys were listed completely.
	keyScopesListed []string

	// agents holds the agent IDs of each project whose listing completed.
	agents         map[string][]string
	agentsComplete map[string]bool
	// keysWithUsage holds, per project, the keys with num_model_requests > 0
	// in usage/completions over the window.
	keysWithUsage map[string]map[string]bool

	tallies      []*tally
	tallyIdx     map[tallyKey]*tally
	unattributed map[string][]string
	// onProject lists, per source call, the projects whose evidence went to
	// the project finding because it could not be tied to one key.
	onProject   map[string][]string
	skippedRows map[string]int
}

// tally sums the observations of one signal on one finding, so the signal
// is added once with totals instead of once per usage row.
type tally struct {
	f      *sa.Finding
	code   string
	source string
	fields []string
	counts map[string]int64
	days   map[time.Time]bool
}

type tallyKey struct {
	f      *sa.Finding
	code   string
	source string
}

// Scan runs every call the connection enables over the window.
func (c *Connector) Scan(ctx context.Context, conn sa.Connection, w sa.Window) *sa.Result {
	s := &scan{
		c: c, conn: conn, w: w,
		calls: sa.NewCalls(), fs: sa.NewFindings(),
		projectIdx: map[string]int{}, keyIdx: map[string]int{}, keyProject: map[string]string{},
		agents: map[string][]string{}, agentsComplete: map[string]bool{},
		keysWithUsage: map[string]map[string]bool{},
		tallyIdx:      map[tallyKey]*tally{}, unattributed: map[string][]string{}, skippedRows: map[string]int{},
		onProject: map[string][]string{},
	}
	s.run(ctx)
	return s.result()
}

func (s *scan) run(ctx context.Context) {
	base, err := baseURL(s.conn)
	if err != nil {
		s.calls.Record(callProjects, 0, &sa.CallError{Outcome: models.ShadowCallFailed, Message: sa.ScrubText(err.Error())})
		return
	}
	s.base = base
	if strings.TrimSpace(s.conn.Secret.APIKey) == "" {
		// Project keys only: the organization routes need the Admin key, so
		// only the projects with a project key are read, and keys, usage,
		// costs and audit logs are not.
		for _, call := range []string{
			callProjects, callAPIKeys, callAuditLogs, callUsage, callCosts,
			callWebSearch, callFileSearch, callCodeInterpreter,
		} {
			s.calls.Skip(call, reasonNeedsAdminKey)
		}
		s.listAgents(ctx)
		s.deepInspect(ctx)
		return
	}
	s.admin = s.c.api(strings.TrimSpace(s.conn.Secret.APIKey))
	if !s.listProjects(ctx) {
		return
	}
	s.listAPIKeys(ctx)
	s.listAuditLogs(ctx)
	s.listAgents(ctx)
	s.readCompletionsUsage(ctx)
	s.readCosts(ctx)
	s.readWebSearch(ctx)
	s.readFileSearch(ctx)
	s.readCodeInterpreter(ctx)
	s.deepInspect(ctx)
}

func (s *scan) result() *sa.Result {
	for _, t := range s.tallies {
		obs := map[string]any{}
		for _, f := range t.fields {
			obs[f] = t.counts[f]
		}
		obs["days"] = int64(len(t.days))
		t.f.AddSignal(sa.Signal{Code: t.code, Source: t.source, Observed: obs})
	}
	s.finishProjectFindings()
	for _, call := range sortedKeys(s.onProject) {
		reason := "the connection has no Admin API key, so the project's keys are not known"
		if s.admin != nil {
			reason = "more than one key of the project, or none, had usage in the window"
		}
		s.calls.Skip(call+suffixOnProject, sa.Truncate(fmt.Sprintf(
			"evidence in %s was put on the project's finding, not on a key: %s (%s)",
			plural(len(s.onProject[call]), "project", "projects"), reason, strings.Join(s.onProject[call], ", ")), 300))
	}
	for _, call := range sortedKeys(s.unattributed) {
		s.calls.Skip(call+suffixNotAttributed, sa.Truncate(fmt.Sprintf(
			"evidence in %s was not attached to a key: a project-level source names a key only when exactly one key "+
				"of the project had usage in the window (%s)",
			plural(len(s.unattributed[call]), "project", "projects"), strings.Join(s.unattributed[call], ", ")), 300))
	}
	findings := s.fs.All()
	for _, f := range findings {
		f.Attributes = sa.SanitizeAttributes(f.Attributes)
		f.OwnerHint = sa.MinimiseOwnerHint(f.OwnerHint)
		f.DisplayName = sa.SanitizeName(f.DisplayName)
	}
	for i := range s.keys {
		s.keys[i].OwnerHint = sa.MinimiseOwnerHint(s.keys[i].OwnerHint)
	}
	res := &sa.Result{
		Findings: findings, Keys: s.keys, Calls: s.calls.Results(),
		KeysListed: s.keysListed, KeyScopesListed: s.keyScopesListed,
	}
	failed := 0
	for _, r := range res.Calls {
		if r.Outcome != models.ShadowCallOK && r.Outcome != models.ShadowCallSkipped {
			failed++
		}
	}
	s.c.logger.Info("Shadow agent discovery OpenAI scan finished",
		"connectionId", s.conn.ID.String(), "projects", len(s.projects), "keys", len(s.keys),
		"findings", len(findings), "calls", len(res.Calls), "failedCalls", failed,
		"unattributedUsageRows", s.skippedRows[callUsage], "unattributedCostRows", s.skippedRows[callCosts])
	return res
}

// tally adds counts observed on day for signal code on f.
func (s *scan) tally(f *sa.Finding, code, source string, day time.Time, counts map[string]int64) {
	k := tallyKey{f: f, code: code, source: source}
	t, ok := s.tallyIdx[k]
	if !ok {
		t = &tally{f: f, code: code, source: source, counts: map[string]int64{}, days: map[time.Time]bool{}}
		s.tallyIdx[k] = t
		s.tallies = append(s.tallies, t)
	}
	for _, name := range sortedKeys(counts) {
		if _, seen := t.counts[name]; !seen {
			t.fields = append(t.fields, name)
		}
		t.counts[name] += counts[name]
	}
	t.days[sa.DayOf(day)] = true
}

func (s *scan) pageLimit(call string, pages int) {
	s.calls.Skip(call+suffixPageLimit, fmt.Sprintf("stopped after %d pages; later pages were not read", pages))
}

func (s *scan) projectLabel(id string) string {
	if i, ok := s.projectIdx[id]; ok && s.projects[i].Name != "" {
		return s.projects[i].Name
	}
	return id
}

func (s *scan) projectArchived(id string) bool {
	i, ok := s.projectIdx[id]
	return ok && s.projects[i].archived()
}

// scopedProjects returns the project IDs that have a project key, sorted.
func (s *scan) scopedProjects() []string {
	out := []string{}
	for _, id := range sortedKeys(s.conn.Secret.ScopedKeys) {
		if strings.TrimSpace(id) != "" && strings.TrimSpace(s.conn.Secret.ScopedKeys[id]) != "" {
			out = append(out, id)
		}
	}
	return out
}

func (s *scan) projectAPI(id string) *sa.API {
	return s.c.api(strings.TrimSpace(s.conn.Secret.ScopedKeys[id]))
}

// listProjects lists every project, archived ones included. It returns
// false when the Admin key was rejected, which ends the scan.
func (s *scan) listProjects(ctx context.Context) bool {
	q := url.Values{"include_archived": []string{"true"}}
	truncated, err := listAll(ctx, s.admin, s.base+"/organization/projects", q, nil, listPageSize, maxListPages,
		func(p project) bool {
			if p.ID == "" {
				return true
			}
			if _, dup := s.projectIdx[p.ID]; !dup {
				s.projectIdx[p.ID] = len(s.projects)
				s.projects = append(s.projects, p)
			}
			return true
		})
	s.calls.Record(callProjects, len(s.projects), err)
	if truncated {
		s.pageLimit(callProjects, maxListPages)
	}
	if sa.OutcomeOf(err) == models.ShadowCallAuthFailed {
		s.c.logger.Info("Shadow agent discovery OpenAI scan stopped: the Admin key was rejected", "connectionId", s.conn.ID.String())
		return false
	}
	// Key listing is complete only if the project listing was.
	s.keysListed = err == nil && !truncated
	return true
}

// listAPIKeys lists each project's API keys (owner_project_access=any, so
// keys whose owner lost project access are included).
func (s *scan) listAPIKeys(ctx context.Context) {
	if len(s.projects) == 0 {
		s.calls.Skip(callAPIKeys, "no projects")
		return
	}
	archivedRefused := 0
	for _, p := range s.projects {
		if ctx.Err() != nil {
			s.keysListed = false
			break
		}
		var got []apiKey
		u := s.base + "/organization/projects/" + url.PathEscape(p.ID) + "/api_keys"
		q := url.Values{"owner_project_access": []string{"any"}}
		truncated, err := listAll(ctx, s.admin, u, q, nil, listPageSize, maxListPages, func(k apiKey) bool {
			got = append(got, k)
			return true
		})
		if err != nil && p.archived() && statusOf(err) == http.StatusBadRequest {
			// Documented: the endpoint returns 400 for an archived project.
			// Its keys are unknown, so the listing is not complete.
			archivedRefused++
			s.keysListed = false
			continue
		}
		s.calls.Record(callAPIKeys, len(got), err)
		if err != nil || truncated {
			s.keysListed = false
		} else {
			s.keyScopesListed = append(s.keyScopesListed, p.ID)
		}
		if truncated {
			s.pageLimit(callAPIKeys, maxListPages)
		}
		for _, k := range got {
			s.addKey(p, k)
		}
	}
	if archivedRefused > 0 {
		s.calls.Skip(callAPIKeysArchived, fmt.Sprintf(
			"the API returns HTTP 400 for archived projects; the keys of %s are not listed",
			plural(archivedRefused, "archived project", "archived projects")))
	}
}

func (s *scan) addKey(p project, k apiKey) {
	if k.ID == "" {
		return
	}
	if _, dup := s.keyIdx[k.ID]; dup {
		return
	}
	created := unixTime(k.CreatedAt)
	lastUsed := unixPtr(k.LastUsedAt)
	status := stateActive
	switch {
	case p.archived():
		status = stateArchived
	case k.ExpiresAt != nil && *k.ExpiresAt > 0 && !time.Unix(*k.ExpiresAt, 0).After(s.w.End):
		status = stateExpired
	}
	owner := keyOwnerHint(k.Owner)
	s.keyIdx[k.ID] = len(s.keys)
	s.keys = append(s.keys, sa.Key{
		KeyID: k.ID, Name: sa.SanitizeName(k.Name), RedactedHint: redactedHint(k.RedactedValue),
		Status: status, Scope: p.ID, OwnerHint: owner, CreatedAt: created, LastUsedAt: lastUsed,
	})
	s.keyProject[k.ID] = p.ID

	f := s.fs.Get(models.ShadowKindAPIKey, k.ID)
	f.DisplayName = k.Name
	if strings.TrimSpace(f.DisplayName) == "" {
		f.DisplayName = k.ID
	}
	f.Scope = p.ID
	f.State = status
	f.OwnerHint = owner
	f.ProviderCreatedAt = created
	if lastUsed != nil {
		widenLast(f, *lastUsed)
	}
	f.AddKeyID(k.ID)
	f.Attributes["project"] = s.projectLabel(p.ID)
	if p.archived() {
		f.Attributes["archived"] = true
	}
}

func keyOwnerHint(o apiKeyOwner) models.ShadowOwnerHint {
	h := models.ShadowOwnerHint{Source: callAPIKeys}
	switch {
	case o.Type == ownerTypeUser && o.User != nil:
		h.Type = ownerTypeUser
		h.Name = o.User.Name
		h.Email = o.User.Email
		h.Username = o.User.ID
	case o.Type == ownerTypeServiceAcct && o.ServiceAccount != nil:
		h.Type = ownerTypeServiceAcct
		h.Name = o.ServiceAccount.Name
		h.Username = o.ServiceAccount.ID
	default:
		h.Source = ""
	}
	return h
}

// creator is who created a key, from an api_key.created audit event.
type creator struct {
	kind  string
	id    string
	email string
	at    time.Time
}

// listAuditLogs reads api_key.created events and adds their creator to the
// owner hints of the listed keys.
func (s *scan) listAuditLogs(ctx context.Context) {
	creators := map[string]creator{}
	events := 0
	q := url.Values{"event_types[]": []string{"api_key.created"}}
	truncated, err := listAll(ctx, s.admin, s.base+"/organization/audit_logs", q, nil, listPageSize, maxAuditPages,
		func(e auditLog) bool {
			events++
			if e.Created == nil || e.Created.ID == "" {
				return true
			}
			if cr, ok := auditCreator(e); ok {
				creators[e.Created.ID] = cr
			}
			return true
		})
	s.calls.Record(callAuditLogs, events, err)
	if truncated {
		s.pageLimit(callAuditLogs, maxAuditPages)
	}
	for i := range s.keys {
		cr, ok := creators[s.keys[i].KeyID]
		if !ok {
			continue
		}
		h := mergeCreator(s.keys[i].OwnerHint, cr)
		s.keys[i].OwnerHint = h
		if f, ok := s.fs.Lookup(models.ShadowKindAPIKey, s.keys[i].KeyID); ok {
			f.OwnerHint = h
		}
	}
}

// auditCreator reads the creator of an api_key.created event: the session
// user, or the user or service account of the API key that made the call.
// The actor may be null.
func auditCreator(e auditLog) (creator, bool) {
	a := e.Actor
	cr := creator{at: time.Unix(e.EffectiveAt, 0).UTC()}
	if a == nil {
		return cr, e.EffectiveAt > 0
	}
	switch {
	case a.Type == "session" && a.Session != nil && a.Session.User != nil:
		cr.kind, cr.id, cr.email = ownerTypeUser, a.Session.User.ID, a.Session.User.Email
	case a.Type == "api_key" && a.APIKey != nil && a.APIKey.Type == ownerTypeUser && a.APIKey.User != nil:
		cr.kind, cr.id, cr.email = ownerTypeUser, a.APIKey.User.ID, a.APIKey.User.Email
	case a.Type == "api_key" && a.APIKey != nil && a.APIKey.Type == ownerTypeServiceAcct && a.APIKey.ServiceAccount != nil:
		cr.kind, cr.id = ownerTypeServiceAcct, a.APIKey.ServiceAccount.ID
	}
	return cr, true
}

// mergeCreator completes a key's owner hint with its creator: the owner
// from the key listing wins; the creator fills what is missing (a service
// account key gets the email of the person who created it).
func mergeCreator(h models.ShadowOwnerHint, cr creator) models.ShadowOwnerHint {
	if !cr.at.IsZero() && cr.at.Unix() > 0 {
		at := cr.at
		h.CreatedAt = &at
	}
	used := false
	if h.Email == "" && cr.email != "" {
		h.Email = cr.email
		used = true
	}
	if h.Type == "" && cr.kind != "" {
		h.Type = cr.kind
		used = true
	}
	if h.Username == "" && cr.id != "" {
		h.Username = cr.id
		used = true
	}
	switch {
	case used && h.Source != "":
		h.Source = h.Source + "; " + callAuditLogs
	case used || h.Source == "":
		h.Source = callAuditLogs
	}
	return h
}

// keyFinding returns the finding of key id, creating one for a key the
// listing did not return (e.g. deleted, or in a project whose keys could
// not be listed) but that has usage.
func (s *scan) keyFinding(id, projectID string) *sa.Finding {
	if f, ok := s.fs.Lookup(models.ShadowKindAPIKey, id); ok {
		return f
	}
	f := s.fs.Get(models.ShadowKindAPIKey, id)
	f.DisplayName = id
	f.Scope = projectID
	f.AddKeyID(id)
	if projectID != "" {
		f.Attributes["project"] = s.projectLabel(projectID)
	}
	return f
}

// projectOf returns the project of a usage row, falling back to the
// project the key was listed under.
func (s *scan) projectOf(projectID, keyID string) string {
	if projectID != "" {
		return projectID
	}
	return s.keyProject[keyID]
}

// soleAgent returns the project's agent when the project's agent listing
// completed and returned exactly one agent: Agents API usage of the
// project's keys then belongs to it.
func (s *scan) soleAgent(projectID string) (*sa.Finding, bool) {
	if !s.agentsComplete[projectID] || len(s.agents[projectID]) != 1 {
		return nil, false
	}
	return s.fs.Lookup(models.ShadowKindPlatformAgent, s.agents[projectID][0])
}

// toAgent routes Agents API evidence of key keyID to the project's sole
// agent, linking the key to it.
func (s *scan) toAgent(ag *sa.Finding, keyID string) *sa.Finding {
	ag.AddKeyID(keyID)
	if kf, ok := s.fs.Lookup(models.ShadowKindAPIKey, keyID); ok {
		for _, r := range kf.Related {
			if r.ExternalID == ag.ExternalID && r.Relation == relationUsedByAgent {
				return ag
			}
		}
		kf.Related = append(kf.Related, sa.Relation{
			ExternalID: ag.ExternalID, Kind: models.ShadowKindPlatformAgent, Relation: relationUsedByAgent,
			Reason: "Agents API usage (api_source agents_api) of this key, in a project with exactly one agent",
		})
	}
	return ag
}

// attributeProject attaches project-level evidence (a source that does not
// name a key) to the project's key when exactly one key had usage in the
// window; otherwise it is reported in the call results.
// attributeProject puts project-level evidence (read with a project key) on
// the one key of the project that had usage in the window. When that key is
// not known (no Admin key) or not unique, the evidence goes on the project's
// own finding, with the candidate keys when they are known.
func (s *scan) attributeProject(projectID string, sig sa.Signal) {
	keys := s.keysWithUsage[projectID]
	if s.admin != nil && len(keys) == 1 {
		for id := range keys {
			s.keyFinding(id, projectID).AddSignal(sig)
		}
		return
	}
	f := s.projectFinding(projectID)
	f.AddSignal(sig)
	note := projectID + ": project keys only"
	if s.admin != nil {
		note = fmt.Sprintf("%s: %s with usage", projectID, plural(len(keys), "key", "keys"))
	}
	if list := s.onProject[sig.Source]; len(list) == 0 || list[len(list)-1] != note {
		s.onProject[sig.Source] = append(list, note)
	}
}

// projectFinding returns the finding of a project, creating it.
func (s *scan) projectFinding(projectID string) *sa.Finding {
	if f, ok := s.fs.Lookup(models.ShadowKindProject, projectID); ok {
		return f
	}
	f := s.fs.Get(models.ShadowKindProject, projectID)
	f.DisplayName = "Project " + s.projectLabel(projectID)
	f.Scope = projectID
	f.State = stateActive
	if s.projectArchived(projectID) {
		f.State = stateArchived
		f.Attributes["archived"] = true
	}
	f.Attributes["project"] = s.projectLabel(projectID)
	return f
}

// finishProjectFindings links each project finding to the agents found in
// the project and, when the Admin key lists them, to the keys that may have
// made its calls.
func (s *scan) finishProjectFindings() {
	for _, f := range s.fs.All() {
		if f.Kind != models.ShadowKindProject {
			continue
		}
		pid := f.ExternalID
		for _, id := range s.agents[pid] {
			f.Related = append(f.Related, sa.Relation{
				ExternalID: id, Kind: models.ShadowKindPlatformAgent, Relation: "agent_in_project", Reason: "agent in this project",
			})
		}
		if s.admin == nil {
			continue
		}
		reason := "had usage in this project in the window"
		candidates := sortedKeys(s.keysWithUsage[pid])
		if len(candidates) == 0 {
			reason = "listed in this project"
			candidates = s.listedKeysOf(pid)
		}
		for _, id := range candidates {
			f.Related = append(f.Related, sa.Relation{
				ExternalID: id, Kind: models.ShadowKindAPIKey, Relation: "candidate_key", Reason: reason,
			})
		}
	}
}
