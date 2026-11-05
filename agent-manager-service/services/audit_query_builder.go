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

package services

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Audit record field values written by the log pipeline (Fluent Bit adds
// audit_source; see the amp-fluent-bit ConfigMap in the observability chart).
const (
	auditSourceGateway      = "gateway"
	auditSourceControlPlane = "control-plane"

	// auditAMSIssuer is the issuer of the tokens AMS mints for agents; the
	// gateway's /otel route authenticates them, with the agent name as subject.
	auditAMSIssuer = "agent-manager-service"
)

// Audit query limits.
const (
	AuditDefaultLimit = 50
	AuditMaxLimit     = 200
	// AuditMaxRange is the retention the pipeline keeps (six calendar months).
	AuditMaxRange       = 186 * 24 * time.Hour
	AuditDefaultRange   = 24 * time.Hour
	auditMaxFilterText  = 256
	auditMaxAgentValues = 20
	auditMaxNameLength  = 128
	auditMaxCursorBytes = 1024
	// auditTrackTotalHits bounds the exact count; beyond it total is a lower
	// bound and totalRelation says "gte".
	auditTrackTotalHits = 10000
)

// Audit categories and outcomes, as returned by the API.
const (
	AuditCategoryOperational = "OPERATIONAL"
	AuditCategoryLLM         = "LLM"
	AuditCategoryMCP         = "MCP"
	AuditCategoryA2A         = "A2A"
	AuditCategoryOther       = "OTHER"

	AuditOutcomeSuccess = "SUCCESS"
	AuditOutcomeDenied  = "DENIED"
	AuditOutcomeFailed  = "FAILED"
	// AuditOutcomeStarted is a control-plane intent record (outcome "unknown"),
	// written before a privileged external mutation. Its result is a separate
	// record linked by details.attemptEventId, so the intent is neither a
	// success nor a failure. Gateway records never carry it.
	AuditOutcomeStarted = "STARTED"
)

// AuditCategories lists every category in display order.
var AuditCategories = []string{
	AuditCategoryOperational, AuditCategoryLLM, AuditCategoryMCP, AuditCategoryA2A, AuditCategoryOther,
}

var auditOutcomes = []string{AuditOutcomeSuccess, AuditOutcomeDenied, AuditOutcomeFailed, AuditOutcomeStarted}

// llmAPIKinds are the gateway API kinds whose traffic is LLM traffic.
var llmAPIKinds = []string{"LlmProxy", "LlmProvider"}

// ErrAuditInvalidQuery wraps every caller error in an audit query.
var ErrAuditInvalidQuery = errors.New("invalid audit query")

// AuditQuery is a validated audit query. OUID and OrgHandle come from the
// caller's token, never from the request.
type AuditQuery struct {
	OUID      string
	OrgHandle string

	Start      time.Time
	End        time.Time
	Categories []string
	// Agents are "project/agent" or "agent" values.
	Agents      []string
	Project     string
	Environment string
	Outcomes    []string
	Actor       string
	Search      string
	Limit       int
	Cursor      string
	Ascending   bool
}

func invalidAuditQuery(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrAuditInvalidQuery, fmt.Sprintf(format, args...))
}

// Normalize applies defaults and validates the query. now is the reference
// for the default time range.
func (q *AuditQuery) Normalize(now time.Time) error {
	if q.OUID == "" || q.OrgHandle == "" {
		// Not a caller error: a request without a resolved org must never reach
		// the store, where a missing scope would mean no scope.
		return errors.New("audit query: missing organization scope")
	}
	if q.End.IsZero() {
		q.End = now
	}
	if q.Start.IsZero() {
		q.Start = q.End.Add(-AuditDefaultRange)
	}
	if !q.Start.Before(q.End) {
		return invalidAuditQuery("startTime must be before endTime")
	}
	if q.End.Sub(q.Start) > AuditMaxRange {
		return invalidAuditQuery("the time range may not exceed %d days", int(AuditMaxRange.Hours()/24))
	}
	if q.Limit == 0 {
		q.Limit = AuditDefaultLimit
	}
	if q.Limit < 1 || q.Limit > AuditMaxLimit {
		return invalidAuditQuery("limit must be between 1 and %d", AuditMaxLimit)
	}

	var err error
	if q.Categories, err = normalizeEnumList("category", q.Categories, AuditCategories); err != nil {
		return err
	}
	if q.Outcomes, err = normalizeEnumList("outcome", q.Outcomes, auditOutcomes); err != nil {
		return err
	}
	if len(q.Agents) > auditMaxAgentValues {
		return invalidAuditQuery("at most %d agent values are allowed", auditMaxAgentValues)
	}
	agents := make([]string, 0, len(q.Agents))
	seen := map[string]bool{}
	for _, a := range q.Agents {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		if _, _, err := splitAuditAgentFilter(a); err != nil {
			return err
		}
		seen[a] = true
		agents = append(agents, a)
	}
	q.Agents = agents

	q.Project = strings.TrimSpace(q.Project)
	q.Environment = strings.TrimSpace(q.Environment)
	q.Actor = strings.TrimSpace(q.Actor)
	q.Search = strings.TrimSpace(q.Search)
	if len(q.Project) > auditMaxNameLength || len(q.Environment) > auditMaxNameLength {
		return invalidAuditQuery("project and environment may be at most %d characters", auditMaxNameLength)
	}
	if len(q.Actor) > auditMaxFilterText || len(q.Search) > auditMaxFilterText {
		return invalidAuditQuery("actor and search may be at most %d characters", auditMaxFilterText)
	}
	if q.Cursor != "" {
		if _, err := decodeAuditCursor(q.Cursor, q.Ascending); err != nil {
			return err
		}
	}
	return nil
}

func normalizeEnumList(name string, values, allowed []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		ok := false
		for _, a := range allowed {
			if v == a {
				ok = true
				break
			}
		}
		if !ok {
			return nil, invalidAuditQuery("unknown %s %q (valid: %s)", name, v, strings.Join(allowed, ", "))
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}

// splitAuditAgentFilter splits "project/agent" or "agent".
func splitAuditAgentFilter(v string) (project, name string, err error) {
	if len(v) > 2*auditMaxNameLength+1 {
		return "", "", invalidAuditQuery("agent filter %q is too long", v)
	}
	parts := strings.Split(v, "/")
	switch {
	case len(parts) == 1 && parts[0] != "":
		return "", parts[0], nil
	case len(parts) == 2 && parts[0] != "" && parts[1] != "":
		return parts[0], parts[1], nil
	default:
		return "", "", invalidAuditQuery("agent filter %q must be \"agent\" or \"project/agent\"", v)
	}
}

// auditCursor is the decoded form of the opaque cursor: the sort values of the
// last event returned, and the direction they were sorted in.
type auditCursor struct {
	Order string            `json:"o"`
	After []json.RawMessage `json:"a"`
}

func auditSortOrder(asc bool) string {
	if asc {
		return "asc"
	}
	return "desc"
}

func encodeAuditCursor(sortValues []json.RawMessage, asc bool) (string, error) {
	b, err := json.Marshal(auditCursor{Order: auditSortOrder(asc), After: sortValues})
	if err != nil {
		return "", fmt.Errorf("encode audit cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// decodeAuditCursor accepts only the shape this service issues — a timestamp
// in epoch milliseconds and a document id — so a crafted cursor cannot inject
// anything else into the search_after clause.
func decodeAuditCursor(s string, asc bool) ([]any, error) {
	if len(s) > auditMaxCursorBytes {
		return nil, invalidAuditQuery("cursor is too long")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, invalidAuditQuery("cursor is malformed")
	}
	var c auditCursor
	if err := json.Unmarshal(b, &c); err != nil || len(c.After) != 2 {
		return nil, invalidAuditQuery("cursor is malformed")
	}
	if c.Order != auditSortOrder(asc) {
		return nil, invalidAuditQuery("cursor was issued for a different sort order")
	}
	var ts json.Number
	dec := json.NewDecoder(strings.NewReader(string(c.After[0])))
	dec.UseNumber()
	if err := dec.Decode(&ts); err != nil {
		return nil, invalidAuditQuery("cursor is malformed")
	}
	if _, err := ts.Int64(); err != nil {
		return nil, invalidAuditQuery("cursor is malformed")
	}
	var id string
	if err := json.Unmarshal(c.After[1], &id); err != nil || id == "" || len(id) > 512 {
		return nil, invalidAuditQuery("cursor is malformed")
	}
	return []any{ts, id}, nil
}

// ---------------------------------------------------------------------------
// OpenSearch query DSL helpers. Bodies are built as maps and serialised with
// encoding/json, so no caller-supplied value is ever spliced into JSON text.

type osQuery = map[string]any

func osTerm(field string, value any) osQuery {
	return osQuery{"term": osQuery{field: value}}
}

func osTerms(field string, values []string) osQuery {
	return osQuery{"terms": osQuery{field: values}}
}

func osExists(field string) osQuery {
	return osQuery{"exists": osQuery{"field": field}}
}

func osBool(clauses map[string][]osQuery) osQuery {
	b := osQuery{}
	for k, v := range clauses {
		if len(v) > 0 {
			b[k] = v
		}
	}
	if len(clauses["should"]) > 0 {
		b["minimum_should_match"] = 1
	}
	return osQuery{"bool": b}
}

func osAnd(qs ...osQuery) osQuery    { return osBool(map[string][]osQuery{"filter": qs}) }
func osOr(qs ...osQuery) osQuery     { return osBool(map[string][]osQuery{"should": qs}) }
func osNot(qs ...osQuery) osQuery    { return osBool(map[string][]osQuery{"must_not": qs}) }
func osSource(source string) osQuery { return osTerm("audit_source", source) }

// osContains is a case-insensitive substring match on a keyword field.
func osContains(field, text string) osQuery {
	return osQuery{"wildcard": osQuery{field: osQuery{
		"value":            "*" + escapeAuditWildcard(text) + "*",
		"case_insensitive": true,
	}}}
}

// escapeAuditWildcard neutralises the wildcard query's metacharacters so the
// caller's text is matched literally.
func escapeAuditWildcard(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`)
	return r.Replace(s)
}

// auditOrgScope admits only the caller's org: control-plane records by the OU
// id AMS stamped on them, gateway records by the organization the gateway was
// configured with. It is ANDed into every query and is not optional.
func auditOrgScope(ouID, orgHandle string, namespaceFallback bool) osQuery {
	controlPlane := osAnd(osSource(auditSourceControlPlane), osTerm("event.ouId", ouID))
	gatewayOrg := osTerm("gateway.organization", orgHandle)
	if namespaceFallback {
		// Only for records whose gateway predates gateway.organization: the
		// gateway's namespace is "<org>-<env>" by convention.
		gatewayOrg = osOr(
			gatewayOrg,
			osAnd(
				osNot(osExists("gateway.organization")),
				osQuery{"prefix": osQuery{"kubernetes.namespace_name": osQuery{"value": orgHandle + "-"}}},
			),
		)
	}
	return osOr(controlPlane, osAnd(osSource(auditSourceGateway), gatewayOrg))
}

// auditCategoryQuery mirrors auditCategoryOf, the Go rule used for the
// normalised field; the two are tested against each other.
func auditCategoryQuery(category string) osQuery {
	gw := osSource(auditSourceGateway)
	llm := osTerms("api.kind", llmAPIKinds)
	mcp := osTerm("api.kind", "Mcp")
	a2a := osExists("a2a")
	switch category {
	case AuditCategoryOperational:
		return osSource(auditSourceControlPlane)
	case AuditCategoryLLM:
		return osAnd(gw, llm)
	case AuditCategoryMCP:
		return osAnd(gw, mcp)
	case AuditCategoryA2A:
		return osBool(map[string][]osQuery{"filter": {gw, a2a}, "must_not": {llm, mcp}})
	default: // AuditCategoryOther
		return osBool(map[string][]osQuery{"filter": {gw}, "must_not": {llm, mcp, a2a}})
	}
}

func auditGatewayDenied() osQuery {
	return osOr(
		osTerm("decision.terminalReason", "policy_denied"),
		osQuery{"terms": osQuery{"status": []int{401, 403}}},
	)
}

func auditGatewayFailed() osQuery {
	return osOr(
		osQuery{"range": osQuery{"status": osQuery{"gte": 400}}},
		osTerm("mcp.isError", true),
	)
}

// auditOutcomeQuery mirrors auditGatewayOutcome / auditControlPlaneOutcome.
func auditOutcomeQuery(outcome string) osQuery {
	gw := osSource(auditSourceGateway)
	cp := osSource(auditSourceControlPlane)
	switch outcome {
	case AuditOutcomeDenied:
		return osOr(osAnd(gw, auditGatewayDenied()), osAnd(cp, osTerm("event.outcome", "deny")))
	case AuditOutcomeFailed:
		return osOr(
			osBool(map[string][]osQuery{"filter": {gw, auditGatewayFailed()}, "must_not": {auditGatewayDenied()}}),
			osAnd(cp, osTerm("event.outcome", "failure")),
		)
	case AuditOutcomeStarted:
		// Intent records exist only on the control plane.
		return osAnd(cp, osTerm("event.outcome", "unknown"))
	default: // AuditOutcomeSuccess
		// Only "success": an intent record ("unknown") is STARTED, so a failed
		// or refused privileged operation does not also appear as a success.
		return osOr(
			osBool(map[string][]osQuery{"filter": {gw}, "must_not": {auditGatewayDenied(), auditGatewayFailed()}}),
			osAnd(cp, osTerm("event.outcome", "success")),
		)
	}
}

func setToSorted(sets ...map[string]struct{}) []string {
	seen := map[string]struct{}{}
	for _, s := range sets {
		for k := range s {
			seen[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// auditTelemetryByName matches telemetry exports authenticated with an
// AMS-minted agent token, whose subject is the bare agent name.
func auditTelemetryByName(names []string) osQuery {
	return osAnd(osSource(auditSourceGateway), osTerm("auth.issuer", auditAMSIssuer), osTerms("auth.subject", names))
}

// auditAgentIdentifierClauses matches gateway records carrying any identifier
// of the given agents. Telemetry exports name the agent without its project,
// so they count for an agent only when its name is unique in the org — the
// same rule the normaliser applies (AuditAgentIndex.AgentByName).
func auditAgentIdentifierClauses(agents []*auditAgentIdentifiers, idx *AuditAgentIndex) []osQuery {
	apiNames := map[string]struct{}{}
	apiIDs := map[string]struct{}{}
	agentIDs := map[string]struct{}{}
	clientIDs := map[string]struct{}{}
	tokenIDs := map[string]struct{}{}
	names := map[string]struct{}{}
	for _, a := range agents {
		for k := range a.apiNames {
			apiNames[k] = struct{}{}
		}
		for k := range a.apiIDs {
			apiIDs[k] = struct{}{}
		}
		for k := range a.agentIDs {
			agentIDs[k] = struct{}{}
		}
		for k := range a.clientIDs {
			clientIDs[k] = struct{}{}
		}
		for k := range a.tokenIDs {
			tokenIDs[k] = struct{}{}
		}
		if ref, ok := idx.AgentByName(a.ref.Name); ok && ref.Project == a.ref.Project {
			names[a.ref.Name] = struct{}{}
		}
	}
	var out []osQuery
	if apis := setToSorted(apiNames, apiIDs); len(apis) > 0 {
		out = append(out, osTerms("api.name", apis), osTerms("api.id", apis))
	}
	if ids := setToSorted(agentIDs); len(ids) > 0 {
		out = append(out, osTerms("auth.subject", ids), osTerms("auth.claims.act.sub", ids))
	}
	if ids := setToSorted(clientIDs); len(ids) > 0 {
		out = append(out, osTerms("auth.clientId", ids))
	}
	if ids := setToSorted(tokenIDs); len(ids) > 0 {
		out = append(out, osTerms("auth.tokenId", ids))
	}
	var clauses []osQuery
	if len(out) > 0 {
		clauses = append(clauses, osAnd(osSource(auditSourceGateway), osOr(out...)))
	}
	if n := setToSorted(names); len(n) > 0 {
		clauses = append(clauses, auditTelemetryByName(n))
	}
	return clauses
}

// auditAgentFilter matches one agent filter value: every identifier AMS knows
// for the agent, plus the name-based fields that need no lookup (control-plane
// records naming the agent, and — for an agent AMS does not know, filtered
// without a project — telemetry exports whose token subject is that name).
func auditAgentFilter(value string, idx *AuditAgentIndex) osQuery {
	project, name, _ := splitAuditAgentFilter(value)
	matches := idx.match(project, name)
	clauses := auditAgentIdentifierClauses(matches, idx)
	if len(matches) == 0 && project == "" {
		clauses = append(clauses, auditTelemetryByName([]string{name}))
	}

	cp := []osQuery{osSource(auditSourceControlPlane)}
	if project != "" {
		cp = append(cp, osTerm("event.projectName", project))
	}
	byResource := append(append([]osQuery{}, cp...), osTerm("event.resourceType", "agent"), osTerm("event.resourceName", name))
	byDetail := append(append([]osQuery{}, cp...), osTerm("event.details.agentName", name))
	clauses = append(clauses, osAnd(byResource...), osAnd(byDetail...))
	return osOr(clauses...)
}

func auditProjectFilter(project string, idx *AuditAgentIndex) osQuery {
	clauses := auditAgentIdentifierClauses(idx.match(project, ""), idx)
	clauses = append(clauses, osAnd(osSource(auditSourceControlPlane), osTerm("event.projectName", project)))
	return osOr(clauses...)
}

func auditActorFilter(actor string) osQuery {
	return osOr(
		osContains("auth.subject", actor),
		osContains("auth.clientId", actor),
		osContains("event.actorId", actor),
		osContains("event.actorDisplay", actor),
	)
}

func auditSearchFilter(text string) osQuery {
	fields := []string{
		"event.action", "event.resourceName", "api.name", "mcp.name", "mcp.method",
		"ai.model", "ai.requestModel", "decision.deniedBy.policy", "a2a.operation",
	}
	qs := make([]osQuery, 0, len(fields))
	for _, f := range fields {
		qs = append(qs, osContains(f, text))
	}
	return osOr(qs...)
}

// buildAuditSearchBody builds the _search body for a normalised query. The
// category filter goes in post_filter so categoryCounts, computed by the
// aggregation, reflect every other filter but not the category itself.
func buildAuditSearchBody(q *AuditQuery, idx *AuditAgentIndex, namespaceFallback bool) (osQuery, error) {
	if q.OUID == "" || q.OrgHandle == "" {
		return nil, errors.New("audit query: missing organization scope")
	}
	filters := []osQuery{
		auditOrgScope(q.OUID, q.OrgHandle, namespaceFallback),
		{"range": osQuery{"@timestamp": osQuery{
			"gte":    q.Start.UTC().Format(time.RFC3339Nano),
			"lte":    q.End.UTC().Format(time.RFC3339Nano),
			"format": "strict_date_optional_time",
		}}},
	}
	if len(q.Agents) > 0 {
		agentClauses := make([]osQuery, 0, len(q.Agents))
		for _, a := range q.Agents {
			agentClauses = append(agentClauses, auditAgentFilter(a, idx))
		}
		filters = append(filters, osOr(agentClauses...))
	}
	if q.Project != "" {
		filters = append(filters, auditProjectFilter(q.Project, idx))
	}
	if q.Environment != "" {
		filters = append(filters, osOr(
			osAnd(osSource(auditSourceControlPlane), osTerm("event.environment", q.Environment)),
			osAnd(osSource(auditSourceGateway), osTerm("gateway.environment", q.Environment)),
		))
	}
	if len(q.Outcomes) > 0 {
		oc := make([]osQuery, 0, len(q.Outcomes))
		for _, o := range q.Outcomes {
			oc = append(oc, auditOutcomeQuery(o))
		}
		filters = append(filters, osOr(oc...))
	}
	if q.Actor != "" {
		filters = append(filters, auditActorFilter(q.Actor))
	}
	if q.Search != "" {
		filters = append(filters, auditSearchFilter(q.Search))
	}

	categoryAggs := osQuery{}
	for _, c := range AuditCategories {
		categoryAggs[c] = auditCategoryQuery(c)
	}

	order := auditSortOrder(q.Ascending)
	body := osQuery{
		// One more than the page, to know whether a next page exists.
		"size":             q.Limit + 1,
		"track_total_hits": auditTrackTotalHits,
		"query":            osAnd(filters...),
		"sort": []osQuery{
			{"@timestamp": osQuery{"order": order, "unmapped_type": "date"}},
			{"_id": osQuery{"order": order}},
		},
		"aggs": osQuery{"categories": osQuery{"filters": osQuery{"filters": categoryAggs}}},
	}
	if len(q.Categories) > 0 {
		cc := make([]osQuery, 0, len(q.Categories))
		for _, c := range q.Categories {
			cc = append(cc, auditCategoryQuery(c))
		}
		body["post_filter"] = osOr(cc...)
	}
	if q.Cursor != "" {
		after, err := decodeAuditCursor(q.Cursor, q.Ascending)
		if err != nil {
			return nil, err
		}
		body["search_after"] = after
	}
	return body, nil
}
