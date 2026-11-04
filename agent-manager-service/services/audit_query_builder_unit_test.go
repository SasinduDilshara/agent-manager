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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evalOS evaluates the subset of the OpenSearch query DSL the builder emits
// against one document, with keyword semantics (exact match), which is how the
// amp-audit index template maps these fields. It lets the tests check the
// query's meaning rather than its exact JSON.
func evalOS(t *testing.T, q any, doc map[string]any) bool {
	t.Helper()
	// Round-trip through JSON so the evaluator sees exactly what is sent.
	b, err := json.Marshal(q)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return evalOSNode(t, m, doc)
}

func osDocValues(doc map[string]any, field string) []any {
	var cur any = doc
	for _, p := range strings.Split(field, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	switch v := cur.(type) {
	case nil:
		return nil
	case []any:
		return v
	default:
		return []any{v}
	}
}

func osEq(a, b any) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

func evalOSNode(t *testing.T, q map[string]any, doc map[string]any) bool {
	t.Helper()
	require.Len(t, q, 1, "query node %v", q)
	for kind, raw := range q {
		body := raw.(map[string]any)
		switch kind {
		case "bool":
			for _, c := range asList(body["filter"]) {
				if !evalOSNode(t, c.(map[string]any), doc) {
					return false
				}
			}
			for _, c := range asList(body["must_not"]) {
				if evalOSNode(t, c.(map[string]any), doc) {
					return false
				}
			}
			should := asList(body["should"])
			if len(should) == 0 {
				return true
			}
			for _, c := range should {
				if evalOSNode(t, c.(map[string]any), doc) {
					return true
				}
			}
			return false
		case "term":
			for f, v := range body {
				for _, dv := range osDocValues(doc, f) {
					if osEq(dv, v) {
						return true
					}
				}
			}
			return false
		case "terms":
			for f, vs := range body {
				for _, v := range vs.([]any) {
					for _, dv := range osDocValues(doc, f) {
						if osEq(dv, v) {
							return true
						}
					}
				}
			}
			return false
		case "exists":
			return len(osDocValues(doc, body["field"].(string))) > 0
		case "prefix":
			for f, spec := range body {
				p := spec.(map[string]any)["value"].(string)
				for _, dv := range osDocValues(doc, f) {
					if strings.HasPrefix(fmt.Sprint(dv), p) {
						return true
					}
				}
			}
			return false
		case "wildcard":
			for f, spec := range body {
				pat := spec.(map[string]any)["value"].(string)
				require.True(t, strings.HasPrefix(pat, "*") && strings.HasSuffix(pat, "*"))
				needle := strings.NewReplacer(`\*`, "*", `\?`, "?", `\\`, `\`).Replace(pat[1 : len(pat)-1])
				for _, dv := range osDocValues(doc, f) {
					if strings.Contains(strings.ToLower(fmt.Sprint(dv)), strings.ToLower(needle)) {
						return true
					}
				}
			}
			return false
		case "range":
			for f, spec := range body {
				r := spec.(map[string]any)
				vals := osDocValues(doc, f)
				if len(vals) == 0 {
					return false
				}
				dv := vals[0]
				if f == "@timestamp" {
					ts, err := time.Parse(time.RFC3339Nano, fmt.Sprint(dv))
					require.NoError(t, err)
					gte, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(r["gte"]))
					lte, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(r["lte"]))
					return !ts.Before(gte) && !ts.After(lte)
				}
				var n float64
				if _, err := fmt.Sscan(fmt.Sprint(dv), &n); err != nil {
					return false
				}
				g, ok := r["gte"]
				return !ok || n >= g.(float64)
			}
			return false
		default:
			t.Fatalf("evaluator does not support %q", kind)
		}
	}
	return false
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// auditFixtureTime is inside the range used by these tests.
var auditFixtureTime = time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC)

// allAuditFixtures returns every live record, stamped with @timestamp.
func allAuditFixtures(t *testing.T) []map[string]any {
	t.Helper()
	docs := append(loadGatewayFixture(t), loadControlPlaneFixture(t)...)
	for _, d := range docs {
		d["@timestamp"] = auditFixtureTime.Format(time.RFC3339Nano)
	}
	return docs
}

func baseAuditQuery() *AuditQuery {
	return &AuditQuery{
		OUID: auditTestOUID, OrgHandle: auditTestOrgHandle,
		Start: auditFixtureTime.Add(-time.Hour), End: auditFixtureTime.Add(time.Hour),
	}
}

// matchBody reports whether a document is returned as a hit by the body:
// query AND post_filter.
func matchBody(t *testing.T, body osQuery, doc map[string]any) bool {
	t.Helper()
	if !evalOS(t, body["query"], doc) {
		return false
	}
	if pf, ok := body["post_filter"]; ok {
		return evalOS(t, pf, doc)
	}
	return true
}

func mustBuild(t *testing.T, q *AuditQuery, fallback bool) osQuery {
	t.Helper()
	require.NoError(t, q.Normalize(auditFixtureTime))
	body, err := buildAuditSearchBody(q, auditTestIndex(t), fallback)
	require.NoError(t, err)
	return body
}

func TestBuildAuditSearchBody_OrgScoping(t *testing.T) {
	gw := func(org, ns string) map[string]any {
		d := map[string]any{
			"audit_source": auditSourceGateway, "status": json.Number("200"),
			"@timestamp": auditFixtureTime.Format(time.RFC3339Nano),
			"kubernetes": map[string]any{"namespace_name": ns},
		}
		if org != "" {
			d["gateway"] = map[string]any{"organization": org}
		}
		return d
	}
	cp := func(ouID, handle string) map[string]any {
		return map[string]any{
			"audit_source": auditSourceControlPlane, "log_type": "audit",
			"@timestamp": auditFixtureTime.Format(time.RFC3339Nano),
			"event":      map[string]any{"ouId": ouID, "orgHandle": handle, "outcome": "success"},
		}
	}
	cases := []struct {
		name         string
		doc          map[string]any
		want         bool
		wantFallback bool
	}{
		{"own gateway record", gw("default", "default-default"), true, true},
		{"other org's gateway record", gw("acme", "acme-prod"), false, false},
		{"other org's gateway record in a look-alike namespace", gw("acme", "default-default"), false, false},
		{"own control-plane record", cp(auditTestOUID, "default"), true, true},
		{"other org's control-plane record", cp("other-ou", "acme"), false, false},
		// The OU id is authoritative; a matching handle on another OU is not ours.
		{"control-plane record with our handle but another OU", cp("other-ou", "default"), false, false},
		{"control-plane record with no OU", cp("", ""), false, false},
		// Without gateway.organization, only the opt-in namespace fallback admits it.
		{"unlabelled gateway record in our namespace", gw("", "default-default"), false, true},
		{"unlabelled gateway record in another namespace", gw("", "acme-prod"), false, false},
		{"record with no source", map[string]any{"@timestamp": auditFixtureTime.Format(time.RFC3339Nano), "gateway": map[string]any{"organization": "default"}}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, matchBody(t, mustBuild(t, baseAuditQuery(), false), c.doc), "default")
			assert.Equal(t, c.wantFallback, matchBody(t, mustBuild(t, baseAuditQuery(), true), c.doc), "with namespace fallback")
		})
	}

	// The org clause is the first filter of every query, whatever else is set.
	q := baseAuditQuery()
	q.Agents = []string{"ext-audit-agent"}
	q.Categories = []string{"LLM"}
	q.Actor, q.Search = "x", "y"
	body := mustBuild(t, q, false)
	filters := body["query"].(osQuery)["bool"].(osQuery)["filter"].([]osQuery)
	assert.Equal(t, auditOrgScope(auditTestOUID, auditTestOrgHandle, false), filters[0])

	// Every live record in the fixtures belongs to org "default"; querying as
	// another org returns none of them.
	other := &AuditQuery{OUID: "another-ou", OrgHandle: "acme", Start: auditFixtureTime.Add(-time.Hour), End: auditFixtureTime.Add(time.Hour)}
	require.NoError(t, other.Normalize(auditFixtureTime))
	otherBody, err := buildAuditSearchBody(other, newAuditAgentIndex(), true)
	require.NoError(t, err)
	for _, d := range allAuditFixtures(t) {
		assert.False(t, matchBody(t, otherBody, d), "leaked %s", docString(d, "eventId"))
	}

	// A missing org is refused, never treated as "all orgs".
	_, err = buildAuditSearchBody(&AuditQuery{OUID: auditTestOUID}, newAuditAgentIndex(), false)
	require.Error(t, err)
}

func TestBuildAuditSearchBody_TimeRange(t *testing.T) {
	q := baseAuditQuery()
	q.Start, q.End = auditFixtureTime.Add(time.Minute), auditFixtureTime.Add(time.Hour)
	body := mustBuild(t, q, false)
	for _, d := range allAuditFixtures(t) {
		assert.False(t, matchBody(t, body, d))
	}
}

// filterCase checks one filter against the live fixtures: the documents the
// query matches must be exactly those the predicate selects from the
// normalised events.
func assertFilterMatches(t *testing.T, mutate func(*AuditQuery), want func(doc map[string]any) bool) {
	t.Helper()
	q := baseAuditQuery()
	mutate(q)
	body := mustBuild(t, q, false)
	matched := 0
	for _, d := range allAuditFixtures(t) {
		got := matchBody(t, body, d)
		// Records with no org (AMS startup, gateway key sync on the internal
		// surface) are never returned to an org, whatever the filters.
		expected := auditFixtureInOrg(d) && want(d)
		if got != expected {
			t.Errorf("record %s %s: query matched=%v, expected %v",
				firstNonEmpty(docString(d, "eventId"), docString(d, "event", "eventId")),
				firstNonEmpty(docString(d, "client", "userAgent"), docString(d, "event", "action")), got, expected)
		}
		if got {
			matched++
		}
	}
	assert.Positive(t, matched, "filter matched nothing; the case proves nothing")
}

func auditFixtureInOrg(d map[string]any) bool {
	if auditSourceOf(d) == auditSourceControlPlane {
		return docString(d, "event", "ouId") == auditTestOUID
	}
	return docString(d, "gateway", "organization") == auditTestOrgHandle
}

func TestBuildAuditSearchBody_Filters(t *testing.T) {
	idx := auditTestIndex(t)
	norm := func(d map[string]any) normalizedForTest {
		e := normalizeAuditDocument("", d, idx)
		n := normalizedForTest{category: string(e.Category), outcome: string(e.Outcome), env: e.Environment, project: e.Project, action: e.Action}
		if a := e.Agent.Get(); a != nil {
			n.agent = a.Project + "/" + a.Name
		}
		n.actorID, n.clientID = e.Actor.Id, e.Actor.ClientId
		n.subject = docString(d, "auth", "subject")
		return n
	}

	t.Run("agent, project-qualified", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Agents = []string{"default/ext-audit-agent"} },
			func(d map[string]any) bool { return norm(d).agent == "default/ext-audit-agent" })
	})
	t.Run("agent, any project, several", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Agents = []string{"int-audit-agent", "a2a-notes-agent"} },
			func(d map[string]any) bool {
				a := norm(d).agent
				return a == "default/int-audit-agent" || a == "default/a2a-notes-agent"
			})
	})
	t.Run("agent in another project matches nothing", func(t *testing.T) {
		q := baseAuditQuery()
		q.Agents = []string{"other/ext-audit-agent"}
		body := mustBuild(t, q, false)
		for _, d := range allAuditFixtures(t) {
			assert.False(t, matchBody(t, body, d))
		}
	})
	t.Run("agent unknown to AMS still matches records naming it", func(t *testing.T) {
		q := baseAuditQuery()
		q.Agents = []string{"ghost-agent"}
		doc := map[string]any{
			"audit_source": auditSourceGateway, "@timestamp": auditFixtureTime.Format(time.RFC3339Nano),
			"gateway": map[string]any{"organization": "default"},
			"api":     map[string]any{"kind": "RestApi", "context": "/otel"},
			"auth":    map[string]any{"subject": "ghost-agent", "issuer": auditAMSIssuer, "authenticated": true},
		}
		assert.True(t, matchBody(t, mustBuild(t, q, false), doc))
		require.NotNil(t, normalizeAuditDocument("", doc, idx).Agent.Get())
		assert.Equal(t, "ghost-agent", normalizeAuditDocument("", doc, idx).Agent.Get().Name)
	})
	t.Run("project", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Project = "default" },
			func(d map[string]any) bool { return norm(d).project == "default" })
	})
	t.Run("environment", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Environment = "default" },
			func(d map[string]any) bool { return norm(d).env == "default" })
	})
	for _, o := range auditOutcomes {
		t.Run("outcome "+o, func(t *testing.T) {
			assertFilterMatches(t, func(q *AuditQuery) { q.Outcomes = []string{o} },
				func(d map[string]any) bool { return norm(d).outcome == o })
		})
	}
	for _, c := range AuditCategories {
		t.Run("category "+c, func(t *testing.T) {
			assertFilterMatches(t, func(q *AuditQuery) { q.Categories = []string{c} },
				func(d map[string]any) bool { return norm(d).category == c })
		})
	}
	t.Run("actor substring, case-insensitive", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Actor = "XSEACX4P" },
			func(d map[string]any) bool { return norm(d).clientID == "XSEAcx4PKsuGH_oNsN4LkA" })
	})
	t.Run("actor matches control-plane actor id", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Actor = "amp-api-client" },
			func(d map[string]any) bool { return docString(d, "event", "actorId") == "amp-api-client" })
	})
	t.Run("search over tool name", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Search = "orderpizza" },
			func(d map[string]any) bool { return docString(d, "mcp", "name") == "orderPizza" })
	})
	t.Run("search over denying policy", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Search = "content-length" },
			func(d map[string]any) bool {
				return docString(d, "decision", "deniedBy", "policy") == "content-length-guardrail"
			})
	})
	t.Run("search over control-plane action", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) { q.Search = "thunder-url:" },
			func(d map[string]any) bool { return docString(d, "event", "action") == "thunder-url:set" })
	})
	t.Run("filters combine with AND", func(t *testing.T) {
		assertFilterMatches(t, func(q *AuditQuery) {
			q.Agents = []string{"ext-audit-agent"}
			q.Categories = []string{"MCP"}
			q.Outcomes = []string{"DENIED"}
		}, func(d map[string]any) bool {
			n := norm(d)
			return n.agent == "default/ext-audit-agent" && n.category == "MCP" && n.outcome == "DENIED"
		})
	})
}

type normalizedForTest struct {
	category, outcome, env, project, action, agent, actorID, clientID, subject string
}

func TestBuildAuditSearchBody_WildcardInputIsLiteral(t *testing.T) {
	q := baseAuditQuery()
	q.Search = `*`
	body := mustBuild(t, q, false)
	for _, d := range allAuditFixtures(t) {
		assert.False(t, matchBody(t, body, d), "a literal * must not match everything")
	}
	assert.Equal(t, `a\*b\?c\\d`, escapeAuditWildcard(`a*b?c\d`))
}

func TestBuildAuditSearchBody_CategoryCountsIgnoreCategoryFilter(t *testing.T) {
	q := baseAuditQuery()
	q.Categories = []string{"LLM"}
	q.Outcomes = []string{"DENIED"}
	body := mustBuild(t, q, false)

	// The category filter is only in post_filter, never in the query the
	// aggregation runs over.
	queryJSON, err := json.Marshal(body["query"])
	require.NoError(t, err)
	assert.NotContains(t, string(queryJSON), "LlmProvider")
	require.Contains(t, body, "post_filter")

	aggs := body["aggs"].(osQuery)["categories"].(osQuery)["filters"].(osQuery)["filters"].(osQuery)
	assert.Len(t, aggs, len(AuditCategories))

	// Counting with the aggregation's filters over the query's matches gives
	// per-category counts across every category, not just LLM.
	counts := map[string]int{}
	for _, d := range allAuditFixtures(t) {
		if !evalOS(t, body["query"], d) {
			continue
		}
		for c, f := range aggs {
			if evalOS(t, f, d) {
				counts[c]++
			}
		}
	}
	assert.Positive(t, counts["LLM"])
	assert.Positive(t, counts["MCP"])
	assert.Positive(t, counts["OTHER"])
}

func TestBuildAuditSearchBody_SortAndPaging(t *testing.T) {
	q := baseAuditQuery()
	q.Limit = 10
	body := mustBuild(t, q, false)
	assert.Equal(t, 11, body["size"], "one extra hit detects a next page")
	assert.Equal(t, auditTrackTotalHits, body["track_total_hits"])
	sortSpec := body["sort"].([]osQuery)
	assert.Equal(t, "desc", sortSpec[0]["@timestamp"].(osQuery)["order"])
	assert.Equal(t, "desc", sortSpec[1]["_id"].(osQuery)["order"])
	assert.NotContains(t, body, "search_after")

	asc := baseAuditQuery()
	asc.Ascending = true
	assert.Equal(t, "asc", mustBuild(t, asc, false)["sort"].([]osQuery)[0]["@timestamp"].(osQuery)["order"])
}

func TestAuditCursor_RoundTrip(t *testing.T) {
	sortValues := []json.RawMessage{json.RawMessage(`1793799288935`), json.RawMessage(`"F319EB70-2BB2"`)}
	cur, err := encodeAuditCursor(sortValues, false)
	require.NoError(t, err)

	q := baseAuditQuery()
	q.Cursor = cur
	body := mustBuild(t, q, false)
	b, err := json.Marshal(body["search_after"])
	require.NoError(t, err)
	assert.JSONEq(t, `[1793799288935,"F319EB70-2BB2"]`, string(b))

	// A cursor is bound to its sort order.
	q2 := baseAuditQuery()
	q2.Cursor, q2.Ascending = cur, true
	require.ErrorIs(t, q2.Normalize(auditFixtureTime), ErrAuditInvalidQuery)
}

func TestAuditCursor_RejectsTampering(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, cur := range map[string]string{
		"not base64":         "%%%",
		"not json":           enc("nope"),
		"wrong arity":        enc(`{"o":"desc","a":[1]}`),
		"extra values":       enc(`{"o":"desc","a":[1,"x",{"match_all":{}}]}`),
		"object timestamp":   enc(`{"o":"desc","a":[{"script":"x"},"x"]}`),
		"fractional ts":      enc(`{"o":"desc","a":[1.5,"x"]}`),
		"non-string id":      enc(`{"o":"desc","a":[1,{"a":1}]}`),
		"empty id":           enc(`{"o":"desc","a":[1,""]}`),
		"oversized":          strings.Repeat("A", auditMaxCursorBytes+1),
		"wrong order marker": enc(`{"o":"sideways","a":[1,"x"]}`),
	} {
		t.Run(name, func(t *testing.T) {
			q := baseAuditQuery()
			q.Cursor = cur
			require.ErrorIs(t, q.Normalize(auditFixtureTime), ErrAuditInvalidQuery)
		})
	}
}

func TestAuditQuery_Normalize(t *testing.T) {
	now := auditFixtureTime
	t.Run("defaults", func(t *testing.T) {
		q := &AuditQuery{OUID: "o", OrgHandle: "h"}
		require.NoError(t, q.Normalize(now))
		assert.Equal(t, now, q.End)
		assert.Equal(t, now.Add(-24*time.Hour), q.Start)
		assert.Equal(t, AuditDefaultLimit, q.Limit)
	})
	t.Run("enums are case-insensitive and deduplicated", func(t *testing.T) {
		q := &AuditQuery{OUID: "o", OrgHandle: "h", Categories: []string{"llm", "LLM", " mcp "}, Outcomes: []string{"denied"}}
		require.NoError(t, q.Normalize(now))
		assert.Equal(t, []string{"LLM", "MCP"}, q.Categories)
		assert.Equal(t, []string{"DENIED"}, q.Outcomes)
	})
	invalid := map[string]func(*AuditQuery){
		"start after end":          func(q *AuditQuery) { q.Start, q.End = now, now.Add(-time.Hour) },
		"empty range":              func(q *AuditQuery) { q.Start, q.End = now, now },
		"range over 186 days":      func(q *AuditQuery) { q.Start, q.End = now.Add(-187*24*time.Hour), now },
		"limit too large":          func(q *AuditQuery) { q.Limit = AuditMaxLimit + 1 },
		"negative limit":           func(q *AuditQuery) { q.Limit = -1 },
		"unknown category":         func(q *AuditQuery) { q.Categories = []string{"SECRET"} },
		"unknown outcome":          func(q *AuditQuery) { q.Outcomes = []string{"MAYBE"} },
		"agent with two slashes":   func(q *AuditQuery) { q.Agents = []string{"a/b/c"} },
		"agent with empty project": func(q *AuditQuery) { q.Agents = []string{"/b"} },
		"too many agents": func(q *AuditQuery) {
			for i := 0; i <= auditMaxAgentValues; i++ {
				q.Agents = append(q.Agents, fmt.Sprintf("a%d", i))
			}
		},
		"long search": func(q *AuditQuery) { q.Search = strings.Repeat("x", auditMaxFilterText+1) },
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			q := &AuditQuery{OUID: "o", OrgHandle: "h"}
			mutate(q)
			require.ErrorIs(t, q.Normalize(now), ErrAuditInvalidQuery)
		})
	}
	t.Run("exactly 186 days is allowed", func(t *testing.T) {
		q := &AuditQuery{OUID: "o", OrgHandle: "h", Start: now.Add(-AuditMaxRange), End: now}
		require.NoError(t, q.Normalize(now))
	})
	t.Run("missing org is not a caller error", func(t *testing.T) {
		err := (&AuditQuery{OrgHandle: "h"}).Normalize(now)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrAuditInvalidQuery)
	})
}
