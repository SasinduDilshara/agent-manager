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

package authz

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/wso2/agent-manager/test/e2e/framework"
)

// SEC-AUDIT-001..005 — the org audit trail API (GET /orgs/{org}/audit/events).
//
// The API is feature-flagged (agentManagerService.config.auditQuery.enabled).
// When it is off the route must still be authorised and answer 503; the
// data specs are then skipped, since there is no trail to read.

const auditScope = "amp:audit:read"

// auditEvent is the part of an AuditEvent these specs read.
type auditEvent struct {
	ID         string                         `json:"id"`
	Source     string                         `json:"source"`
	Category   string                         `json:"category"`
	Action     string                         `json:"action"`
	Outcome    string                         `json:"outcome"`
	StatusCode *int                           `json:"statusCode"`
	Gateway    *struct{ Organization string } `json:"gateway"`
	Raw        map[string]any                 `json:"raw"`
}

type auditPage struct {
	Events         []auditEvent     `json:"events"`
	Total          int64            `json:"total"`
	CategoryCounts map[string]int64 `json:"categoryCounts"`
}

func auditPath(org string, q url.Values) string {
	return fmt.Sprintf("/api/v1/orgs/%s/audit/events?%s", org, q.Encode())
}

// readAudit GETs the trail. It returns the status, and the page when 200.
func readAudit(ctx SpecContext, c *framework.AMPClient, org string, q url.Values) (int, auditPage, string) {
	resp, err := c.GetWithContext(ctx, auditPath(org, q))
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var page auditPage
	if resp.StatusCode == http.StatusOK {
		Expect(json.Unmarshal(body, &page)).To(Succeed(), "decode audit page: %s", body)
	}
	return resp.StatusCode, page, string(body)
}

// requireAuditAPI skips the data specs when the deployment has the API off,
// after checking that "off" is reported as 503 and not as anything else.
func requireAuditAPI(ctx SpecContext) {
	status, _, body := readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{"limit": {"1"}})
	if status == http.StatusServiceUnavailable {
		Expect(body).To(ContainSubstring("not enabled"))
		Skip("the audit query API is not enabled on this deployment (503)")
	}
	Expect(status).To(Equal(http.StatusOK), "audit API: %s", body)
}

func detailsOf(e auditEvent) map[string]any {
	ev, _ := e.Raw["event"].(map[string]any)
	d, _ := ev["details"].(map[string]any)
	return d
}

var _ = Describe("SEC-AUDIT: org audit trail", Label("security", "audit"), func() {
	It("SEC-AUDIT-001: refuses a token holding every scope but audit:read, log-read included", func(ctx SpecContext) {
		deny := clientWithScopes(ctx, framework.ScopesExcept(auditScope))
		status, _, body := readAudit(ctx, deny, Cfg.DefaultOrg, url.Values{"limit": {"1"}})
		Expect(status).To(Equal(http.StatusForbidden), body)
	})

	It("SEC-AUDIT-002: answers 200 or, with the API off, 503 to an audit:read token", func(ctx SpecContext) {
		allow := clientWithScopes(ctx, []string{auditScope})
		status, _, body := readAudit(ctx, allow, Cfg.DefaultOrg, url.Values{"limit": {"1"}})
		Expect(status).To(BeElementOf(http.StatusOK, http.StatusServiceUnavailable), body)
	})

	It("SEC-AUDIT-003: scopes records to the token's org whatever the path names, and hides platform metadata", func(ctx SpecContext) {
		requireAuditAPI(ctx)
		q := url.Values{"limit": {"200"}, "startTime": {time.Now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)}}
		status, page, body := readAudit(ctx, Client, "e2e-test-not-my-org", q)
		Expect(status).To(Equal(http.StatusOK), body)
		for _, e := range page.Events {
			if e.Gateway != nil && e.Gateway.Organization != "" {
				Expect(e.Gateway.Organization).To(Equal(Cfg.DefaultOrg), "gateway record %s", e.ID)
			}
			if ev, ok := e.Raw["event"].(map[string]any); ok {
				if h, _ := ev["orgHandle"].(string); h != "" {
					Expect(h).To(Equal(Cfg.DefaultOrg), "control-plane record %s", e.ID)
				}
			}
			raw, _ := json.Marshal(e.Raw)
			for _, leak := range []string{`"pod_ip"`, `"host"`, `"annotations"`, `"labels"`, `"container_image"`, `"docker_id"`} {
				Expect(string(raw)).NotTo(ContainSubstring(leak), "raw of %s exposes platform metadata", e.ID)
			}
		}
	})

	It("SEC-AUDIT-004: applies category and outcome filters and rejects bad ones", func(ctx SpecContext) {
		requireAuditAPI(ctx)
		since := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)

		status, page, body := readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{"category": {"OPERATIONAL"}, "startTime": {since}, "limit": {"100"}})
		Expect(status).To(Equal(http.StatusOK), body)
		for _, e := range page.Events {
			Expect(e.Category).To(Equal("OPERATIONAL"))
			Expect(e.Source).To(Equal("CONTROL_PLANE"))
		}

		status, page, body = readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{"outcome": {"DENIED"}, "startTime": {since}, "limit": {"100"}})
		Expect(status).To(Equal(http.StatusOK), body)
		for _, e := range page.Events {
			Expect(e.Outcome).To(Equal("DENIED"))
		}

		status, _, body = readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{"outcome": {"MAYBE"}})
		Expect(status).To(Equal(http.StatusBadRequest), body)
		status, _, body = readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{"limit": {"ten"}})
		Expect(status).To(Equal(http.StatusBadRequest), body)
		// Substring search over more than 31 days needs an agent or project.
		status, _, body = readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{
			"search": {"agent"}, "startTime": {time.Now().Add(-60 * 24 * time.Hour).UTC().Format(time.RFC3339)},
		})
		Expect(status).To(Equal(http.StatusBadRequest), body)
		Expect(body).To(ContainSubstring("31 days"))
	})

	It("SEC-AUDIT-005: records each read of the trail once, with its filters and status", func(ctx SpecContext) {
		requireAuditAPI(ctx)
		start := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		// Word-shaped, so the secret masker leaves it as sent.
		marker := "e2eauditmarker" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

		status, _, body := readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{"search": {marker}, "limit": {"5"}})
		Expect(status).To(Equal(http.StatusOK), body)
		status, _, body = readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{"search": {marker}, "limit": {"ten"}})
		Expect(status).To(Equal(http.StatusBadRequest), body)

		By("waiting for the two audit:read records to reach the trail (log pipeline delay)")
		var mine []auditEvent
		Eventually(func(g Gomega) {
			mine = nil
			st, page, b := readAudit(ctx, Client, Cfg.DefaultOrg, url.Values{
				"category": {"OPERATIONAL"}, "search": {"audit:read"}, "startTime": {start}, "limit": {"200"},
			})
			g.Expect(st).To(Equal(http.StatusOK), b)
			for _, e := range page.Events {
				if d := detailsOf(e); d != nil && d["search"] == marker {
					mine = append(mine, e)
				}
			}
			g.Expect(mine).To(HaveLen(2))
		}).WithContext(ctx).WithTimeout(3 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())

		statuses := map[int]auditEvent{}
		for _, e := range mine {
			Expect(e.Action).To(Equal("audit:read"))
			Expect(e.StatusCode).NotTo(BeNil(), "record %s carries the response status", e.ID)
			statuses[*e.StatusCode] = e
			Expect(detailsOf(e)).NotTo(HaveKey("envelope"), "one record per read, not an envelope beside it")
		}
		Expect(statuses).To(HaveKey(http.StatusOK))
		Expect(statuses).To(HaveKey(http.StatusBadRequest))
		Expect(detailsOf(statuses[http.StatusBadRequest])["rejectedParameter"]).To(Equal("limit"))
		Expect(statuses[http.StatusOK].Outcome).To(Equal("SUCCESS"))
		Expect(statuses[http.StatusBadRequest].Outcome).To(Equal("FAILED"))
	})
})
