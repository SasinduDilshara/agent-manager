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

// Package azure holds the Azure OpenAI and the Microsoft Foundry Agent
// Service connectors of Shadow Agent Discovery. Both sign in with the same
// Entra app (client credentials), read Azure Resource Manager for
// subscriptions, Cognitive Services accounts, deployments, Foundry projects,
// Azure Monitor metrics and the Activity Log, and the Foundry connector also
// reads the Foundry project data plane (agents, classic agents and, with
// deep inspection, stored responses).
package azure

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// API versions (evidence/azure_openai.md §2.0-2.4, evidence/foundry.md).
const (
	apiSubscriptions = "2022-12-01" // Subscriptions_List
	apiCognitive     = "2025-06-01" // Accounts_List, Deployments_List, Projects_List
	apiMetrics       = "2023-10-01" // Metrics_List
	apiFoundry       = "v1"         // Foundry data plane /agents and classic /assistants
)

// Bounds.
const (
	maxARMPages   = 100 // ARM list pages (1,000 items per page typical)
	maxAgentPages = 100 // Foundry /agents and /assistants pages of 100
	metricsTop    = 1000
	// metricsMaxAttempts retries the metrics backend's 529, which the Azure
	// SDK pipeline does not retry.
	metricsMaxAttempts = 3
)

// Call names, recorded per scope (subscription, account, project).
const (
	callSignIn        = "Microsoft Entra sign-in"
	callSubscriptions = "GET /subscriptions"
	callAccounts      = "GET /subscriptions/{subscriptionId}/providers/Microsoft.CognitiveServices/accounts"
	callMetrics       = "GET {accountId}/providers/Microsoft.Insights/metrics"
	callProjects      = "GET {accountId}/projects"
	callProjectEP     = `ARM project properties.endpoints["AI Foundry API"]`
	callAgents        = "GET {projectEndpoint}/agents"
	callAssistants    = "GET {projectEndpoint}/assistants"
	callResponses     = "GET {projectEndpoint}/openai/v1/responses"
)

// Account kinds (free strings in the spec; documented in Learn prose).
const (
	kindAIServices = "AIServices"
)

// base is what the Foundry connector holds: the HTTP client, the logger and
// the wait used between metrics retries.
type base struct {
	httpClient *http.Client
	logger     *slog.Logger
	sleep      func(ctx context.Context, d time.Duration) error
}

func newBase(httpClient *http.Client, logger *slog.Logger) base {
	if httpClient == nil {
		httpClient = sa.NewHTTPClient(nil)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return base{httpClient: httpClient, logger: logger, sleep: sleepCtx}
}

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

// jsonGetter is the part of sa.AzureClient the connectors use.
type jsonGetter interface {
	GetJSON(ctx context.Context, u string, out any) error
}

// armClient calls ARM at the configured endpoint.
type armClient struct {
	client jsonGetter
	base   *url.URL
	sleep  func(ctx context.Context, d time.Duration) error
}

// session is one scan's (or test's) signed-in clients.
type session struct {
	cred azcore.TokenCredential
	arm  *armClient
}

// newSession builds the Entra credential and the ARM client from the
// connection. Every URL comes from the connection's endpoints.
func (b base) newSession(conn sa.Connection) (*session, error) {
	login, err := sa.Expand(sa.EndpointOf(conn, sa.EPAzureLogin), nil)
	if err != nil || login == "" {
		return nil, &sa.CallError{Outcome: models.ShadowCallFailed, Message: "the Microsoft Entra login endpoint is not set"}
	}
	armRaw, err := sa.Expand(sa.EndpointOf(conn, sa.EPAzureARM), nil)
	if err != nil || armRaw == "" {
		return nil, &sa.CallError{Outcome: models.ShadowCallFailed, Message: "the Azure Resource Manager endpoint is not set"}
	}
	armURL, err := url.Parse(armRaw)
	if err != nil || armURL.Host == "" || (armURL.Scheme != "https" && armURL.Scheme != "http") {
		return nil, &sa.CallError{Outcome: models.ShadowCallFailed, Message: "the Azure Resource Manager endpoint is not a valid URL"}
	}
	armURL.RawQuery, armURL.Fragment = "", ""
	cred, err := sa.AzureCredential(b.httpClient, login, conn.Config.TenantID, conn.Config.ClientID, conn.Secret.ClientSecret)
	if err != nil {
		return nil, &sa.CallError{Outcome: models.ShadowCallAuthFailed, Message: sa.ScrubText(err.Error())}
	}
	return &session{
		cred: cred,
		arm: &armClient{
			client: sa.NewAzureClient(b.httpClient, cred, sa.AzureARMScope),
			base:   armURL,
			sleep:  b.sleep,
		},
	}, nil
}

// qp is one query parameter, kept in order.
type qp struct{ k, v string }

// buildURL joins base, path and query. Query keys starting with "$" keep the
// "$" literal (ARM's $filter, $top); values are escaped with %20 for spaces,
// so ARM's OData filters arrive exactly as documented.
func buildURL(baseURL, path string, params ...qp) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(baseURL, "/"))
	b.WriteString((&url.URL{Path: path}).EscapedPath())
	for i, p := range params {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		if strings.HasPrefix(p.k, "$") {
			b.WriteString("$" + queryEscape(p.k[1:]))
		} else {
			b.WriteString(queryEscape(p.k))
		}
		b.WriteByte('=')
		b.WriteString(queryEscape(p.v))
	}
	return b.String()
}

func queryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// url returns an ARM URL for path (an absolute ARM path such as
// /subscriptions/x or an ARM resource ID plus a suffix).
func (a *armClient) url(path string, params ...qp) string {
	return buildURL(strings.TrimRight(a.base.String(), "/"), path, params...)
}

// sameOrigin reports whether link has the configured ARM endpoint's scheme
// and host: a nextLink pointing anywhere else is never followed, so the ARM
// token is never sent to a host the user did not configure.
func (a *armClient) sameOrigin(link string) bool {
	u, err := url.Parse(link)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Scheme, a.base.Scheme) && strings.EqualFold(u.Host, a.base.Host)
}

// armPage is the generic ARM list envelope.
type armPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"nextLink"`
}

// armList pages an ARM list through nextLink. It returns the item count,
// a reason when it stopped before the end (page limit, foreign nextLink),
// and the error of the failing page.
func armList[T any](ctx context.Context, a *armClient, first string, maxPages int, each func(T)) (int, string, error) {
	n := 0
	next := first
	for page := 0; next != ""; page++ {
		if page == maxPages {
			return n, fmt.Sprintf("stopped after %d pages; the results are partial", maxPages), nil
		}
		if err := ctx.Err(); err != nil {
			return n, "", &sa.CallError{Outcome: models.ShadowCallFailed, Message: "cancelled: " + err.Error()}
		}
		var p armPage[T]
		if err := a.client.GetJSON(ctx, next, &p); err != nil {
			return n, "", err
		}
		for _, v := range p.Value {
			each(v)
			n++
		}
		next = strings.TrimSpace(p.NextLink)
		if next != "" && !a.sameOrigin(next) {
			return n, "nextLink points outside the configured Azure Resource Manager endpoint; it was not followed and the results are partial", nil
		}
	}
	return n, "", nil
}

// record records an ARM list call and, when it stopped early, a skipped
// "(more pages)" entry saying why.
func record(calls *sa.Calls, logger *slog.Logger, call string, n int, stop string, err error) {
	calls.Record(call, n, err)
	if stop != "" {
		calls.Skip(call+" (more pages)", stop)
		logger.Warn("Shadow agent discovery stopped paging", "call", call, "reason", stop)
	}
}

func isAuthFailure(err error) bool {
	return sa.OutcomeOf(err) == models.ShadowCallAuthFailed
}

func statusOf(err error) int {
	var ce *sa.CallError
	if errors.As(err, &ce) {
		return ce.Status
	}
	return 0
}

// subscription is a Subscriptions_List item.
type subscription struct {
	SubscriptionID string `json:"subscriptionId"`
	State          string `json:"state"`
}

// subscriptions returns the subscriptions to scan: every Enabled
// subscription the app can read, or the configured list. stop is true when
// the very first ARM call failed authentication.
func (a *armClient) subscriptions(ctx context.Context, conn sa.Connection, calls *sa.Calls, logger *slog.Logger) ([]string, bool) {
	if !conn.Config.AllSubscriptions {
		var out []string
		seen := map[string]bool{}
		for _, s := range conn.Config.SubscriptionIDs {
			s = strings.TrimSpace(s)
			if s != "" && !seen[strings.ToLower(s)] {
				seen[strings.ToLower(s)] = true
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			calls.Skip(callSubscriptions, "no subscription IDs are configured")
		}
		return out, false
	}
	var out []string
	disabled := 0
	n, stop, err := armList(ctx, a, a.url("/subscriptions", qp{"api-version", apiSubscriptions}), maxARMPages, func(s subscription) {
		// Skip any state other than Enabled (evidence §2.0).
		if s.SubscriptionID == "" || !strings.EqualFold(s.State, "Enabled") {
			disabled++
			return
		}
		out = append(out, s.SubscriptionID)
	})
	record(calls, logger, callSubscriptions, n, stop, err)
	if disabled > 0 {
		logger.Debug("Shadow agent discovery skipped subscriptions that are not enabled", "count", disabled)
	}
	return out, err != nil && isAuthFailure(err)
}

// systemData is the ARM common-types systemData (optional, readOnly).
type systemData struct {
	CreatedBy     string `json:"createdBy"`
	CreatedByType string `json:"createdByType"`
	CreatedAt     string `json:"createdAt"`
}

// account is an Accounts_List item (2025-06-01).
type account struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Kind       string      `json:"kind"`
	Location   string      `json:"location"`
	SystemData *systemData `json:"systemData"`
	Properties struct {
		DisableLocalAuth       *bool  `json:"disableLocalAuth"`
		AllowProjectManagement *bool  `json:"allowProjectManagement"`
		ProvisioningState      string `json:"provisioningState"`
	} `json:"properties"`
	subscriptionID string
}

// accounts lists the subscription's Cognitive Services accounts whose kind
// is one of kinds (case-insensitive).
func (a *armClient) accounts(ctx context.Context, sub string, kinds []string, calls *sa.Calls, logger *slog.Logger) ([]*account, error) {
	var out []*account
	u := a.url("/subscriptions/"+sub+"/providers/Microsoft.CognitiveServices/accounts", qp{"api-version", apiCognitive})
	n, stop, err := armList(ctx, a, u, maxARMPages, func(acc account) {
		if acc.ID == "" {
			return
		}
		for _, k := range kinds {
			if strings.EqualFold(acc.Kind, k) {
				acc.subscriptionID = sub
				out = append(out, &acc)
				return
			}
		}
	})
	record(calls, logger, callAccounts, n, stop, err)
	return out, err
}

// parseTime parses an RFC 3339 timestamp leniently.
func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

// ownerHint builds a minimised owner hint from a principal string (an
// email, a UPN or an application/object ID).
func ownerHint(principal, typ, source string, at *time.Time) models.ShadowOwnerHint {
	principal = strings.TrimSpace(principal)
	h := models.ShadowOwnerHint{Type: typ, Source: source, CreatedAt: at}
	if strings.Contains(principal, "@") {
		h.Email = principal
	} else {
		h.Username = principal
	}
	return sa.MinimiseOwnerHint(h)
}

func hasOwner(h models.ShadowOwnerHint) bool {
	return h.Email != "" || h.Username != "" || h.Name != ""
}
