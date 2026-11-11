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
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// variantConn is a connection with only a cloud variant set up (no Admin
// key, no workspace keys), so the first-party calls are skipped.
func (h *harness) variantConn() sa.Connection {
	conn := h.conn()
	conn.Secret = models.ShadowConnectionSecret{}
	conn.Config.IncludeCloudVariants = true
	conn.Config.Endpoints[sa.EPAnthropicAWS] = h.m.srv.URL + "/aws/{region}"
	conn.Config.Endpoints[sa.EPAnthropicAWSSTS] = h.m.srv.URL + "/sts/{region}"
	conn.Config.Endpoints[sa.EPAnthropicGCP] = h.m.srv.URL + "/gcp"
	conn.Config.Endpoints[sa.EPAnthropicGCPToken] = h.m.srv.URL + "/token"
	return conn
}

func (h *harness) awsConn() sa.Connection {
	conn := h.variantConn()
	conn.Config.Regions = []string{"us-west-2"}
	conn.Config.AccessKeyID = awsAccessKey
	conn.Secret.SecretAccessKey = awsSecret
	return conn
}

func TestVariantsNotConfigured(t *testing.T) {
	h := newHarness(t)
	res := h.scan(h.variantConn())
	for _, call := range []string{"Claude Platform on AWS", "Claude Models on Google Cloud"} {
		if c := callOf(t, res, call); c.Outcome != models.ShadowCallSkipped || c.Message != "not configured" {
			t.Errorf("%s = %+v", call, c)
		}
	}
	// Variants off: nothing is recorded for them.
	conn := h.variantConn()
	conn.Config.IncludeCloudVariants = false
	for _, c := range h.scan(conn).Calls {
		if strings.HasPrefix(c.Call, "Claude ") {
			t.Errorf("variant call recorded with the option off: %+v", c)
		}
	}
}

func TestAWSVariant(t *testing.T) {
	h := newHarness(t)
	for _, r := range []string{"aws /v1/organizations/api_keys", "aws /v1/organizations/users"} {
		h.m.forbid[r] = true
	}
	res := h.scan(h.awsConn())

	// SigV4, region and the workspace header are checked by the mock.
	if n := h.m.hits("aws /v1/organizations/workspaces"); n != 2 {
		t.Errorf("AWS workspaces pages = %d", n)
	}
	for _, ws := range []string{wsA, wsB} {
		found := false
		for _, r := range h.m.requestsTo("aws /v1/agents") {
			if r.Header.Get("anthropic-workspace-id") == ws && r.Region == "us-west-2" {
				found = true
			}
		}
		if !found {
			t.Errorf("no AWS agents call for workspace %s", ws)
		}
	}
	usage := h.m.requestsTo("aws /v1/organizations/analytics/usage")
	// The SigV4 signer rewrites the query to its canonical form (brackets
	// percent-encoded, values sorted); the values are what matter.
	if len(usage) != 1 {
		t.Fatalf("AWS usage requests = %d", len(usage))
	}
	gb := queryOf(t, usage[0].RawQuery)["group_by[]"]
	sort.Strings(gb)
	if strings.Join(gb, ",") != "actor,agent_id,api_key_id,model,product" {
		t.Errorf("AWS usage group_by = %v", gb)
	}
	for _, call := range []string{prefixAWS + callAPIKeys, prefixAWS + callUsers} {
		if c := callOf(t, res, call); c.Outcome != models.ShadowCallSkipped || !strings.Contains(c.Message, "not available") {
			t.Errorf("%s = %+v", call, c)
		}
	}
	for _, call := range []string{callWorkspaces, callUsage, callCost, callAgents, callSessions, callEvents, callBatches, callBatchResults} {
		if c := callOf(t, res, prefixAWS+call); c.Outcome != models.ShadowCallOK {
			t.Errorf("%s = %+v", prefixAWS+call, c)
		}
	}
	if res.KeysListed || len(res.Keys) != 0 {
		t.Errorf("no key listing on AWS: KeysListed %v keys %d", res.KeysListed, len(res.Keys))
	}

	// The federated IAM principal becomes a principal finding.
	pf := findingOf(t, res, models.ShadowKindPrincipal, "aws:arn:aws:iam::123456789012:role/app")
	if pf.Scope != "aws:us-west-2" || pf.Attributes["region"] != "us-west-2" || pf.Attributes["accountId"] != "123456789012" ||
		pf.OwnerHint.Username != "arn:aws:iam::123456789012:role/app" || pf.OwnerHint.Type != "federated_actor" {
		t.Errorf("principal = %+v", pf)
	}
	for _, code := range []string{sa.SigAnthropicPlainUsage, sa.SigAnthropicServerWebSearch, sa.SigAnthropicServerCodeExec} {
		s, ok := signalOf(pf, code)
		if !ok || !strings.HasPrefix(s.Source, prefixAWS) {
			t.Errorf("principal signal %s = %+v %v", code, s, ok)
		}
	}
	if len(pf.Usage) != 2 {
		t.Errorf("principal usage = %+v", pf.Usage)
	}
	// Agents carry the variant in Scope and attributes.
	ag := findingOf(t, res, models.ShadowKindPlatformAgent, agent1)
	if ag.Scope != "aws:us-west-2:workspace:"+wsB && ag.Scope != "aws:us-west-2:workspace:"+wsA {
		t.Errorf("AWS agent scope = %s", ag.Scope)
	}
	if ag.Attributes["region"] != "us-west-2" {
		t.Errorf("AWS agent attributes = %v", ag.Attributes)
	}
	// Batch tool use cannot be tied to a key on AWS (no key list).
	found := false
	for _, c := range res.Calls {
		if strings.HasPrefix(c.Call, prefixAWS+"tool calls in batch results") && strings.Contains(c.Message, "no API key list") {
			found = true
		}
	}
	if !found {
		t.Errorf("AWS batch attribution note missing: %+v", res.Calls)
	}
	// ... so it is on the AWS workspace's own finding.
	onWorkspace := false
	for _, f := range res.Findings {
		if f.Kind == models.ShadowKindProject && strings.HasPrefix(f.Scope, "aws:") {
			if _, ok := signalOf(f, sa.SigAnthropicToolCallBatch); ok && f.Attributes["region"] != nil {
				onWorkspace = true
			}
		}
	}
	if !onWorkspace {
		t.Errorf("AWS batch tool use is not on an AWS workspace finding")
	}
	out, _ := json.Marshal(res)
	for _, mk := range []string{awsSecret, "SECRET-PROMPT-MARKER", "SECRET-INPUT-MARKER"} {
		if strings.Contains(string(out), mk) || strings.Contains(h.logs.String(), mk) {
			t.Errorf("leaked %q", mk)
		}
	}
}

func TestAWSConfiguredWorkspacesAndRole(t *testing.T) {
	h := newHarness(t)
	h.m.forbid["aws /v1/organizations/workspaces"] = true
	conn := h.awsConn()
	conn.Config.AWSWorkspaceIDs = []string{wsA}
	conn.Config.RoleARN = "arn:aws:iam::123456789012:role/AmpShadowDiscovery"
	conn.Config.ExternalID = "ext-123"
	conn.Config.DeepInspection = false
	res := h.scan(conn)
	if c := callOf(t, res, prefixAWS+callWorkspaces); c.Outcome != models.ShadowCallSkipped {
		t.Errorf("workspaces = %+v", c)
	}
	if h.m.stsCalls == 0 {
		t.Error("the role was not assumed")
	}
	agents := h.m.requestsTo("aws /v1/agents")
	if len(agents) == 0 {
		t.Fatal("no AWS agents call")
	}
	r := agents[0]
	if !strings.Contains(r.Header.Get("Authorization"), "Credential="+awsTempKey+"/") || r.Header.Get("X-Amz-Security-Token") != awsTempToken {
		t.Errorf("requests not signed with the assumed role: %q", r.Header.Get("Authorization"))
	}
	if r.Header.Get("anthropic-workspace-id") != wsA {
		t.Errorf("workspace header = %q", r.Header.Get("anthropic-workspace-id"))
	}
}

func TestAWSAuthFailureStops(t *testing.T) {
	h := newHarness(t)
	h.m.override["aws /v1/organizations/workspaces"] = func(w http.ResponseWriter, _ *http.Request) bool {
		anthropicError(w, http.StatusUnauthorized, "authentication_error", "signature mismatch")
		return true
	}
	for _, r := range []string{"aws /v1/organizations/analytics/usage", "aws /v1/agents"} {
		h.m.forbid[r] = true
	}
	conn := h.awsConn()
	conn.Config.Regions = []string{"us-west-2", "us-east-1"}
	res := h.scan(conn)
	if c := callOf(t, res, prefixAWS+callWorkspaces); c.Outcome != models.ShadowCallAuthFailed {
		t.Errorf("workspaces = %+v", c)
	}
	if c := callOf(t, res, prefixAWS+callUsage); c.Outcome != models.ShadowCallSkipped {
		t.Errorf("usage = %+v", c)
	}
	if h.m.hits("aws /v1/organizations/workspaces") != 1 {
		t.Error("the second region should not be called after the credentials were rejected")
	}
}

func TestGCPVariant(t *testing.T) {
	h := newHarness(t)
	conn := h.variantConn()
	conn.Config.GCPProjectID = gcpProject
	conn.Config.GCPWorkspaceIDs = []string{gcpWorkspace}
	conn.Secret.ServiceAccountJSON = serviceAccountJSON(t)
	for _, r := range []string{"gcp /v1/organizations/workspaces", "gcp /v1/organizations/api_keys", "gcp /v1/organizations/users"} {
		h.m.forbid[r] = true
	}
	res := h.scan(conn)
	for _, call := range []string{callUsage, callCost, callAgents, callSessions, callEvents, callBatches, callBatchResults} {
		if c := callOf(t, res, prefixGCP+call); c.Outcome != models.ShadowCallOK {
			t.Errorf("%s = %+v", prefixGCP+call, c)
		}
	}
	for _, call := range []string{callWorkspaces, callAPIKeys, callUsers} {
		if c := callOf(t, res, prefixGCP+call); c.Outcome != models.ShadowCallSkipped {
			t.Errorf("%s = %+v", prefixGCP+call, c)
		}
	}
	// Workspace routes carry the workspace in the URL (checked by the mock:
	// no anthropic-workspace-id header, Google bearer token).
	agents := h.m.requestsTo("gcp /v1/agents")
	if len(agents) != 2 || agents[0].WS != gcpWorkspace ||
		agents[0].Path != "/gcp/v1/projects/my-proj/locations/global/workspaces/"+gcpWorkspace+"/invoke/v1/agents" {
		t.Errorf("Google agents requests = %+v", agents)
	}
	if h.m.hits("gcp /v1/organizations/analytics/usage") != 1 {
		t.Error("Google analytics not called at the organization URL")
	}
	pf := findingOf(t, res, models.ShadowKindPrincipal, "gcp:serviceAccount:agent@my-proj.iam.gserviceaccount.com")
	if pf.Scope != "gcp:"+gcpProject || pf.Attributes["project"] != gcpProject {
		t.Errorf("Google principal = %+v", pf)
	}
	ag := findingOf(t, res, models.ShadowKindPlatformAgent, agent1)
	if ag.Scope != "gcp:"+gcpProject+":workspace:"+gcpWorkspace || ag.Attributes["project"] != gcpProject {
		t.Errorf("Google agent = %+v", ag)
	}
	out, _ := json.Marshal(res)
	if strings.Contains(string(out), "PRIVATE KEY") || strings.Contains(h.logs.String(), "PRIVATE KEY") || strings.Contains(string(out), gcpToken) {
		t.Error("leaked the service account key or token")
	}
	info := h.c.Test(context.Background(), conn)
	var names []string
	for _, c := range info.Checks {
		names = append(names, c.Name+"="+c.Outcome)
	}
	joined := strings.Join(names, ";")
	for _, want := range []string{
		"Claude Models on Google Cloud (my-proj): Usage analytics=ok",
		"Claude Models on Google Cloud (my-proj): Workspace " + gcpWorkspace + ": Managed Agents=ok",
		"Claude Platform on AWS=skipped",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("test checks %s missing %s", joined, want)
		}
	}
}
