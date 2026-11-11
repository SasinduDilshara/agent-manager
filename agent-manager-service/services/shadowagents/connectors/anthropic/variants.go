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
	"strings"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// variantGroupBy are the analytics dimensions on the cloud variants. Calls
// there carry cloud credentials, not API keys, so the federated actor (the
// IAM principal ARN or Google principal) is grouped by as well, to tie the
// usage to a workload (anthropic_cloud_variants.md §2.1, §3). Five is the
// documented maximum.
var variantGroupBy = []string{"actor", "api_key_id", "model", "product", "agent_id"}

// awsCallNames are every call made on Claude Platform on AWS.
var awsCallNames = []string{callWorkspaces, callUsage, callCost, callAgents, callSessions, callEvents, callBatches, callBatchResults}

// aws scans Claude Platform on AWS, region by region (workspaces are bound
// to one region and analytics cover one region a request). The API keys and
// users routes do not exist there and are not called.
func (s *scan) aws(ctx context.Context) {
	cfg := s.conn.Config
	regions := cleanList(cfg.Regions)
	if len(regions) == 0 || strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(s.conn.Secret.SecretAccessKey) == "" {
		s.calls.Skip(strings.TrimSuffix(prefixAWS, ": "), "not configured")
		return
	}
	for _, call := range []string{callAPIKeys, callUsers} {
		s.calls.Skip(prefixAWS+call, "not available on Claude Platform on AWS")
	}
	configured := cleanList(cfg.AWSWorkspaceIDs)
	for i, region := range regions {
		if ctx.Err() != nil {
			return
		}
		p, err := s.awsPlatform(region)
		if err != nil {
			for _, call := range awsCallNames {
				s.calls.Record(prefixAWS+call, 0, err)
			}
			continue
		}
		var ids []string
		var first error
		if len(configured) > 0 {
			ids = configured
			s.calls.Skip(p.call(callWorkspaces), "workspace IDs are configured")
			first = s.analytics(ctx, p)
		} else {
			wss, werr := s.listWorkspaces(ctx, p)
			first = werr
			for _, w := range wss {
				ids = append(ids, w.ID)
			}
		}
		if sa.OutcomeOf(first) == models.ShadowCallAuthFailed {
			reason := "not called: the AWS credentials were rejected in " + region
			for _, call := range awsCallNames {
				s.calls.Skip(prefixAWS+call, reason)
			}
			if i == 0 {
				return
			}
			continue
		}
		if len(configured) == 0 {
			_ = s.analytics(ctx, p) // the outcome is recorded in the calls
		}
		s.workspaces(ctx, p, ids, "no workspaces in the region")
	}
}

// awsPlatform builds the platform of one AWS region: SigV4 for the service
// aws-external-anthropic in that region, with the connection's access key
// (and role, assumed through the configured STS endpoint).
func (s *scan) awsPlatform(region string) (*platform, error) {
	vars := map[string]string{"region": region}
	base, err := sa.Expand(sa.EndpointOf(s.conn, sa.EPAnthropicAWS), vars)
	if err != nil {
		return nil, err
	}
	stsEP, err := sa.Expand(sa.EndpointOf(s.conn, sa.EPAnthropicAWSSTS), vars)
	if err != nil {
		return nil, err
	}
	cfg := s.conn.Config
	awsCfg, err := sa.AWSConfig(s.c.http, region, stsEP, sa.AWSCredentials{
		AccessKeyID:     strings.TrimSpace(cfg.AccessKeyID),
		SecretAccessKey: strings.TrimSpace(s.conn.Secret.SecretAccessKey),
		SessionToken:    strings.TrimSpace(s.conn.Secret.SessionToken),
		RoleARN:         strings.TrimSpace(cfg.RoleARN),
		ExternalID:      strings.TrimSpace(cfg.ExternalID),
	})
	if err != nil {
		return nil, err
	}
	p := &platform{
		kind: platformAWS, prefix: prefixAWS, region: region, base: base,
		wsHeader: true, analyticsGroupBy: variantGroupBy,
	}
	p.orgAPI = s.newAPI(func(h http.Header) { h.Set(headerVersion, apiVersion) },
		sa.SigV4Authorizer(awsCfg, awsSigV4ServiceName, region))
	p.wsAPI = func(string) (*sa.API, bool) { return p.orgAPI, true }
	return p, nil
}

// gcp scans Claude Models on Google Cloud (Anthropic managed) for one
// project. Workspaces have no list route there, so the configured IDs are
// scanned; API keys and users do not exist.
func (s *scan) gcp(ctx context.Context) {
	cfg := s.conn.Config
	project := strings.TrimSpace(cfg.GCPProjectID)
	if project == "" || strings.TrimSpace(s.conn.Secret.ServiceAccountJSON) == "" {
		s.calls.Skip(strings.TrimSuffix(prefixGCP, ": "), "not configured")
		return
	}
	for _, call := range []string{callAPIKeys, callUsers, callWorkspaces} {
		s.calls.Skip(prefixGCP+call, "not available on Claude Models on Google Cloud")
	}
	p, err := s.gcpPlatform(ctx, project)
	if err != nil {
		for _, call := range []string{callUsage, callCost, callAgents} {
			s.calls.Record(prefixGCP+call, 0, err)
		}
		return
	}
	if err := s.analytics(ctx, p); sa.OutcomeOf(err) == models.ShadowCallAuthFailed {
		for _, call := range []string{callAgents, callSessions, callEvents, callBatches, callBatchResults} {
			s.calls.Skip(p.call(call), "not called: the Google Cloud credentials were rejected")
		}
		return
	}
	s.workspaces(ctx, p, cleanList(cfg.GCPWorkspaceIDs), "no workspace IDs configured")
}

func (s *scan) gcpPlatform(ctx context.Context, project string) (*platform, error) {
	base, err := sa.Expand(sa.EndpointOf(s.conn, sa.EPAnthropicGCP), nil)
	if err != nil {
		return nil, err
	}
	tokenURL, err := sa.Expand(sa.EndpointOf(s.conn, sa.EPAnthropicGCPToken), nil)
	if err != nil {
		return nil, err
	}
	ts, err := sa.GoogleTokenSource(ctx, s.c.http, s.conn.Secret.ServiceAccountJSON, tokenURL)
	if err != nil {
		return nil, &sa.CallError{Outcome: models.ShadowCallAuthFailed, Message: err.Error()}
	}
	p := &platform{
		kind: platformGCP, prefix: prefixGCP, project: project, base: base,
		wsHeader: false, analyticsGroupBy: variantGroupBy,
	}
	p.orgAPI = s.newAPI(func(h http.Header) { h.Set(headerVersion, apiVersion) }, sa.BearerAuthorizer(ts))
	p.wsAPI = func(string) (*sa.API, bool) { return p.orgAPI, true }
	return p, nil
}

// cleanList trims, drops empty values and duplicates, keeping the order.
func cleanList(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
