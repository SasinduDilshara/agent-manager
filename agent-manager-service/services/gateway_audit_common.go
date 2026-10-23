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
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
)

// What the gateway audit feeds share: whichever feed is kept, the caller, the
// classification of a request and the resolution of its agent stay the same.

// provenanceObserved marks a record as relayed from a gateway's best-effort
// feed, as opposed to one this service produced.
const provenanceObserved = "observed-best-effort"

// How the acting agent of an observed request was identified.
const (
	resolutionApplication   = "application"    // the gateway's application id (API-key routes)
	resolutionAgentIdentity = "agent-identity" // the AgentID token subject (JWT routes)
	resolutionUnresolved    = "unresolved"     // neither named a known agent of the gateway's org
)

// GatewayAuditCaller is the authenticated gateway delivering a batch. Its
// organization comes from its credential, never from the batch.
type GatewayAuditCaller struct {
	GatewayID string
	OUID      string
}

// GatewayAuditIngestResult reports what became of a delivered batch.
type GatewayAuditIngestResult struct {
	Accepted int
	Rejected int
	// RejectReasons counts rejected records by reason.
	RejectReasons map[string]int
}

// classifyGatewayRequest names the action and resource type of a request from
// the kind of API it reached (the gateway's artifact kinds: LlmProxy,
// LlmProvider, Mcp, Agent, RestApi, ...). Unknown kinds are recorded as a plain
// API call rather than dropped.
func classifyGatewayRequest(apiKind, mcpMethod string) (audit.Action, string) {
	switch strings.ToLower(apiKind) {
	case "llmproxy":
		return audit.ActionLLMCall, audit.ResourceLLMProxy
	case "llmprovider":
		return audit.ActionLLMCall, audit.ResourceLLMProvider
	case "mcp":
		if mcpMethod == "tools/call" {
			return audit.ActionMCPToolCall, audit.ResourceMCPProxy
		}
		return audit.ActionMCPCall, audit.ResourceMCPProxy
	case "agent":
		return audit.ActionAgentInvoke, audit.ResourceAgent
	default:
		return audit.ActionAPICall, audit.ResourceAPI
	}
}

// --- Agent resolution --------------------------------------------------------

type resolvedAgent struct {
	agentName       string
	projectName     string
	environmentName string
	resolution      string
}

// gatewayAgentResolver names the agent behind an observed request. Every
// lookup is confined to the delivering gateway's organization, so a request
// naming another organization's application or identity resolves to nothing.
type gatewayAgentResolver struct {
	apps       repositories.AIApplicationRepository
	identities repositories.AgentThunderClientRepository
	ttl        time.Duration

	mu    sync.Mutex
	cache map[string]cachedAgent
}

type cachedAgent struct {
	agent   resolvedAgent
	expires time.Time
}

// resolverCacheMax bounds the cache; past it the cache is cleared rather than
// growing with every distinct id a gateway reports.
const resolverCacheMax = 10000

func newGatewayAgentResolver(
	apps repositories.AIApplicationRepository, identities repositories.AgentThunderClientRepository, ttl time.Duration,
) *gatewayAgentResolver {
	return &gatewayAgentResolver{apps: apps, identities: identities, ttl: ttl, cache: map[string]cachedAgent{}}
}

// resolve tries the application id first (API-key routes), then the token
// subject (AgentID-authenticated routes). A lookup that fails for any reason
// other than "not found" is returned as an error.
func (r *gatewayAgentResolver) resolve(ctx context.Context, ouID, applicationID, subject string) (resolvedAgent, error) {
	if applicationID != "" {
		agent, found, err := r.cached("app|"+ouID+"|"+applicationID, func() (resolvedAgent, bool, error) {
			app, err := r.apps.GetByHandle(ctx, ouID, applicationID)
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return resolvedAgent{}, false, nil
			}
			if err != nil {
				return resolvedAgent{}, false, err
			}
			return agentFromApplication(app), true, nil
		})
		if err != nil || found {
			return agent, err
		}
	}
	if subject != "" {
		agent, found, err := r.cached("sub|"+ouID+"|"+subject, func() (resolvedAgent, bool, error) {
			c, err := r.identities.FindByThunderIdentity(ctx, ouID, subject)
			if errors.Is(err, repositories.ErrAgentThunderClientNotFound) {
				return resolvedAgent{}, false, nil
			}
			if err != nil {
				return resolvedAgent{}, false, err
			}
			return agentFromIdentity(c), true, nil
		})
		if err != nil || found {
			return agent, err
		}
	}
	return resolvedAgent{resolution: resolutionUnresolved}, nil
}

// cached memoises lookups, including misses, for the TTL. Errors are not cached.
func (r *gatewayAgentResolver) cached(key string, lookup func() (resolvedAgent, bool, error)) (resolvedAgent, bool, error) {
	now := time.Now()
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && now.Before(e.expires) {
		r.mu.Unlock()
		return e.agent, e.agent.agentName != "", nil
	}
	r.mu.Unlock()

	// Looked up without the lock held: never hold a lock across I/O.
	agent, found, err := lookup()
	if err != nil {
		return resolvedAgent{}, false, err
	}
	if r.ttl > 0 {
		r.mu.Lock()
		if len(r.cache) >= resolverCacheMax {
			r.cache = map[string]cachedAgent{}
		}
		r.cache[key] = cachedAgent{agent: agent, expires: now.Add(r.ttl)}
		r.mu.Unlock()
	}
	return agent, found, nil
}

func agentFromApplication(app *models.AIApplication) resolvedAgent {
	return resolvedAgent{
		agentName:       app.AgentID,
		projectName:     app.ProjectName,
		environmentName: app.EnvironmentName,
		resolution:      resolutionApplication,
	}
}

func agentFromIdentity(c *models.AgentThunderClient) resolvedAgent {
	return resolvedAgent{
		agentName:       c.AgentName,
		projectName:     c.ProjectName,
		environmentName: c.EnvironmentName,
		resolution:      resolutionAgentIdentity,
	}
}

// bodyExcerpt is the first maxBytes of a captured body, cut on a UTF-8
// boundary, and whether it was cut. Both gateway feeds use it for their opt-in
// body excerpts; the excerpt is scrubbed again when the record is written.
func bodyExcerpt(body string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || body == "" {
		return "", false
	}
	if len(body) <= maxBytes {
		return body, false
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(body[cut]) {
		cut--
	}
	return body[:cut], true
}

// bodyExcerptOptions records the opt-in excerpts of a request's bodies.
func bodyExcerptOptions(requestBody, responseBody string, maxBytes int) []audit.Option {
	var opts []audit.Option
	truncated := false
	if excerpt, cut := bodyExcerpt(requestBody, maxBytes); excerpt != "" {
		opts = append(opts, audit.Detail("requestBodyExcerpt", excerpt))
		truncated = truncated || cut
	}
	if excerpt, cut := bodyExcerpt(responseBody, maxBytes); excerpt != "" {
		opts = append(opts, audit.Detail("responseBodyExcerpt", excerpt))
		truncated = truncated || cut
	}
	if truncated {
		opts = append(opts, audit.Detail("bodyExcerptTruncated", true))
	}
	return opts
}
