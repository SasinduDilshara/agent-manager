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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
)

// auditAgentIndexTTL bounds how stale attribution can be. An agent created a
// minute ago may show unattributed for up to this long; nothing is hidden by
// it, because attribution never filters records out on its own.
const auditAgentIndexTTL = 60 * time.Second

// auditTokenFingerprintPrefix is how the gateway marks a protected credential
// fingerprint in auth.tokenId.
const auditTokenFingerprintPrefix = "hmac-sha256:"

// AuditAgentRef names an agent an audit record is attributed to.
type AuditAgentRef struct {
	Name    string
	Project string
	// UUID is the OpenChoreo component id when AMS knows it, otherwise empty.
	UUID string
}

// auditAgentIdentifiers are every value under which an agent appears in
// gateway traffic records. The agent filter matches any of them.
type auditAgentIdentifiers struct {
	ref AuditAgentRef
	// apiNames are LLM proxy handles (api.name / api.id).
	apiNames map[string]struct{}
	// apiIDs are agent API artifact UUIDs (api.id) — ingress to the agent.
	apiIDs map[string]struct{}
	// agentIDs are AgentID ids (auth.subject, or act.sub when delegated).
	agentIDs map[string]struct{}
	// clientIDs are AgentID OAuth client ids (auth.clientId).
	clientIDs map[string]struct{}
	// tokenIDs are protected API-key fingerprints (auth.tokenId).
	tokenIDs map[string]struct{}
}

// auditKeyRef is what an API-key fingerprint resolves to.
type auditKeyRef struct {
	keyName string
	agent   *AuditAgentRef
}

// AuditAgentIndex maps the identifiers found in audit records to agents, for
// one org. It is immutable once built.
type AuditAgentIndex struct {
	byLLMProxy      map[string]AuditAgentRef
	byAgentArtifact map[string]AuditAgentRef
	byAgentID       map[string]AuditAgentRef
	byClientID      map[string]AuditAgentRef
	byFingerprint   map[string]auditKeyRef
	// agents is keyed by "project/name".
	agents map[string]*auditAgentIdentifiers
}

func newAuditAgentIndex() *AuditAgentIndex {
	return &AuditAgentIndex{
		byLLMProxy:      map[string]AuditAgentRef{},
		byAgentArtifact: map[string]AuditAgentRef{},
		byAgentID:       map[string]AuditAgentRef{},
		byClientID:      map[string]AuditAgentRef{},
		byFingerprint:   map[string]auditKeyRef{},
		agents:          map[string]*auditAgentIdentifiers{},
	}
}

func auditAgentKey(project, name string) string { return project + "/" + name }

// agent returns the identifier set for an agent, creating it on first use.
// A UUID learnt later fills in one learnt earlier without it.
func (idx *AuditAgentIndex) agent(project, name, agentUUID string) *auditAgentIdentifiers {
	key := auditAgentKey(project, name)
	a, ok := idx.agents[key]
	if !ok {
		a = &auditAgentIdentifiers{
			ref:       AuditAgentRef{Name: name, Project: project},
			apiNames:  map[string]struct{}{},
			apiIDs:    map[string]struct{}{},
			agentIDs:  map[string]struct{}{},
			clientIDs: map[string]struct{}{},
			tokenIDs:  map[string]struct{}{},
		}
		idx.agents[key] = a
	}
	if a.ref.UUID == "" && agentUUID != "" {
		a.ref.UUID = agentUUID
	}
	return a
}

// finalize copies the UUIDs learnt from any source into every lookup map, so a
// record attributed through an LLM proxy carries the same UUID as one
// attributed through the agent's API artifact.
func (idx *AuditAgentIndex) finalize() {
	fill := func(m map[string]AuditAgentRef) {
		for k, ref := range m {
			if a, ok := idx.agents[auditAgentKey(ref.Project, ref.Name)]; ok {
				m[k] = a.ref
			}
		}
	}
	fill(idx.byLLMProxy)
	fill(idx.byAgentArtifact)
	fill(idx.byAgentID)
	fill(idx.byClientID)
	for k, kr := range idx.byFingerprint {
		if kr.agent != nil {
			if a, ok := idx.agents[auditAgentKey(kr.agent.Project, kr.agent.Name)]; ok {
				ref := a.ref
				kr.agent = &ref
				idx.byFingerprint[k] = kr
			}
		}
	}
}

// LLMProxyAgent returns the agent whose model configuration owns the LLM proxy
// named by api.name or api.id.
func (idx *AuditAgentIndex) LLMProxyAgent(nameOrID string) (AuditAgentRef, bool) {
	ref, ok := idx.byLLMProxy[nameOrID]
	return ref, ok && nameOrID != ""
}

// AgentArtifactAgent returns the agent whose API artifact has this UUID.
func (idx *AuditAgentIndex) AgentArtifactAgent(apiID string) (AuditAgentRef, bool) {
	ref, ok := idx.byAgentArtifact[apiID]
	return ref, ok && apiID != ""
}

// AgentIDAgent returns the agent holding this AgentID (a token subject).
func (idx *AuditAgentIndex) AgentIDAgent(subject string) (AuditAgentRef, bool) {
	ref, ok := idx.byAgentID[subject]
	return ref, ok && subject != ""
}

// ClientIDAgent returns the agent owning this AgentID OAuth client.
func (idx *AuditAgentIndex) ClientIDAgent(clientID string) (AuditAgentRef, bool) {
	ref, ok := idx.byClientID[clientID]
	return ref, ok && clientID != ""
}

// FingerprintKey returns the API key behind a protected fingerprint, and the
// agent that owns it when there is one.
func (idx *AuditAgentIndex) FingerprintKey(tokenID string) (keyName string, agent *AuditAgentRef, ok bool) {
	kr, found := idx.byFingerprint[tokenID]
	if !found || tokenID == "" {
		return "", nil, false
	}
	return kr.keyName, kr.agent, true
}

// AgentByName returns the agent with this name when exactly one project has
// one. A name used in several projects is ambiguous and resolves to nothing,
// rather than to an arbitrary one of them.
func (idx *AuditAgentIndex) AgentByName(name string) (AuditAgentRef, bool) {
	var found *AuditAgentRef
	for _, a := range idx.agents {
		if a.ref.Name != name {
			continue
		}
		if found != nil {
			return AuditAgentRef{}, false
		}
		ref := a.ref
		found = &ref
	}
	if found == nil {
		return AuditAgentRef{}, false
	}
	return *found, true
}

// AgentInProject returns the named agent of a project, if AMS knows it.
func (idx *AuditAgentIndex) AgentInProject(project, name string) (AuditAgentRef, bool) {
	a, ok := idx.agents[auditAgentKey(project, name)]
	if !ok {
		return AuditAgentRef{}, false
	}
	return a.ref, true
}

// match returns the identifier sets of the agents a filter value names:
// "project/agent" names one agent, "agent" names that agent in every project.
// The result is sorted for a deterministic query.
func (idx *AuditAgentIndex) match(project, name string) []*auditAgentIdentifiers {
	var out []*auditAgentIdentifiers
	for _, a := range idx.agents {
		if a.ref.Name != name && name != "" {
			continue
		}
		if project != "" && a.ref.Project != project {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		return auditAgentKey(out[i].ref.Project, out[i].ref.Name) < auditAgentKey(out[j].ref.Project, out[j].ref.Name)
	})
	return out
}

// AuditAgentResolver builds the per-org attribution index.
type AuditAgentResolver interface {
	Index(ctx context.Context, ouID string) (*AuditAgentIndex, error)
}

type cachedAuditIndex struct {
	index   *AuditAgentIndex
	builtAt time.Time
}

type auditAgentResolver struct {
	repo           repositories.AuditAttributionRepository
	fingerprintKey []byte
	ttl            time.Duration
	now            func() time.Time

	mu    sync.Mutex
	cache map[string]cachedAuditIndex
	group singleflight.Group
}

// NewAuditAgentResolver creates a resolver that caches each org's index for
// about a minute. fingerprintKey is the gateway's token fingerprint key; when
// empty, API-key fingerprints are not resolved.
func NewAuditAgentResolver(repo repositories.AuditAttributionRepository, fingerprintKey string) AuditAgentResolver {
	return newAuditAgentResolver(repo, fingerprintKey, auditAgentIndexTTL, time.Now)
}

func newAuditAgentResolver(
	repo repositories.AuditAttributionRepository, fingerprintKey string, ttl time.Duration, now func() time.Time,
) *auditAgentResolver {
	var key []byte
	if fingerprintKey != "" {
		key = []byte(fingerprintKey)
	}
	return &auditAgentResolver{
		repo:           repo,
		fingerprintKey: key,
		ttl:            ttl,
		now:            now,
		cache:          map[string]cachedAuditIndex{},
	}
}

func (r *auditAgentResolver) Index(ctx context.Context, ouID string) (*AuditAgentIndex, error) {
	if ouID == "" {
		return nil, fmt.Errorf("audit agent index: missing organization")
	}
	r.mu.Lock()
	cached, ok := r.cache[ouID]
	r.mu.Unlock()
	if ok && r.now().Sub(cached.builtAt) < r.ttl {
		return cached.index, nil
	}

	// One build per org at a time; the lock is not held across the queries.
	v, err, _ := r.group.Do(ouID, func() (any, error) {
		idx, err := r.build(ctx, ouID)
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.cache[ouID] = cachedAuditIndex{index: idx, builtAt: r.now()}
		r.mu.Unlock()
		return idx, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*AuditAgentIndex), nil
}

func (r *auditAgentResolver) build(ctx context.Context, ouID string) (*AuditAgentIndex, error) {
	idx := newAuditAgentIndex()

	artifacts, err := r.repo.ListAgentArtifacts(ctx, ouID)
	if err != nil {
		return nil, err
	}
	for _, art := range artifacts {
		project, name, ok := parseAgentArtifactHandle(art.Handle)
		if !ok {
			continue // a RestApi artifact that is not an agent's
		}
		a := idx.agent(project, name, art.AgentUUID)
		a.apiIDs[art.ArtifactUUID] = struct{}{}
		idx.byAgentArtifact[art.ArtifactUUID] = a.ref
	}

	proxies, err := r.repo.ListLLMProxyAgents(ctx, ouID)
	if err != nil {
		return nil, err
	}
	proxyAgents := map[string]AuditAgentRef{}
	for _, p := range proxies {
		a := idx.agent(p.ProjectName, p.AgentName, "")
		a.apiNames[p.Handle] = struct{}{}
		a.apiNames[p.ArtifactUUID] = struct{}{}
		idx.byLLMProxy[p.Handle] = a.ref
		idx.byLLMProxy[p.ArtifactUUID] = a.ref
		proxyAgents[p.Handle] = a.ref
	}

	identities, err := r.repo.ListAgentIdentities(ctx, ouID)
	if err != nil {
		return nil, err
	}
	for _, id := range identities {
		a := idx.agent(id.ProjectName, id.AgentName, "")
		if id.ThunderAgentID != "" {
			a.agentIDs[id.ThunderAgentID] = struct{}{}
			idx.byAgentID[id.ThunderAgentID] = a.ref
		}
		if id.ThunderClientID != "" {
			a.clientIDs[id.ThunderClientID] = struct{}{}
			idx.byClientID[id.ThunderClientID] = a.ref
		}
	}

	if r.fingerprintKey != nil {
		keys, err := r.repo.ListAPIKeys(ctx, ouID)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if k.APIKeyHash == "" {
				continue
			}
			fp := auditTokenFingerprint(r.fingerprintKey, k.APIKeyHash)
			kr := auditKeyRef{keyName: k.Name}
			// A proxy's own key is bound to the proxy; the provider key the
			// platform issues for a proxy is named after the proxy's handle.
			owner := k.ArtifactHandle
			if k.ArtifactKind == models.KindLLMProvider {
				owner = k.Name
			}
			if ref, ok := proxyAgents[owner]; ok {
				refCopy := ref
				kr.agent = &refCopy
				idx.agent(ref.Project, ref.Name, "").tokenIDs[fp] = struct{}{}
			}
			idx.byFingerprint[fp] = kr
		}
	}

	idx.finalize()
	return idx, nil
}

// auditTokenFingerprint reproduces the gateway's protected credential
// fingerprint: HMAC-SHA256(key, <SHA-256 hex of the credential>), which is the
// verifier AMS stores as api_key_hash.
func auditTokenFingerprint(key []byte, apiKeyHash string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.ToLower(apiKeyHash)))
	return auditTokenFingerprintPrefix + hex.EncodeToString(mac.Sum(nil))
}

// parseAgentArtifactHandle splits a per-environment agent API artifact handle,
// "<project>/<agent>/<environmentID>".
func parseAgentArtifactHandle(handle string) (project, name string, ok bool) {
	parts := strings.Split(handle, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
