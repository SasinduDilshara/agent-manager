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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/repositories"
)

func TestAuditAgentIndex_Lookups(t *testing.T) {
	idx := auditTestIndex(t)

	tests := []struct {
		name   string
		lookup func() (AuditAgentRef, bool)
		want   string // "project/name", "" for no match
	}{
		{"LLM proxy by handle", func() (AuditAgentRef, bool) { return idx.LLMProxyAgent(auditTestExtProxy) }, "default/ext-audit-agent"},
		{"LLM proxy by artifact uuid", func() (AuditAgentRef, bool) {
			return idx.LLMProxyAgent("25084105-65fe-4208-bd14-03cbd94ea604")
		}, "default/int-audit-agent"},
		{"unknown LLM proxy", func() (AuditAgentRef, bool) { return idx.LLMProxyAgent("someone-elses-proxy") }, ""},
		{"empty LLM proxy", func() (AuditAgentRef, bool) { return idx.LLMProxyAgent("") }, ""},
		{"AgentID subject", func() (AuditAgentRef, bool) { return idx.AgentIDAgent(auditTestIntAgentID) }, "default/int-audit-agent"},
		{"AgentID client", func() (AuditAgentRef, bool) { return idx.ClientIDAgent(auditTestExtClientID) }, "default/ext-audit-agent"},
		{"agent API artifact", func() (AuditAgentRef, bool) { return idx.AgentArtifactAgent(auditTestA2AArtifact) }, "default/a2a-notes-agent"},
		{"non-agent REST artifact is ignored", func() (AuditAgentRef, bool) {
			return idx.AgentArtifactAgent("22222222-2222-2222-2222-222222222222")
		}, ""},
		{"unique name", func() (AuditAgentRef, bool) { return idx.AgentByName("int-audit-agent") }, "default/int-audit-agent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, ok := tt.lookup()
			if tt.want == "" {
				assert.False(t, ok)
				return
			}
			require.True(t, ok)
			assert.Equal(t, tt.want, ref.Project+"/"+ref.Name)
		})
	}

	// The agent UUID learnt from the agent's API artifact is carried by every
	// lookup for that agent.
	ref, ok := idx.AgentIDAgent(auditTestIntAgentID)
	require.True(t, ok)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", ref.UUID)
}

func TestAuditAgentIndex_AmbiguousNameResolvesToNothing(t *testing.T) {
	repo := auditTestRepo()
	repo.ListAgentIdentitiesFunc = func(_ context.Context, _ string) ([]repositories.AuditAgentIdentity, error) {
		return []repositories.AuditAgentIdentity{
			{ProjectName: "p1", AgentName: "bot", ThunderAgentID: "id-1"},
			{ProjectName: "p2", AgentName: "bot", ThunderAgentID: "id-2"},
		}, nil
	}
	idx, err := NewAuditAgentResolver(repo, "").Index(context.Background(), auditTestOUID)
	require.NoError(t, err)
	_, ok := idx.AgentByName("bot")
	assert.False(t, ok, "a name in two projects must not be attributed to either")
	ref, ok := idx.AgentInProject("p2", "bot")
	require.True(t, ok)
	assert.Equal(t, "p2", ref.Project)
	assert.Len(t, idx.match("", "bot"), 2)
	assert.Len(t, idx.match("p1", "bot"), 1)
}

func TestAuditAgentResolver_FingerprintJoin(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef-test-key"
	proxyKeyHash := hex.EncodeToString(sha256.New().Sum([]byte("proxy-key")))
	providerKeyHash := hex.EncodeToString(sha256.New().Sum([]byte("provider-key")))
	ingressKeyHash := hex.EncodeToString(sha256.New().Sum([]byte("ingress-key")))

	repo := auditTestRepo()
	called := false
	repo.ListAPIKeysFunc = func(_ context.Context, ouID string) ([]repositories.AuditAPIKey, error) {
		called = true
		assert.Equal(t, auditTestOUID, ouID)
		return []repositories.AuditAPIKey{
			{Name: "audit-llm-key", APIKeyHash: proxyKeyHash, ArtifactHandle: auditTestExtProxy, ArtifactKind: "LlmProxy"},
			// The provider key the platform issues for a proxy is named after it.
			{Name: auditTestIntProxy, APIKeyHash: providerKeyHash, ArtifactHandle: "openai-audit", ArtifactKind: "LlmProvider"},
			{Name: "standalone", APIKeyHash: ingressKeyHash, ArtifactHandle: "openai-audit", ArtifactKind: "LlmProvider"},
		}, nil
	}
	idx, err := NewAuditAgentResolver(repo, key).Index(context.Background(), auditTestOUID)
	require.NoError(t, err)
	require.True(t, called)

	fp := func(hash string) string {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(hash))
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	}
	name, agent, ok := idx.FingerprintKey(fp(proxyKeyHash))
	require.True(t, ok)
	assert.Equal(t, "audit-llm-key", name)
	require.NotNil(t, agent)
	assert.Equal(t, "ext-audit-agent", agent.Name)

	_, agent, ok = idx.FingerprintKey(fp(providerKeyHash))
	require.True(t, ok)
	require.NotNil(t, agent)
	assert.Equal(t, "int-audit-agent", agent.Name)

	name, agent, ok = idx.FingerprintKey(fp(ingressKeyHash))
	require.True(t, ok)
	assert.Equal(t, "standalone", name)
	assert.Nil(t, agent)

	_, _, ok = idx.FingerprintKey("hmac-sha256:deadbeef")
	assert.False(t, ok)

	// An API-key call is attributed to the key's agent, but the caller stays
	// anonymous: possession of a key is not an identity.
	doc := map[string]any{
		"audit_source": auditSourceGateway,
		"api":          map[string]any{"kind": "LlmProvider", "name": "openai-audit"},
		"auth":         map[string]any{"authenticated": true, "type": "apikey", "tokenId": fp(proxyKeyHash)},
	}
	e := normalizeAuditDocument("", doc, idx)
	assert.Equal(t, "ANONYMOUS", e.Actor.Type)
	assert.Equal(t, "apikey", e.Actor.AuthMethod)
	assert.Equal(t, fp(proxyKeyHash), e.Actor.TokenId)
	require.NotNil(t, e.Agent.Get())
	assert.Equal(t, "ext-audit-agent", e.Agent.Get().Name)

	// And the agent filter reaches the call through the fingerprint.
	q := baseAuditQuery()
	q.Agents = []string{"ext-audit-agent"}
	require.NoError(t, q.Normalize(auditFixtureTime))
	body, err := buildAuditSearchBody(q, idx, false)
	require.NoError(t, err)
	doc["@timestamp"] = auditFixtureTime.Format(time.RFC3339Nano)
	doc["gateway"] = map[string]any{"organization": auditTestOrgHandle}
	assert.True(t, matchBody(t, body, doc))
}

func TestAuditAgentResolver_NoFingerprintKeySkipsKeys(t *testing.T) {
	repo := auditTestRepo()
	repo.ListAPIKeysFunc = nil // must not be called
	_, err := NewAuditAgentResolver(repo, "").Index(context.Background(), auditTestOUID)
	require.NoError(t, err)
}

func TestAuditAgentResolver_CachesPerOrgWithTTL(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	repo := auditTestRepo()
	inner := repo.ListAgentIdentitiesFunc
	repo.ListAgentIdentitiesFunc = func(ctx context.Context, ouID string) ([]repositories.AuditAgentIdentity, error) {
		mu.Lock()
		calls[ouID]++
		mu.Unlock()
		return inner(ctx, ouID)
	}
	now := time.Unix(1_000_000, 0)
	r := newAuditAgentResolver(repo, "", time.Minute, func() time.Time { return now })

	a1, err := r.Index(context.Background(), auditTestOUID)
	require.NoError(t, err)
	a2, err := r.Index(context.Background(), auditTestOUID)
	require.NoError(t, err)
	assert.Same(t, a1, a2)
	assert.Equal(t, 1, calls[auditTestOUID])

	// Another org gets its own index, built from its own rows only.
	other, err := r.Index(context.Background(), "other-ou")
	require.NoError(t, err)
	assert.Equal(t, 1, calls["other-ou"])
	_, ok := other.AgentIDAgent(auditTestExtAgentID)
	assert.False(t, ok, "one org's agents must not resolve in another org's index")

	now = now.Add(61 * time.Second)
	a3, err := r.Index(context.Background(), auditTestOUID)
	require.NoError(t, err)
	assert.NotSame(t, a1, a3)
	assert.Equal(t, 2, calls[auditTestOUID])
}

func TestAuditAgentResolver_ErrorsAreReturnedNotCached(t *testing.T) {
	boom := errors.New("db down")
	repo := auditTestRepo()
	fail := true
	inner := repo.ListLLMProxyAgentsFunc
	repo.ListLLMProxyAgentsFunc = func(ctx context.Context, ouID string) ([]repositories.AuditLLMProxyAgent, error) {
		if fail {
			return nil, boom
		}
		return inner(ctx, ouID)
	}
	r := NewAuditAgentResolver(repo, "")
	_, err := r.Index(context.Background(), auditTestOUID)
	require.ErrorIs(t, err, boom)

	fail = false
	idx, err := r.Index(context.Background(), auditTestOUID)
	require.NoError(t, err)
	_, ok := idx.LLMProxyAgent(auditTestExtProxy)
	assert.True(t, ok)

	_, err = r.Index(context.Background(), "")
	require.Error(t, err, "an empty org is refused")
}

func TestParseAgentArtifactHandle(t *testing.T) {
	p, n, ok := parseAgentArtifactHandle("proj/agent/" + auditTestEnvUUID)
	require.True(t, ok)
	assert.Equal(t, []string{"proj", "agent"}, []string{p, n})
	for _, h := range []string{"", "orders-api", "a/b", "a//c", "/b/c", "a/b/c/d"} {
		_, _, ok := parseAgentArtifactHandle(h)
		assert.False(t, ok, h)
	}
}

// One caller going away must not fail the others waiting on the same build.
func TestAuditAgentResolver_ACancelledCallerDoesNotFailConcurrentOnes(t *testing.T) {
	repo := auditTestRepo()
	inner := repo.ListAgentArtifactsFunc
	started := make(chan struct{})
	release := make(chan struct{})
	var buildCtxErr error
	repo.ListAgentArtifactsFunc = func(ctx context.Context, ouID string) ([]repositories.AuditAgentArtifact, error) {
		close(started)
		<-release
		buildCtxErr = ctx.Err()
		return inner(ctx, ouID)
	}
	r := newAuditAgentResolver(repo, "", time.Minute, time.Now)

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := r.Index(firstCtx, auditTestOUID)
		firstErr <- err
	}()
	<-started

	type result struct {
		idx *AuditAgentIndex
		err error
	}
	second := make(chan result, 1)
	go func() {
		idx, err := r.Index(context.Background(), auditTestOUID)
		second <- result{idx, err}
	}()

	cancelFirst()
	require.ErrorIs(t, <-firstErr, context.Canceled, "the cancelled caller returns its own cancellation")

	close(release)
	got := <-second
	require.NoError(t, got.err, "the other caller still gets the index")
	_, ok := got.idx.LLMProxyAgent(auditTestExtProxy)
	assert.True(t, ok)
	assert.NoError(t, buildCtxErr, "the shared build is not cancelled with the first caller")
}

func TestAuditAgentResolver_EvictsIndicesOfIdleOrgs(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	r := newAuditAgentResolver(auditTestRepo(), "", time.Minute, func() time.Time { return now })
	_, err := r.Index(context.Background(), "idle-ou")
	require.NoError(t, err)
	now = now.Add(auditAgentIndexRetention)
	_, err = r.Index(context.Background(), auditTestOUID)
	require.NoError(t, err)
	r.mu.Lock()
	defer r.mu.Unlock()
	assert.NotContains(t, r.cache, "idle-ou")
	assert.Contains(t, r.cache, auditTestOUID)
}
