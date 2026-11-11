//go:build integration

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

package repositories

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/db"
	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// countScore scores a finding as the number of distinct codes, so tests can
// see that rescoring read the stored signals.
func countScore(kind string, codes []string) (int, string) {
	seen := map[string]bool{}
	for _, c := range codes {
		seen[c] = true
	}
	if kind == models.ShadowKindToolInfra {
		return len(seen), models.ShadowVerdictToolInfra
	}
	return len(seen), models.ShadowVerdictLLMConsumer
}

func newShadowConnection(t *testing.T, repo ShadowAgentRepository, ouID, name string) *models.ShadowConnection {
	t.Helper()
	c := &models.ShadowConnection{
		ID: uuid.New(), OUID: ouID, Name: name, Provider: models.ShadowProviderOpenAI,
		Config:          models.ShadowConnectionConfig{Endpoints: map[string]string{"api": "https://api.openai.com/v1"}},
		SecretEncrypted: []byte("ciphertext"), SecretHints: map[string]string{},
	}
	require.NoError(t, repo.CreateConnection(context.Background(), c))
	t.Cleanup(func() { _, _ = repo.DeleteConnection(context.Background(), ouID, c.ID) })
	return c
}

func day(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestShadowApplyConnectionResultIsIdempotentAndMerges(t *testing.T) {
	ctx := context.Background()
	repo := NewShadowAgentRepository(db.GetDB())
	ou := "ou-" + uuid.NewString()
	c := newShadowConnection(t, repo, ou, "conn")
	first, last := day("2026-11-01"), day("2026-11-03")
	scan1 := time.Now().UTC().Truncate(time.Microsecond)
	in := ShadowConnectionApply{
		OUID: ou, ConnectionID: c.ID, ScanID: uuid.New(), ScanStartedAt: scan1, WindowStart: day("2026-10-01"),
		Findings: []ShadowFindingInput{
			{
				Finding: models.ShadowFinding{
					Provider: models.ShadowProviderOpenAI, Kind: models.ShadowKindAPIKey, ExternalID: "key_1",
					DisplayName: "prod", OwnerHint: models.ShadowOwnerHint{Email: "alice@example.com"},
					Attributes: map[string]any{"model": "gpt-4.1"}, FirstUsedAt: &first, LastUsedAt: &last,
				},
				Signals: []models.ShadowFindingSignal{{Code: "openai.plain_usage", Tier: "low", Weight: 5, Source: "usage", DetectedAt: scan1}},
				Usage: []models.ShadowUsageDaily{
					{Day: day("2026-11-01"), KeyID: "key_1", Model: "gpt-4.1", Requests: 3, InputTokens: 30},
					{Day: day("2026-11-02"), KeyID: "key_1", Model: "gpt-4.1", Requests: 4},
				},
				Related: []ShadowRelationInput{{Kind: models.ShadowKindPlatformAgent, ExternalID: "agent_1", Relation: "used_by_agent"}},
			},
			{
				Finding: models.ShadowFinding{Provider: models.ShadowProviderOpenAI, Kind: models.ShadowKindPlatformAgent, ExternalID: "agent_1", DisplayName: "Bot"},
				Signals: []models.ShadowFindingSignal{{Code: "openai.agent_object", Tier: "definitive", Weight: 60, Source: "agents", DetectedAt: scan1}},
			},
		},
		Keys:       []models.ShadowAPIKey{{KeyID: "key_1", Name: "prod", RedactedHint: "sk-abc...def", Status: "active", Scope: "proj_1"}},
		KeysListed: true,
	}
	n, err := repo.ApplyConnectionResult(ctx, in, countScore)
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	// The same scan again: nothing is duplicated.
	_, err = repo.ApplyConnectionResult(ctx, in, countScore)
	require.NoError(t, err)
	rows, total, err := repo.ListFindings(ctx, ou, ShadowFindingFilter{Limit: 50})
	require.NoError(t, err)
	require.Equal(t, 2, total)
	var key *ShadowFindingRow
	for i := range rows {
		if rows[i].ExternalID == "key_1" {
			key = &rows[i]
		}
	}
	require.NotNil(t, key)
	assert.Equal(t, int64(7), key.Requests, "usage is upserted per day, never added twice")
	assert.Equal(t, 1, key.Score, "score from the stored signals")
	assert.Equal(t, "conn", key.ConnectionName)
	require.Len(t, key.Related, 1)
	assert.Equal(t, "used_by_agent", key.Related[0].Relation)
	usage, err := repo.ListUsage(ctx, ou, key.ID)
	require.NoError(t, err)
	assert.Len(t, usage, 2)

	// A later scan without an owner keeps the owner; used times only widen.
	earlier, later := day("2026-10-20"), day("2026-11-02")
	in2 := in
	in2.ScanID, in2.ScanStartedAt = uuid.New(), scan1.Add(time.Hour)
	in2.Findings = []ShadowFindingInput{{Finding: models.ShadowFinding{
		Provider: models.ShadowProviderOpenAI, Kind: models.ShadowKindAPIKey, ExternalID: "key_1", DisplayName: "prod",
		FirstUsedAt: &earlier, LastUsedAt: &later,
	}}}
	in2.Keys = nil
	in2.KeysListed = true
	_, err = repo.ApplyConnectionResult(ctx, in2, countScore)
	require.NoError(t, err)
	got, err := repo.GetFinding(ctx, ou, key.ID)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", got.OwnerHint.Email)
	assert.True(t, got.FirstUsedAt.Equal(earlier))
	assert.True(t, got.LastUsedAt.Equal(last))
	signals, err := repo.ListSignals(ctx, ou, key.ID)
	require.NoError(t, err)
	assert.Len(t, signals, 1, "evidence inside the window stays")
	keys, err := repo.ListFindingKeys(ctx, ou, key.ID)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.False(t, keys[0].Present, "a complete listing without the key marks it gone")

	// Evidence older than the window ages out.
	in3 := in2
	in3.ScanStartedAt, in3.WindowStart = scan1.Add(2*time.Hour), scan1.Add(time.Minute)
	_, err = repo.ApplyConnectionResult(ctx, in3, countScore)
	require.NoError(t, err)
	signals, err = repo.ListSignals(ctx, ou, key.ID)
	require.NoError(t, err)
	assert.Empty(t, signals)

	// Other orgs see nothing.
	_, total, err = repo.ListFindings(ctx, "ou-"+uuid.NewString(), ShadowFindingFilter{Limit: 50})
	require.NoError(t, err)
	assert.Zero(t, total)
	_, err = repo.GetFinding(ctx, "ou-"+uuid.NewString(), key.ID)
	assert.True(t, IsShadowNotFound(err))
}

func TestShadowKeysMarkedGoneOnlyInListedScopes(t *testing.T) {
	ctx := context.Background()
	repo := NewShadowAgentRepository(db.GetDB())
	ou := "ou-" + uuid.NewString()
	c := newShadowConnection(t, repo, ou, "conn")
	start := time.Now().UTC()
	base := ShadowConnectionApply{
		OUID: ou, ConnectionID: c.ID, ScanID: uuid.New(), ScanStartedAt: start, WindowStart: start.AddDate(0, 0, -30),
		Keys: []models.ShadowAPIKey{{KeyID: "a1", Scope: "proj_a"}, {KeyID: "b1", Scope: "proj_b"}}, KeysListed: true,
	}
	_, err := repo.ApplyConnectionResult(ctx, base, countScore)
	require.NoError(t, err)

	next := ShadowConnectionApply{
		OUID: ou, ConnectionID: c.ID, ScanID: uuid.New(), ScanStartedAt: start.Add(time.Hour),
		WindowStart: start.AddDate(0, 0, -30), KeyScopesListed: []string{"proj_a"},
	}
	_, err = repo.ApplyConnectionResult(ctx, next, countScore)
	require.NoError(t, err)
	var present []models.ShadowAPIKey
	require.NoError(t, db.GetDB().Where("ou_id = ?", ou).Order("key_id").Find(&present).Error)
	require.Len(t, present, 2)
	assert.False(t, present[0].Present, "proj_a was listed in full and no longer has a1")
	assert.True(t, present[1].Present, "proj_b was not listed, so b1 is not assumed gone")
}

func TestShadowScansOneActivePerOrgAndLeases(t *testing.T) {
	ctx := context.Background()
	repo := NewShadowAgentRepository(db.GetDB())
	ou := "ou-" + uuid.NewString()
	s1 := &models.ShadowScan{ID: uuid.New(), OUID: ou, Status: models.ShadowScanQueued, LookbackDays: 30, ConnectionIDs: []string{}}
	require.NoError(t, repo.CreateScan(ctx, s1))
	t.Cleanup(func() { db.GetDB().Exec("DELETE FROM shadow_scans WHERE ou_id = ?", ou) })
	err := repo.CreateScan(ctx, &models.ShadowScan{ID: uuid.New(), OUID: ou, Status: models.ShadowScanQueued, LookbackDays: 30, ConnectionIDs: []string{}})
	assert.ErrorIs(t, err, utils.ErrShadowScanInProgress)

	now := time.Now().UTC()
	var claimed []models.ShadowScan
	for i := 0; i < 50 && len(claimed) == 0; i++ {
		got, err := repo.ClaimDueScans(ctx, now, time.Minute, 100)
		require.NoError(t, err)
		for _, s := range got {
			if s.ID == s1.ID {
				claimed = append(claimed, s)
			} else {
				// Another test's scan: release it.
				db.GetDB().Exec("UPDATE shadow_scans SET status = 'queued', claimed_until = NULL WHERE id = ?", s.ID)
			}
		}
	}
	require.Len(t, claimed, 1)
	assert.Equal(t, models.ShadowScanRunning, claimed[0].Status)
	assert.Equal(t, 1, claimed[0].Attempts)

	again, err := repo.ClaimDueScans(ctx, now, time.Minute, 100)
	require.NoError(t, err)
	for _, s := range again {
		assert.NotEqual(t, s1.ID, s.ID, "a leased scan is not claimed twice")
	}
	expired, err := repo.ClaimDueScans(ctx, now.Add(2*time.Minute), time.Minute, 100)
	require.NoError(t, err)
	var reclaimed bool
	for _, s := range expired {
		if s.ID == s1.ID {
			reclaimed = true
			assert.Equal(t, 2, s.Attempts)
		}
	}
	assert.True(t, reclaimed, "a scan whose lease ran out is claimed again")

	finished := time.Now().UTC()
	s1.Status, s1.FinishedAt = models.ShadowScanSucceeded, &finished
	s1.Results = []models.ShadowScanConnectionResult{{ConnectionID: "x", Outcome: "ok", Calls: []models.ShadowScanCallResult{}}}
	require.NoError(t, repo.FinishScan(ctx, s1))
	require.NoError(t, repo.CreateScan(ctx, &models.ShadowScan{ID: uuid.New(), OUID: ou, Status: models.ShadowScanQueued, LookbackDays: 7, ConnectionIDs: []string{}}),
		"a new scan can be queued once the last one finished")
	latest, err := repo.LatestScan(ctx, ou)
	require.NoError(t, err)
	assert.Equal(t, 7, latest.LookbackDays)
}

func TestShadowOnboardIsAtomicAndConnectionCascades(t *testing.T) {
	ctx := context.Background()
	repo := NewShadowAgentRepository(db.GetDB())
	ou := "ou-" + uuid.NewString()
	c := newShadowConnection(t, repo, ou, "conn")
	start := time.Now().UTC()
	_, err := repo.ApplyConnectionResult(ctx, ShadowConnectionApply{
		OUID: ou, ConnectionID: c.ID, ScanID: uuid.New(), ScanStartedAt: start,
		WindowStart: start.AddDate(0, 0, -30), Findings: []ShadowFindingInput{{Finding: models.ShadowFinding{
			Provider: models.ShadowProviderOpenAI, Kind: models.ShadowKindAPIKey, ExternalID: "k", DisplayName: "50%_off key",
		}}},
	}, countScore)
	require.NoError(t, err)
	rows, _, err := repo.ListFindings(ctx, ou, ShadowFindingFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	id := rows[0].ID

	require.NoError(t, repo.OnboardFinding(ctx, ou, id, "p", "a", "u", time.Now()))
	assert.ErrorIs(t, repo.OnboardFinding(ctx, ou, id, "p", "b", "u", time.Now()), utils.ErrShadowAlreadyOnboarded)
	onboarded, err := repo.ListOnboardedFindings(ctx, ou)
	require.NoError(t, err)
	require.Len(t, onboarded, 1)
	assert.Equal(t, models.ShadowRetirementMonitoring, onboarded[0].RetirementState)
	now := time.Now().UTC()
	require.NoError(t, repo.SetRetirement(ctx, ou, id, models.ShadowRetirementRetired, "", nil, &now))
	got, err := repo.GetFinding(ctx, ou, id)
	require.NoError(t, err)
	assert.Equal(t, models.ShadowStatusRetired, got.Status)

	// Search treats % and _ literally: "5_%" and "k%y" would match
	// "50%_off key" only as LIKE wildcards.
	for q, want := range map[string]int{"50%_off": 1, "%_": 1, "OFF KEY": 1, "5_%": 0, "k%y": 0} {
		got, _, err := repo.ListFindings(ctx, ou, ShadowFindingFilter{Search: q, Limit: 10})
		require.NoError(t, err)
		assert.Len(t, got, want, q)
	}

	sum, err := repo.Summary(ctx, ou)
	require.NoError(t, err)
	assert.Equal(t, 1, sum.Total)
	assert.Equal(t, 1, sum.Connections)

	deleted, err := repo.DeleteConnection(ctx, ou, c.ID)
	require.NoError(t, err)
	assert.True(t, deleted)
	_, total, err := repo.ListFindings(ctx, ou, ShadowFindingFilter{Limit: 10})
	require.NoError(t, err)
	assert.Zero(t, total, "findings are deleted with their connection")
}

func TestShadowCorrelationReplacesOnlyItsOwnRelations(t *testing.T) {
	ctx := context.Background()
	repo := NewShadowAgentRepository(db.GetDB())
	ou := "ou-" + uuid.NewString()
	c := newShadowConnection(t, repo, ou, "conn")
	start := time.Now().UTC()
	_, err := repo.ApplyConnectionResult(ctx, ShadowConnectionApply{
		OUID: ou, ConnectionID: c.ID, ScanID: uuid.New(), ScanStartedAt: start,
		WindowStart: start.AddDate(0, 0, -30), Findings: []ShadowFindingInput{
			{
				Finding: models.ShadowFinding{Provider: models.ShadowProviderOpenAI, Kind: models.ShadowKindAPIKey, ExternalID: "k"},
				Related: []ShadowRelationInput{{Kind: models.ShadowKindPlatformAgent, ExternalID: "a", Relation: "used_by_key"}},
			},
			{Finding: models.ShadowFinding{Provider: models.ShadowProviderOpenAI, Kind: models.ShadowKindPlatformAgent, ExternalID: "a"}},
		},
	}, countScore)
	require.NoError(t, err)
	all, err := repo.ListOrgFindings(ctx, ou)
	require.NoError(t, err)
	sort.Slice(all, func(i, j int) bool { return all[i].Kind < all[j].Kind })
	keyID, agentID := all[0].ID, all[1].ID

	apply := func() {
		require.NoError(t, repo.ApplyCorrelation(ctx, ou,
			map[uuid.UUID][]models.ShadowFindingRelation{keyID: {{FindingID: agentID.String(), Relation: "possible_duplicate"}}},
			map[uuid.UUID][]models.ShadowFindingSignal{keyID: {{Code: "foundry.external_possible_duplicate", Tier: "info", DetectedAt: start}}},
			countScore))
	}
	apply()
	apply()
	got, err := repo.GetFinding(ctx, ou, keyID)
	require.NoError(t, err)
	relations := map[string]int{}
	for _, r := range got.Related {
		relations[r.Relation]++
	}
	assert.Equal(t, map[string]int{"used_by_key": 1, "possible_duplicate": 1}, relations)
	signals, err := repo.ListSignals(ctx, ou, keyID)
	require.NoError(t, err)
	assert.Len(t, signals, 1)

	require.NoError(t, repo.ApplyCorrelation(ctx, ou, nil, nil, countScore))
	got, err = repo.GetFinding(ctx, ou, keyID)
	require.NoError(t, err)
	require.Len(t, got.Related, 1, "the connector's relation stays when correlation clears its own")
	assert.Equal(t, "used_by_key", got.Related[0].Relation)
}
