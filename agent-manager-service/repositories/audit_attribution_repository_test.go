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
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/db"
	"github.com/wso2/agent-manager/agent-manager-service/models"
)

// auditSeed is one org's attribution rows. Two orgs are seeded with the same
// project, agent and key names, so a query missing an ou_id predicate returns
// the other org's rows and the assertions below catch it.
type auditSeed struct {
	ouID          string
	proxyArtifact uuid.UUID
	agentArtifact uuid.UUID
	restArtifact  uuid.UUID
	agentUUID     uuid.UUID
	agentID       string
	clientID      string
}

func seedAuditOrg(t *testing.T, gdb *gorm.DB) auditSeed {
	t.Helper()
	s := auditSeed{
		ouID:          "ou-audit-" + uuid.New().String()[:8],
		proxyArtifact: uuid.New(),
		agentArtifact: uuid.New(),
		restArtifact:  uuid.New(),
		agentUUID:     uuid.New(),
		agentID:       "agentid-" + uuid.New().String()[:8],
		clientID:      "client-" + uuid.New().String()[:8],
	}
	artifacts := NewArtifactRepo(gdb)
	for _, a := range []*models.Artifact{
		{UUID: s.proxyArtifact, Handle: "bot-llm-proxy", Name: "bot-llm-proxy-" + s.ouID, Version: "v1", Kind: models.KindLLMProxy, OUID: s.ouID},
		{UUID: s.agentArtifact, Handle: "shop/bot/dev", Name: "bot-dev-" + s.ouID, Version: "v1", Kind: models.KindAgent, OUID: s.ouID},
		{UUID: s.restArtifact, Handle: "shop/bot/prod", Name: "bot-prod-" + s.ouID, Version: "v1", Kind: models.KindRestAPI, OUID: s.ouID},
	} {
		require.NoError(t, artifacts.Create(gdb, a))
	}

	config := &models.AgentConfiguration{Name: "bot-llm", AgentID: "bot", OUID: s.ouID, ProjectName: "shop"}
	require.NoError(t, gdb.Create(config).Error)

	// The mapping's llm_proxy_uuid is the proxy artifact's uuid; the
	// llm_proxies row it also references is not under test, so FK checks are
	// off for this one insert (as in env_agent_model_mapping_repository_test.go).
	require.NoError(t, gdb.Connection(func(tx *gorm.DB) error {
		if err := tx.Exec("SET session_replication_role = 'replica'").Error; err != nil {
			return err
		}
		defer func() { _ = tx.Exec("SET session_replication_role = 'origin'").Error }()
		return tx.Exec(`INSERT INTO env_agent_model_mapping (config_uuid, environment_uuid, llm_proxy_uuid) VALUES (?, ?, ?)`,
			config.UUID, uuid.New(), s.proxyArtifact).Error
	}))

	require.NoError(t, gdb.Create(&models.AgentThunderClient{
		OUID: s.ouID, ProjectName: "shop", AgentName: "bot", EnvironmentName: "dev",
		ProvisioningType: models.AgentProvisioningTypeExternal, Status: models.AgentThunderStatusCompleted,
		ThunderAgentID: s.agentID, ThunderClientID: s.clientID,
	}).Error)

	require.NoError(t, gdb.Create(&models.PlatformAgentExposure{
		OUID: s.ouID, ProjectName: "shop", AgentName: "bot", EnvironmentName: "dev",
		EnvironmentUUID: uuid.New(), ArtifactUUID: s.agentArtifact, AgentUUID: &s.agentUUID,
	}).Error)

	// One key on the LLM proxy (returned), one on the agent artifact (not an
	// LLM kind, never returned).
	require.NoError(t, gdb.Exec(`INSERT INTO api_keys (name, artifact_uuid, api_key_hash, ou_id) VALUES (?, ?, ?, ?), (?, ?, ?, ?)`,
		"key-1", s.proxyArtifact, "hash-"+s.ouID, s.ouID,
		"agent-key", s.agentArtifact, "agent-hash-"+s.ouID, s.ouID).Error)

	t.Cleanup(func() {
		gdb.Exec(`DELETE FROM api_keys WHERE ou_id = ?`, s.ouID)
		gdb.Exec(`DELETE FROM platform_agent_exposures WHERE ou_id = ?`, s.ouID)
		gdb.Exec(`DELETE FROM agent_thunder_clients WHERE ou_id = ?`, s.ouID)
		gdb.Exec(`DELETE FROM env_agent_model_mapping WHERE config_uuid = ?`, config.UUID)
		gdb.Exec(`DELETE FROM agent_configurations WHERE uuid = ?`, config.UUID)
		gdb.Exec(`DELETE FROM artifacts WHERE ou_id = ?`, s.ouID)
	})
	return s
}

func TestAuditAttributionRepo_ListLLMProxyAgentsIsOrgScoped(t *testing.T) {
	gdb := db.GetDB()
	a, b := seedAuditOrg(t, gdb), seedAuditOrg(t, gdb)
	repo := NewAuditAttributionRepository(gdb)

	rows, err := repo.ListLLMProxyAgents(context.Background(), a.ouID)
	require.NoError(t, err)
	require.Equal(t, []AuditLLMProxyAgent{{
		ArtifactUUID: a.proxyArtifact.String(), Handle: "bot-llm-proxy", ProjectName: "shop", AgentName: "bot",
	}}, rows)

	rows, err = repo.ListLLMProxyAgents(context.Background(), b.ouID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, b.proxyArtifact.String(), rows[0].ArtifactUUID)

	none, err := repo.ListLLMProxyAgents(context.Background(), "ou-unknown")
	require.NoError(t, err)
	assert.Empty(t, none)
}

// A mapping whose configuration and proxy belong to different orgs is
// returned for neither: both tables carry their own ou_id predicate.
func TestAuditAttributionRepo_ListLLMProxyAgentsRequiresBothSidesInTheOrg(t *testing.T) {
	gdb := db.GetDB()
	a, b := seedAuditOrg(t, gdb), seedAuditOrg(t, gdb)
	cross := &models.AgentConfiguration{Name: "cross", AgentID: "cross-bot", OUID: a.ouID, ProjectName: "shop"}
	require.NoError(t, gdb.Create(cross).Error)
	t.Cleanup(func() {
		gdb.Exec(`DELETE FROM env_agent_model_mapping WHERE config_uuid = ?`, cross.UUID)
		gdb.Exec(`DELETE FROM agent_configurations WHERE uuid = ?`, cross.UUID)
	})
	require.NoError(t, gdb.Connection(func(tx *gorm.DB) error {
		if err := tx.Exec("SET session_replication_role = 'replica'").Error; err != nil {
			return err
		}
		defer func() { _ = tx.Exec("SET session_replication_role = 'origin'").Error }()
		return tx.Exec(`INSERT INTO env_agent_model_mapping (config_uuid, environment_uuid, llm_proxy_uuid) VALUES (?, ?, ?)`,
			cross.UUID, uuid.New(), b.proxyArtifact).Error
	}))
	repo := NewAuditAttributionRepository(gdb)
	for _, ou := range []string{a.ouID, b.ouID} {
		rows, err := repo.ListLLMProxyAgents(context.Background(), ou)
		require.NoError(t, err)
		for _, r := range rows {
			assert.NotEqual(t, "cross-bot", r.AgentName, "org %s", ou)
		}
	}
}

func TestAuditAttributionRepo_ListAgentIdentitiesIsOrgScoped(t *testing.T) {
	gdb := db.GetDB()
	a, b := seedAuditOrg(t, gdb), seedAuditOrg(t, gdb)
	repo := NewAuditAttributionRepository(gdb)

	rows, err := repo.ListAgentIdentities(context.Background(), a.ouID)
	require.NoError(t, err)
	require.Equal(t, []AuditAgentIdentity{{
		ProjectName: "shop", AgentName: "bot", EnvironmentName: "dev", ThunderAgentID: a.agentID, ThunderClientID: a.clientID,
	}}, rows)

	rows, err = repo.ListAgentIdentities(context.Background(), b.ouID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, b.agentID, rows[0].ThunderAgentID)
}

func TestAuditAttributionRepo_ListAgentArtifactsIsOrgScoped(t *testing.T) {
	gdb := db.GetDB()
	a, b := seedAuditOrg(t, gdb), seedAuditOrg(t, gdb)
	repo := NewAuditAttributionRepository(gdb)

	rows, err := repo.ListAgentArtifacts(context.Background(), a.ouID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []AuditAgentArtifact{
		{ArtifactUUID: a.agentArtifact.String(), Handle: "shop/bot/dev", Kind: models.KindAgent, AgentUUID: a.agentUUID.String()},
		{ArtifactUUID: a.restArtifact.String(), Handle: "shop/bot/prod", Kind: models.KindRestAPI, AgentUUID: ""},
	}, rows, "agent kinds only (no LLM proxy), and the exposure's agent uuid when there is one")

	rows, err = repo.ListAgentArtifacts(context.Background(), b.ouID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, r := range rows {
		assert.NotEqual(t, a.agentArtifact.String(), r.ArtifactUUID)
		assert.NotEqual(t, a.agentUUID.String(), r.AgentUUID)
	}
}

func TestAuditAttributionRepo_ListAPIKeysIsOrgScoped(t *testing.T) {
	gdb := db.GetDB()
	a, b := seedAuditOrg(t, gdb), seedAuditOrg(t, gdb)
	repo := NewAuditAttributionRepository(gdb)

	rows, err := repo.ListAPIKeys(context.Background(), a.ouID)
	require.NoError(t, err)
	require.Equal(t, []AuditAPIKey{{
		Name: "key-1", APIKeyHash: "hash-" + a.ouID, ArtifactHandle: "bot-llm-proxy", ArtifactKind: models.KindLLMProxy,
	}}, rows, "only keys bound to LLM proxies and providers, only this org's")

	rows, err = repo.ListAPIKeys(context.Background(), b.ouID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "hash-"+b.ouID, rows[0].APIKeyHash)
}
