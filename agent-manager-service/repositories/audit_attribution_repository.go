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
	"fmt"

	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/models"
)

// AuditLLMProxyAgent links an agent-owned LLM proxy artifact to its agent.
// Gateway traffic records name the proxy as api.name / api.id (its handle).
type AuditLLMProxyAgent struct {
	ArtifactUUID string
	Handle       string
	ProjectName  string
	AgentName    string
}

// AuditAgentIdentity is an agent's AgentID in one environment. MCP traffic
// records carry it as auth.subject (or act.sub when delegated) and the
// OAuth client as auth.clientId.
type AuditAgentIdentity struct {
	ProjectName     string
	AgentName       string
	EnvironmentName string
	ThunderAgentID  string
	ThunderClientID string
}

// AuditAgentArtifact is a platform agent's per-environment API artifact.
// Ingress traffic to the agent (REST and A2A) carries its UUID as api.id.
type AuditAgentArtifact struct {
	ArtifactUUID string
	Handle       string
	Kind         string
	// AgentUUID is the OpenChoreo component id when known, otherwise empty.
	AgentUUID string
}

// AuditAPIKey is a stored API key verifier with the artifact it is bound to.
// The verifier is the SHA-256 hex the gateway fingerprints into auth.tokenId.
type AuditAPIKey struct {
	Name           string
	APIKeyHash     string
	ArtifactHandle string
	ArtifactKind   string
}

// AuditAttributionRepository reads the identifiers that let audit records be
// attributed to agents. Every method is scoped to one org (ou_id) and
// read-only.
//
//go:generate moq -rm -fmt goimports -skip-ensure -pkg repomocks -out repomocks/audit_attribution_repository_mock.go . AuditAttributionRepository:AuditAttributionRepositoryMock
type AuditAttributionRepository interface {
	// ListLLMProxyAgents returns every LLM proxy created for an agent model
	// configuration in the org.
	ListLLMProxyAgents(ctx context.Context, ouID string) ([]AuditLLMProxyAgent, error)
	// ListAgentIdentities returns every agent AgentID binding in the org.
	ListAgentIdentities(ctx context.Context, ouID string) ([]AuditAgentIdentity, error)
	// ListAgentArtifacts returns every per-environment agent API artifact in the org.
	ListAgentArtifacts(ctx context.Context, ouID string) ([]AuditAgentArtifact, error)
	// ListAPIKeys returns the org's API key verifiers bound to LLM proxies and
	// LLM providers. Only called when a fingerprint key is configured.
	ListAPIKeys(ctx context.Context, ouID string) ([]AuditAPIKey, error)
}

type auditAttributionRepository struct {
	db *gorm.DB
}

// NewAuditAttributionRepository creates the repository.
func NewAuditAttributionRepository(db *gorm.DB) AuditAttributionRepository {
	return &auditAttributionRepository{db: db}
}

func (r *auditAttributionRepository) ListLLMProxyAgents(ctx context.Context, ouID string) ([]AuditLLMProxyAgent, error) {
	var rows []AuditLLMProxyAgent
	err := r.db.WithContext(ctx).
		Table("env_agent_model_mapping eam").
		Select("DISTINCT a.uuid::text AS artifact_uuid, a.handle AS handle, ac.project_name AS project_name, ac.agent_id AS agent_name").
		Joins("JOIN artifacts a ON a.uuid = eam.llm_proxy_uuid").
		Joins("JOIN agent_configurations ac ON ac.uuid = eam.config_uuid").
		Where("ac.ou_id = ? AND a.ou_id = ?", ouID, ouID).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list agent LLM proxies: %w", err)
	}
	return rows, nil
}

func (r *auditAttributionRepository) ListAgentIdentities(ctx context.Context, ouID string) ([]AuditAgentIdentity, error) {
	var rows []AuditAgentIdentity
	err := r.db.WithContext(ctx).
		Table("agent_thunder_clients").
		Select("project_name, agent_name, environment_name, thunder_agent_id, thunder_client_id").
		Where("ou_id = ?", ouID).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list agent identities: %w", err)
	}
	return rows, nil
}

func (r *auditAttributionRepository) ListAgentArtifacts(ctx context.Context, ouID string) ([]AuditAgentArtifact, error) {
	var rows []AuditAgentArtifact
	err := r.db.WithContext(ctx).
		Table("artifacts a").
		Select("a.uuid::text AS artifact_uuid, a.handle AS handle, a.kind AS kind, COALESCE(MAX(pae.agent_uuid::text), '') AS agent_uuid").
		Joins("LEFT JOIN platform_agent_exposures pae ON pae.artifact_uuid = a.uuid AND pae.ou_id = a.ou_id").
		Where("a.ou_id = ? AND a.kind IN ?", ouID, models.AgentArtifactKinds).
		Group("a.uuid, a.handle, a.kind").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list agent artifacts: %w", err)
	}
	return rows, nil
}

func (r *auditAttributionRepository) ListAPIKeys(ctx context.Context, ouID string) ([]AuditAPIKey, error) {
	var rows []AuditAPIKey
	err := r.db.WithContext(ctx).
		Table("api_keys k").
		Select("k.name AS name, k.api_key_hash AS api_key_hash, a.handle AS artifact_handle, a.kind AS artifact_kind").
		Joins("JOIN artifacts a ON a.uuid = k.artifact_uuid").
		Where("k.ou_id = ? AND a.ou_id = ? AND a.kind IN ?", ouID, ouID, []string{models.KindLLMProxy, models.KindLLMProvider}).
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list API key verifiers: %w", err)
	}
	return rows, nil
}
