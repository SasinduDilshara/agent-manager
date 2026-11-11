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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	"github.com/wso2/agent-manager/agent-manager-service/repositories/repomocks"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

const (
	shadowTestOU     = "ou-1"
	shadowSecretKey  = "sk-admin-SECRETSECRETSECRET-wxyz"
	shadowPromptMark = "SECRET-PROMPT-MARKER"
)

var shadowTestKey = bytes.Repeat([]byte{7}, 32)

type shadowAgentLookupStub struct {
	GetAgentFunc func(ctx context.Context, ouID, projectName, agentName string) (*models.AgentResponse, error)
}

func (s *shadowAgentLookupStub) GetAgent(ctx context.Context, ouID, projectName, agentName string) (*models.AgentResponse, error) {
	return s.GetAgentFunc(ctx, ouID, projectName, agentName)
}

func newShadowSvc(repo *repomocks.ShadowAgentRepositoryMock, agents ShadowAgentLookup) *shadowAgentService {
	return NewShadowAgentService(repo, ShadowConnectors{}, agents, shadowTestKey, discardLogger()).(*shadowAgentService)
}

func openAIInput() ShadowConnectionInput {
	return ShadowConnectionInput{
		Name: "OpenAI prod", Provider: models.ShadowProviderOpenAI,
		Settings: map[string]any{"apiKey": shadowSecretKey},
	}
}

// ---- connections ----

func TestShadowCreateConnection_EncryptsSecretAndReturnsOnlyHints(t *testing.T) {
	var stored *models.ShadowConnection
	repo := &repomocks.ShadowAgentRepositoryMock{
		ListConnectionsFunc: func(context.Context, string) ([]models.ShadowConnection, error) {
			return []models.ShadowConnection{}, nil
		},
		CreateConnectionFunc: func(_ context.Context, c *models.ShadowConnection) error {
			stored = c
			return nil
		},
	}
	svc := newShadowSvc(repo, nil)
	v, err := svc.CreateConnection(auditableCtx(t), shadowTestOU, openAIInput())
	require.NoError(t, err)
	require.NotNil(t, stored)

	assert.Equal(t, shadowTestOU, stored.OUID)
	assert.NotContains(t, string(stored.SecretEncrypted), "SECRETSECRET", "the secret is stored encrypted")
	secret, err := decryptShadowSecret(stored.SecretEncrypted, shadowTestKey)
	require.NoError(t, err)
	assert.Equal(t, shadowSecretKey, secret.APIKey)
	assert.Equal(t, "sk-a…wxyz", stored.SecretHints["apiKey"])
	assert.Equal(t, "https://api.openai.com/v1", stored.Config.Endpoints[sa.EPOpenAIAPI])

	view, err := json.Marshal(v.Settings)
	require.NoError(t, err)
	assert.NotContains(t, string(view), "SECRETSECRET", "settings never carry a secret")
	assert.Empty(t, v.EndpointWarnings)
}

func TestShadowCreateConnection_RefusesWithoutAuditRecorder(t *testing.T) {
	repo := &repomocks.ShadowAgentRepositoryMock{
		ListConnectionsFunc: func(context.Context, string) ([]models.ShadowConnection, error) {
			return []models.ShadowConnection{}, nil
		},
		// CreateConnectionFunc nil: must not be reached.
	}
	_, err := newShadowSvc(repo, nil).CreateConnection(context.Background(), shadowTestOU, openAIInput())
	assert.ErrorIs(t, err, audit.ErrRecorderUnavailable)
}

func TestShadowCreateConnection_Validation(t *testing.T) {
	repo := &repomocks.ShadowAgentRepositoryMock{
		ListConnectionsFunc: func(context.Context, string) ([]models.ShadowConnection, error) {
			return []models.ShadowConnection{}, nil
		},
	}
	svc := newShadowSvc(repo, nil)
	tests := map[string]ShadowConnectionInput{
		"unknown provider":        {Name: "x", Provider: "acme", Settings: map[string]any{}},
		"missing name":            {Name: " ", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{"apiKey": "k"}},
		"missing required secret": {Name: "x", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{}},
		"unknown setting":         {Name: "x", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{"apiKey": "k", "region": "x"}},
		"unknown endpoint": {
			Name: "x", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{"apiKey": "k"},
			Endpoints: map[string]string{"nope": "https://x"},
		},
		"endpoint with a query": {
			Name: "x", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{"apiKey": "k"},
			Endpoints: map[string]string{sa.EPOpenAIAPI: "https://api.openai.com/v1?key=1"},
		},
		"wrong type": {Name: "x", Provider: models.ShadowProviderBedrock, Settings: map[string]any{
			"regions": "us-east-1", "accessKeyId": "AKIA", "secretAccessKey": "s",
		}},
		"missing required list": {Name: "x", Provider: models.ShadowProviderGoogle, Settings: map[string]any{
			"projectIds": []any{}, "locations": []any{"us-central1"}, "serviceAccountJson": `{"type":"service_account"}`,
		}},
		"service account key is not JSON": {Name: "x", Provider: models.ShadowProviderGoogle, Settings: map[string]any{
			"projectIds": []any{"p"}, "locations": []any{"us-central1"}, "serviceAccountJson": "not json",
		}},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := svc.CreateConnection(auditableCtx(t), shadowTestOU, in)
			assert.ErrorIs(t, err, utils.ErrInvalidInput)
		})
	}
}

func TestShadowCreateConnection_CustomEndpointWarnsButIsAllowed(t *testing.T) {
	repo := &repomocks.ShadowAgentRepositoryMock{
		ListConnectionsFunc: func(context.Context, string) ([]models.ShadowConnection, error) {
			return []models.ShadowConnection{}, nil
		},
		CreateConnectionFunc: func(context.Context, *models.ShadowConnection) error { return nil },
	}
	in := openAIInput()
	in.Endpoints = map[string]string{sa.EPOpenAIAPI: "http://localhost:18080/v1/"}
	v, err := newShadowSvc(repo, nil).CreateConnection(auditableCtx(t), shadowTestOU, in)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:18080/v1", v.Connection.Config.Endpoints[sa.EPOpenAIAPI])
	require.Len(t, v.EndpointWarnings, 1)
	assert.Contains(t, v.EndpointWarnings[0], "not an official OpenAI host")
}

func TestShadowCreateConnection_AzureCheckboxDefaultsAndOptionalFields(t *testing.T) {
	var stored *models.ShadowConnection
	repo := &repomocks.ShadowAgentRepositoryMock{
		ListConnectionsFunc: func(context.Context, string) ([]models.ShadowConnection, error) {
			return []models.ShadowConnection{}, nil
		},
		CreateConnectionFunc: func(_ context.Context, c *models.ShadowConnection) error {
			stored = c
			return nil
		},
	}
	_, err := newShadowSvc(repo, nil).CreateConnection(auditableCtx(t), shadowTestOU, ShadowConnectionInput{
		Name: "Foundry", Provider: models.ShadowProviderFoundry,
		Settings: map[string]any{"tenantId": "t", "clientId": "c", "clientSecret": "s3cr3t-value-123456"},
	})
	require.NoError(t, err)
	assert.True(t, stored.Config.AllSubscriptions, "ticked by default")
	assert.True(t, stored.Config.IncludeClassicAgents, "ticked by default")
	assert.False(t, stored.Config.DeepInspection, "deep inspection is opt-in")
}

func TestShadowUpdateConnection_EmptySecretKeepsStoredOne(t *testing.T) {
	ctx := auditableCtx(t)
	encrypted, err := (&shadowAgentService{encryptionKey: shadowTestKey}).encryptSecret(models.ShadowConnectionSecret{
		APIKey: shadowSecretKey, ScopedKeys: map[string]string{"proj_a": "sk-proj-AAAAAAAAAAAAAAAA"},
	})
	require.NoError(t, err)
	id := uuid.New()
	existing := &models.ShadowConnection{
		ID: id, OUID: shadowTestOU, Name: "OpenAI", Provider: models.ShadowProviderOpenAI,
		Config:          models.ShadowConnectionConfig{Endpoints: sa.DefaultEndpoints(models.ShadowProviderOpenAI)},
		SecretEncrypted: encrypted,
	}
	var updated *models.ShadowConnection
	repo := &repomocks.ShadowAgentRepositoryMock{
		GetConnectionFunc: func(context.Context, string, uuid.UUID) (*models.ShadowConnection, error) {
			c := *existing
			return &c, nil
		},
		UpdateConnectionFunc: func(_ context.Context, c *models.ShadowConnection) error {
			updated = c
			return nil
		},
	}
	svc := newShadowSvc(repo, nil)
	_, err = svc.UpdateConnection(ctx, shadowTestOU, id, ShadowConnectionInput{
		Name: "OpenAI renamed", Provider: models.ShadowProviderOpenAI,
		// Empty admin key and an empty value for a known project key: keep both.
		Settings: map[string]any{"apiKey": "", "scopedKeys": map[string]any{"proj_a": ""}},
	})
	require.NoError(t, err)
	secret, err := decryptShadowSecret(updated.SecretEncrypted, shadowTestKey)
	require.NoError(t, err)
	assert.Equal(t, shadowSecretKey, secret.APIKey)
	assert.Equal(t, "sk-proj-AAAAAAAAAAAAAAAA", secret.ScopedKeys["proj_a"])
	assert.Equal(t, []string{"proj_a"}, updated.Config.ScopedKeyIDs)

	_, err = svc.UpdateConnection(ctx, shadowTestOU, id, ShadowConnectionInput{
		Name: "x", Provider: models.ShadowProviderAnthropic, Settings: map[string]any{},
	})
	assert.ErrorIs(t, err, utils.ErrInvalidInput, "the provider cannot change")
}

// TestShadowCredentialChoice: OpenAI and Anthropic need an Admin API key or
// at least one project/workspace key; either alone is enough.
func TestShadowCredentialChoice(t *testing.T) {
	repo := &repomocks.ShadowAgentRepositoryMock{
		ListConnectionsFunc: func(context.Context, string) ([]models.ShadowConnection, error) {
			return []models.ShadowConnection{}, nil
		},
		CreateConnectionFunc: func(context.Context, *models.ShadowConnection) error { return nil },
	}
	svc := newShadowSvc(repo, nil)
	ok := map[string]ShadowConnectionInput{
		"openai admin key only": {Name: "a", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{"apiKey": "sk-admin-x"}},
		"openai project keys only": {Name: "b", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{
			"scopedKeys": map[string]any{"proj_a": "sk-proj-a"},
		}},
		"anthropic workspace keys only": {Name: "c", Provider: models.ShadowProviderAnthropic, Settings: map[string]any{
			"scopedKeys": map[string]any{"wrkspc_a": "sk-ant-api03-a"}, "includeCloudVariants": false,
		}},
	}
	for name, in := range ok {
		t.Run(name, func(t *testing.T) {
			_, err := svc.CreateConnection(auditableCtx(t), shadowTestOU, in)
			assert.NoError(t, err)
		})
	}
	bad := map[string]struct {
		in   ShadowConnectionInput
		want string
	}{
		"openai neither": {ShadowConnectionInput{Name: "d", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{
			"scopedKeys": map[string]any{},
		}}, "Add an Admin API key (recommended) or at least one project key."},
		"anthropic neither": {ShadowConnectionInput{Name: "e", Provider: models.ShadowProviderAnthropic, Settings: map[string]any{
			"apiKey": "  ", "includeCloudVariants": false,
		}}, "Add an Admin API key (recommended) or at least one workspace key."},
		"removeSecrets on create": {ShadowConnectionInput{
			Name: "f", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{"apiKey": "k"}, RemoveSecrets: []string{"apiKey"},
		}, "removeSecrets applies only when updating"},
	}
	for name, tc := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := svc.CreateConnection(auditableCtx(t), shadowTestOU, tc.in)
			require.ErrorIs(t, err, utils.ErrInvalidInput)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestShadowUpdateConnection_RemoveSecrets: an optional stored secret can be
// removed, a required one cannot, and the credential choice still applies.
func TestShadowUpdateConnection_RemoveSecrets(t *testing.T) {
	stored := func(t *testing.T, secret models.ShadowConnectionSecret, provider string) (*repomocks.ShadowAgentRepositoryMock, uuid.UUID, **models.ShadowConnection) {
		t.Helper()
		encrypted, err := (&shadowAgentService{encryptionKey: shadowTestKey}).encryptSecret(secret)
		require.NoError(t, err)
		id := uuid.New()
		existing := &models.ShadowConnection{
			ID: id, OUID: shadowTestOU, Name: "c", Provider: provider,
			Config: models.ShadowConnectionConfig{Endpoints: sa.DefaultEndpoints(provider)}, SecretEncrypted: encrypted,
		}
		var updated *models.ShadowConnection
		repo := &repomocks.ShadowAgentRepositoryMock{
			GetConnectionFunc: func(context.Context, string, uuid.UUID) (*models.ShadowConnection, error) {
				c := *existing
				return &c, nil
			},
			UpdateConnectionFunc: func(_ context.Context, c *models.ShadowConnection) error {
				updated = c
				return nil
			},
		}
		return repo, id, &updated
	}
	both := models.ShadowConnectionSecret{APIKey: shadowSecretKey, ScopedKeys: map[string]string{"proj_a": "sk-proj-AAAAAAAAAAAAAAAA"}}

	t.Run("remove the Admin key, keep project keys", func(t *testing.T) {
		repo, id, updated := stored(t, both, models.ShadowProviderOpenAI)
		v, err := newShadowSvc(repo, nil).UpdateConnection(auditableCtx(t), shadowTestOU, id, ShadowConnectionInput{
			Name: "c", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{}, RemoveSecrets: []string{"apiKey"},
		})
		require.NoError(t, err)
		secret, err := decryptShadowSecret((*updated).SecretEncrypted, shadowTestKey)
		require.NoError(t, err)
		assert.Empty(t, secret.APIKey)
		assert.Equal(t, "sk-proj-AAAAAAAAAAAAAAAA", secret.ScopedKeys["proj_a"])
		assert.NotContains(t, v.Connection.SecretHints, "apiKey")
		assert.Contains(t, v.Connection.SecretHints, "scopedKeys.proj_a")
	})
	t.Run("removing the only credential is refused", func(t *testing.T) {
		repo, id, _ := stored(t, models.ShadowConnectionSecret{APIKey: shadowSecretKey}, models.ShadowProviderOpenAI)
		_, err := newShadowSvc(repo, nil).UpdateConnection(auditableCtx(t), shadowTestOU, id, ShadowConnectionInput{
			Name: "c", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{}, RemoveSecrets: []string{"apiKey"},
		})
		require.ErrorIs(t, err, utils.ErrInvalidInput)
		assert.Contains(t, err.Error(), "at least one project key")
		assert.Empty(t, repo.UpdateConnectionCalls())
	})
	t.Run("removing project keys keeps a stored Admin key valid", func(t *testing.T) {
		repo, id, updated := stored(t, both, models.ShadowProviderOpenAI)
		_, err := newShadowSvc(repo, nil).UpdateConnection(auditableCtx(t), shadowTestOU, id, ShadowConnectionInput{
			Name: "c", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{"scopedKeys": map[string]any{}},
		})
		require.NoError(t, err)
		secret, err := decryptShadowSecret((*updated).SecretEncrypted, shadowTestKey)
		require.NoError(t, err)
		assert.Equal(t, shadowSecretKey, secret.APIKey)
		assert.Empty(t, secret.ScopedKeys)
	})
	t.Run("a required secret cannot be removed", func(t *testing.T) {
		repo, id, _ := stored(t, models.ShadowConnectionSecret{ClientSecret: "s3cr3t-value-123456"}, models.ShadowProviderFoundry)
		_, err := newShadowSvc(repo, nil).UpdateConnection(auditableCtx(t), shadowTestOU, id, ShadowConnectionInput{
			Name: "c", Provider: models.ShadowProviderFoundry,
			Settings:      map[string]any{"tenantId": "t", "clientId": "c"},
			RemoveSecrets: []string{"clientSecret"},
		})
		require.ErrorIs(t, err, utils.ErrInvalidInput)
		assert.Contains(t, err.Error(), "cannot be removed")
	})
	t.Run("remove and set in one request", func(t *testing.T) {
		repo, id, _ := stored(t, both, models.ShadowProviderOpenAI)
		_, err := newShadowSvc(repo, nil).UpdateConnection(auditableCtx(t), shadowTestOU, id, ShadowConnectionInput{
			Name: "c", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{"apiKey": "sk-admin-new"}, RemoveSecrets: []string{"apiKey"},
		})
		assert.ErrorIs(t, err, utils.ErrInvalidInput)
	})
	t.Run("not a secret field", func(t *testing.T) {
		repo, id, _ := stored(t, both, models.ShadowProviderOpenAI)
		for _, k := range []string{"scopedKeys", "deepInspection", "nope"} {
			_, err := newShadowSvc(repo, nil).UpdateConnection(auditableCtx(t), shadowTestOU, id, ShadowConnectionInput{
				Name: "c", Provider: models.ShadowProviderOpenAI, Settings: map[string]any{}, RemoveSecrets: []string{k},
			})
			assert.ErrorIs(t, err, utils.ErrInvalidInput, k)
		}
	})
}

// TestShadowServiceOptions: unticked Bedrock/Google services are stored as
// DisabledServices and read back as unticked; a connection saved before the
// options existed has every service on; a Bedrock connection needs at least
// one service.
func TestShadowServiceOptions(t *testing.T) {
	var stored *models.ShadowConnection
	repo := &repomocks.ShadowAgentRepositoryMock{
		ListConnectionsFunc: func(context.Context, string) ([]models.ShadowConnection, error) {
			return []models.ShadowConnection{}, nil
		},
		CreateConnectionFunc: func(_ context.Context, c *models.ShadowConnection) error {
			stored = c
			return nil
		},
	}
	svc := newShadowSvc(repo, nil)
	bedrock := func(name string, extra map[string]any) ShadowConnectionInput {
		settings := map[string]any{"regions": []any{"us-east-1"}, "accessKeyId": "AKIA", "secretAccessKey": "s"}
		for k, v := range extra {
			settings[k] = v
		}
		return ShadowConnectionInput{Name: name, Provider: models.ShadowProviderBedrock, Settings: settings}
	}
	v, err := svc.CreateConnection(auditableCtx(t), shadowTestOU, bedrock("b1", map[string]any{
		sa.OptBedrockRegistry: false, sa.OptBedrockInvocationLogs: false,
	}))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{sa.OptBedrockRegistry, sa.OptBedrockInvocationLogs}, stored.Config.DisabledServices)
	assert.Equal(t, false, v.Settings[sa.OptBedrockRegistry])
	assert.Equal(t, false, v.Settings[sa.OptBedrockInvocationLogs])
	assert.Equal(t, true, v.Settings[sa.OptBedrockAgentCore])
	assert.Equal(t, true, v.Settings[sa.OptBedrockCloudTrail])

	// Defaults: every service on.
	_, err = svc.CreateConnection(auditableCtx(t), shadowTestOU, bedrock("b2", nil))
	require.NoError(t, err)
	assert.Empty(t, stored.Config.DisabledServices)

	// A connection stored before the options existed reads as all on.
	legacy := shadowSettingsOf(models.ShadowProviderBedrock, models.ShadowConnectionConfig{Regions: []string{"us-east-1"}})
	for _, k := range []string{
		sa.OptBedrockAgentCore, sa.OptBedrockRegistry, sa.OptBedrockClassicAgents,
		sa.OptBedrockMetrics, sa.OptBedrockCloudTrail, sa.OptBedrockInvocationLogs,
	} {
		assert.Equal(t, true, legacy[k], k)
	}
	assert.True(t, sa.ServiceEnabled(models.ShadowConnectionConfig{}, sa.OptGoogleMonitoring))

	// Nothing selected: refused.
	_, err = svc.CreateConnection(auditableCtx(t), shadowTestOU, bedrock("b3", map[string]any{
		sa.OptBedrockAgentCore: false, sa.OptBedrockRegistry: false, sa.OptBedrockClassicAgents: false,
		sa.OptBedrockMetrics: false, sa.OptBedrockCloudTrail: false, sa.OptBedrockInvocationLogs: false,
	}))
	require.ErrorIs(t, err, utils.ErrInvalidInput)
	assert.Contains(t, err.Error(), "Select at least one Bedrock service to scan.")

	// Google: the engines always run, so unticking every optional service is allowed.
	_, err = svc.CreateConnection(auditableCtx(t), shadowTestOU, ShadowConnectionInput{
		Name: "g", Provider: models.ShadowProviderGoogle, Settings: map[string]any{
			"projectIds": []any{"p"}, "locations": []any{"us-central1"}, "serviceAccountJson": `{"type":"service_account"}`,
			sa.OptGoogleRegistry: false, sa.OptGoogleMonitoring: false, sa.OptGoogleAuditLogs: false,
		},
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{sa.OptGoogleRegistry, sa.OptGoogleMonitoring, sa.OptGoogleAuditLogs}, stored.Config.DisabledServices)
}

func TestShadowGetConnection_NotFoundIsNotMasked(t *testing.T) {
	repo := &repomocks.ShadowAgentRepositoryMock{
		GetConnectionFunc: func(context.Context, string, uuid.UUID) (*models.ShadowConnection, error) {
			return nil, gorm.ErrRecordNotFound
		},
	}
	_, err := newShadowSvc(repo, nil).GetConnection(context.Background(), shadowTestOU, uuid.New())
	assert.ErrorIs(t, err, utils.ErrShadowConnectionNotFound)

	repo.GetConnectionFunc = func(context.Context, string, uuid.UUID) (*models.ShadowConnection, error) {
		return nil, assert.AnError
	}
	_, err = newShadowSvc(repo, nil).GetConnection(context.Background(), shadowTestOU, uuid.New())
	assert.NotErrorIs(t, err, utils.ErrShadowConnectionNotFound)
	assert.ErrorIs(t, err, assert.AnError)
}

// ---- scans ----

func TestShadowCreateScan(t *testing.T) {
	c1 := models.ShadowConnection{ID: uuid.New()}
	var created *models.ShadowScan
	repo := &repomocks.ShadowAgentRepositoryMock{
		ListConnectionsFunc: func(context.Context, string) ([]models.ShadowConnection, error) {
			return []models.ShadowConnection{c1}, nil
		},
		CreateScanFunc: func(_ context.Context, s *models.ShadowScan) error {
			created = s
			return nil
		},
	}
	svc := newShadowSvc(repo, nil)
	scan, err := svc.CreateScan(auditableCtx(t), shadowTestOU, nil, 0)
	require.NoError(t, err)
	assert.Equal(t, ShadowDefaultLookbackDays, scan.LookbackDays)
	assert.Equal(t, models.ShadowScanQueued, created.Status)
	assert.Equal(t, []string{c1.ID.String()}, created.ConnectionIDs)

	_, err = svc.CreateScan(auditableCtx(t), shadowTestOU, nil, 91)
	assert.ErrorIs(t, err, utils.ErrInvalidInput)
	_, err = svc.CreateScan(auditableCtx(t), shadowTestOU, []uuid.UUID{uuid.New()}, 7)
	assert.ErrorIs(t, err, utils.ErrInvalidInput, "a connection of another org is not found")

	repo.CreateScanFunc = func(context.Context, *models.ShadowScan) error { return utils.ErrShadowScanInProgress }
	_, err = svc.CreateScan(auditableCtx(t), shadowTestOU, nil, 7)
	assert.ErrorIs(t, err, utils.ErrShadowScanInProgress)

	repo.ListConnectionsFunc = func(context.Context, string) ([]models.ShadowConnection, error) {
		return []models.ShadowConnection{}, nil
	}
	_, err = svc.CreateScan(auditableCtx(t), shadowTestOU, nil, 7)
	assert.ErrorIs(t, err, utils.ErrShadowNoConnections)
}

// ---- findings ----

func findingRepo(f models.ShadowFinding) *repomocks.ShadowAgentRepositoryMock {
	return &repomocks.ShadowAgentRepositoryMock{
		GetFindingFunc: func(context.Context, string, uuid.UUID) (*repositories.ShadowFindingRow, error) {
			return &repositories.ShadowFindingRow{ShadowFinding: f}, nil
		},
		ListSignalsFunc: func(context.Context, string, uuid.UUID) ([]models.ShadowFindingSignal, error) {
			return []models.ShadowFindingSignal{}, nil
		},
		ListFindingKeysFunc: func(context.Context, string, uuid.UUID) ([]models.ShadowAPIKey, error) {
			return []models.ShadowAPIKey{}, nil
		},
		ListUsageFunc: func(context.Context, string, uuid.UUID) ([]models.ShadowUsageDaily, error) {
			return []models.ShadowUsageDaily{}, nil
		},
		LatestScanFunc: func(context.Context, string) (*models.ShadowScan, error) {
			return nil, gorm.ErrRecordNotFound
		},
	}
}

func TestShadowOnboard_ChecksTheAgentExistsInTheCallersOrg(t *testing.T) {
	f := models.ShadowFinding{ID: uuid.New(), OUID: shadowTestOU, Kind: models.ShadowKindAPIKey, Provider: models.ShadowProviderOpenAI}
	repo := findingRepo(f)
	var lookedUpOU string
	agents := &shadowAgentLookupStub{GetAgentFunc: func(_ context.Context, ouID, _, _ string) (*models.AgentResponse, error) {
		lookedUpOU = ouID
		return nil, utils.ErrAgentNotFound
	}}
	_, err := newShadowSvc(repo, agents).Onboard(auditableCtx(t), shadowTestOU, f.ID, "proj", "agent")
	assert.ErrorIs(t, err, utils.ErrAgentNotFound)
	assert.Equal(t, shadowTestOU, lookedUpOU)
	assert.Empty(t, repo.OnboardFindingCalls(), "nothing is linked to a missing agent")

	agents.GetAgentFunc = func(context.Context, string, string, string) (*models.AgentResponse, error) {
		return &models.AgentResponse{}, nil
	}
	repo.OnboardFindingFunc = func(_ context.Context, ouID string, _ uuid.UUID, project, agent, _ string, _ time.Time) error {
		assert.Equal(t, shadowTestOU, ouID)
		assert.Equal(t, "proj", project)
		assert.Equal(t, "agent", agent)
		return nil
	}
	_, err = newShadowSvc(repo, agents).Onboard(auditableCtx(t), shadowTestOU, f.ID, " proj ", " agent ")
	require.NoError(t, err)
	assert.Len(t, repo.OnboardFindingCalls(), 1)
}

func TestShadowOnboard_RefusesToolInfrastructure(t *testing.T) {
	f := models.ShadowFinding{ID: uuid.New(), Kind: models.ShadowKindToolInfra}
	_, err := newShadowSvc(findingRepo(f), nil).Onboard(auditableCtx(t), shadowTestOU, f.ID, "p", "a")
	assert.ErrorIs(t, err, utils.ErrInvalidInput)
}

func TestShadowConfirmRetirement_NeedsReadyState(t *testing.T) {
	onboarded := time.Now().UTC().AddDate(0, 0, -3)
	f := models.ShadowFinding{
		ID: uuid.New(), Kind: models.ShadowKindAPIKey, LinkedAgent: "a", OnboardedAt: &onboarded,
		RetirementState: models.ShadowRetirementMonitoring, LastSeenAt: time.Now().UTC(),
	}
	_, err := newShadowSvc(findingRepo(f), nil).ConfirmRetirement(auditableCtx(t), shadowTestOU, f.ID)
	assert.ErrorIs(t, err, utils.ErrConflict, "3 zero days are not enough")

	f.LinkedAgent = ""
	_, err = newShadowSvc(findingRepo(f), nil).ConfirmRetirement(auditableCtx(t), shadowTestOU, f.ID)
	assert.ErrorIs(t, err, utils.ErrShadowNotOnboarded)
}

// TestShadowProjectFinding_OnboardButNoRetirement: a project finding can be
// onboarded (linked to an agent) but has no credential to retire.
func TestShadowProjectFinding_OnboardButNoRetirement(t *testing.T) {
	f := models.ShadowFinding{ID: uuid.New(), OUID: shadowTestOU, Kind: models.ShadowKindProject, Provider: models.ShadowProviderOpenAI}
	repo := findingRepo(f)
	repo.OnboardFindingFunc = func(context.Context, string, uuid.UUID, string, string, string, time.Time) error { return nil }
	agents := &shadowAgentLookupStub{GetAgentFunc: func(context.Context, string, string, string) (*models.AgentResponse, error) {
		return &models.AgentResponse{}, nil
	}}
	_, err := newShadowSvc(repo, agents).Onboard(auditableCtx(t), shadowTestOU, f.ID, "proj", "agent")
	require.NoError(t, err)
	assert.Len(t, repo.OnboardFindingCalls(), 1)

	onboarded := day("2026-10-01")
	through := day("2026-11-12")
	pf := &models.ShadowFinding{
		Provider: models.ShadowProviderOpenAI, Kind: models.ShadowKindProject, LinkedAgent: "a", OnboardedAt: &onboarded,
	}
	v := EvaluateShadowRetirement(pf, nil, nil, &through, &through)
	assert.Empty(t, v.State, "no retirement for a project")
	assert.Empty(t, v.Guidance.Title)
	assert.Empty(t, v.Guidance.Steps)

	now := time.Now().UTC().AddDate(0, 0, -30)
	f2 := models.ShadowFinding{ID: uuid.New(), Kind: models.ShadowKindProject, LinkedAgent: "a", OnboardedAt: &now, LastSeenAt: time.Now().UTC()}
	_, err = newShadowSvc(findingRepo(f2), nil).ConfirmRetirement(auditableCtx(t), shadowTestOU, f2.ID)
	assert.ErrorIs(t, err, utils.ErrConflict, "a project cannot be retired")
}

func TestShadowUpdateFindingStatus(t *testing.T) {
	f := models.ShadowFinding{ID: uuid.New()}
	repo := findingRepo(f)
	repo.UpdateFindingStatusFunc = func(context.Context, string, uuid.UUID, string) error { return nil }
	svc := newShadowSvc(repo, nil)
	_, err := svc.UpdateFindingStatus(auditableCtx(t), shadowTestOU, f.ID, models.ShadowStatusDismissed)
	require.NoError(t, err)
	_, err = svc.UpdateFindingStatus(auditableCtx(t), shadowTestOU, f.ID, models.ShadowStatusOnboarded)
	assert.ErrorIs(t, err, utils.ErrInvalidInput, "onboarding has its own endpoint")
}

// ---- retirement ----

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestZeroUsageDays(t *testing.T) {
	onboarded := day("2026-11-01").Add(10 * time.Hour)
	through := day("2026-11-10").Add(5 * time.Hour)
	// Complete days after onboarding up to the day before the data's end: 2..9.
	assert.Equal(t, 8, zeroUsageDays(onboarded, nil, &through))
	last := day("2026-11-05")
	assert.Equal(t, 4, zeroUsageDays(onboarded, &last, &through), "counting restarts after the last direct use")
	assert.Equal(t, 0, zeroUsageDays(onboarded, nil, nil))
}

func TestEvaluateShadowRetirement(t *testing.T) {
	onboarded := day("2026-11-01")
	f := &models.ShadowFinding{
		Provider: models.ShadowProviderOpenAI, Kind: models.ShadowKindAPIKey, LinkedAgent: "a", OnboardedAt: &onboarded,
		RetirementState: models.ShadowRetirementMonitoring,
	}
	through := day("2026-11-06")
	v := EvaluateShadowRetirement(f, nil, nil, &through, &through)
	assert.Equal(t, models.ShadowRetirementMonitoring, v.State)
	assert.Equal(t, 4, v.ZeroUsageDays)

	through = day("2026-11-12")
	v = EvaluateShadowRetirement(f, nil, nil, &through, &through)
	assert.Equal(t, models.ShadowRetirementReady, v.State)
	assert.Contains(t, v.Guidance.Title, "OpenAI")

	usage := []models.ShadowUsageDaily{{Day: day("2026-11-09"), Requests: 3}}
	v = EvaluateShadowRetirement(f, usage, nil, &through, &through)
	assert.Equal(t, models.ShadowRetirementMonitoring, v.State, "direct usage after onboarding restarts the window")
	assert.Equal(t, 2, v.ZeroUsageDays)
}

func TestVerifyShadowRetirement(t *testing.T) {
	marked := day("2026-11-10")
	after := day("2026-11-12")
	key := func(present bool, status string) []models.ShadowAPIKey {
		return []models.ShadowAPIKey{{KeyID: "k", Name: "prod", Present: present, Status: status}}
	}
	f := &models.ShadowFinding{Kind: models.ShadowKindAPIKey, RetirementMarkedAt: &marked, LastSeenAt: after}

	ok, msg := verifyShadowRetirement(f, nil, key(true, "active"), &marked)
	assert.False(t, ok)
	assert.Contains(t, msg, "Run a scan")
	ok, msg = verifyShadowRetirement(f, nil, key(true, "active"), &after)
	assert.False(t, ok)
	assert.Contains(t, msg, "still lists")
	ok, _ = verifyShadowRetirement(f, nil, key(true, "archived"), &after)
	assert.True(t, ok, "Anthropic archived keys stay listed")
	ok, _ = verifyShadowRetirement(f, nil, key(false, ""), &after)
	assert.True(t, ok, "OpenAI deleted keys disappear")
	ok, msg = verifyShadowRetirement(f, []models.ShadowUsageDaily{{Day: day("2026-11-11"), Requests: 1}}, key(false, ""), &after)
	assert.False(t, ok)
	assert.Contains(t, msg, "after you confirmed")

	foundry := &models.ShadowFinding{Kind: models.ShadowKindPlatformAgent, State: "disabled", RetirementMarkedAt: &marked, LastSeenAt: after}
	ok, _ = verifyShadowRetirement(foundry, nil, nil, &after)
	assert.True(t, ok)

	gone := &models.ShadowFinding{Kind: models.ShadowKindRuntime, RetirementMarkedAt: &marked, LastSeenAt: marked}
	ok, msg = verifyShadowRetirement(gone, nil, nil, &after)
	assert.True(t, ok, msg)

	principal := &models.ShadowFinding{Kind: models.ShadowKindPrincipal, RetirementMarkedAt: &marked, LastSeenAt: after}
	nextDay := day("2026-11-11")
	ok, _ = verifyShadowRetirement(principal, nil, nil, &nextDay)
	assert.False(t, ok, "a principal needs a full day of CloudTrail data")
	ok, _ = verifyShadowRetirement(principal, nil, nil, &after)
	assert.True(t, ok)
}

func TestDataThroughStrictNeedsAFullySuccessfulConnection(t *testing.T) {
	conn := uuid.New()
	seen := day("2026-11-05")
	started, finished := day("2026-11-08"), day("2026-11-08").Add(time.Minute)
	f := &models.ShadowFinding{ConnectionID: conn, LastSeenAt: seen}
	scan := &models.ShadowScan{StartedAt: &started, FinishedAt: &finished, Results: []models.ShadowScanConnectionResult{
		{ConnectionID: conn.String(), Outcome: shadowConnectionPartial},
	}}
	assert.Equal(t, started, *dataThrough(f, scan, false))
	assert.Equal(t, seen, *dataThrough(f, scan, true), "a partial scan does not prove the finding is gone")
}

// ---- correlation ----

func TestCorrelateShadowFindings(t *testing.T) {
	account := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct"
	agent := models.ShadowFinding{
		ID: uuid.New(), Provider: models.ShadowProviderFoundry, Kind: models.ShadowKindPlatformAgent,
		DisplayName: "Support Bot", Attributes: map[string]any{"resourceId": account, "deployment": "gpt-4o", "agentKind": "prompt"},
	}
	external := models.ShadowFinding{
		ID: uuid.New(), Provider: models.ShadowProviderFoundry, Kind: models.ShadowKindPlatformAgent,
		DisplayName: "Orders-Agent", Attributes: map[string]any{"agentKind": "external"},
	}
	bedrock := models.ShadowFinding{ID: uuid.New(), Provider: models.ShadowProviderBedrock, Kind: models.ShadowKindRuntime, DisplayName: "orders agent"}
	unrelated := models.ShadowFinding{ID: uuid.New(), Provider: models.ShadowProviderGoogle, Kind: models.ShadowKindRuntime, DisplayName: "Support Bot"}

	rel, sig := CorrelateShadowFindings([]models.ShadowFinding{agent, external, bedrock, unrelated}, time.Now())

	assert.Empty(t, rel[agent.ID], "a Foundry agent that is not external is not matched")
	assert.Empty(t, sig[agent.ID])

	require.Len(t, rel[external.ID], 1)
	assert.Equal(t, "possible_duplicate", rel[external.ID][0].Relation)
	assert.Equal(t, bedrock.ID.String(), rel[external.ID][0].FindingID)
	assert.Equal(t, sa.SigFoundryPossibleDupOf, sig[external.ID][0].Code)
	assert.Empty(t, rel[unrelated.ID], "only Foundry external agents are matched by name")
}

// ---- persistence input: retention, catalog weights, aggregation ----

func TestToShadowApply_AppliesRetentionAndCatalog(t *testing.T) {
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	nan := math.NaN()
	out := &sa.Result{
		Findings: []*sa.Finding{
			{
				Kind: models.ShadowKindPlatformAgent, ExternalID: "agent_1", DisplayName: "Bot",
				Attributes: map[string]any{"model": "gpt-4.1", "instructions": shadowPromptMark, "system": shadowPromptMark},
				Signals: []sa.Signal{
					{Code: sa.SigOpenAIAgentObject, Source: "GET /v1/agents", Observed: map[string]any{
						"count": 1, "prompt": shadowPromptMark + strings.Repeat("x", 100), "nan": nan,
					}},
					{Code: "made.up.signal", Source: "x"},
				},
				Usage: []sa.UsageDay{{Day: day("2026-11-01").Add(5 * time.Hour), Requests: 3, CostAmount: &nan}},
			},
			{Kind: "not_a_kind", ExternalID: "x"},
			{Kind: models.ShadowKindAPIKey, ExternalID: " "},
		},
		Keys: []sa.Key{{KeyID: "key_1", Name: "prod", RedactedHint: "sk-proj-FULLKEYFULLKEYFULLKEY"}},
	}
	scan := &models.ShadowScan{ID: uuid.New(), OUID: shadowTestOU}
	conn := &models.ShadowConnection{ID: uuid.New(), Provider: models.ShadowProviderOpenAI}
	in := toShadowApply(scan, conn, out, sa.NewWindow(time.Now(), 30), time.Now(), time.Now(), log)

	require.Len(t, in.Findings, 1, "invalid kinds and empty IDs are dropped")
	f := in.Findings[0]
	require.Len(t, f.Signals, 1, "unknown signal codes are dropped")
	d, _ := sa.Def(sa.SigOpenAIAgentObject)
	assert.Equal(t, d.Weight, f.Signals[0].Weight, "weights come from the catalog")
	assert.Equal(t, d.Condition, f.Signals[0].Condition)
	assert.NotContains(t, f.Signals[0].Observed, "prompt", "long free text is not observed data")
	assert.NotContains(t, f.Signals[0].Observed, "nan")
	assert.Nil(t, f.Usage[0].CostAmount, "a non-finite cost is dropped")
	assert.Equal(t, day("2026-11-01"), f.Usage[0].Day)
	assert.Equal(t, models.ShadowProviderOpenAI, f.Finding.Provider)

	stored, err := json.Marshal(in)
	require.NoError(t, err)
	assert.NotContains(t, string(stored), shadowPromptMark)
	assert.NotContains(t, string(stored), "FULLKEYFULLKEY", "a whole key is never stored as a hint")
	assert.NotContains(t, logs.String(), shadowPromptMark)
}

func TestValidShadowKind_IncludesProject(t *testing.T) {
	for _, k := range []string{
		models.ShadowKindPlatformAgent, models.ShadowKindRuntime, models.ShadowKindAPIKey,
		models.ShadowKindPrincipal, models.ShadowKindToolInfra, models.ShadowKindProject,
	} {
		assert.True(t, validShadowKind(k), k)
	}
	assert.False(t, validShadowKind("workspace"))
	assert.False(t, validShadowKind("deployment"), "Azure OpenAI deployments are no longer a finding kind")
}

func TestConnectionOutcome(t *testing.T) {
	ok := models.ShadowScanCallResult{Call: "a", Outcome: models.ShadowCallOK}
	skip := models.ShadowScanCallResult{Call: "b", Outcome: models.ShadowCallSkipped}
	denied := models.ShadowScanCallResult{Call: "c", Outcome: models.ShadowCallPermissionDenied, Message: "no"}
	auth := models.ShadowScanCallResult{Call: "d", Outcome: models.ShadowCallAuthFailed, Message: "bad key"}
	o, _ := connectionOutcome([]models.ShadowScanCallResult{ok, skip})
	assert.Equal(t, shadowConnectionOK, o)
	o, msg := connectionOutcome([]models.ShadowScanCallResult{ok, denied})
	assert.Equal(t, shadowConnectionPartial, o)
	assert.Contains(t, msg, "1 of 2 calls failed")
	o, _ = connectionOutcome([]models.ShadowScanCallResult{auth, skip})
	assert.Equal(t, models.ShadowCallAuthFailed, o)
	o, _ = connectionOutcome([]models.ShadowScanCallResult{denied})
	assert.Equal(t, shadowConnectionFailed, o)
}

// ---- scanner ----

type fakeShadowConnector struct {
	provider string
	scan     func(conn sa.Connection) *sa.Result
}

func (f *fakeShadowConnector) Provider() string { return f.provider }
func (f *fakeShadowConnector) Scan(_ context.Context, conn sa.Connection, _ sa.Window) *sa.Result {
	return f.scan(conn)
}

func (f *fakeShadowConnector) Test(context.Context, sa.Connection) models.ShadowConnectionTestInfo {
	return models.ShadowConnectionTestInfo{OK: true, Checks: []models.ShadowConnectionCheck{}}
}

// One provider failing (here, panicking) never breaks the others: its
// connection fails, the other's findings are saved, the scan is partial.
func TestShadowScannerIsolatesFailingProviders(t *testing.T) {
	enc, err := (&shadowAgentService{encryptionKey: shadowTestKey}).encryptSecret(models.ShadowConnectionSecret{APIKey: shadowSecretKey})
	require.NoError(t, err)
	good := models.ShadowConnection{ID: uuid.New(), OUID: shadowTestOU, Name: "good", Provider: models.ShadowProviderOpenAI, SecretEncrypted: enc}
	bad := models.ShadowConnection{ID: uuid.New(), OUID: shadowTestOU, Name: "bad", Provider: models.ShadowProviderAnthropic, SecretEncrypted: enc}
	connectors := ShadowConnectors{
		models.ShadowProviderOpenAI: &fakeShadowConnector{provider: models.ShadowProviderOpenAI, scan: func(conn sa.Connection) *sa.Result {
			assert.Equal(t, shadowSecretKey, conn.Secret.APIKey, "the connector gets the decrypted secret")
			return &sa.Result{
				Findings: []*sa.Finding{{Kind: models.ShadowKindAPIKey, ExternalID: "key_1", Signals: []sa.Signal{{Code: sa.SigOpenAIPlainUsage}}}},
				Calls:    []models.ShadowScanCallResult{{Call: "GET /usage", Outcome: models.ShadowCallOK, Items: 1}},
			}
		}},
		models.ShadowProviderAnthropic: &fakeShadowConnector{provider: models.ShadowProviderAnthropic, scan: func(sa.Connection) *sa.Result {
			panic("connector bug")
		}},
	}
	started := time.Now().UTC()
	scan := models.ShadowScan{
		ID: uuid.New(), OUID: shadowTestOU, Status: models.ShadowScanRunning, LookbackDays: 30, Attempts: 1,
		StartedAt: &started, ConnectionIDs: []string{good.ID.String(), bad.ID.String()},
	}
	var finished *models.ShadowScan
	// Connections run concurrently, so the mock's callbacks are too.
	var mu sync.Mutex
	var applied []repositories.ShadowConnectionApply
	repo := &repomocks.ShadowAgentRepositoryMock{
		ClaimDueScansFunc: func(context.Context, time.Time, time.Duration, int) ([]models.ShadowScan, error) {
			return []models.ShadowScan{scan}, nil
		},
		GetConnectionFunc: func(_ context.Context, _ string, id uuid.UUID) (*models.ShadowConnection, error) {
			if id == good.ID {
				return &good, nil
			}
			return &bad, nil
		},
		ApplyConnectionResultFunc: func(_ context.Context, in repositories.ShadowConnectionApply, _ repositories.ShadowScoreFunc) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			applied = append(applied, in)
			return len(in.Findings), nil
		},
		ListOrgFindingsFunc: func(context.Context, string) ([]models.ShadowFinding, error) { return []models.ShadowFinding{}, nil },
		ApplyCorrelationFunc: func(context.Context, string, map[uuid.UUID][]models.ShadowFindingRelation,
			map[uuid.UUID][]models.ShadowFindingSignal, repositories.ShadowScoreFunc,
		) error {
			return nil
		},
		FinishScanFunc: func(_ context.Context, s *models.ShadowScan) error {
			finished = s
			return nil
		},
		ListOnboardedFindingsFunc: func(context.Context, string) ([]models.ShadowFinding, error) { return []models.ShadowFinding{}, nil },
		RenewScanLeaseFunc:        func(context.Context, uuid.UUID, time.Time) error { return nil },
	}
	logs := &bytes.Buffer{}
	scanner := NewShadowAgentScanner(repo, connectors, shadowTestKey, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	scanner.RunOnce(context.Background())

	require.NotNil(t, finished)
	assert.Equal(t, models.ShadowScanPartial, finished.Status)
	require.Len(t, finished.Results, 2)
	byName := map[string]models.ShadowScanConnectionResult{}
	for _, r := range finished.Results {
		byName[r.ConnectionName] = r
	}
	assert.Equal(t, shadowConnectionOK, byName["good"].Outcome)
	assert.Equal(t, 1, byName["good"].FindingsCount)
	assert.Equal(t, shadowConnectionFailed, byName["bad"].Outcome)
	assert.Contains(t, byName["bad"].Calls[0].Message, "internal error")
	require.NotEmpty(t, applied)
	assert.NotContains(t, logs.String(), "SECRETSECRET", "the credential is never logged")
}

func TestShadowScannerGivesUpAfterMaxAttempts(t *testing.T) {
	scan := models.ShadowScan{ID: uuid.New(), OUID: shadowTestOU, Attempts: shadowScanMaxAttempts + 1, ConnectionIDs: []string{uuid.New().String()}}
	var finished *models.ShadowScan
	repo := &repomocks.ShadowAgentRepositoryMock{
		ClaimDueScansFunc: func(context.Context, time.Time, time.Duration, int) ([]models.ShadowScan, error) {
			return []models.ShadowScan{scan}, nil
		},
		FinishScanFunc: func(_ context.Context, s *models.ShadowScan) error {
			finished = s
			return nil
		},
	}
	NewShadowAgentScanner(repo, ShadowConnectors{}, shadowTestKey, discardLogger()).RunOnce(context.Background())
	require.NotNil(t, finished)
	assert.Equal(t, models.ShadowScanFailed, finished.Status)
}
