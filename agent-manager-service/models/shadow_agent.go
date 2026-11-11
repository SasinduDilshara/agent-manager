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

package models

import (
	"time"

	"github.com/google/uuid"
)

// Shadow Agent Discovery providers (Method 1: provider and cloud admin APIs).
const (
	ShadowProviderOpenAI    = "openai"
	ShadowProviderAnthropic = "anthropic"
	ShadowProviderBedrock   = "bedrock"
	ShadowProviderGoogle    = "google"
	ShadowProviderFoundry   = "foundry"
	// Source repository hosts (Method 2). Connections are stored now; the
	// source code analysis that scans them is added separately.
	ShadowProviderGitHub      = "github"
	ShadowProviderAzureDevOps = "azure_devops"
)

// ShadowProviders lists every supported provider, in display order.
var ShadowProviders = []string{
	ShadowProviderOpenAI, ShadowProviderAnthropic,
	ShadowProviderBedrock, ShadowProviderGoogle, ShadowProviderFoundry,
	ShadowProviderGitHub, ShadowProviderAzureDevOps,
}

// Finding kinds: what a finding stands for at the provider.
const (
	// ShadowKindPlatformAgent is an agent object hosted by the provider
	// (OpenAI agent, Anthropic Managed Agent, Bedrock classic agent,
	// Foundry agent, Google Agent Registry agent).
	ShadowKindPlatformAgent = "platform_agent"
	// ShadowKindRuntime is an AgentCore runtime or a Google Agent Runtime
	// (reasoning engine).
	ShadowKindRuntime = "runtime"
	// ShadowKindAPIKey is a provider API key and the workload behind it.
	ShadowKindAPIKey = "api_key"
	// ShadowKindPrincipal is a cloud identity (an IAM user or role) calling
	// models directly.
	ShadowKindPrincipal = "principal"
	// ShadowKindToolInfra is tool infrastructure agents use (an MCP gateway
	// or a registered MCP server). It is evidence, never an agent itself.
	ShadowKindToolInfra = "tool_infrastructure"
	// ShadowKindProject is an OpenAI project or an Anthropic workspace. It
	// holds evidence read with a project or workspace key (tool calls in
	// stored completions or batches) that cannot be tied to one API key:
	// without the Admin key the keys are unknown, and with it more than one
	// key of the project had usage. It has no credential of its own to retire.
	ShadowKindProject = "project"
)

// Verdicts, from the score.
const (
	ShadowVerdictAgent         = "agent"
	ShadowVerdictPossibleAgent = "possible_agent"
	ShadowVerdictLLMConsumer   = "llm_consumer"
	// ShadowVerdictToolInfra marks tool infrastructure (MCP gateways and
	// registered MCP servers): evidence agents exist, never an agent itself.
	ShadowVerdictToolInfra = "tool_infrastructure"
)

// Finding review statuses.
const (
	ShadowStatusNew       = "new"
	ShadowStatusReviewed  = "reviewed"
	ShadowStatusDismissed = "dismissed"
	ShadowStatusOnboarded = "onboarded"
	ShadowStatusRetired   = "retired"
)

// Retirement states of the direct provider credential behind an onboarded
// finding. Agent Manager never revokes anything: it watches the usage and
// guides the user.
const (
	// ShadowRetirementMonitoring: onboarded; waiting for the direct usage to
	// stay at zero for the observation window.
	ShadowRetirementMonitoring = "monitoring"
	// ShadowRetirementReady: no direct usage for the whole window; the user
	// is guided to revoke the credential.
	ShadowRetirementReady = "ready_to_retire"
	// ShadowRetirementPendingVerify: the user says it is revoked; the next
	// scan checks it.
	ShadowRetirementPendingVerify = "pending_verification"
	// ShadowRetirementRetired: a scan confirmed the credential is revoked or
	// disabled at the provider.
	ShadowRetirementRetired = "retired"
)

// Signal tiers and their weights. Weights are fixed and documented in
// docs/shadow-agent-discovery.md.
const (
	ShadowTierDefinitive = "definitive"
	ShadowTierHigh       = "high"
	ShadowTierMedium     = "medium"
	ShadowTierLow        = "low"
	ShadowTierInfo       = "info"
)

// Scan statuses.
const (
	ShadowScanQueued    = "queued"
	ShadowScanRunning   = "running"
	ShadowScanSucceeded = "succeeded"
	ShadowScanPartial   = "partial"
	ShadowScanFailed    = "failed"
)

// Outcomes of one provider call (or one connection) within a scan.
const (
	ShadowCallOK               = "ok"
	ShadowCallSkipped          = "skipped"
	ShadowCallAuthFailed       = "auth_failed"
	ShadowCallPermissionDenied = "permission_denied"
	ShadowCallNotFound         = "not_found"
	ShadowCallRateLimited      = "rate_limited"
	ShadowCallUnsupported      = "unsupported_response"
	ShadowCallFailed           = "failed"
)

// ShadowConnection is one provider account an org scans: the credential and
// where to reach the provider. The secret is AES-GCM encrypted and never
// returned by the API.
type ShadowConnection struct {
	ID       uuid.UUID              `gorm:"column:id;primaryKey;type:uuid;default:gen_random_uuid()"`
	OUID     string                 `gorm:"column:ou_id;not null"`
	Name     string                 `gorm:"column:name;not null"`
	Provider string                 `gorm:"column:provider;not null"`
	Config   ShadowConnectionConfig `gorm:"column:config;type:jsonb;serializer:json;not null"`
	// SecretEncrypted is the AES-GCM encrypted JSON of ShadowConnectionSecret.
	SecretEncrypted []byte `gorm:"column:secret_encrypted;not null"`
	// SecretHints are redacted hints of the stored secrets ("sk-a...wxyz"),
	// so the UI can say which credential is stored without revealing it.
	SecretHints    map[string]string         `gorm:"column:secret_hints;type:jsonb;serializer:json;not null"`
	LastTestedAt   *time.Time                `gorm:"column:last_tested_at"`
	LastTestResult *ShadowConnectionTestInfo `gorm:"column:last_test_result;type:jsonb;serializer:json"`
	CreatedBy      string                    `gorm:"column:created_by;not null"`
	CreatedAt      time.Time                 `gorm:"column:created_at;not null;default:NOW()"`
	UpdatedAt      time.Time                 `gorm:"column:updated_at;not null;default:NOW()"`
}

func (ShadowConnection) TableName() string { return "shadow_connections" }

// ShadowConnectionConfig is a connection's non-secret settings. Fields apply
// to the providers named in their comment; others leave them empty.
type ShadowConnectionConfig struct {
	// Endpoints holds the base URL of every provider endpoint the connector
	// calls, keyed by endpoint name. Values may contain placeholders such as
	// {region}, {location} or {account}; the user sees the official values
	// prefilled and may change them.
	Endpoints map[string]string `json:"endpoints"`

	// DeepInspection lets the connector read sources that hold prompts or
	// tool payloads (batches, stored responses, invocation logs, session
	// events) in memory to derive tool-use signals. Nothing read is stored.
	DeepInspection bool `json:"deepInspection"`

	// Foundry and Azure DevOps (with UseEntra): the Entra app. Foundry: the
	// subscriptions to scan.
	TenantID         string   `json:"tenantId,omitempty"`
	ClientID         string   `json:"clientId,omitempty"`
	AllSubscriptions bool     `json:"allSubscriptions,omitempty"`
	SubscriptionIDs  []string `json:"subscriptionIds,omitempty"`
	// Foundry: also list classic (assistants-style) agents.
	IncludeClassicAgents bool `json:"includeClassicAgents,omitempty"`

	// Bedrock: regions, the role to assume and the access key that assumes it.
	Regions     []string `json:"regions,omitempty"`
	RoleARN     string   `json:"roleArn,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	AccessKeyID string   `json:"accessKeyId,omitempty"`

	// Google: projects and locations to scan.
	ProjectIDs []string `json:"projectIds,omitempty"`
	Locations  []string `json:"locations,omitempty"`
	// IncludeGlobalAndMultiRegion adds the "global" Agent Registry location
	// and the us/eu multi-region Agent Runtime locations.
	IncludeGlobalAndMultiRegion bool `json:"includeGlobalAndMultiRegion,omitempty"`

	// Anthropic: also scan Claude Platform on AWS and Claude Models on Google
	// Cloud (Anthropic managed). The AWS variant uses Regions, AccessKeyID,
	// RoleARN and ExternalID above; the Google variant uses GCPProjectID and
	// the service account key in the secret.
	IncludeCloudVariants bool     `json:"includeCloudVariants,omitempty"`
	AWSWorkspaceIDs      []string `json:"awsWorkspaceIds,omitempty"`
	GCPProjectID         string   `json:"gcpProjectId,omitempty"`
	GCPWorkspaceIDs      []string `json:"gcpWorkspaceIds,omitempty"`
	// OpenAI project IDs / Anthropic workspace IDs that have a scoped key in
	// the secret (the keys themselves are in the secret).
	ScopedKeyIDs []string `json:"scopedKeyIds,omitempty"`

	// GitHub, Azure DevOps: the organization (or GitHub user account) whose
	// repositories are scanned.
	Organization string `json:"organization,omitempty"`
	// GitHub: every repository the token can read, or only Repositories.
	AllRepositories bool     `json:"allRepositories,omitempty"`
	Repositories    []string `json:"repositories,omitempty"`
	// Azure DevOps: every project the credential can read, or only Projects.
	AllProjects bool     `json:"allProjects,omitempty"`
	Projects    []string `json:"projects,omitempty"`
	// Azure DevOps: sign in with a Microsoft Entra service principal
	// (TenantID, ClientID and the client secret) instead of a PAT.
	UseEntra bool `json:"useEntra,omitempty"`
	// GitHub, Azure DevOps: also read CI pipeline definitions and .env
	// example files.
	ReadCIAndEnvFiles bool `json:"readCiAndEnvFiles,omitempty"`

	// DisabledServices are the optional services (Bedrock, Google) the user
	// unticked: the scan does not call them. Listing the disabled ones keeps
	// every service on for connections saved before the option existed.
	DisabledServices []string `json:"disabledServices,omitempty"`
}

// ShadowConnectionSecret is the secret part of a connection. It exists in
// plain text only in memory while a connector runs; it is stored encrypted
// and never returned, logged or audited.
type ShadowConnectionSecret struct {
	// APIKey is the OpenAI or Anthropic Admin API key.
	APIKey string `json:"apiKey,omitempty"`
	// ScopedKeys maps an OpenAI project ID or an Anthropic workspace ID to a
	// read-only key for it, for the endpoints an Admin key cannot call.
	ScopedKeys map[string]string `json:"scopedKeys,omitempty"`
	// ClientSecret is the Entra app's client secret (Foundry, Azure DevOps).
	ClientSecret string `json:"clientSecret,omitempty"`
	// SecretAccessKey and SessionToken complete the AWS access key.
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	SessionToken    string `json:"sessionToken,omitempty"`
	// ServiceAccountJSON is a Google service account key file.
	ServiceAccountJSON string `json:"serviceAccountJson,omitempty"`
	// PersonalAccessToken is a GitHub fine-grained or Azure DevOps personal
	// access token.
	PersonalAccessToken string `json:"personalAccessToken,omitempty"`
}

// ShadowConnectionTestInfo is the outcome of a connection test: one entry
// per probed capability.
type ShadowConnectionTestInfo struct {
	OK     bool                    `json:"ok"`
	Checks []ShadowConnectionCheck `json:"checks"`
}

// ShadowConnectionCheck is one probed call of a connection test.
type ShadowConnectionCheck struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Message string `json:"message,omitempty"`
	// Unlocks names the signals this call provides, so a failed check says
	// what a scan will miss.
	Unlocks []string `json:"unlocks,omitempty"`
}

// ShadowScan is one discovery run over some of an org's connections.
type ShadowScan struct {
	ID            uuid.UUID                    `gorm:"column:id;primaryKey;type:uuid;default:gen_random_uuid()"`
	OUID          string                       `gorm:"column:ou_id;not null"`
	Status        string                       `gorm:"column:status;not null"`
	LookbackDays  int                          `gorm:"column:lookback_days;not null"`
	ConnectionIDs []string                     `gorm:"column:connection_ids;type:jsonb;serializer:json;not null"`
	Results       []ShadowScanConnectionResult `gorm:"column:results;type:jsonb;serializer:json;not null"`
	FindingsCount int                          `gorm:"column:findings_count;not null"`
	RequestedBy   string                       `gorm:"column:requested_by;not null"`
	ClaimedUntil  *time.Time                   `gorm:"column:claimed_until"`
	Attempts      int                          `gorm:"column:attempts;not null"`
	StartedAt     *time.Time                   `gorm:"column:started_at"`
	FinishedAt    *time.Time                   `gorm:"column:finished_at"`
	CreatedAt     time.Time                    `gorm:"column:created_at;not null;default:NOW()"`
	UpdatedAt     time.Time                    `gorm:"column:updated_at;not null;default:NOW()"`
}

func (ShadowScan) TableName() string { return "shadow_scans" }

// ShadowScanConnectionResult is how one connection fared in a scan.
type ShadowScanConnectionResult struct {
	ConnectionID   string                 `json:"connectionId"`
	ConnectionName string                 `json:"connectionName"`
	Provider       string                 `json:"provider"`
	Outcome        string                 `json:"outcome"`
	Message        string                 `json:"message,omitempty"`
	FindingsCount  int                    `json:"findingsCount"`
	Calls          []ShadowScanCallResult `json:"calls"`
}

// ShadowScanCallResult is the outcome of one provider call (all its pages
// and scopes) in a scan. Messages are sanitised: no bodies, no secrets.
type ShadowScanCallResult struct {
	Call    string `json:"call"`
	Outcome string `json:"outcome"`
	Message string `json:"message,omitempty"`
	Items   int    `json:"items"`
}

// ShadowOwnerHint is the minimised personal data kept to say who is behind a
// finding: no more than a name, an email and a username or principal.
type ShadowOwnerHint struct {
	Name      string     `json:"name,omitempty"`
	Email     string     `json:"email,omitempty"`
	Username  string     `json:"username,omitempty"`
	Type      string     `json:"type,omitempty"`
	Source    string     `json:"source,omitempty"`
	CreatedAt *time.Time `json:"createdAt,omitempty"`
}

// ShadowFindingRelation links a finding to another one about the same or a
// connected workload.
type ShadowFindingRelation struct {
	FindingID string `json:"findingId"`
	// Relation is "uses_deployment", "used_by_agent", "possible_duplicate" or
	// "registered_as".
	Relation string `json:"relation"`
	Reason   string `json:"reason,omitempty"`
	// Source is "correlation" for relations found across connections, empty
	// for those the finding's own connector reported.
	Source string `json:"source,omitempty"`
}

// ShadowFinding is a potential agent: everything the scans learnt about one
// workload, its score and verdict, and where it is in onboarding.
type ShadowFinding struct {
	ID                   uuid.UUID               `gorm:"column:id;primaryKey;type:uuid;default:gen_random_uuid()"`
	OUID                 string                  `gorm:"column:ou_id;not null"`
	ConnectionID         uuid.UUID               `gorm:"column:connection_id;type:uuid;not null"`
	Provider             string                  `gorm:"column:provider;not null"`
	Kind                 string                  `gorm:"column:kind;not null"`
	ExternalID           string                  `gorm:"column:external_id;not null"`
	DisplayName          string                  `gorm:"column:display_name;not null"`
	Scope                string                  `gorm:"column:scope;not null"`
	State                string                  `gorm:"column:state;not null"`
	Score                int                     `gorm:"column:score;not null"`
	Verdict              string                  `gorm:"column:verdict;not null"`
	Status               string                  `gorm:"column:status;not null"`
	OwnerHint            ShadowOwnerHint         `gorm:"column:owner_hint;type:jsonb;serializer:json;not null"`
	Attributes           map[string]any          `gorm:"column:attributes;type:jsonb;serializer:json;not null"`
	Related              []ShadowFindingRelation `gorm:"column:related;type:jsonb;serializer:json;not null"`
	ProviderCreatedAt    *time.Time              `gorm:"column:provider_created_at"`
	FirstUsedAt          *time.Time              `gorm:"column:first_used_at"`
	LastUsedAt           *time.Time              `gorm:"column:last_used_at"`
	FirstSeenAt          time.Time               `gorm:"column:first_seen_at;not null"`
	LastSeenAt           time.Time               `gorm:"column:last_seen_at;not null"`
	LastScanID           *uuid.UUID              `gorm:"column:last_scan_id;type:uuid"`
	LinkedProject        string                  `gorm:"column:linked_project;not null"`
	LinkedAgent          string                  `gorm:"column:linked_agent;not null"`
	OnboardedAt          *time.Time              `gorm:"column:onboarded_at"`
	OnboardedBy          string                  `gorm:"column:onboarded_by;not null"`
	RetirementState      string                  `gorm:"column:retirement_state;not null"`
	RetirementMarkedAt   *time.Time              `gorm:"column:retirement_marked_at"`
	RetirementMarkedBy   string                  `gorm:"column:retirement_marked_by;not null"`
	RetirementVerifiedAt *time.Time              `gorm:"column:retirement_verified_at"`
	CreatedAt            time.Time               `gorm:"column:created_at;not null;default:NOW()"`
	UpdatedAt            time.Time               `gorm:"column:updated_at;not null;default:NOW()"`
}

func (ShadowFinding) TableName() string { return "shadow_findings" }

// ShadowFindingSignal is one piece of evidence on a finding: a signal from
// the design's signal tables, the call that produced it, and what was
// observed (counts and flags only).
type ShadowFindingSignal struct {
	ID         uuid.UUID      `gorm:"column:id;primaryKey;type:uuid;default:gen_random_uuid()"`
	OUID       string         `gorm:"column:ou_id;not null"`
	FindingID  uuid.UUID      `gorm:"column:finding_id;type:uuid;not null"`
	Code       string         `gorm:"column:code;not null"`
	Tier       string         `gorm:"column:tier;not null"`
	Weight     int            `gorm:"column:weight;not null"`
	Source     string         `gorm:"column:source;not null"`
	Condition  string         `gorm:"column:condition;not null"`
	Observed   map[string]any `gorm:"column:observed;type:jsonb;serializer:json;not null"`
	ScanID     *uuid.UUID     `gorm:"column:scan_id;type:uuid"`
	DetectedAt time.Time      `gorm:"column:detected_at;not null"`
}

func (ShadowFindingSignal) TableName() string { return "shadow_finding_signals" }

// ShadowAPIKey is a provider API key, recorded as the retention rules allow:
// ID, name, redacted hint, status and timestamps, plus a minimised owner hint.
type ShadowAPIKey struct {
	ID                uuid.UUID       `gorm:"column:id;primaryKey;type:uuid;default:gen_random_uuid()"`
	OUID              string          `gorm:"column:ou_id;not null"`
	ConnectionID      uuid.UUID       `gorm:"column:connection_id;type:uuid;not null"`
	FindingID         *uuid.UUID      `gorm:"column:finding_id;type:uuid"`
	KeyID             string          `gorm:"column:key_id;not null"`
	Name              string          `gorm:"column:name;not null"`
	RedactedHint      string          `gorm:"column:redacted_hint;not null"`
	Status            string          `gorm:"column:status;not null"`
	Scope             string          `gorm:"column:scope;not null"`
	OwnerHint         ShadowOwnerHint `gorm:"column:owner_hint;type:jsonb;serializer:json;not null"`
	ProviderCreatedAt *time.Time      `gorm:"column:provider_created_at"`
	LastUsedAt        *time.Time      `gorm:"column:last_used_at"`
	LastSeenAt        time.Time       `gorm:"column:last_seen_at;not null"`
	// Present is false once a scan's key listing no longer returns the key.
	Present   bool      `gorm:"column:present;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null;default:NOW()"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null;default:NOW()"`
}

func (ShadowAPIKey) TableName() string { return "shadow_api_keys" }

// ShadowUsageDaily is one day of usage for a finding, per key and model.
type ShadowUsageDaily struct {
	OUID         string    `gorm:"column:ou_id;not null"`
	FindingID    uuid.UUID `gorm:"column:finding_id;type:uuid;primaryKey"`
	KeyID        string    `gorm:"column:key_id;primaryKey"`
	Model        string    `gorm:"column:model;primaryKey"`
	Day          time.Time `gorm:"column:day;type:date;primaryKey"`
	Requests     int64     `gorm:"column:requests;not null"`
	InputTokens  int64     `gorm:"column:input_tokens;not null"`
	OutputTokens int64     `gorm:"column:output_tokens;not null"`
	CostAmount   *float64  `gorm:"column:cost_amount"`
	Currency     string    `gorm:"column:currency;not null"`
	UpdatedAt    time.Time `gorm:"column:updated_at;not null;default:NOW()"`
}

func (ShadowUsageDaily) TableName() string { return "shadow_usage_daily" }
