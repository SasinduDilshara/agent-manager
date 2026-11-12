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

// Wire types. Each one decodes only the fields the connector uses; content
// fields (the agent's system prompt, custom tool input_schema, session
// titles and agent snapshots, event input and content, batch message
// content text and input) are deliberately absent, so they are never held
// in a typed value, let alone stored.

// idPage is the envelope of the Admin API lists and the batches list:
// {data, has_more, first_id, last_id}; the next page is after_id=last_id.
type idPage[T any] struct {
	Data    *[]T    `json:"data"`
	HasMore bool    `json:"has_more"`
	LastID  *string `json:"last_id"`
}

// cursorPage is the envelope of the Managed Agents lists and the analytics
// endpoints: {data, next_page} (+ has_more and data_refreshed_at on
// analytics); the next page is page=next_page.
type cursorPage[T any] struct {
	Data            *[]T    `json:"data"`
	NextPage        *string `json:"next_page"`
	HasMore         *bool   `json:"has_more"`
	DataRefreshedAt *string `json:"data_refreshed_at"`
}

type workspace struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	ArchivedAt *string `json:"archived_at"`
}

type user struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type apiKey struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      string     `json:"created_at"`
	CreatedBy      *creator   `json:"created_by"`
	PartialKeyHint *string    `json:"partial_key_hint"`
	Status         string     `json:"status"`
	Principal      *principal `json:"principal"`
	Scope          *keyScope  `json:"scope"`
	// WorkspaceID is the anthropic-version 2023-06-01 field; read only as a
	// fallback should the pinned version ever be ignored.
	WorkspaceID *string `json:"workspace_id"`
}

type creator struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type principal struct {
	Type             string `json:"type"`
	UserID           string `json:"user_id"`
	ServiceAccountID string `json:"service_account_id"`
}

type keyScope struct {
	Type        string `json:"type"`
	WorkspaceID string `json:"workspace_id"`
}

// usageRow is one BetaAnalyticsUsageItem.
type usageRow struct {
	StartingAt string        `json:"starting_at"`
	Group      analyticGroup `json:"group"`
	Usage      struct {
		UncachedInputTokens int64 `json:"uncached_input_tokens"`
		CacheCreation       struct {
			Ephemeral1h int64 `json:"ephemeral_1h_input_tokens"`
			Ephemeral5m int64 `json:"ephemeral_5m_input_tokens"`
		} `json:"cache_creation"`
		CacheReadInputTokens int64 `json:"cache_read_input_tokens"`
		OutputTokens         int64 `json:"output_tokens"`
		Requests             int64 `json:"requests"`
		ServerToolUse        *struct {
			WebSearchRequests int64 `json:"web_search_requests"`
		} `json:"server_tool_use"`
	} `json:"usage"`
}

// costRow is one BetaAnalyticsCostItem.
type costRow struct {
	StartingAt string        `json:"starting_at"`
	Group      analyticGroup `json:"group"`
	Cost       struct {
		Amount   string `json:"amount"`
		Currency string `json:"currency"`
	} `json:"cost"`
}

// analyticGroup holds the grouping dimensions the connector asks for.
type analyticGroup struct {
	APIKeyID *string `json:"api_key_id"`
	AgentID  *string `json:"agent_id"`
	Model    *string `json:"model"`
	Product  *string `json:"product"`
	CostType *string `json:"cost_type"`
}

// agent is a BetaManagedAgentsAgent, without system and the custom tools'
// description and input_schema.
type agent struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Model       *struct {
		ID string `json:"id"`
	} `json:"model"`
	Tools []struct {
		Type          string `json:"type"`
		Name          string `json:"name"`
		MCPServerName string `json:"mcp_server_name"`
		Configs       []struct {
			Name    string `json:"name"`
			Type    string `json:"type"`
			Enabled *bool  `json:"enabled"`
		} `json:"configs"`
	} `json:"tools"`
	MCPServers []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"mcp_servers"`
	Skills []struct {
		SkillID string `json:"skill_id"`
		Type    string `json:"type"`
	} `json:"skills"`
	ExecutionIdentity *struct {
		Type    string `json:"type"`
		RoleARN string `json:"role_arn"`
	} `json:"execution_identity"`
	CreatedAt  string  `json:"created_at"`
	ArchivedAt *string `json:"archived_at"`
	Version    int64   `json:"version"`
}

// session is a BetaManagedAgentsSession: status, times and the GitHub
// repository resources. The agent snapshot, title, metadata, outcome
// evaluations and memory store instructions are not decoded.
type session struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Resources []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"resources"`
}

// event keeps only the event type and processed_at; input and content are
// never decoded.
type event struct {
	Type        string `json:"type"`
	ProcessedAt string `json:"processed_at"`
}

type batch struct {
	ID               string `json:"id"`
	ProcessingStatus string `json:"processing_status"`
	CreatedAt        string `json:"created_at"`
	RequestCounts    struct {
		Succeeded int64 `json:"succeeded"`
	} `json:"request_counts"`
}

// batchResultLine is one line of a batch results JSONL file, reduced to the
// result type, the stop reason and the content block types.
type batchResultLine struct {
	Result struct {
		Type    string `json:"type"`
		Message *struct {
			StopReason string `json:"stop_reason"`
			Content    []struct {
				Type string `json:"type"`
			} `json:"content"`
		} `json:"message"`
	} `json:"result"`
}
