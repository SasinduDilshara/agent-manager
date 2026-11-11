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

package openai

import "encoding/json"

// The wire types below declare only the fields the connector uses. Fields
// that can hold content (instructions, tool parameters, messages, metadata,
// IP addresses, user agents) are deliberately absent, so they are never
// kept after decoding. Nullable strings decode to "".

// listPage is the cursor list shape of OpenAI list endpoints: data,
// has_more and last_id (the next page is after=last_id).
type listPage[T any] struct {
	Data    *[]T    `json:"data"`
	HasMore bool    `json:"has_more"`
	LastID  *string `json:"last_id"`
}

// usagePage is the page shape of the usage and costs endpoints: time
// buckets, has_more and next_page (the next page is page=next_page).
type usagePage[T any] struct {
	Data     *[]usageBucket[T] `json:"data"`
	HasMore  bool              `json:"has_more"`
	NextPage *string           `json:"next_page"`
}

type usageBucket[T any] struct {
	StartTime int64 `json:"start_time"`
	EndTime   int64 `json:"end_time"`
	Results   []T   `json:"results"`
}

// project is an organization.project (GET /v1/organization/projects).
type project struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  int64  `json:"created_at"`
	ArchivedAt *int64 `json:"archived_at"`
	Status     string `json:"status"`
}

func (p project) archived() bool {
	return p.Status == "archived" || (p.ArchivedAt != nil && *p.ArchivedAt > 0)
}

// apiKey is an organization.project.api_key.
type apiKey struct {
	ID                 string      `json:"id"`
	Name               string      `json:"name"`
	RedactedValue      string      `json:"redacted_value"`
	CreatedAt          int64       `json:"created_at"`
	ExpiresAt          *int64      `json:"expires_at"`
	LastUsedAt         *int64      `json:"last_used_at"`
	OwnerProjectAccess string      `json:"owner_project_access"`
	Owner              apiKeyOwner `json:"owner"`
}

type apiKeyOwner struct {
	Type string `json:"type"`
	User *struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
	ServiceAccount *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"service_account"`
}

// auditLog is an AuditLog of type api_key.created. Only the creator's
// identity is decoded: never the IP address or user agent.
type auditLog struct {
	ID          string      `json:"id"`
	Type        string      `json:"type"`
	EffectiveAt int64       `json:"effective_at"`
	Actor       *auditActor `json:"actor"`
	Created     *struct {
		ID string `json:"id"`
	} `json:"api_key.created"`
}

type auditActor struct {
	Type    string `json:"type"`
	Session *struct {
		User *auditUser `json:"user"`
	} `json:"session"`
	APIKey *struct {
		Type           string     `json:"type"`
		User           *auditUser `json:"user"`
		ServiceAccount *struct {
			ID string `json:"id"`
		} `json:"service_account"`
	} `json:"api_key"`
}

type auditUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// completionsResult is an organization.usage.completions.result.
type completionsResult struct {
	InputTokens      int64  `json:"input_tokens"`
	OutputTokens     int64  `json:"output_tokens"`
	NumModelRequests int64  `json:"num_model_requests"`
	ProjectID        string `json:"project_id"`
	APIKeyID         string `json:"api_key_id"`
	Model            string `json:"model"`
	APISource        string `json:"api_source"`
}

// costsResult is an organization.costs.result.
type costsResult struct {
	Amount *struct {
		Value    float64 `json:"value"`
		Currency string  `json:"currency"`
	} `json:"amount"`
	ProjectID string `json:"project_id"`
	APIKeyID  string `json:"api_key_id"`
	APISource string `json:"api_source"`
}

// searchResult is an organization.usage.web_searches.result or an
// organization.usage.file_searches.result (which has no api_source).
type searchResult struct {
	NumRequests int64  `json:"num_requests"`
	ProjectID   string `json:"project_id"`
	APIKeyID    string `json:"api_key_id"`
	APISource   string `json:"api_source"`
}

// codeInterpreterResult is an
// organization.usage.code_interpreter_sessions.result.
type codeInterpreterResult struct {
	NumSessions int64  `json:"num_sessions"`
	ProjectID   string `json:"project_id"`
}

// agent is an AgentResource (GET /v1/agents). instructions and metadata are
// not decoded.
type agent struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Model     string      `json:"model"`
	CreatedAt int64       `json:"created_at"`
	UpdatedAt int64       `json:"updated_at"`
	Tools     []agentTool `json:"tools"`
}

// agentTool is a PersistedAgentToolResource: its type, its name (function
// tools) and, for MCP tools, the server label and whatever carries the
// server URL. Parameters, descriptions, request metadata and credentials
// are not decoded.
type agentTool struct {
	Type             string          `json:"type"`
	Name             string          `json:"name"`
	ServerLabel      string          `json:"server_label"`
	ServerURL        string          `json:"server_url"`
	Transport        json.RawMessage `json:"transport"`
	ConnectionOrigin json.RawMessage `json:"connection_origin"`
}

// agentSession is a SessionResource (GET /v1/agents/sessions): only its
// root agent and activity times.
type agentSession struct {
	ID           string `json:"id"`
	CreatedAt    int64  `json:"created_at"`
	LastActiveAt int64  `json:"last_active_at"`
	Agent        *struct {
		ID string `json:"id"`
	} `json:"agent"`
}

// storedCompletion is a stored chat.completion: only what the tool-call
// rule reads.
type storedCompletion struct {
	ID      string       `json:"id"`
	Created int64        `json:"created"`
	Choices []chatChoice `json:"choices"`
}

type chatChoice struct {
	FinishReason string `json:"finish_reason"`
	Message      *struct {
		ToolCalls []struct {
			Type string `json:"type"`
		} `json:"tool_calls"`
		FunctionCall *struct{} `json:"function_call"`
	} `json:"message"`
}

// batch is a Batch (GET /v1/batches).
type batch struct {
	ID           string `json:"id"`
	Endpoint     string `json:"endpoint"`
	Status       string `json:"status"`
	InputFileID  string `json:"input_file_id"`
	OutputFileID string `json:"output_file_id"`
	CreatedAt    int64  `json:"created_at"`
}

// batchOutputLine is one line of a batch output file (Batch guide shape:
// {id, custom_id, response:{status_code, request_id, body}, error}).
type batchOutputLine struct {
	Response *struct {
		StatusCode int `json:"status_code"`
		Body       *struct {
			Choices []chatChoice `json:"choices"`
			Output  []struct {
				Type string `json:"type"`
			} `json:"output"`
		} `json:"body"`
	} `json:"response"`
}

// batchInputLine is one line of a batch input file (Batch guide shape:
// {custom_id, method, url, body}).
type batchInputLine struct {
	URL  string `json:"url"`
	Body *struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
		// Input is a string or a list of input items (Responses API).
		Input json.RawMessage `json:"input"`
	} `json:"body"`
}

type inputItem struct {
	Type string `json:"type"`
	Role string `json:"role"`
}
