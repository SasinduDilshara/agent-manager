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

package ocauditsvc

// Wire types of the OpenChoreo Observer audit API (openchoreo v1.3.x,
// openapi/observer-api.yaml and internal/observer/types/auditlogs.go).

// ActorFilter selects records by actor. Every list is OR within itself.
type ActorFilter struct {
	IDs          []string `json:"id,omitempty"`
	Types        []string `json:"type,omitempty"`
	Issuers      []string `json:"issuer,omitempty"`
	SessionIDs   []string `json:"session_id,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
}

// ResourceFilter selects records by the resource acted upon.
type ResourceFilter struct {
	Types        []string `json:"type,omitempty"`
	Namespaces   []string `json:"namespace,omitempty"`
	Environments []string `json:"environment,omitempty"`
	Projects     []string `json:"project,omitempty"`
	Components   []string `json:"component,omitempty"`
	Resources    []string `json:"resource,omitempty"`
	Names        []string `json:"name,omitempty"`
}

// QueryRequest is the body of POST /api/v1alpha1/audit-logs/query.
//
// The window is [StartTime, EndTime), RFC3339, at most 366 days. Limit is
// 1..1000 (default 100). Filters are ANDed together.
type QueryRequest struct {
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`

	Actor    ActorFilter    `json:"actor"`
	Resource ResourceFilter `json:"resource"`

	Actions      []string `json:"action,omitempty"`
	Categories   []string `json:"category,omitempty"`
	Results      []string `json:"result,omitempty"`
	Producers    []string `json:"producer,omitempty"`
	Surfaces     []string `json:"surface,omitempty"`
	OperationIDs []string `json:"operation_id,omitempty"`
	RequestIDs   []string `json:"request_id,omitempty"`
	EventIDs     []string `json:"event_id,omitempty"`
	SourceIPs    []string `json:"source_ip,omitempty"`
	UserAgents   []string `json:"user_agent,omitempty"`

	// SearchPhrase is a case-sensitive substring match over the raw record.
	SearchPhrase string `json:"searchPhrase,omitempty"`

	Limit int `json:"limit,omitempty"`
	// SortOrder is "asc" or "desc" (the Observer's default).
	SortOrder string `json:"sortOrder,omitempty"`
}

// Actor is a record's actor.
type Actor struct {
	Type         string              `json:"type"`
	ID           string              `json:"id"`
	Issuer       string              `json:"issuer,omitempty"`
	SessionID    string              `json:"session_id,omitempty"`
	Entitlements map[string][]string `json:"entitlements,omitempty"`
}

// HTTPInfo is a record's request method and path.
type HTTPInfo struct {
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

// Resource is a record's resource.
type Resource struct {
	Type        string         `json:"type,omitempty"`
	Namespace   string         `json:"namespace,omitempty"`
	Environment string         `json:"environment,omitempty"`
	Project     string         `json:"project,omitempty"`
	Component   string         `json:"component,omitempty"`
	Resource    string         `json:"resource,omitempty"`
	UID         string         `json:"uid,omitempty"`
	Name        string         `json:"name,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Record is one audit record as the Observer returns it.
type Record struct {
	SchemaVersion string         `json:"schema_version"`
	EventID       string         `json:"event_id"`
	EventTime     string         `json:"event_time"`
	Actor         Actor          `json:"actor"`
	Action        string         `json:"action"`
	Category      string         `json:"category"`
	Result        string         `json:"result"`
	RequestID     string         `json:"request_id"`
	SourceIP      string         `json:"source_ip"`
	UserAgent     string         `json:"user_agent"`
	Producer      string         `json:"producer"`
	Surface       string         `json:"surface,omitempty"`
	OperationID   string         `json:"operation_id,omitempty"`
	HTTP          *HTTPInfo      `json:"http,omitempty"`
	Resource      *Resource      `json:"resource,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// QueryResponse is the Observer's answer to a query. Total is exact: the number
// of records matching the request, of which Records is the first page.
type QueryResponse struct {
	Records []Record `json:"records"`
	Total   int64    `json:"total"`
	TookMs  int64    `json:"tookMs"`
}

// FilterValuesRequest asks for the distinct values of one field among the
// records Query matches.
type FilterValuesRequest struct {
	Query       QueryRequest `json:"query"`
	Filter      string       `json:"filter"`
	ValueSearch string       `json:"valueSearch,omitempty"`
	MaxValues   int          `json:"maxValues,omitempty"`
}

// FilterValue is one distinct value and how many matching records carry it.
type FilterValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// FilterValuesResponse is the answer to a filter-values request.
type FilterValuesResponse struct {
	Filter      string        `json:"filter"`
	Values      []FilterValue `json:"values"`
	TotalValues int64         `json:"totalValues"`
	TookMs      int64         `json:"tookMs"`
}
