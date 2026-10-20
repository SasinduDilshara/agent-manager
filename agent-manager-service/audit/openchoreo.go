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

package audit

import (
	"time"
)

// This file renders an Event as an OpenChoreo audit record, so that Agent
// Manager writes into the audit trail OpenChoreo already collects, stores and
// serves: its logs module routes the record to the audit index, and its
// Observer answers queries over it.
//
// The contract is OpenChoreo's published record (schema 1.0, OpenChoreo
// v1.3.x, internal/server/middleware/audit/types.go). It is reproduced here
// rather than imported because that package is internal to OpenChoreo's
// module. Only the fields of that schema are indexed downstream — the audit
// index is mapped with dynamic:false — so everything Agent Manager records
// beyond them travels in metadata, where it is stored and returned but cannot
// be used as a query filter.

const (
	// OpenChoreoSchemaVersion is the OpenChoreo audit schema the records
	// conform to. Minor versions only add fields, so a 1.x consumer reads it.
	OpenChoreoSchemaVersion = "1.0"

	// OpenChoreoRoutingKey is the message OpenChoreo's log collector selects
	// audit records by. It must appear in the line and must not be followed by
	// "-" (that suffix marks OpenChoreo's own render-failure lines).
	OpenChoreoRoutingKey = "AUDIT-LOG"

	// OpenChoreoProducer names this workload in every record. OpenChoreo keys
	// producers on the deployed workload's name, and the logs module's
	// trusted-producer allowlist entry for this service carries the same name.
	OpenChoreoProducer = "agent-manager-service"

	// ampMetadataKey namespaces Agent Manager's own fields inside a record's
	// metadata, so they cannot collide with anything OpenChoreo adds later.
	ampMetadataKey = "amp"
)

// OpenChoreo audit vocabularies. The Observer validates its category, result
// and surface filters against these closed sets, so a record carrying any other
// value is stored but cannot be selected by that filter.
const (
	ocCategoryManagement    = "management"
	ocCategoryAuthorization = "authorization"
	ocCategoryAccess        = "access"

	ocResultSuccess = "success"
	ocResultFailure = "failure"
	ocResultDenied  = "denied"
	// ocResultUnknown has no OpenChoreo counterpart. It marks an intent record
	// whose outcome never arrived (see Begin), and is written verbatim rather
	// than coerced into failure, which would claim something not observed.
	ocResultUnknown = "unknown"

	ocSurfaceREST = "rest"
	ocSurfaceMCP  = "mcp"
)

// ocRecord is the published OpenChoreo audit record. Field order is part of
// that contract and is kept here.
type ocRecord struct {
	SchemaVersion string         `json:"schema_version"`
	EventID       string         `json:"event_id"`
	EventTime     time.Time      `json:"event_time"`
	Actor         ocActor        `json:"actor"`
	Action        string         `json:"action"`
	Category      string         `json:"category"`
	Result        string         `json:"result"`
	RequestID     string         `json:"request_id"`
	SourceIP      string         `json:"source_ip"`
	UserAgent     string         `json:"user_agent"`
	Producer      string         `json:"producer"`
	Surface       string         `json:"surface,omitempty"`
	OperationID   string         `json:"operation_id,omitempty"`
	HTTP          *ocHTTP        `json:"http,omitempty"`
	Resource      *ocResource    `json:"resource,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type ocActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type ocHTTP struct {
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

type ocResource struct {
	Type        string `json:"type,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Environment string `json:"environment,omitempty"`
	Project     string `json:"project,omitempty"`
	Component   string `json:"component,omitempty"`
	Resource    string `json:"resource,omitempty"`
	UID         string `json:"uid,omitempty"`
	Name        string `json:"name,omitempty"`
}

// toOpenChoreoRecord maps an event onto the OpenChoreo record.
//
// resource.namespace carries the organization's OU id, which is the tenant key
// every read through QueryAuditLogs is confined to. Agent Manager maps all of
// its organizations onto one OpenChoreo namespace, so the real namespace could
// not separate tenants; the OU id is immutable, unlike the org handle.
func toOpenChoreoRecord(e *Event) ocRecord {
	rec := ocRecord{
		SchemaVersion: OpenChoreoSchemaVersion,
		EventID:       e.EventID.String(),
		EventTime:     e.OccurredAt.UTC(),
		Actor:         openChoreoActor(e),
		Action:        string(e.Action),
		Category:      openChoreoCategory(e.ActionClass),
		Result:        openChoreoResult(e.Outcome),
		RequestID:     e.CorrelationID,
		SourceIP:      e.SourceIP,
		UserAgent:     e.UserAgent,
		Producer:      OpenChoreoProducer,
		Surface:       openChoreoSurface(e.Surface),
	}
	if e.RequestMethod != "" || e.RequestPath != "" {
		rec.HTTP = &ocHTTP{Method: e.RequestMethod, Path: e.RequestPath}
	}
	rec.Resource = &ocResource{
		Type:        e.ResourceType,
		Namespace:   e.OUID,
		Environment: e.Environment,
		Project:     e.ProjectName,
		Component:   concernedAgent(e),
		UID:         e.ResourceID,
		Name:        e.ResourceName,
	}
	rec.Metadata = map[string]any{ampMetadataKey: ampMetadata(e)}
	return rec
}

// openChoreoActor fills the actor OpenChoreo's reader requires. Its logs
// module skips, as malformed, any record without actor.type and actor.id
// (observability-logs-opensearch ParseAuditRecord), so a caller with no
// identity — an unauthenticated request, or gateway traffic whose agent could
// not be resolved — is named by its type rather than left out of the trail.
func openChoreoActor(e *Event) ocActor {
	actorType := string(e.ActorType)
	if actorType == "" {
		actorType = string(ActorAnonymous)
	}
	id := e.ActorID
	if id == "" {
		id = actorType
	}
	return ocActor{Type: actorType, ID: id}
}

// concernedAgent names the agent a record concerns, which the store indexes as
// the component so one filter finds everything about an agent: the agent a
// gateway observed acting, else an agent that is itself the resource, else the
// agent an operation on one of its parts names in its agentName detail.
func concernedAgent(e *Event) string {
	if e.AgentName != "" {
		return e.AgentName
	}
	if e.ResourceType == ResourceAgent && e.ResourceName != "" {
		return e.ResourceName
	}
	if name, ok := e.Details["agentName"].(string); ok {
		return name
	}
	return ""
}

// ampMetadata carries every Event field the OpenChoreo schema has no place
// for, under the same JSON names the Event itself uses, so a reader can map a
// record back without a second vocabulary.
func ampMetadata(e *Event) map[string]any {
	m := map[string]any{
		"schemaVersion": e.SchemaVersion,
		"actionClass":   string(e.ActionClass),
		"severity":      int(e.Severity),
		"outcome":       string(e.Outcome),
		"surface":       string(e.Surface),
	}
	putString(m, "actorDisplay", e.ActorDisplay)
	putString(m, "actorOuId", e.ActorOUID)
	putString(m, "actorTokenId", e.ActorTokenID)
	putString(m, "authMethod", e.AuthMethod)
	putString(m, "onBehalfOf", e.OnBehalfOf)
	putString(m, "orgHandle", e.OrgHandle)
	putString(m, "errorCode", e.ErrorCode)
	putString(m, "errorMessage", e.ErrorMessage)
	putString(m, "requiredPermission", e.RequiredPermission)
	if e.StatusCode != 0 {
		m["statusCode"] = e.StatusCode
	}
	if e.DurationMs != 0 {
		m["durationMs"] = e.DurationMs
	}
	if len(e.Details) > 0 {
		m["details"] = e.Details
	}
	return m
}

func putString(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}

// openChoreoCategory maps an action class onto OpenChoreo's three categories:
// authorization for privilege and membership changes, access for reads,
// refusals and observed agent activity, management for every other change.
// The exact class is kept in metadata.amp.actionClass.
func openChoreoCategory(class ActionClass) string {
	switch class {
	case ClassIdentity:
		return ocCategoryAuthorization
	case ClassRead, ClassAuthn, ClassAuthz, ClassActivity:
		return ocCategoryAccess
	default:
		return ocCategoryManagement
	}
}

func openChoreoResult(o Outcome) string {
	switch o {
	case OutcomeSuccess:
		return ocResultSuccess
	case OutcomeDeny:
		return ocResultDenied
	case OutcomeUnknown:
		return ocResultUnknown
	default:
		return ocResultFailure
	}
}

// openChoreoSurface maps the two surfaces OpenChoreo has a name for. The
// others (internal, system, publisher, gateway) are left empty, which the
// schema allows, and kept in metadata.amp.surface.
func openChoreoSurface(s Surface) string {
	switch s {
	case SurfaceAPI:
		return ocSurfaceREST
	case SurfaceMCP:
		return ocSurfaceMCP
	default:
		return ""
	}
}
