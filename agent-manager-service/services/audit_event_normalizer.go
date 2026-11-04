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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/spec"
)

// Normalisation turns a stored record — a gateway traffic line or a
// control-plane audit record, each with the Kubernetes metadata Fluent Bit
// adds — into the one AuditEvent shape the API returns. It never fails: a
// field that is missing or of an unexpected type normalises to its zero value,
// and the original document is always returned under raw.

// Audit actor types, as returned by the API.
const (
	auditActorUser      = "USER"
	auditActorAgent     = "AGENT"
	auditActorService   = "SERVICE"
	auditActorGateway   = "GATEWAY"
	auditActorSystem    = "SYSTEM"
	auditActorAnonymous = "ANONYMOUS"
)

// --- typed accessors over a decoded JSON document -------------------------

func docMap(m map[string]any, path ...string) map[string]any {
	cur := m
	for _, p := range path {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func docValue(m map[string]any, path ...string) any {
	if len(path) == 0 {
		return nil
	}
	parent := docMap(m, path[:len(path)-1]...)
	if parent == nil {
		return nil
	}
	return parent[path[len(path)-1]]
}

func docString(m map[string]any, path ...string) string {
	switch v := docValue(m, path...).(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func docInt(m map[string]any, path ...string) (int64, bool) {
	switch v := docValue(m, path...).(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
		if f, err := v.Float64(); err == nil {
			return int64(f), true
		}
	case float64:
		return int64(v), true
	}
	return 0, false
}

func docFloat(m map[string]any, path ...string) (float64, bool) {
	switch v := docValue(m, path...).(type) {
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f, true
		}
	case float64:
		return v, true
	}
	return 0, false
}

func docBool(m map[string]any, path ...string) (value, ok bool) {
	b, ok := docValue(m, path...).(bool)
	return b, ok
}

func docTime(m map[string]any, path ...string) (time.Time, bool) {
	s := docString(m, path...)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- source and category ----------------------------------------------------

// auditSourceOf reports where a record came from. Fluent Bit stamps
// audit_source; the structural fallback covers a record indexed without it.
func auditSourceOf(doc map[string]any) string {
	switch docString(doc, "audit_source") {
	case auditSourceControlPlane:
		return auditSourceControlPlane
	case auditSourceGateway:
		return auditSourceGateway
	}
	if docString(doc, "log_type") == "audit" && docMap(doc, "event") != nil {
		return auditSourceControlPlane
	}
	return auditSourceGateway
}

// auditCategoryOf is the Go form of auditCategoryQuery.
func auditCategoryOf(doc map[string]any) string {
	if auditSourceOf(doc) == auditSourceControlPlane {
		return AuditCategoryOperational
	}
	kind := docString(doc, "api", "kind")
	for _, k := range llmAPIKinds {
		if kind == k {
			return AuditCategoryLLM
		}
	}
	if kind == "Mcp" {
		return AuditCategoryMCP
	}
	if docMap(doc, "a2a") != nil {
		return AuditCategoryA2A
	}
	return AuditCategoryOther
}

// auditGatewayOutcome is the Go form of the gateway half of auditOutcomeQuery.
func auditGatewayOutcome(doc map[string]any) string {
	status, _ := docInt(doc, "status")
	if docString(doc, "decision", "terminalReason") == "policy_denied" || status == 401 || status == 403 {
		return AuditOutcomeDenied
	}
	if isErr, _ := docBool(doc, "mcp", "isError"); status >= 400 || isErr {
		return AuditOutcomeFailed
	}
	return AuditOutcomeSuccess
}

// auditControlPlaneOutcome maps the AMS record outcome. "unknown" marks an
// intent record written before an external mutation; its result is recorded
// by a later record that links back to it (details.attemptEventId), so the
// intent itself is not shown as a failure.
func auditControlPlaneOutcome(outcome string) string {
	switch outcome {
	case "deny":
		return AuditOutcomeDenied
	case "failure":
		return AuditOutcomeFailed
	default:
		return AuditOutcomeSuccess
	}
}

// --- shared builders -------------------------------------------------------

func nullableAgent(ref *AuditAgentRef) spec.NullableAuditAgentRef {
	if ref == nil {
		return *spec.NewNullableAuditAgentRef(nil)
	}
	return *spec.NewNullableAuditAgentRef(spec.NewAuditAgentRef(ref.Name, ref.Project, ref.UUID))
}

func nullableInt32(v int64, ok bool) spec.NullableInt32 {
	if !ok {
		return *spec.NewNullableInt32(nil)
	}
	i := int32(v) //nolint:gosec // HTTP status codes fit in int32
	return *spec.NewNullableInt32(&i)
}

// normalizeAuditDocument converts one stored record. id is the store's
// document id, used when the record carries no event id of its own.
func normalizeAuditDocument(docID string, doc map[string]any, idx *AuditAgentIndex) spec.AuditEvent {
	if doc == nil {
		doc = map[string]any{}
	}
	if idx == nil {
		idx = newAuditAgentIndex()
	}
	if auditSourceOf(doc) == auditSourceControlPlane {
		return normalizeControlPlaneRecord(docID, doc, idx)
	}
	return normalizeGatewayRecord(docID, doc, idx)
}

// --- control plane -----------------------------------------------------------

func controlPlaneActorType(t string) string {
	switch t {
	case "user":
		return auditActorUser
	case "service":
		return auditActorService
	case "agent":
		return auditActorAgent
	case "gateway":
		return auditActorGateway
	case "system":
		return auditActorSystem
	default:
		return auditActorAnonymous
	}
}

func normalizeControlPlaneRecord(docID string, doc map[string]any, idx *AuditAgentIndex) spec.AuditEvent {
	ev := docMap(doc, "event")
	if ev == nil {
		ev = map[string]any{}
	}
	ts, ok := docTime(ev, "occurredAt")
	if !ok {
		if ts, ok = docTime(doc, "time"); !ok {
			ts, _ = docTime(doc, "@timestamp")
		}
	}
	action := docString(ev, "action")
	outcome := auditControlPlaneOutcome(docString(ev, "outcome"))
	status, hasStatus := docInt(ev, "statusCode")

	actorID := docString(ev, "actorId")
	actor := spec.NewAuditActor(
		controlPlaneActorType(docString(ev, "actorType")),
		actorID,
		firstNonEmpty(docString(ev, "actorDisplay"), actorID, docString(ev, "actorType")),
		docString(ev, "authMethod"),
		"",
		docString(ev, "actorTokenId"),
	)

	onBehalfOf := *spec.NewNullableAuditOnBehalfOf(nil)
	if obo := docString(ev, "onBehalfOf"); obo != "" {
		onBehalfOf = *spec.NewNullableAuditOnBehalfOf(spec.NewAuditOnBehalfOf(obo, []string{}))
	}

	project := docString(ev, "projectName")
	resourceType := docString(ev, "resourceType")
	resourceName := docString(ev, "resourceName")
	agentName := docString(ev, "details", "agentName")
	if agentName == "" && resourceType == "agent" {
		agentName = resourceName
	}
	var agent *AuditAgentRef
	if agentName != "" {
		ref := AuditAgentRef{Name: agentName, Project: project}
		if known, ok := idx.AgentInProject(project, agentName); ok {
			ref = known
		}
		agent = &ref
	}

	errBlock := *spec.NewNullableAuditError(nil)
	if code, msg := docString(ev, "errorCode"), docString(ev, "errorMessage"); code != "" || msg != "" {
		errBlock = *spec.NewNullableAuditError(spec.NewAuditError(code, int32(status), msg)) //nolint:gosec // status code
	}

	summary := fmt.Sprintf("%s %s", actor.Display, action)
	if target := strings.Trim(resourceType+" "+firstNonEmpty(resourceName, docString(ev, "resourceId")), " "); target != "" {
		summary += " " + target
	}
	switch docString(ev, "outcome") {
	case "unknown":
		summary += " (started)"
	case "":
	default:
		summary += " (" + docString(ev, "outcome") + ")"
	}

	return *spec.NewAuditEvent(
		firstNonEmpty(docString(ev, "eventId"), docID),
		ts,
		"CONTROL_PLANE",
		spec.AuditEventCategory(AuditCategoryOperational),
		action,
		spec.AuditEventOutcome(outcome),
		nullableInt32(status, hasStatus),
		summary,
		*actor,
		onBehalfOf,
		nullableAgent(agent),
		firstNonEmpty(project, func() string {
			if agent != nil {
				return agent.Project
			}
			return ""
		}()),
		docString(ev, "environment"),
		*spec.NewAuditResource(resourceType, resourceName, docString(ev, "resourceId")),
		*spec.NewNullableAuditDecision(nil),
		*spec.NewNullableAuditLLM(nil),
		*spec.NewNullableAuditMCP(nil),
		*spec.NewNullableAuditA2A(nil),
		*spec.NewNullableAuditGuardrail(nil),
		errBlock,
		*spec.NewAuditNetwork(docString(ev, "sourceIp"), docString(ev, "userAgent")),
		docString(ev, "correlationId"),
		*spec.NewNullableAuditGateway(nil),
		doc,
	)
}

// --- gateway -----------------------------------------------------------------

// actChain flattens a nested RFC 8693 act claim into the acting parties'
// subjects, outermost (the current actor) first.
func actChain(auth map[string]any) []string {
	chain := []string{}
	act := docMap(auth, "claims", "act")
	for depth := 0; act != nil && depth < 10; depth++ {
		if sub := docString(act, "sub"); sub != "" {
			chain = append(chain, sub)
		}
		act = docMap(act, "act")
	}
	return chain
}

func agentDisplay(ref AuditAgentRef) string {
	if ref.Project == "" {
		return "agent " + ref.Name
	}
	return "agent " + ref.Project + "/" + ref.Name
}

// gatewayActor works out who made the call. Precedence: a delegation (act)
// claim names the acting party; otherwise the token subject; otherwise an
// API key, whose holder is known only when the key belongs to an agent.
func gatewayActor(doc map[string]any, idx *AuditAgentIndex) (spec.AuditActor, spec.NullableAuditOnBehalfOf, *AuditAgentRef) {
	auth := docMap(doc, "auth")
	authMethod := docString(auth, "type")
	clientID := docString(auth, "clientId")
	tokenID := docString(auth, "tokenId")
	subject := docString(auth, "subject")
	noOBO := *spec.NewNullableAuditOnBehalfOf(nil)
	authenticated, _ := docBool(auth, "authenticated")

	if chain := actChain(auth); len(chain) > 0 {
		obo := *spec.NewNullableAuditOnBehalfOf(spec.NewAuditOnBehalfOf(subject, chain))
		if ref, ok := idx.AgentIDAgent(chain[0]); ok {
			return *spec.NewAuditActor(auditActorAgent, chain[0], agentDisplay(ref), authMethod, clientID, tokenID), obo, &ref
		}
		return *spec.NewAuditActor(auditActorService, chain[0], chain[0], authMethod, clientID, tokenID), obo, nil
	}
	if auth == nil || !authenticated {
		return *spec.NewAuditActor(auditActorAnonymous, "", "anonymous", authMethod, clientID, tokenID), noOBO, nil
	}
	if subject != "" {
		if ref, ok := idx.AgentIDAgent(subject); ok {
			return *spec.NewAuditActor(auditActorAgent, subject, agentDisplay(ref), authMethod, clientID, tokenID), noOBO, &ref
		}
		if docString(auth, "issuer") == auditAMSIssuer {
			// AMS-minted agent token: the subject is the agent name.
			ref, ok := idx.AgentByName(subject)
			if !ok {
				ref = AuditAgentRef{Name: subject}
			}
			return *spec.NewAuditActor(auditActorAgent, subject, agentDisplay(ref), authMethod, clientID, tokenID), noOBO, &ref
		}
		return *spec.NewAuditActor(auditActorUser, subject, subject, authMethod, clientID, tokenID), noOBO, nil
	}
	if strings.EqualFold(authMethod, "apikey") || strings.HasPrefix(tokenID, auditTokenFingerprintPrefix) {
		// An API key proves possession, not identity: whoever holds the key is
		// the caller. The actor stays ANONYMOUS; the key is named by its
		// fingerprint (tokenId), and when the key belongs to an agent the record
		// is still attributed to that agent through the agent field.
		if keyName, agent, ok := idx.FingerprintKey(tokenID); ok {
			display := "API key " + keyName
			if agent != nil {
				display = fmt.Sprintf("API key %s of %s", keyName, agentDisplay(*agent))
			}
			return *spec.NewAuditActor(auditActorAnonymous, tokenID, display, authMethod, clientID, tokenID), noOBO, agent
		}
		return *spec.NewAuditActor(auditActorAnonymous, tokenID, "API key", authMethod, clientID, tokenID), noOBO, nil
	}
	if clientID != "" {
		return *spec.NewAuditActor(auditActorService, clientID, clientID, authMethod, clientID, tokenID), noOBO, nil
	}
	return *spec.NewAuditActor(auditActorAnonymous, "", "anonymous", authMethod, clientID, tokenID), noOBO, nil
}

// requestPathOf returns the request path: operation.path when the gateway
// logged it, else the path part of target.destination ("host[:port]/path").
func requestPathOf(doc map[string]any) string {
	if p := docString(doc, "operation", "path"); p != "" {
		return p
	}
	dest := docString(doc, "target", "destination")
	if i := strings.Index(dest, "/"); i >= 0 {
		return dest[i:]
	}
	return ""
}

func isTelemetryRoute(doc map[string]any) bool {
	return docString(doc, "api", "context") == "/otel" || strings.HasPrefix(docString(doc, "operation", "path"), "/otel/")
}

func llmAction(doc map[string]any) string {
	path := requestPathOf(doc)
	if ctx := docString(doc, "api", "context"); ctx != "" && ctx != "/" {
		path = strings.TrimPrefix(path, ctx)
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	path = strings.Trim(path, "/")
	switch {
	case strings.HasSuffix(path, "chat/completions"):
		return "llm:chat"
	case path == "":
		return "llm:request"
	default:
		return "llm:" + path[strings.LastIndex(path, "/")+1:]
	}
}

func gatewayAction(doc map[string]any, category string, calledAgent bool) string {
	switch category {
	case AuditCategoryLLM:
		return llmAction(doc)
	case AuditCategoryMCP:
		if m := docString(doc, "mcp", "method"); m != "" {
			return "mcp:" + m
		}
		return "mcp:request"
	case AuditCategoryA2A:
		if op := firstNonEmpty(docString(doc, "a2a", "operation"), docString(doc, "a2a", "requestType")); op != "" {
			return "a2a:" + op
		}
		return "a2a:request"
	}
	if isTelemetryRoute(doc) {
		return "telemetry:export"
	}
	kind := docString(doc, "api", "kind")
	if calledAgent || kind == "RestApi" || kind == "Agent" {
		return "agent:invoke"
	}
	return "api:invoke"
}

// gatewayAgent attributes a gateway record to an agent. For LLM, MCP and
// telemetry traffic that is the caller; for agent-endpoint and A2A traffic it
// is the agent being called.
func gatewayAgent(doc map[string]any, category string, actorAgent *AuditAgentRef, idx *AuditAgentIndex) (*AuditAgentRef, bool) {
	apiName := docString(doc, "api", "name")
	apiID := docString(doc, "api", "id")
	switch category {
	case AuditCategoryLLM:
		if ref, ok := idx.LLMProxyAgent(apiName); ok {
			return &ref, false
		}
		if ref, ok := idx.LLMProxyAgent(apiID); ok {
			return &ref, false
		}
		return actorAgent, false
	case AuditCategoryMCP:
		if actorAgent != nil {
			return actorAgent, false
		}
		if ref, ok := idx.ClientIDAgent(docString(doc, "auth", "clientId")); ok {
			return &ref, false
		}
		return nil, false
	}
	if ref, ok := idx.AgentArtifactAgent(apiID); ok {
		return &ref, true
	}
	if isTelemetryRoute(doc) {
		return actorAgent, false
	}
	return nil, false
}

func gatewaySummary(doc map[string]any, action, outcome string, status int64, hasStatus bool, agent *AuditAgentRef, calledAgent bool) string {
	var b strings.Builder
	b.WriteString(action)
	switch {
	case docString(doc, "mcp", "name") != "":
		b.WriteString(" " + docString(doc, "mcp", "name"))
	case docString(doc, "ai", "model") != "" || docString(doc, "ai", "requestModel") != "":
		b.WriteString(" " + firstNonEmpty(docString(doc, "ai", "model"), docString(doc, "ai", "requestModel")))
	}
	if agent != nil {
		if calledAgent {
			b.WriteString(" on " + agentDisplay(*agent))
		} else {
			b.WriteString(" by " + agentDisplay(*agent))
		}
	} else if name := docString(doc, "api", "name"); name != "" {
		b.WriteString(" via " + name)
	}
	if outcome == AuditOutcomeDenied {
		if policy := docString(doc, "decision", "deniedBy", "policy"); policy != "" {
			b.WriteString(" denied by " + policy)
		} else {
			b.WriteString(" denied")
		}
	}
	if hasStatus {
		fmt.Fprintf(&b, " (%d)", status)
	}
	if total, ok := docInt(doc, "ai", "totalTokens"); ok && total > 0 {
		fmt.Fprintf(&b, ", %d tokens", total)
	}
	return b.String()
}

func normalizeGatewayRecord(docID string, doc map[string]any, idx *AuditAgentIndex) spec.AuditEvent {
	ts, ok := docTime(doc, "timestamp")
	if !ok {
		ts, _ = docTime(doc, "@timestamp")
	}
	category := auditCategoryOf(doc)
	outcome := auditGatewayOutcome(doc)
	status, hasStatus := docInt(doc, "status")

	actor, onBehalfOf, actorAgent := gatewayActor(doc, idx)
	agent, calledAgent := gatewayAgent(doc, category, actorAgent, idx)
	action := gatewayAction(doc, category, calledAgent)

	decision := *spec.NewNullableAuditDecision(nil)
	if dec := docMap(doc, "decision"); dec != nil {
		deniedBy := *spec.NewNullableAuditDeniedBy(nil)
		if db := docMap(dec, "deniedBy"); db != nil {
			deniedBy = *spec.NewNullableAuditDeniedBy(spec.NewAuditDeniedBy(
				docString(db, "policy"), docString(db, "version"), docString(db, "phase")))
		}
		decision = *spec.NewNullableAuditDecision(spec.NewAuditDecision(docString(dec, "terminalReason"), deniedBy))
	}

	llm := *spec.NewNullableAuditLLM(nil)
	if ai := docMap(doc, "ai"); ai != nil {
		prompt, _ := docInt(ai, "promptTokens")
		completion, _ := docInt(ai, "completionTokens")
		total, _ := docInt(ai, "totalTokens")
		cost := *spec.NewNullableFloat64(nil)
		if c, ok := docFloat(ai, "cost"); ok {
			cost = *spec.NewNullableFloat64(&c)
		}
		llm = *spec.NewNullableAuditLLM(spec.NewAuditLLM(
			docString(ai, "provider"), docString(ai, "requestModel"), docString(ai, "model"),
			prompt, completion, total, cost))
	}

	mcp := *spec.NewNullableAuditMCP(nil)
	if m := docMap(doc, "mcp"); m != nil {
		isErr, _ := docBool(m, "isError")
		mcp = *spec.NewNullableAuditMCP(spec.NewAuditMCP(
			docString(doc, "api", "name"), docString(m, "method"), docString(m, "name"),
			docString(m, "sessionId"), docString(m, "id"), isErr))
	}

	a2a := *spec.NewNullableAuditA2A(nil)
	if a := docMap(doc, "a2a"); a != nil {
		block := spec.AuditA2A{
			RequestType:          nil,
			Operation:            nil,
			AdditionalProperties: map[string]any{},
		}
		for k, v := range a {
			block.AdditionalProperties[k] = v
		}
		a2a = *spec.NewNullableAuditA2A(&block)
	}

	guardrail := *spec.NewNullableAuditGuardrail(nil)
	if g := docMap(doc, "guardrail"); g != nil {
		hit, _ := docBool(g, "hit")
		guardrail = *spec.NewNullableAuditGuardrail(spec.NewAuditGuardrail(hit, docString(g, "name")))
	}

	errBlock := *spec.NewNullableAuditError(nil)
	if errType, errMap := docString(doc, "errorType"), docMap(doc, "error"); errType != "" || errMap != nil {
		code, _ := docInt(errMap, "errorCode")
		errBlock = *spec.NewNullableAuditError(spec.NewAuditError(errType, int32(code), docString(errMap, "errorMessage"))) //nolint:gosec // status code
	}

	gateway := *spec.NewNullableAuditGateway(nil)
	if g := docMap(doc, "gateway"); g != nil {
		gateway = *spec.NewNullableAuditGateway(spec.NewAuditGateway(
			docString(g, "id"), docString(g, "organization"), docString(g, "environment")))
	}

	project := ""
	if agent != nil {
		project = agent.Project
	}

	return *spec.NewAuditEvent(
		firstNonEmpty(docString(doc, "eventId"), docID),
		ts,
		"GATEWAY",
		spec.AuditEventCategory(category),
		action,
		spec.AuditEventOutcome(outcome),
		nullableInt32(status, hasStatus),
		gatewaySummary(doc, action, outcome, status, hasStatus, agent, calledAgent),
		actor,
		onBehalfOf,
		nullableAgent(agent),
		project,
		docString(doc, "gateway", "environment"),
		*spec.NewAuditResource(docString(doc, "api", "kind"), docString(doc, "api", "name"), docString(doc, "api", "id")),
		decision,
		llm,
		mcp,
		a2a,
		guardrail,
		errBlock,
		*spec.NewAuditNetwork(docString(doc, "client", "ip"), docString(doc, "client", "userAgent")),
		docString(doc, "correlationId"),
		gateway,
		doc,
	)
}
