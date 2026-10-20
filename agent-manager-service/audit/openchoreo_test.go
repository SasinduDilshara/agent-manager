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
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleEvent() Event {
	return Event{
		EventID:       uuid.MustParse("0192b7c4-5e1a-7d3f-9c2e-1a2b3c4d5e6f"),
		SchemaVersion: SchemaVersion,
		OccurredAt:    time.Date(2026, 10, 20, 9, 15, 2, 481000000, time.UTC),
		Action:        "git-secret:create",
		ActionClass:   ClassCredential,
		Severity:      SeverityCritical,
		ActorType:     ActorUser,
		ActorID:       "8c1f04b2",
		ActorTokenID:  "jti-7c1e",
		AuthMethod:    "jwt-bearer",
		Surface:       SurfaceAPI,
		SourceIP:      "203.0.113.77",
		UserAgent:     "amctl/1.2.3",
		CorrelationID: "c0ffee",
		RequestMethod: "POST",
		RequestPath:   "/orgs/{orgName}/git-secrets",
		OUID:          "ou-9f2",
		OrgHandle:     "acme",
		ResourceType:  "git-secret",
		ResourceID:    "gs-7",
		ResourceName:  "deploy-key",
		ProjectName:   "payments",
		Environment:   "production",
		AgentName:     "checkout-agent",
		Outcome:       OutcomeSuccess,
		StatusCode:    201,
		Details:       map[string]any{"secretType": "ssh"},
	}
}

// TestOpenChoreoLineShape pins the record OpenChoreo's collector, index and
// Observer consume: routing key, schema version, OpenChoreo field names and
// order, the tenant in resource.namespace, and everything else under
// metadata.amp. Field order is part of OpenChoreo's published contract.
func TestOpenChoreoLineShape(t *testing.T) {
	e := sampleEvent()
	line, err := renderOpenChoreoLine(&e, time.Date(2026, 10, 20, 9, 15, 3, 0, time.UTC))
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(line, []byte("\n")), "one record per line")

	want := `{"time":"2026-10-20T09:15:03Z","level":"INFO","msg":"AUDIT-LOG",` +
		`"schema_version":"1.0","event_id":"0192b7c4-5e1a-7d3f-9c2e-1a2b3c4d5e6f",` +
		`"event_time":"2026-10-20T09:15:02.481Z","actor":{"type":"user","id":"8c1f04b2"},` +
		`"action":"git-secret:create","category":"management","result":"success",` +
		`"request_id":"c0ffee","source_ip":"203.0.113.77","user_agent":"amctl/1.2.3",` +
		`"producer":"agent-manager-service","surface":"rest",` +
		`"http":{"method":"POST","path":"/orgs/{orgName}/git-secrets"},` +
		`"resource":{"type":"git-secret","namespace":"ou-9f2","environment":"production",` +
		`"project":"payments","component":"checkout-agent","uid":"gs-7","name":"deploy-key"},` +
		`"metadata":{"amp":{"actionClass":"credential","actorTokenId":"jti-7c1e","authMethod":"jwt-bearer",` +
		`"details":{"secretType":"ssh"},"orgHandle":"acme","outcome":"success","schemaVersion":1,` +
		`"severity":4,"statusCode":201,"surface":"api"}}}` + "\n"
	assert.Equal(t, want, string(line))
}

// TestOpenChoreoRoutingKeyIsNotTheFailureMarker guards the collector's rule
// AUDIT-LOG(?!-): the key must be followed by a quote, never by "-".
func TestOpenChoreoRoutingKeyIsNotTheFailureMarker(t *testing.T) {
	e := sampleEvent()
	line, err := renderOpenChoreoLine(&e, time.Now())
	require.NoError(t, err)
	assert.Contains(t, string(line), `"msg":"AUDIT-LOG"`)
	assert.NotContains(t, string(line), "AUDIT-LOG-")
}

func TestOpenChoreoVocabularies(t *testing.T) {
	cases := []struct {
		class ActionClass
		want  string
	}{
		{ClassIdentity, "authorization"},
		{ClassRead, "access"},
		{ClassAuthn, "access"},
		{ClassAuthz, "access"},
		{ClassActivity, "access"},
		{ClassCredential, "management"},
		{ClassDeployment, "management"},
		{ClassConfig, "management"},
		{ClassSystem, "management"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, openChoreoCategory(c.class), "class %s", c.class)
	}

	assert.Equal(t, "success", openChoreoResult(OutcomeSuccess))
	assert.Equal(t, "failure", openChoreoResult(OutcomeFailure))
	assert.Equal(t, "denied", openChoreoResult(OutcomeDeny))
	// An intent record never resolved must not be reported as a failure that
	// was observed.
	assert.Equal(t, "unknown", openChoreoResult(OutcomeUnknown))

	assert.Equal(t, "rest", openChoreoSurface(SurfaceAPI))
	assert.Equal(t, "mcp", openChoreoSurface(SurfaceMCP))
	for _, s := range []Surface{SurfaceInternal, SurfaceSystem, SurfacePublisher, SurfaceGateway} {
		assert.Empty(t, openChoreoSurface(s), "surface %s has no OpenChoreo name", s)
	}
}

func TestOpenChoreoLineOmitsOversizedDetails(t *testing.T) {
	e := sampleEvent()
	big := make([]string, 0, maxListLen)
	for i := 0; i < 200; i++ {
		big = append(big, strings.Repeat("x", maxStringLen))
	}
	e.Details = map[string]any{"members": big}

	line, err := renderOpenChoreoLine(&e, time.Now())
	require.NoError(t, err)
	assert.LessOrEqual(t, len(line), maxOpenChoreoLineBytes+1)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(line, &decoded))
	amp := decoded["metadata"].(map[string]any)["amp"].(map[string]any)
	assert.NotContains(t, amp, "details")
	assert.Equal(t, true, amp["detailsOmitted"])
	assert.Greater(t, amp["originalBytes"], float64(maxOpenChoreoLineBytes))
	// The record itself survives: identity and tenant are intact.
	assert.Equal(t, "0192b7c4-5e1a-7d3f-9c2e-1a2b3c4d5e6f", decoded["event_id"])
	assert.Equal(t, "ou-9f2", decoded["resource"].(map[string]any)["namespace"])
}

func TestOpenChoreoSinkWritesOneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	sink := newOpenChoreoSink(&buf)
	events := []Event{sampleEvent(), sampleEvent()}
	events[1].EventID = uuid.New()

	require.NoError(t, sink.Write(context.Background(), events))
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	for _, l := range lines {
		assert.True(t, json.Valid([]byte(l)), "each line is a JSON object: %s", l)
	}
}

func TestOpenChoreoSinkStopsOnCancelledContext(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := newOpenChoreoSink(&buf).Write(ctx, []Event{sampleEvent()})
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, buf.Len())
}

func TestSinkNames(t *testing.T) {
	sink := NewMemorySink()
	rec := NewRecorder(NewMultiSink(sink, NewMemorySink()), nil, Config{})
	t.Cleanup(func() { _ = rec.Close(context.Background()) })
	assert.Equal(t, []string{sink.Name(), sink.Name()}, SinkNames(rec))

	single := NewRecorder(sink, nil, Config{})
	t.Cleanup(func() { _ = single.Close(context.Background()) })
	assert.Equal(t, []string{sink.Name()}, SinkNames(single))

	assert.Nil(t, SinkNames(NewNoopRecorder()))
}

// TestWriteSyncRedacts keeps relayed records on the same redaction path as
// every other record: an undeclared detail key is dropped, not written.
func TestWriteSyncRedacts(t *testing.T) {
	sink := NewMemorySink()
	e := BuildObservedEvent(ActionLLMCall,
		Detail("requestModel", "gpt-4o"),
		Detail("authorizationHeader", "Bearer secret"),
	)
	require.NoError(t, WriteSync(context.Background(), sink, []Event{e}))

	got := sink.Events()
	require.Len(t, got, 1)
	assert.Equal(t, "gpt-4o", got[0].Details["requestModel"])
	assert.NotContains(t, got[0].Details, "authorizationHeader")
	assert.Equal(t, []string{"authorizationHeader"}, got[0].Details["_droppedKeys"])
	assert.NotEqual(t, uuid.Nil, got[0].EventID)
	assert.Equal(t, ClassActivity, got[0].ActionClass)
}

// TestBuildObservedEventIgnoresRequestContext: a relayed record describes what
// the gateway saw, so nothing from the delivering request may leak into it.
func TestBuildObservedEventIgnoresRequestContext(t *testing.T) {
	e := BuildObservedEvent(ActionLLMCall)
	assert.Equal(t, ActorAnonymous, e.ActorType)
	assert.Empty(t, e.ActorID)
	assert.Empty(t, e.OUID)
	assert.Empty(t, e.CorrelationID)
}

// TestDroppedEventsAreReportedInTheTrail: overflow drops must reach the trail
// as system:audit-dropped, not only the application log.
func TestDroppedEventsAreReportedInTheTrail(t *testing.T) {
	sink := NewMemorySink()
	r := &bufferedRecorder{sink: sink, logger: quietLogger()}
	r.dropped.Store(7)

	reporter := dropReporter{interval: time.Hour}
	reporter.report(r, false)
	reporter.report(r, false) // nothing new: no second record

	got := sink.Events()
	require.Len(t, got, 1)
	assert.Equal(t, ActionSystemAuditDropped, got[0].Action)
	assert.Equal(t, int64(7), got[0].Details["droppedTotal"])
	assert.Equal(t, ActorSystem, got[0].ActorType)

	// New drops within the interval wait; the final report on shutdown does not.
	r.dropped.Store(9)
	reporter.report(r, false)
	require.Len(t, sink.Events(), 1)
	reporter.report(r, true)
	got = sink.Events()
	require.Len(t, got, 2)
	assert.Equal(t, int64(9), got[1].Details["droppedTotal"])
}

// TestOpenChoreoComponentNamesTheConcernedAgent: the agent filter must find a
// control-plane operation on an agent, not only gateway-observed activity.
func TestOpenChoreoComponentNamesTheConcernedAgent(t *testing.T) {
	render := func(e Event) string {
		line, err := renderOpenChoreoLine(&e, time.Now())
		require.NoError(t, err)
		var decoded struct {
			Resource struct {
				Component string `json:"component"`
			} `json:"resource"`
		}
		require.NoError(t, json.Unmarshal(line, &decoded))
		return decoded.Resource.Component
	}

	observed := sampleEvent()
	assert.Equal(t, "checkout-agent", render(observed))

	deploy := sampleEvent()
	deploy.AgentName = ""
	deploy.ResourceType, deploy.ResourceID, deploy.ResourceName = ResourceAgent, "uuid-1", "billing-agent"
	assert.Equal(t, "billing-agent", render(deploy))

	config := sampleEvent()
	config.AgentName = ""
	config.ResourceType, config.ResourceName = "agent-config", "cfg-1"
	config.Details = map[string]any{"agentName": "billing-agent"}
	assert.Equal(t, "billing-agent", render(config))

	unrelated := sampleEvent()
	unrelated.AgentName = ""
	unrelated.Details = nil
	assert.Empty(t, render(unrelated))
}

// TestOpenChoreoLineCarriesWhatTheReaderRequires: OpenChoreo's logs module
// drops a record lacking schema_version, event_id, actor.type, actor.id,
// result or event_time, so even a record with no identity must carry them.
func TestOpenChoreoLineCarriesWhatTheReaderRequires(t *testing.T) {
	e := BuildObservedEvent(ActionLLMCall)
	e.ActorType, e.ActorID = "", ""
	e.Outcome = ""
	line, err := renderOpenChoreoLine(&e, time.Now())
	require.NoError(t, err)

	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		EventID       string `json:"event_id"`
		EventTime     string `json:"event_time"`
		Result        string `json:"result"`
		Actor         struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"actor"`
	}
	require.NoError(t, json.Unmarshal(line, &decoded))
	assert.NotEmpty(t, decoded.SchemaVersion)
	assert.NotEmpty(t, decoded.EventID)
	assert.NotEmpty(t, decoded.EventTime)
	assert.NotEmpty(t, decoded.Result)
	assert.Equal(t, "anonymous", decoded.Actor.Type)
	assert.Equal(t, "anonymous", decoded.Actor.ID)

	known := sampleEvent()
	line, err = renderOpenChoreoLine(&known, time.Now())
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(line, &decoded))
	assert.Equal(t, "8c1f04b2", decoded.Actor.ID, "a known actor keeps its id")
}
