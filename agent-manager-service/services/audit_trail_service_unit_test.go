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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/clients/clientmocks"
	"github.com/wso2/agent-manager/agent-manager-service/clients/ocauditsvc"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

var trailT0 = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

func trailRecord(id string, at time.Time, ou string) ocauditsvc.Record {
	return ocauditsvc.Record{
		SchemaVersion: audit.OpenChoreoSchemaVersion,
		EventID:       id,
		EventTime:     at.UTC().Format(time.RFC3339Nano),
		Actor:         ocauditsvc.Actor{Type: "agent", ID: "support-agent"},
		Action:        "llm:call",
		Category:      "access",
		Result:        "success",
		Producer:      audit.OpenChoreoProducer,
		Resource:      &ocauditsvc.Resource{Type: "llm-proxy", Namespace: ou, Name: "proxy-1", Component: "support-agent"},
		Metadata: map[string]any{"amp": map[string]any{
			"actionClass": "activity", "severity": float64(1), "surface": "gateway", "outcome": "success",
			"statusCode": float64(200), "durationMs": float64(1834),
			"details": map[string]any{"requestModel": "gpt-4o", "provenance": "observed-best-effort"},
		}},
	}
}

// fakeAuditStore answers queries the way the Observer does: the window is
// [start, end) at millisecond precision, records ordered by time, the first
// Limit returned and Total exact. Records sharing an instant are ordered by id,
// or kept in stored order with tiesInStoredOrder, since the export must not
// depend on how the store breaks ties. It ignores filters other than the window
// — the request filters are asserted separately.
type fakeAuditStore struct {
	records           []ocauditsvc.Record
	tiesInStoredOrder bool
	requests          []ocauditsvc.QueryRequest
	// afterCalls, when set, runs after each query (to simulate late arrivals).
	afterCalls func(n int)
}

func (f *fakeAuditStore) mock() *clientmocks.OCAuditClientMock {
	return &clientmocks.OCAuditClientMock{
		QueryAuditLogsFunc: func(_ context.Context, req ocauditsvc.QueryRequest) (*ocauditsvc.QueryResponse, error) {
			f.requests = append(f.requests, req)
			start, _ := time.Parse(time.RFC3339Nano, req.StartTime)
			end, _ := time.Parse(time.RFC3339Nano, req.EndTime)
			var match []ocauditsvc.Record
			for _, r := range f.records {
				ms, _ := recordMillis(r)
				if ms >= start.UnixMilli() && ms < end.UnixMilli() {
					match = append(match, r)
				}
			}
			sort.SliceStable(match, func(i, j int) bool {
				mi, _ := recordMillis(match[i])
				mj, _ := recordMillis(match[j])
				if mi != mj || f.tiesInStoredOrder {
					return mi < mj
				}
				return match[i].EventID < match[j].EventID
			})
			total := int64(len(match))
			if req.Limit > 0 && len(match) > req.Limit {
				match = match[:req.Limit]
			}
			if f.afterCalls != nil {
				f.afterCalls(len(f.requests))
			}
			return &ocauditsvc.QueryResponse{Records: match, Total: total}, nil
		},
		QueryFilterValuesFunc: func(_ context.Context, req ocauditsvc.FilterValuesRequest) (*ocauditsvc.FilterValuesResponse, error) {
			f.requests = append(f.requests, req.Query)
			return &ocauditsvc.FilterValuesResponse{Filter: req.Filter}, nil
		},
	}
}

func baseTrailQuery() AuditTrailQuery {
	return AuditTrailQuery{
		StartTime: trailT0, EndTime: trailT0.Add(time.Hour), Limit: 100, SortOrder: "desc",
	}
}

func newTrailService(client ocauditsvc.Client) *auditTrailService {
	svc := NewAuditTrailService(client, 1000, time.Minute, discardLogger()).(*auditTrailService)
	svc.now = func() time.Time { return trailT0.Add(24 * time.Hour) }
	return svc
}

// TestAuditTrail_ReadsAreConfinedToTheCallersOrganization is the tenancy
// guarantee: the store's reader is cluster-wide, so the organization and
// producer filters must be on every request, set from the caller alone.
func TestAuditTrail_ReadsAreConfinedToTheCallersOrganization(t *testing.T) {
	store := &fakeAuditStore{records: []ocauditsvc.Record{trailRecord("e1", trailT0, "ou-acme")}}
	svc := newTrailService(store.mock())

	q := baseTrailQuery()
	q.Projects = []string{"customer-care"}
	q.Agents = []string{"support-agent"}
	_, err := svc.Query(auditableCtx(t), "ou-acme", q)
	require.NoError(t, err)
	_, err = svc.FilterValues(auditableCtx(t), "ou-acme", "action", q, "", 0)
	require.NoError(t, err)

	for _, req := range store.requests {
		assert.Equal(t, []string{"ou-acme"}, req.Resource.Namespaces)
		assert.Equal(t, []string{audit.OpenChoreoProducer}, req.Producers)
		assert.Equal(t, []string{"customer-care"}, req.Resource.Projects)
		assert.Equal(t, []string{"support-agent"}, req.Resource.Components)
	}
}

// TestAuditTrail_DropsRecordsOutsideTheOrganization: the query excludes them,
// so one arriving is a fault — logged, never shown.
func TestAuditTrail_DropsRecordsOutsideTheOrganization(t *testing.T) {
	foreign := trailRecord("e2", trailT0, "ou-globex")
	otherProducer := trailRecord("e3", trailT0, "ou-acme")
	otherProducer.Producer = "openchoreo-api"
	client := &clientmocks.OCAuditClientMock{
		QueryAuditLogsFunc: func(_ context.Context, _ ocauditsvc.QueryRequest) (*ocauditsvc.QueryResponse, error) {
			return &ocauditsvc.QueryResponse{
				Records: []ocauditsvc.Record{trailRecord("e1", trailT0, "ou-acme"), foreign, otherProducer}, Total: 3,
			}, nil
		},
	}
	resp, err := newTrailService(client).Query(auditableCtx(t), "ou-acme", baseTrailQuery())
	require.NoError(t, err)
	require.Len(t, resp.Records, 1)
	assert.Equal(t, "e1", resp.Records[0].EventId)
}

func TestAuditTrail_RecordMapping(t *testing.T) {
	store := &fakeAuditStore{records: []ocauditsvc.Record{trailRecord("e1", trailT0.Add(481*time.Millisecond), "ou-acme")}}
	resp, err := newTrailService(store.mock()).Query(auditableCtx(t), "ou-acme", baseTrailQuery())
	require.NoError(t, err)
	require.Len(t, resp.Records, 1)
	r := resp.Records[0]
	assert.Equal(t, trailT0.Add(481*time.Millisecond), r.OccurredAt)
	assert.Equal(t, "llm:call", r.Action)
	assert.Equal(t, "success", r.Result)
	assert.Equal(t, "agent", r.Actor.Type)
	assert.Equal(t, "support-agent", r.Actor.Id)
	assert.Equal(t, "activity", *r.ActionClass)
	assert.Equal(t, "gateway", *r.Surface)
	assert.Equal(t, int32(1), *r.Severity)
	assert.Equal(t, int32(200), *r.StatusCode)
	assert.Equal(t, int64(1834), *r.DurationMs)
	assert.Equal(t, "llm-proxy", *r.Resource.Type)
	assert.Equal(t, "support-agent", *r.Resource.Agent)
	assert.Equal(t, "gpt-4o", r.Details["requestModel"])
	assert.Equal(t, int64(1), resp.Total)
}

// TestAuditTrail_UnknownOutcomeIsNotReportedAsFailure keeps an intent record
// whose outcome never arrived distinguishable from a recorded failure.
func TestAuditTrail_UnknownOutcomeIsNotReportedAsFailure(t *testing.T) {
	rec := trailRecord("e1", trailT0, "ou-acme")
	rec.Result = "unknown"
	rec.Metadata["amp"].(map[string]any)["outcome"] = "unknown"
	store := &fakeAuditStore{records: []ocauditsvc.Record{rec}}
	resp, err := newTrailService(store.mock()).Query(auditableCtx(t), "ou-acme", baseTrailQuery())
	require.NoError(t, err)
	assert.Equal(t, "unknown", resp.Records[0].Result)
}

func TestAuditTrail_Validation(t *testing.T) {
	svc := newTrailService(&clientmocks.OCAuditClientMock{})
	many := make([]string, 21)
	for i := range many {
		many[i] = fmt.Sprintf("a%d", i)
	}
	cases := map[string]func(q *AuditTrailQuery){
		"missing start":      func(q *AuditTrailQuery) { q.StartTime = time.Time{} },
		"end before start":   func(q *AuditTrailQuery) { q.EndTime = q.StartTime.Add(-time.Second) },
		"window too long":    func(q *AuditTrailQuery) { q.EndTime = q.StartTime.Add(367 * 24 * time.Hour) },
		"limit too large":    func(q *AuditTrailQuery) { q.Limit = 1001 },
		"limit zero":         func(q *AuditTrailQuery) { q.Limit = 0 },
		"bad sort":           func(q *AuditTrailQuery) { q.SortOrder = "sideways" },
		"unknown result":     func(q *AuditTrailQuery) { q.Results = []string{"maybe"} },
		"unknown category":   func(q *AuditTrailQuery) { q.Categories = []string{"other"} },
		"unknown actor type": func(q *AuditTrailQuery) { q.ActorTypes = []string{"robot"} },
		"too many values":    func(q *AuditTrailQuery) { q.Actions = many },
		"empty value":        func(q *AuditTrailQuery) { q.Projects = []string{""} },
		"search too long":    func(q *AuditTrailQuery) { q.Search = strings.Repeat("x", 257) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			q := baseTrailQuery()
			mutate(&q)
			_, err := svc.Query(auditableCtx(t), "ou-acme", q)
			require.ErrorIs(t, err, utils.ErrInvalidAuditQuery)
		})
	}
}

func TestAuditTrail_NotConfigured(t *testing.T) {
	svc := NewAuditTrailService(nil, 1000, time.Minute, discardLogger())
	_, err := svc.Query(auditableCtx(t), "ou-acme", baseTrailQuery())
	require.ErrorIs(t, err, utils.ErrAuditTrailNotConfigured)
	_, err = svc.Export(auditableCtx(t), "ou-acme", baseTrailQuery(), &bytes.Buffer{})
	require.ErrorIs(t, err, utils.ErrAuditTrailNotConfigured)
}

func TestAuditTrail_ErrorMapping(t *testing.T) {
	cases := []struct {
		clientErr error
		want      error
	}{
		{ocauditsvc.ErrNotSupported, utils.ErrAuditTrailNotSupported},
		{fmt.Errorf("%w: bad window", ocauditsvc.ErrInvalidRequest), utils.ErrInvalidAuditQuery},
		{fmt.Errorf("%w (status 403)", ocauditsvc.ErrAccessDenied), utils.ErrAuditTrailUnavailable},
		{errors.New("connection refused"), utils.ErrAuditTrailUnavailable},
	}
	for _, c := range cases {
		client := &clientmocks.OCAuditClientMock{
			QueryAuditLogsFunc: func(_ context.Context, _ ocauditsvc.QueryRequest) (*ocauditsvc.QueryResponse, error) {
				return nil, c.clientErr
			},
		}
		_, err := newTrailService(client).Query(auditableCtx(t), "ou-acme", baseTrailQuery())
		require.ErrorIs(t, err, c.want, "client error %v", c.clientErr)
	}
}

// TestAuditTrail_StoreRejectionDoesNotEchoTheStore: the store's message names
// the filters this service adds, so it is logged, not returned.
func TestAuditTrail_StoreRejectionDoesNotEchoTheStore(t *testing.T) {
	client := &clientmocks.OCAuditClientMock{
		QueryAuditLogsFunc: func(_ context.Context, _ ocauditsvc.QueryRequest) (*ocauditsvc.QueryResponse, error) {
			return nil, fmt.Errorf("%w: invalid filter resource.namespaces=[ou-acme] producer=agent-manager-service",
				ocauditsvc.ErrInvalidRequest)
		},
	}
	_, err := newTrailService(client).Query(auditableCtx(t), "ou-acme", baseTrailQuery())
	require.ErrorIs(t, err, utils.ErrInvalidAuditQuery)
	assert.NotContains(t, err.Error(), "ou-acme")
	assert.NotContains(t, err.Error(), "producer")
}

func TestAuditTrail_FilterValues(t *testing.T) {
	var got ocauditsvc.FilterValuesRequest
	client := &clientmocks.OCAuditClientMock{
		QueryFilterValuesFunc: func(_ context.Context, req ocauditsvc.FilterValuesRequest) (*ocauditsvc.FilterValuesResponse, error) {
			got = req
			return &ocauditsvc.FilterValuesResponse{
				Filter: req.Filter, TotalValues: 2,
				Values: []ocauditsvc.FilterValue{{Value: "llm:call", Count: 5}, {Value: "mcp:tool-call", Count: 2}},
			}, nil
		},
	}
	svc := newTrailService(client)
	resp, err := svc.FilterValues(auditableCtx(t), "ou-acme", "agent", baseTrailQuery(), "supp", 50)
	require.NoError(t, err)
	assert.Equal(t, "resource.component", got.Filter, "API filter names map onto the Observer's")
	assert.Equal(t, "supp", got.ValueSearch)
	assert.Equal(t, 50, got.MaxValues)
	assert.Equal(t, []string{"ou-acme"}, got.Query.Resource.Namespaces)
	assert.Equal(t, "agent", resp.Filter)
	assert.Len(t, resp.Values, 2)

	_, err = svc.FilterValues(auditableCtx(t), "ou-acme", "resource.namespace", baseTrailQuery(), "", 0)
	require.ErrorIs(t, err, utils.ErrInvalidAuditQuery, "the tenant field cannot be listed")
}

// --- Export ------------------------------------------------------------------------

func readExport(t *testing.T, body []byte) (records []map[string]any, manifest map[string]any) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	require.NotEmpty(t, lines)
	for _, l := range lines[:len(lines)-1] {
		var r map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &r))
		records = append(records, r)
	}
	var last map[string]map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[len(lines)-1]), &last))
	return records, last["manifest"]
}

func exportQuery() AuditTrailQuery {
	return AuditTrailQuery{StartTime: trailT0, EndTime: trailT0.Add(time.Hour)}
}

// TestAuditTrail_ExportIsCompleteAcrossPages: more than a page of records, with
// several sharing the instant a page ends on — every record exactly once.
func TestAuditTrail_ExportIsCompleteAcrossPages(t *testing.T) {
	var recs []ocauditsvc.Record
	for i := 0; i < 2500; i++ {
		// Five records per millisecond, so page boundaries land mid-instant.
		at := trailT0.Add(time.Duration(i/5) * time.Millisecond)
		recs = append(recs, trailRecord(fmt.Sprintf("e%05d", i), at, "ou-acme"))
	}
	store := &fakeAuditStore{records: recs}
	svc := newTrailService(store.mock())
	svc.exportMaxRecords = 10000

	var out bytes.Buffer
	manifest, err := svc.Export(auditableCtx(t), "ou-acme", exportQuery(), &out)
	require.NoError(t, err)
	assert.True(t, manifest.Complete, "reason: %v", manifest.Reason)
	assert.Equal(t, int64(2500), manifest.ExportedCount)
	assert.Equal(t, int64(2500), manifest.StoreCount)

	records, m := readExport(t, out.Bytes())
	require.Len(t, records, 2500)
	seen := map[string]bool{}
	for _, r := range records {
		id := r["eventId"].(string)
		assert.False(t, seen[id], "record %s exported twice", id)
		seen[id] = true
	}
	assert.Equal(t, true, m["complete"])

	// The manifest's digest covers every byte before its own line.
	body := out.Bytes()
	cut := bytes.LastIndex(bytes.TrimSuffix(body, []byte("\n")), []byte("\n")) + 1
	sum := sha256.Sum256(body[:cut])
	assert.Equal(t, hex.EncodeToString(sum[:]), m["sha256"])

	for _, req := range store.requests {
		assert.Equal(t, []string{"ou-acme"}, req.Resource.Namespaces)
		assert.Equal(t, "asc", req.SortOrder)
	}
}

// TestAuditTrail_ExportSkipsStoredDuplicates: a gateway batch delivered twice
// is stored twice under one event id; the export delivers it once and says so.
func TestAuditTrail_ExportSkipsStoredDuplicates(t *testing.T) {
	recs := []ocauditsvc.Record{
		trailRecord("e1", trailT0, "ou-acme"),
		trailRecord("e2", trailT0.Add(time.Millisecond), "ou-acme"),
		trailRecord("e2", trailT0.Add(time.Millisecond), "ou-acme"),
		trailRecord("e3", trailT0.Add(2*time.Millisecond), "ou-acme"),
	}
	svc := newTrailService((&fakeAuditStore{records: recs}).mock())
	var out bytes.Buffer
	manifest, err := svc.Export(auditableCtx(t), "ou-acme", exportQuery(), &out)
	require.NoError(t, err)
	assert.True(t, manifest.Complete)
	assert.Equal(t, int64(3), manifest.ExportedCount)
	assert.Equal(t, int64(1), *manifest.DuplicatesSkipped)
	assert.Equal(t, int64(4), manifest.StoreCount)
}

// TestAuditTrail_ExportCountsDuplicatesSplitByAPage: the two copies of a record
// fall on either side of a page boundary. The copy on the next page is a
// duplicate, not the overlap the next page repeats, so the counts still agree.
func TestAuditTrail_ExportCountsDuplicatesSplitByAPage(t *testing.T) {
	var recs []ocauditsvc.Record
	for i := 0; i < auditExportPageSize-1; i++ {
		recs = append(recs, trailRecord(fmt.Sprintf("a%05d", i), trailT0.Add(time.Duration(i)*time.Millisecond), "ou-acme"))
	}
	edge := trailT0.Add(time.Duration(auditExportPageSize) * time.Millisecond)
	// Ids sort after every "a" id, so with ties by id the page ends between the copies.
	recs = append(recs,
		trailRecord("z-dup", edge, "ou-acme"),
		trailRecord("z-dup", edge, "ou-acme"),
		trailRecord("z-last", edge.Add(time.Millisecond), "ou-acme"),
	)
	svc := newTrailService((&fakeAuditStore{records: recs}).mock())
	svc.exportMaxRecords = 10000

	var out bytes.Buffer
	manifest, err := svc.Export(auditableCtx(t), "ou-acme", exportQuery(), &out)
	require.NoError(t, err)
	assert.True(t, manifest.Complete, "reason: %v", manifest.Reason)
	assert.Equal(t, int64(auditExportPageSize+1), manifest.ExportedCount)
	assert.Equal(t, int64(1), *manifest.DuplicatesSkipped)
	assert.Equal(t, int64(auditExportPageSize+2), manifest.StoreCount)
}

// TestAuditTrail_ExportSkipsDuplicatesWhateverTheTieOrder: a store that does not
// order an instant's records by id can return the copies of a record apart.
func TestAuditTrail_ExportSkipsDuplicatesWhateverTheTieOrder(t *testing.T) {
	recs := []ocauditsvc.Record{
		trailRecord("e2", trailT0, "ou-acme"),
		trailRecord("e1", trailT0, "ou-acme"),
		trailRecord("e2", trailT0, "ou-acme"),
	}
	svc := newTrailService((&fakeAuditStore{records: recs, tiesInStoredOrder: true}).mock())
	var out bytes.Buffer
	manifest, err := svc.Export(auditableCtx(t), "ou-acme", exportQuery(), &out)
	require.NoError(t, err)
	assert.True(t, manifest.Complete, "reason: %v", manifest.Reason)
	assert.Equal(t, int64(2), manifest.ExportedCount)
	assert.Equal(t, int64(1), *manifest.DuplicatesSkipped)
	records, _ := readExport(t, out.Bytes())
	require.Len(t, records, 2)
}

// TestAuditTrail_ExportIsCompleteWhateverTheTieOrder: paging stays exact when a
// page boundary lands mid-instant and the store orders ties arbitrarily.
func TestAuditTrail_ExportIsCompleteWhateverTheTieOrder(t *testing.T) {
	var recs []ocauditsvc.Record
	for i := 0; i < 2500; i++ {
		at := trailT0.Add(time.Duration(i/7) * time.Millisecond)
		// Stored out of id order within each instant.
		recs = append(recs, trailRecord(fmt.Sprintf("e%05d", 2500-i), at, "ou-acme"))
	}
	svc := newTrailService((&fakeAuditStore{records: recs, tiesInStoredOrder: true}).mock())
	svc.exportMaxRecords = 10000
	var out bytes.Buffer
	manifest, err := svc.Export(auditableCtx(t), "ou-acme", exportQuery(), &out)
	require.NoError(t, err)
	assert.True(t, manifest.Complete, "reason: %v", manifest.Reason)
	assert.Equal(t, int64(2500), manifest.ExportedCount)
	assert.Zero(t, *manifest.DuplicatesSkipped)
}

// TestAuditTrail_ExportReportsUnreachableRecords: more records in one instant
// than a page holds cannot be paged past; the export must say so, not skip them.
func TestAuditTrail_ExportReportsUnreachableRecords(t *testing.T) {
	var recs []ocauditsvc.Record
	for i := 0; i < auditExportPageSize+5; i++ {
		recs = append(recs, trailRecord(fmt.Sprintf("e%05d", i), trailT0, "ou-acme"))
	}
	svc := newTrailService((&fakeAuditStore{records: recs}).mock())
	svc.exportMaxRecords = 10000
	var out bytes.Buffer
	manifest, err := svc.Export(auditableCtx(t), "ou-acme", exportQuery(), &out)
	require.NoError(t, err)
	assert.False(t, manifest.Complete)
	require.NotNil(t, manifest.Reason)
	assert.Contains(t, *manifest.Reason, "share the instant")
	assert.Equal(t, int64(auditExportPageSize), manifest.ExportedCount)
}

// TestAuditTrail_ExportDetectsLateArrivals: a record landing in the window
// during the export makes the store's final count disagree.
func TestAuditTrail_ExportDetectsLateArrivals(t *testing.T) {
	store := &fakeAuditStore{records: []ocauditsvc.Record{trailRecord("e1", trailT0, "ou-acme")}}
	store.afterCalls = func(n int) {
		if n == 2 { // after the first data page
			store.records = append(store.records, trailRecord("e0", trailT0, "ou-acme"))
		}
	}
	var out bytes.Buffer
	manifest, err := newTrailService(store.mock()).Export(auditableCtx(t), "ou-acme", exportQuery(), &out)
	require.NoError(t, err)
	assert.False(t, manifest.Complete)
	assert.Equal(t, int64(2), manifest.StoreCount)
}

func TestAuditTrail_ExportRefusesTooManyRecords(t *testing.T) {
	var recs []ocauditsvc.Record
	for i := 0; i < 11; i++ {
		recs = append(recs, trailRecord(fmt.Sprintf("e%d", i), trailT0.Add(time.Duration(i)*time.Millisecond), "ou-acme"))
	}
	svc := newTrailService((&fakeAuditStore{records: recs}).mock())
	svc.exportMaxRecords = 10
	var out bytes.Buffer
	_, err := svc.Export(auditableCtx(t), "ou-acme", exportQuery(), &out)
	require.ErrorIs(t, err, utils.ErrAuditExportTooLarge)
	assert.Zero(t, out.Len(), "nothing written before the refusal")
}

// TestAuditTrail_ExportRefusesWithoutAnIntentRecord: an export that cannot be
// recorded must not start.
func TestAuditTrail_ExportRefusesWithoutAnIntentRecord(t *testing.T) {
	svc := newTrailService((&fakeAuditStore{records: []ocauditsvc.Record{trailRecord("e1", trailT0, "ou-acme")}}).mock())
	var out bytes.Buffer
	_, err := svc.Export(context.Background(), "ou-acme", exportQuery(), &out)
	require.ErrorIs(t, err, utils.ErrAuditExportNotRecorded)
	assert.Zero(t, out.Len())
}

// TestAuditTrail_ExportWindowSettles: the window may not reach into the period
// whose records are still being delivered.
func TestAuditTrail_ExportWindowSettles(t *testing.T) {
	store := &fakeAuditStore{}
	svc := newTrailService(store.mock())
	now := trailT0.Add(time.Hour)
	svc.now = func() time.Time { return now }
	q := AuditTrailQuery{StartTime: trailT0, EndTime: now.Add(time.Hour)}
	var out bytes.Buffer
	manifest, err := svc.Export(auditableCtx(t), "ou-acme", q, &out)
	require.NoError(t, err)
	assert.Equal(t, now.Add(-time.Minute), manifest.EndTime)
}
