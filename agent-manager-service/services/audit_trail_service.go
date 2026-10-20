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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/audit"
	"github.com/wso2/agent-manager/agent-manager-service/clients/ocauditsvc"
	"github.com/wso2/agent-manager/agent-manager-service/spec"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// Query bounds. They match the OpenChoreo Observer's own validation, so a
// request this service accepts is never one the Observer rejects.
const (
	auditMaxWindow       = 366 * 24 * time.Hour
	auditDefaultLimit    = 100
	auditMaxLimit        = 1000
	auditMaxFilterValues = 20
	auditMaxSearchLen    = 256
	// auditExportPageSize is the largest page the Observer serves.
	auditExportPageSize = auditMaxLimit
)

// AuditTrailQuery selects records of one organization's audit trail. Filters
// are ANDed; values within one filter are ORed.
type AuditTrailQuery struct {
	StartTime     time.Time
	EndTime       time.Time
	Limit         int
	SortOrder     string
	Actions       []string
	Results       []string
	Categories    []string
	ActorIDs      []string
	ActorTypes    []string
	ResourceTypes []string
	ResourceNames []string
	Projects      []string
	Environments  []string
	Agents        []string
	RequestIDs    []string
	EventIDs      []string
	Search        string
}

// AuditTrailService reads the audit trail of an organization.
//
// The audit store's reader (the OpenChoreo Observer) grants this service a
// cluster-wide read; it has no notion of an Agent Manager organization. Every
// method therefore confines what it asks for to the caller's organization and
// to this service's own records, on every request, whatever the query says.
type AuditTrailService interface {
	Query(ctx context.Context, ouID string, q AuditTrailQuery) (*spec.AuditLogListResponse, error)
	FilterValues(ctx context.Context, ouID, filter string, q AuditTrailQuery, valueSearch string, maxValues int) (*spec.AuditLogFilterValuesResponse, error)
	// Export streams every matching record to w as newline-delimited JSON,
	// oldest first, then a final {"manifest": ...} line, and returns the
	// manifest. Errors returned before anything was written mean nothing was
	// exported; after that, the absence of a manifest line marks a cut-off file.
	Export(ctx context.Context, ouID string, q AuditTrailQuery, w io.Writer) (*spec.AuditLogExportManifest, error)
}

type auditTrailService struct {
	client           ocauditsvc.Client
	exportMaxRecords int64
	exportSettle     time.Duration
	logger           *slog.Logger
	now              func() time.Time
}

// NewAuditTrailService returns the service. client is nil when reads of the
// trail are not configured; every method then reports utils.ErrAuditTrailNotConfigured.
func NewAuditTrailService(
	client ocauditsvc.Client, exportMaxRecords int64, exportSettle time.Duration, logger *slog.Logger,
) AuditTrailService {
	if logger == nil {
		logger = slog.Default()
	}
	return &auditTrailService{
		client:           client,
		exportMaxRecords: exportMaxRecords,
		exportSettle:     exportSettle,
		logger:           logger,
		now:              time.Now,
	}
}

func (s *auditTrailService) Query(ctx context.Context, ouID string, q AuditTrailQuery) (*spec.AuditLogListResponse, error) {
	if s.client == nil {
		return nil, utils.ErrAuditTrailNotConfigured
	}
	if err := validateAuditTrailQuery(q, true); err != nil {
		return nil, err
	}
	req, err := toObserverQuery(ouID, q)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.QueryAuditLogs(ctx, req)
	if err == nil {
		out := &spec.AuditLogListResponse{Records: s.toRecords(ouID, resp.Records), Total: resp.Total}
		out.TookMs = &resp.TookMs
		s.recordRead(ctx, ouID, "query", q, len(out.Records), resp.Total, nil)
		return out, nil
	}
	err = s.mapClientError(err)
	s.recordRead(ctx, ouID, "query", q, 0, 0, err)
	return nil, err
}

func (s *auditTrailService) FilterValues(
	ctx context.Context, ouID, filter string, q AuditTrailQuery, valueSearch string, maxValues int,
) (*spec.AuditLogFilterValuesResponse, error) {
	if s.client == nil {
		return nil, utils.ErrAuditTrailNotConfigured
	}
	field, ok := auditFilterFields[filter]
	if !ok {
		return nil, fmt.Errorf("%w: unknown filter %q", utils.ErrInvalidAuditQuery, filter)
	}
	if maxValues == 0 {
		maxValues = auditDefaultLimit
	}
	if maxValues < 1 || maxValues > auditMaxLimit {
		return nil, fmt.Errorf("%w: maxValues must be between 1 and %d", utils.ErrInvalidAuditQuery, auditMaxLimit)
	}
	if len(valueSearch) > auditMaxSearchLen {
		return nil, fmt.Errorf("%w: valueSearch is longer than %d characters", utils.ErrInvalidAuditQuery, auditMaxSearchLen)
	}
	if err := validateAuditTrailQuery(q, false); err != nil {
		return nil, err
	}
	req, err := toObserverQuery(ouID, q)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.QueryFilterValues(ctx, ocauditsvc.FilterValuesRequest{
		Query: req, Filter: field, ValueSearch: valueSearch, MaxValues: maxValues,
	})
	if err != nil {
		err = s.mapClientError(err)
		s.recordRead(ctx, ouID, "filter-values", q, 0, 0, err)
		return nil, err
	}
	values := make([]spec.AuditLogFilterValue, 0, len(resp.Values))
	for _, v := range resp.Values {
		values = append(values, spec.AuditLogFilterValue{Value: v.Value, Count: v.Count})
	}
	out := &spec.AuditLogFilterValuesResponse{Filter: filter, Values: values}
	out.TotalValues = &resp.TotalValues
	s.recordRead(ctx, ouID, "filter-values", q, len(values), resp.TotalValues, nil)
	return out, nil
}

// --- Export --------------------------------------------------------------------

// Export pages through the window oldest first. The Observer has no cursor: a
// page is a time window, and the next one starts at the last record's time.
// Records sharing that boundary instant are fetched again and skipped by id.
// When more than one page of records share a single instant, no window can
// reach past them, so the export stops and says so rather than skipping them.
// Completeness is then checked against the store's exact count.
func (s *auditTrailService) Export(
	ctx context.Context, ouID string, q AuditTrailQuery, w io.Writer,
) (*spec.AuditLogExportManifest, error) {
	if s.client == nil {
		return nil, utils.ErrAuditTrailNotConfigured
	}
	q.Limit = auditExportPageSize
	q.SortOrder = "asc"
	// Keep the window behind records still in the delivery pipeline.
	if latest := s.now().Add(-s.exportSettle); q.EndTime.After(latest) {
		q.EndTime = latest
	}
	if err := validateAuditTrailQuery(q, true); err != nil {
		return nil, err
	}

	total, err := s.count(ctx, ouID, q)
	if err != nil {
		return nil, err
	}
	if total > s.exportMaxRecords {
		return nil, fmt.Errorf("%w: %d records match, an export holds at most %d; narrow the window or filters",
			utils.ErrAuditExportTooLarge, total, s.exportMaxRecords)
	}

	// Recorded before any record leaves the platform; refused if it cannot be.
	attempt, err := audit.Begin(ctx, audit.ActionAuditLogExport, s.readOptions(ouID, "export", q)...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", utils.ErrAuditExportNotRecorded, err)
	}

	digest := sha256.New()
	out := io.MultiWriter(w, digest)
	exported, duplicates, reason, err := s.exportPages(ctx, ouID, q, out)
	manifest := &spec.AuditLogExportManifest{
		ExportedCount:     exported,
		DuplicatesSkipped: &duplicates,
		StartTime:         q.StartTime.UTC(),
		EndTime:           q.EndTime.UTC(),
	}
	if err != nil {
		attempt.Complete(ctx, err, audit.Detail("exportedCount", exported), audit.Detail("complete", false))
		return nil, err
	}

	storeCount, err := s.count(ctx, ouID, q)
	if err != nil {
		attempt.Complete(ctx, err, audit.Detail("exportedCount", exported), audit.Detail("complete", false))
		return nil, err
	}
	manifest.StoreCount = storeCount
	switch {
	case reason != "":
	case exported+duplicates != storeCount:
		reason = fmt.Sprintf("the store holds %d matching records but %d were delivered "+
			"(records may have arrived during the export); export again", storeCount, exported+duplicates)
	}
	manifest.Complete = reason == ""
	if reason != "" {
		manifest.Reason = &reason
	}
	generated := s.now().UTC()
	manifest.GeneratedAt = &generated
	manifest.Sha256 = hex.EncodeToString(digest.Sum(nil))

	if err := writeManifestLine(w, manifest); err != nil {
		attempt.Complete(ctx, err, audit.Detail("exportedCount", exported), audit.Detail("complete", false))
		return nil, err
	}
	attempt.Complete(ctx, nil,
		audit.Detail("exportedCount", exported),
		audit.Detail("complete", manifest.Complete),
		audit.Detail("sha256", manifest.Sha256),
	)
	return manifest, nil
}

// exportPages writes every record of the window and returns how many were
// written, how many stored duplicates were skipped, and a reason when some
// records could not be reached.
func (s *auditTrailService) exportPages(
	ctx context.Context, ouID string, q AuditTrailQuery, w io.Writer,
) (exported, duplicates int64, reason string, err error) {
	cursor := q.StartTime
	// Paging is by time: each page after the first starts at the instant (ms)
	// the previous one ended on, inclusive, and so returns that instant's
	// records again. Within one instant the store's order is not relied on, so
	// the copies already handled are recognised by counting: instantSeen is how
	// many copies of each id this export has accounted for at instantMs, and a
	// page's first occurrences of an id at that instant, up to that count, are
	// the ones handled before. Any further occurrence is either a record not yet
	// seen or a stored duplicate of one already exported (a gateway batch
	// delivered twice is stored twice under one id, always at one instant).
	instantMs := int64(-1)
	instantSeen := map[string]int{}
	exportedAtInstant := map[string]bool{}
	enc := json.NewEncoder(w)

	for {
		if err := ctx.Err(); err != nil {
			return exported, duplicates, "", err
		}
		page := q
		page.StartTime = cursor
		req, err := toObserverQuery(ouID, page)
		if err != nil {
			return exported, duplicates, "", err
		}
		resp, err := s.client.QueryAuditLogs(ctx, req)
		if err != nil {
			return exported, duplicates, "", s.mapClientError(err)
		}

		cursorMs := cursor.UnixMilli()
		pageLastMs := int64(-1)
		pageSeen := map[string]int{}
		for _, rec := range resp.Records {
			ms, ok := recordMillis(rec)
			if !ok {
				return exported, duplicates, "", fmt.Errorf("%w: record %s has an unreadable time %q",
					utils.ErrAuditTrailUnavailable, rec.EventID, rec.EventTime)
			}
			pageLastMs = ms
			if ms != instantMs {
				instantMs = ms
				instantSeen = map[string]int{}
				exportedAtInstant = map[string]bool{}
			}
			if ms == cursorMs {
				pageSeen[rec.EventID]++
				if pageSeen[rec.EventID] <= instantSeen[rec.EventID] {
					continue // handled by the previous page
				}
			}
			instantSeen[rec.EventID]++
			if exportedAtInstant[rec.EventID] {
				duplicates++
				continue
			}
			out, ok := s.toRecord(ouID, rec)
			if !ok {
				continue
			}
			if err := enc.Encode(out); err != nil {
				return exported, duplicates, "", err
			}
			exported++
			exportedAtInstant[rec.EventID] = true
		}

		if len(resp.Records) < q.Limit {
			return exported, duplicates, "", nil
		}
		if pageLastMs <= cursorMs {
			// A full page all at the cursor's instant: no later window reaches
			// the rest of that instant.
			return exported, duplicates, fmt.Sprintf(
				"more than %d records share the instant %s and cannot all be reached; narrow the filters and export again",
				q.Limit, time.UnixMilli(pageLastMs).UTC().Format(time.RFC3339Nano)), nil
		}
		if exported > s.exportMaxRecords {
			return exported, duplicates, fmt.Sprintf("the export stopped at the limit of %d records", s.exportMaxRecords), nil
		}
		cursor = time.UnixMilli(pageLastMs).UTC()
	}
}

// count returns the store's exact number of matching records.
func (s *auditTrailService) count(ctx context.Context, ouID string, q AuditTrailQuery) (int64, error) {
	q.Limit = 1
	req, err := toObserverQuery(ouID, q)
	if err != nil {
		return 0, err
	}
	resp, err := s.client.QueryAuditLogs(ctx, req)
	if err != nil {
		return 0, s.mapClientError(err)
	}
	return resp.Total, nil
}

func writeManifestLine(w io.Writer, m *spec.AuditLogExportManifest) error {
	return json.NewEncoder(w).Encode(map[string]any{"manifest": m})
}

// recordMillis is a record's time at the store's precision (milliseconds),
// which is the precision its window bounds and ordering use.
func recordMillis(rec ocauditsvc.Record) (int64, bool) {
	t, err := time.Parse(time.RFC3339Nano, rec.EventTime)
	if err != nil {
		return 0, false
	}
	return t.UnixMilli(), true
}

// --- Request building ----------------------------------------------------------

// auditFilterFields maps this API's filter names onto the Observer's.
var auditFilterFields = map[string]string{
	"action":       "action",
	"result":       "result",
	"category":     "category",
	"actorId":      "actor.id",
	"actorType":    "actor.type",
	"resourceType": "resource.type",
	"resourceName": "resource.name",
	"project":      "resource.project",
	"environment":  "resource.environment",
	"agent":        "resource.component",
}

var (
	auditResults    = map[string]bool{"success": true, "failure": true, "denied": true}
	auditCategories = map[string]bool{"management": true, "authorization": true, "access": true}
	auditActorTypes = map[string]bool{
		string(audit.ActorUser): true, string(audit.ActorService): true, string(audit.ActorAgent): true,
		string(audit.ActorGateway): true, string(audit.ActorSystem): true, string(audit.ActorAnonymous): true,
	}
)

// validateAuditTrailQuery applies the bounds the Observer enforces, so a bad
// query is rejected here with a clear message rather than relayed.
func validateAuditTrailQuery(q AuditTrailQuery, withPaging bool) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", utils.ErrInvalidAuditQuery, fmt.Sprintf(format, args...))
	}
	if q.StartTime.IsZero() || q.EndTime.IsZero() {
		return invalid("startTime and endTime are required")
	}
	if !q.EndTime.After(q.StartTime) {
		return invalid("endTime must be after startTime")
	}
	if q.EndTime.Sub(q.StartTime) > auditMaxWindow {
		return invalid("the window may span at most 366 days")
	}
	if withPaging {
		if q.Limit < 1 || q.Limit > auditMaxLimit {
			return invalid("limit must be between 1 and %d", auditMaxLimit)
		}
		if q.SortOrder != "asc" && q.SortOrder != "desc" {
			return invalid("sortOrder must be asc or desc")
		}
	}
	lists := []struct {
		name   string
		values []string
		max    int
		enum   map[string]bool
	}{
		{"action", q.Actions, auditMaxFilterValues, nil},
		{"result", q.Results, len(auditResults), auditResults},
		{"category", q.Categories, len(auditCategories), auditCategories},
		{"actorId", q.ActorIDs, auditMaxFilterValues, nil},
		{"actorType", q.ActorTypes, len(auditActorTypes), auditActorTypes},
		{"resourceType", q.ResourceTypes, auditMaxFilterValues, nil},
		{"resourceName", q.ResourceNames, auditMaxFilterValues, nil},
		{"project", q.Projects, auditMaxFilterValues, nil},
		{"environment", q.Environments, auditMaxFilterValues, nil},
		{"agent", q.Agents, auditMaxFilterValues, nil},
		{"requestId", q.RequestIDs, auditMaxFilterValues, nil},
		{"eventId", q.EventIDs, auditMaxFilterValues, nil},
	}
	for _, l := range lists {
		if len(l.values) > l.max {
			return invalid("%s accepts at most %d values", l.name, l.max)
		}
		for _, v := range l.values {
			if v == "" {
				return invalid("%s has an empty value", l.name)
			}
			if l.enum != nil && !l.enum[v] {
				return invalid("%s value %q is not one of the accepted values", l.name, v)
			}
		}
	}
	if len(q.Search) > auditMaxSearchLen {
		return invalid("search is longer than %d characters", auditMaxSearchLen)
	}
	return nil
}

// toObserverQuery builds the Observer request. The organization and producer
// filters are set here and only here, from the caller's identity — never from
// the query — so no combination of query parameters can widen a read beyond
// the caller's own organization's records.
func toObserverQuery(ouID string, q AuditTrailQuery) (ocauditsvc.QueryRequest, error) {
	if ouID == "" {
		return ocauditsvc.QueryRequest{}, fmt.Errorf("audit trail: no organization to confine the read to")
	}
	return ocauditsvc.QueryRequest{
		StartTime: q.StartTime.UTC().Format(time.RFC3339Nano),
		EndTime:   q.EndTime.UTC().Format(time.RFC3339Nano),
		Actor:     ocauditsvc.ActorFilter{IDs: q.ActorIDs, Types: q.ActorTypes},
		Resource: ocauditsvc.ResourceFilter{
			Namespaces:   []string{ouID},
			Types:        q.ResourceTypes,
			Names:        q.ResourceNames,
			Projects:     q.Projects,
			Environments: q.Environments,
			Components:   q.Agents,
		},
		Producers:    []string{audit.OpenChoreoProducer},
		Actions:      q.Actions,
		Results:      q.Results,
		Categories:   q.Categories,
		RequestIDs:   q.RequestIDs,
		EventIDs:     q.EventIDs,
		SearchPhrase: q.Search,
		Limit:        q.Limit,
		SortOrder:    q.SortOrder,
	}, nil
}

// mapClientError maps a store error onto the service's sentinels. A query the
// store rejects is the caller's 400, but the store's own message stays in the
// log: it describes the store's query, including the organization and producer
// filters this service adds, not the one the caller sent.
func (s *auditTrailService) mapClientError(err error) error {
	switch {
	case errors.Is(err, ocauditsvc.ErrNotSupported):
		return utils.ErrAuditTrailNotSupported
	case errors.Is(err, ocauditsvc.ErrInvalidRequest):
		s.logger.Warn("Audit store rejected a query", "error", err)
		return fmt.Errorf("%w: the audit store rejected the query", utils.ErrInvalidAuditQuery)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: %w", utils.ErrAuditTrailUnavailable, err)
	}
}

// --- Read auditing ---------------------------------------------------------------

func (s *auditTrailService) readOptions(ouID, operation string, q AuditTrailQuery) []audit.Option {
	return []audit.Option{
		audit.Org(ouID),
		audit.Resource(audit.ResourceAuditLog, ouID),
		audit.Detail("operation", operation),
		audit.Detail("startTime", q.StartTime.UTC().Format(time.RFC3339Nano)),
		audit.Detail("endTime", q.EndTime.UTC().Format(time.RFC3339Nano)),
		audit.Detail("filters", describeAuditFilters(q)),
	}
}

// recordRead writes the reader's own record. The store logs the read too, but
// under this service's identity; this is the record that names the person.
func (s *auditTrailService) recordRead(
	ctx context.Context, ouID, operation string, q AuditTrailQuery, returned int, total int64, err error,
) {
	opts := append(s.readOptions(ouID, operation, q),
		audit.Detail("returnedCount", returned),
		audit.Detail("totalCount", total),
		audit.Result(err),
	)
	audit.Record(ctx, audit.ActionAuditLogRead, opts...)
}

// describeAuditFilters lists the filters a read used as "name=value" pairs, in
// a stable order, so the record says what was looked at.
func describeAuditFilters(q AuditTrailQuery) []string {
	var out []string
	add := func(name string, values []string) {
		for _, v := range values {
			out = append(out, name+"="+v)
		}
	}
	add("action", q.Actions)
	add("result", q.Results)
	add("category", q.Categories)
	add("actorId", q.ActorIDs)
	add("actorType", q.ActorTypes)
	add("resourceType", q.ResourceTypes)
	add("resourceName", q.ResourceNames)
	add("project", q.Projects)
	add("environment", q.Environments)
	add("agent", q.Agents)
	add("requestId", q.RequestIDs)
	add("eventId", q.EventIDs)
	if q.Search != "" {
		out = append(out, "search="+q.Search)
	}
	sort.Strings(out)
	return out
}

// --- Record mapping ----------------------------------------------------------------

func (s *auditTrailService) toRecords(ouID string, recs []ocauditsvc.Record) []spec.AuditLogRecord {
	out := make([]spec.AuditLogRecord, 0, len(recs))
	for _, rec := range recs {
		if r, ok := s.toRecord(ouID, rec); ok {
			out = append(out, r)
		}
	}
	return out
}

// toRecord maps a stored record back to this API's shape, reading Agent
// Manager's own fields from metadata.amp. A record that is not this
// organization's, or not this service's, is dropped: the query already
// excludes those, so one arriving here is a fault worth logging, never data to
// show.
func (s *auditTrailService) toRecord(ouID string, rec ocauditsvc.Record) (spec.AuditLogRecord, bool) {
	if rec.Producer != audit.OpenChoreoProducer || rec.Resource == nil || rec.Resource.Namespace != ouID {
		s.logger.Error("audit trail returned a record outside the requested organization; dropped",
			"eventId", rec.EventID, "producer", rec.Producer)
		return spec.AuditLogRecord{}, false
	}
	occurred, err := time.Parse(time.RFC3339Nano, rec.EventTime)
	if err != nil {
		s.logger.Error("audit record has an unreadable time; dropped", "eventId", rec.EventID, "eventTime", rec.EventTime)
		return spec.AuditLogRecord{}, false
	}
	amp, _ := rec.Metadata["amp"].(map[string]any)
	str := func(key string) string {
		v, _ := amp[key].(string)
		return v
	}
	num := func(key string) (float64, bool) {
		v, ok := amp[key].(float64)
		return v, ok
	}

	result := rec.Result
	if outcome := str("outcome"); outcome == string(audit.OutcomeUnknown) {
		result = string(audit.OutcomeUnknown)
	}
	out := spec.AuditLogRecord{
		EventId:    rec.EventID,
		OccurredAt: occurred.UTC(),
		Action:     rec.Action,
		Result:     result,
		Actor:      spec.AuditLogActor{Type: rec.Actor.Type, Id: rec.Actor.ID},
		Producer:   rec.Producer,
	}
	out.Category = stringPtrIfNotEmpty(rec.Category)
	out.ActionClass = stringPtrIfNotEmpty(str("actionClass"))
	out.Actor.Display = stringPtrIfNotEmpty(str("actorDisplay"))
	out.AuthMethod = stringPtrIfNotEmpty(str("authMethod"))
	out.Surface = stringPtrIfNotEmpty(str("surface"))
	out.SourceIp = stringPtrIfNotEmpty(rec.SourceIP)
	out.UserAgent = stringPtrIfNotEmpty(rec.UserAgent)
	out.RequestId = stringPtrIfNotEmpty(rec.RequestID)
	out.ErrorCode = stringPtrIfNotEmpty(str("errorCode"))
	out.ErrorMessage = stringPtrIfNotEmpty(str("errorMessage"))
	out.RequiredPermission = stringPtrIfNotEmpty(str("requiredPermission"))
	if v, ok := num("severity"); ok {
		sev := int32(v)
		out.Severity = &sev
	}
	if v, ok := num("statusCode"); ok {
		code := int32(v)
		out.StatusCode = &code
	}
	if v, ok := num("durationMs"); ok {
		d := int64(v)
		out.DurationMs = &d
	}
	if rec.HTTP != nil && (rec.HTTP.Method != "" || rec.HTTP.Path != "") {
		out.Request = &spec.AuditLogRequest{
			Method: stringPtrIfNotEmpty(rec.HTTP.Method),
			Path:   stringPtrIfNotEmpty(rec.HTTP.Path),
		}
	}
	out.Resource = &spec.AuditLogResource{
		Type:        stringPtrIfNotEmpty(rec.Resource.Type),
		Id:          stringPtrIfNotEmpty(rec.Resource.UID),
		Name:        stringPtrIfNotEmpty(rec.Resource.Name),
		Project:     stringPtrIfNotEmpty(rec.Resource.Project),
		Environment: stringPtrIfNotEmpty(rec.Resource.Environment),
		Agent:       stringPtrIfNotEmpty(rec.Resource.Component),
	}
	if details, ok := amp["details"].(map[string]any); ok && len(details) > 0 {
		out.Details = details
	}
	return out, true
}
