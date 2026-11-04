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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/clients/auditstoresvc"
	"github.com/wso2/agent-manager/agent-manager-service/config"
	"github.com/wso2/agent-manager/agent-manager-service/spec"
)

// ErrAuditQueryDisabled is returned when the deployment has not enabled the
// audit query API (AUDIT_QUERY_ENABLED).
var ErrAuditQueryDisabled = errors.New("audit query is not enabled")

// ErrAuditStoreUnavailable is returned when the log store cannot be queried or
// answers with something unusable. Callers report it without detail.
var ErrAuditStoreUnavailable = errors.New("audit store unavailable")

// AuditQueryService reads the org's audit trail.
type AuditQueryService interface {
	ListEvents(ctx context.Context, q AuditQuery) (*spec.AuditEventListResponse, error)
}

type auditQueryService struct {
	enabled           bool
	namespaceFallback bool
	store             auditstoresvc.AuditStoreClient
	resolver          AuditAgentResolver
	now               func() time.Time
	logger            *slog.Logger
}

// NewAuditQueryService creates the service. store is nil when the API is
// disabled.
func NewAuditQueryService(
	cfg config.Config, store auditstoresvc.AuditStoreClient, resolver AuditAgentResolver, logger *slog.Logger,
) AuditQueryService {
	return &auditQueryService{
		enabled:           cfg.AuditQuery.Enabled && store != nil,
		namespaceFallback: cfg.AuditQuery.GatewayNamespaceFallback,
		store:             store,
		resolver:          resolver,
		now:               time.Now,
		logger:            logger,
	}
}

// osSearchResponse is the part of an OpenSearch _search response this
// service reads.
type osSearchResponse struct {
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Failed int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int64  `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Hits []struct {
			ID     string            `json:"_id"`
			Source json.RawMessage   `json:"_source"`
			Sort   []json.RawMessage `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
	Aggregations struct {
		Categories struct {
			Buckets map[string]struct {
				DocCount int64 `json:"doc_count"`
			} `json:"buckets"`
		} `json:"categories"`
	} `json:"aggregations"`
}

func (s *auditQueryService) ListEvents(ctx context.Context, q AuditQuery) (*spec.AuditEventListResponse, error) {
	if !s.enabled {
		return nil, ErrAuditQueryDisabled
	}
	if err := q.Normalize(s.now()); err != nil {
		return nil, err
	}

	idx, err := s.resolver.Index(ctx, q.OUID)
	if err != nil {
		return nil, fmt.Errorf("build audit agent index: %w", err)
	}

	body, err := buildAuditSearchBody(&q, idx, s.namespaceFallback)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode audit search: %w", err)
	}

	raw, err := s.store.Search(ctx, payload)
	if err != nil {
		s.logger.Error("audit store search failed", "ouID", q.OUID, "error", err)
		return nil, fmt.Errorf("%w: %w", ErrAuditStoreUnavailable, err)
	}

	var resp osSearchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		s.logger.Error("audit store returned an unreadable response", "ouID", q.OUID, "error", err)
		return nil, fmt.Errorf("%w: decode search response: %w", ErrAuditStoreUnavailable, err)
	}
	// A timed-out or partially failed search would silently omit records; an
	// audit trail that may be missing entries must not pass as complete.
	if resp.TimedOut || resp.Shards.Failed > 0 {
		s.logger.Error("audit store search incomplete", "ouID", q.OUID, "timedOut", resp.TimedOut, "failedShards", resp.Shards.Failed)
		return nil, fmt.Errorf("%w: incomplete search result", ErrAuditStoreUnavailable)
	}

	hits := resp.Hits.Hits
	hasMore := len(hits) > q.Limit
	if hasMore {
		hits = hits[:q.Limit]
	}

	events := make([]spec.AuditEvent, 0, len(hits))
	for _, h := range hits {
		doc := map[string]any{}
		dec := json.NewDecoder(bytes.NewReader(h.Source))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			// One unreadable document must not hide the rest of the page.
			s.logger.Warn("skipping unreadable audit document", "ouID", q.OUID, "id", h.ID, "error", err)
			doc = map[string]any{}
		}
		events = append(events, normalizeAuditDocument(h.ID, doc, idx))
	}

	nextCursor := *spec.NewNullableString(nil)
	if hasMore && len(hits) > 0 {
		cur, err := encodeAuditCursor(hits[len(hits)-1].Sort, q.Ascending)
		if err != nil {
			return nil, err
		}
		nextCursor = *spec.NewNullableString(&cur)
	}

	relation := "eq"
	if resp.Hits.Total.Relation == "gte" {
		relation = "gte"
	}
	buckets := resp.Aggregations.Categories.Buckets
	counts := spec.NewAuditCategoryCounts(
		buckets[AuditCategoryOperational].DocCount,
		buckets[AuditCategoryLLM].DocCount,
		buckets[AuditCategoryMCP].DocCount,
		buckets[AuditCategoryA2A].DocCount,
		buckets[AuditCategoryOther].DocCount,
	)
	return spec.NewAuditEventListResponse(events, nextCursor, resp.Hits.Total.Value, relation, *counts), nil
}
