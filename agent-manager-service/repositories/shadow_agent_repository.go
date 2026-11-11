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

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// ShadowCorrelationSource is the signal source of signals derived across
// connections (not from one provider call).
const ShadowCorrelationSource = "correlation"

// ShadowScoreFunc returns the score and verdict of a finding of kind with
// the given signal codes.
type ShadowScoreFunc func(kind string, codes []string) (int, string)

// ShadowFindingInput is one finding of a connection's scan, as persisted.
type ShadowFindingInput struct {
	Finding models.ShadowFinding
	Signals []models.ShadowFindingSignal
	Usage   []models.ShadowUsageDaily
	// KeyIDs are provider keys the workload uses.
	KeyIDs []string
	// Related links other findings of the same connection.
	Related []ShadowRelationInput
}

// ShadowRelationInput links to another finding of the same connection by
// its provider identity.
type ShadowRelationInput struct {
	Kind       string
	ExternalID string
	Relation   string
	Reason     string
}

// ShadowConnectionApply is what one connection's scan found.
type ShadowConnectionApply struct {
	OUID          string
	ConnectionID  uuid.UUID
	ScanID        uuid.UUID
	ScanStartedAt time.Time
	// WindowStart: evidence detected before it has aged out of the lookback
	// window and is pruned.
	WindowStart time.Time
	Findings    []ShadowFindingInput
	Keys        []models.ShadowAPIKey
	// KeysListed marks stored keys the listing no longer returned as gone;
	// otherwise KeyScopesListed limits that to the scopes listed completely.
	KeysListed      bool
	KeyScopesListed []string
}

// ShadowFindingFilter selects findings.
type ShadowFindingFilter struct {
	Provider     string
	Verdict      string
	Status       string
	Kind         string
	ConnectionID *uuid.UUID
	// ScanID keeps the findings that scan saw.
	ScanID *uuid.UUID
	Search string
	Limit  int
	Offset int
}

// ShadowFindingRow is a finding with its connection's name and the requests
// in its stored usage.
type ShadowFindingRow struct {
	models.ShadowFinding
	ConnectionName string `gorm:"column:connection_name"`
	Requests       int64  `gorm:"column:requests"`
}

// ShadowSummary counts an org's findings.
type ShadowSummary struct {
	Total       int
	ByVerdict   map[string]int
	ByProvider  map[string]int
	ByStatus    map[string]int
	Connections int
}

// ShadowAgentRepository persists Shadow Agent Discovery connections, scans
// and findings. Every method is scoped to an org (ou_id) except the scan
// worker's claim, which works across orgs by design.
//
//go:generate moq -rm -fmt goimports -skip-ensure -pkg repomocks -out repomocks/shadow_agent_repository_mock.go . ShadowAgentRepository:ShadowAgentRepositoryMock
type ShadowAgentRepository interface {
	ListConnections(ctx context.Context, ouID string) ([]models.ShadowConnection, error)
	GetConnection(ctx context.Context, ouID string, id uuid.UUID) (*models.ShadowConnection, error)
	// CreateConnection fails with utils.ErrShadowConnectionNameTaken on a
	// duplicate name.
	CreateConnection(ctx context.Context, c *models.ShadowConnection) error
	UpdateConnection(ctx context.Context, c *models.ShadowConnection) error
	DeleteConnection(ctx context.Context, ouID string, id uuid.UUID) (bool, error)
	SaveConnectionTest(ctx context.Context, ouID string, id uuid.UUID, at time.Time, result models.ShadowConnectionTestInfo) error

	// CreateScan fails with utils.ErrShadowScanInProgress while another scan
	// of the org is queued or running.
	CreateScan(ctx context.Context, s *models.ShadowScan) error
	ListScans(ctx context.Context, ouID string, limit int) ([]models.ShadowScan, error)
	GetScan(ctx context.Context, ouID string, id uuid.UUID) (*models.ShadowScan, error)
	// LatestScan returns gorm.ErrRecordNotFound when the org has none.
	LatestScan(ctx context.Context, ouID string) (*models.ShadowScan, error)
	// ClaimDueScans leases queued scans, and running scans whose lease ran
	// out (their worker died), across orgs.
	ClaimDueScans(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]models.ShadowScan, error)
	RenewScanLease(ctx context.Context, id uuid.UUID, until time.Time) error
	FinishScan(ctx context.Context, s *models.ShadowScan) error

	// ApplyConnectionResult writes one connection's scan in one transaction
	// and returns how many findings it wrote.
	ApplyConnectionResult(ctx context.Context, in ShadowConnectionApply, score ShadowScoreFunc) (int, error)
	// ListOrgFindings returns every finding of the org (for correlation).
	ListOrgFindings(ctx context.Context, ouID string) ([]models.ShadowFinding, error)
	// ApplyCorrelation replaces the org's cross-connection relations and
	// signals and rescores the findings they touch.
	ApplyCorrelation(ctx context.Context, ouID string, relations map[uuid.UUID][]models.ShadowFindingRelation,
		signals map[uuid.UUID][]models.ShadowFindingSignal, score ShadowScoreFunc) error

	ListFindings(ctx context.Context, ouID string, f ShadowFindingFilter) ([]ShadowFindingRow, int, error)
	GetFinding(ctx context.Context, ouID string, id uuid.UUID) (*ShadowFindingRow, error)
	ListSignals(ctx context.Context, ouID string, findingID uuid.UUID) ([]models.ShadowFindingSignal, error)
	ListFindingKeys(ctx context.Context, ouID string, findingID uuid.UUID) ([]models.ShadowAPIKey, error)
	ListUsage(ctx context.Context, ouID string, findingID uuid.UUID) ([]models.ShadowUsageDaily, error)
	UpdateFindingStatus(ctx context.Context, ouID string, id uuid.UUID, status string) error
	// OnboardFinding links the finding to an agent; utils.ErrShadowAlreadyOnboarded
	// when it already is.
	OnboardFinding(ctx context.Context, ouID string, id uuid.UUID, project, agent, by string, at time.Time) error
	// SetRetirement updates the retirement state (and the review status
	// "retired" once verified).
	SetRetirement(ctx context.Context, ouID string, id uuid.UUID, state string, markedBy string, markedAt, verifiedAt *time.Time) error
	ListOnboardedFindings(ctx context.Context, ouID string) ([]models.ShadowFinding, error)
	Summary(ctx context.Context, ouID string) (ShadowSummary, error)
}

type shadowAgentRepository struct {
	db *gorm.DB
}

// NewShadowAgentRepository creates a ShadowAgentRepository.
func NewShadowAgentRepository(db *gorm.DB) ShadowAgentRepository {
	return &shadowAgentRepository{db: db}
}

// ---- connections ----

func (r *shadowAgentRepository) ListConnections(ctx context.Context, ouID string) ([]models.ShadowConnection, error) {
	var out []models.ShadowConnection
	err := r.db.WithContext(ctx).Where("ou_id = ?", ouID).Order("lower(name)").Find(&out).Error
	return out, err
}

func (r *shadowAgentRepository) GetConnection(ctx context.Context, ouID string, id uuid.UUID) (*models.ShadowConnection, error) {
	var c models.ShadowConnection
	if err := r.db.WithContext(ctx).Where("ou_id = ? AND id = ?", ouID, id).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *shadowAgentRepository) CreateConnection(ctx context.Context, c *models.ShadowConnection) error {
	now := time.Now().UTC().Truncate(time.Microsecond)
	c.CreatedAt, c.UpdatedAt = now, now
	err := r.db.WithContext(ctx).Create(c).Error
	if pgErrorCode(err) == pgUniqueViolation {
		return utils.ErrShadowConnectionNameTaken
	}
	return err
}

func (r *shadowAgentRepository) UpdateConnection(ctx context.Context, c *models.ShadowConnection) error {
	c.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	cfg, err := toJSON(c.Config)
	if err != nil {
		return err
	}
	hints, err := toJSON(c.SecretHints)
	if err != nil {
		return err
	}
	res := r.db.WithContext(ctx).Model(&models.ShadowConnection{}).
		Where("ou_id = ? AND id = ?", c.OUID, c.ID).
		Updates(map[string]any{
			"name":             c.Name,
			"config":           gorm.Expr("?::jsonb", cfg),
			"secret_encrypted": c.SecretEncrypted,
			"secret_hints":     gorm.Expr("?::jsonb", hints),
			"updated_at":       c.UpdatedAt,
		})
	if pgErrorCode(res.Error) == pgUniqueViolation {
		return utils.ErrShadowConnectionNameTaken
	}
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *shadowAgentRepository) DeleteConnection(ctx context.Context, ouID string, id uuid.UUID) (bool, error) {
	res := r.db.WithContext(ctx).Where("ou_id = ? AND id = ?", ouID, id).Delete(&models.ShadowConnection{})
	return res.RowsAffected > 0, res.Error
}

func (r *shadowAgentRepository) SaveConnectionTest(
	ctx context.Context, ouID string, id uuid.UUID, at time.Time, result models.ShadowConnectionTestInfo,
) error {
	res, err := toJSON(result)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Model(&models.ShadowConnection{}).
		Where("ou_id = ? AND id = ?", ouID, id).
		Updates(map[string]any{"last_tested_at": at, "last_test_result": gorm.Expr("?::jsonb", res)}).Error
}

// ---- scans ----

func (r *shadowAgentRepository) CreateScan(ctx context.Context, s *models.ShadowScan) error {
	now := time.Now().UTC().Truncate(time.Microsecond)
	s.CreatedAt, s.UpdatedAt = now, now
	if s.Results == nil {
		s.Results = []models.ShadowScanConnectionResult{}
	}
	err := r.db.WithContext(ctx).Create(s).Error
	if pgErrorCode(err) == pgUniqueViolation {
		return utils.ErrShadowScanInProgress
	}
	return err
}

func (r *shadowAgentRepository) ListScans(ctx context.Context, ouID string, limit int) ([]models.ShadowScan, error) {
	var out []models.ShadowScan
	err := r.db.WithContext(ctx).Where("ou_id = ?", ouID).Order("created_at DESC").Limit(limit).Find(&out).Error
	return out, err
}

func (r *shadowAgentRepository) GetScan(ctx context.Context, ouID string, id uuid.UUID) (*models.ShadowScan, error) {
	var s models.ShadowScan
	if err := r.db.WithContext(ctx).Where("ou_id = ? AND id = ?", ouID, id).First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *shadowAgentRepository) LatestScan(ctx context.Context, ouID string) (*models.ShadowScan, error) {
	var s models.ShadowScan
	if err := r.db.WithContext(ctx).Where("ou_id = ?", ouID).Order("created_at DESC").First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *shadowAgentRepository) ClaimDueScans(
	ctx context.Context, now time.Time, lease time.Duration, limit int,
) ([]models.ShadowScan, error) {
	var out []models.ShadowScan
	err := r.db.WithContext(ctx).Raw(`
		UPDATE shadow_scans s
		SET status = 'running', claimed_until = ?, started_at = COALESCE(s.started_at, ?),
			attempts = s.attempts + 1, updated_at = ?
		WHERE s.id IN (
			SELECT id FROM shadow_scans
			WHERE status = 'queued' OR (status = 'running' AND claimed_until < ?)
			ORDER BY created_at ASC
			LIMIT ?
			FOR UPDATE SKIP LOCKED
		)
		RETURNING s.*`,
		now.Add(lease), now, now, now, limit,
	).Scan(&out).Error
	return out, err
}

func (r *shadowAgentRepository) RenewScanLease(ctx context.Context, id uuid.UUID, until time.Time) error {
	return r.db.WithContext(ctx).Model(&models.ShadowScan{}).
		Where("id = ? AND status = 'running'", id).Update("claimed_until", until).Error
}

func (r *shadowAgentRepository) FinishScan(ctx context.Context, s *models.ShadowScan) error {
	now := time.Now().UTC().Truncate(time.Microsecond)
	results, err := toJSON(s.Results)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Model(&models.ShadowScan{}).
		Where("ou_id = ? AND id = ?", s.OUID, s.ID).
		Updates(map[string]any{
			"status":         s.Status,
			"results":        gorm.Expr("?::jsonb", results),
			"findings_count": s.FindingsCount,
			"finished_at":    s.FinishedAt,
			"claimed_until":  nil,
			"updated_at":     now,
		}).Error
}

// ---- scan results ----

func (r *shadowAgentRepository) ApplyConnectionResult(
	ctx context.Context, in ShadowConnectionApply, score ShadowScoreFunc,
) (int, error) {
	written := 0
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		ids := make(map[string]uuid.UUID, len(in.Findings))
		keyFinding := map[string]uuid.UUID{}
		for i := range in.Findings {
			fi := &in.Findings[i]
			id, err := upsertShadowFinding(tx, in, &fi.Finding)
			if err != nil {
				return err
			}
			if err := tx.Exec(`INSERT INTO shadow_scan_findings (ou_id, scan_id, finding_id) VALUES (?, ?, ?)
				ON CONFLICT DO NOTHING`, in.OUID, in.ScanID, id).Error; err != nil {
				return fmt.Errorf("recording the scan's finding: %w", err)
			}
			ids[fi.Finding.Kind+"\x00"+fi.Finding.ExternalID] = id
			if fi.Finding.Kind == models.ShadowKindAPIKey {
				keyFinding[fi.Finding.ExternalID] = id
			}
			for _, k := range fi.KeyIDs {
				if _, taken := keyFinding[k]; !taken {
					keyFinding[k] = id
				}
			}
			for j := range fi.Signals {
				if err := upsertShadowSignal(tx, in.OUID, id, in.ScanID, &fi.Signals[j]); err != nil {
					return err
				}
			}
			for j := range fi.Usage {
				if err := upsertShadowUsage(tx, in.OUID, id, &fi.Usage[j]); err != nil {
					return err
				}
			}
			written++
		}
		// A key-kind finding owns its key even if another finding listed it first.
		for i := range in.Findings {
			if in.Findings[i].Finding.Kind == models.ShadowKindAPIKey {
				keyFinding[in.Findings[i].Finding.ExternalID] = ids[models.ShadowKindAPIKey+"\x00"+in.Findings[i].Finding.ExternalID]
			}
		}
		for i := range in.Keys {
			var fid *uuid.UUID
			if id, ok := keyFinding[in.Keys[i].KeyID]; ok {
				fid = &id
			}
			if err := upsertShadowKey(tx, in, fid, &in.Keys[i]); err != nil {
				return err
			}
		}
		switch {
		case in.KeysListed:
			if err := tx.Exec(`UPDATE shadow_api_keys SET present = FALSE, updated_at = NOW()
				WHERE ou_id = ? AND connection_id = ? AND present AND last_seen_at < ?`,
				in.OUID, in.ConnectionID, in.ScanStartedAt).Error; err != nil {
				return fmt.Errorf("marking removed keys: %w", err)
			}
		case len(in.KeyScopesListed) > 0:
			if err := tx.Exec(`UPDATE shadow_api_keys SET present = FALSE, updated_at = NOW()
				WHERE ou_id = ? AND connection_id = ? AND present AND last_seen_at < ? AND scope IN ?`,
				in.OUID, in.ConnectionID, in.ScanStartedAt, in.KeyScopesListed).Error; err != nil {
				return fmt.Errorf("marking removed keys: %w", err)
			}
		}
		// Evidence older than the lookback window has aged out.
		if err := tx.Exec(`DELETE FROM shadow_finding_signals s USING shadow_findings f
			WHERE s.finding_id = f.id AND f.ou_id = ? AND f.connection_id = ? AND s.source <> ? AND s.detected_at < ?`,
			in.OUID, in.ConnectionID, ShadowCorrelationSource, in.WindowStart).Error; err != nil {
			return fmt.Errorf("pruning aged signals: %w", err)
		}
		// Relations between findings of this connection.
		for i := range in.Findings {
			fi := &in.Findings[i]
			id := ids[fi.Finding.Kind+"\x00"+fi.Finding.ExternalID]
			own := make([]models.ShadowFindingRelation, 0, len(fi.Related))
			for _, rel := range fi.Related {
				if target, ok := ids[rel.Kind+"\x00"+rel.ExternalID]; ok && target != id {
					own = append(own, models.ShadowFindingRelation{FindingID: target.String(), Relation: rel.Relation, Reason: rel.Reason})
				}
			}
			if err := mergeShadowRelations(tx, id, own, false); err != nil {
				return err
			}
		}
		return rescoreShadowFindings(tx, in.OUID, &in.ConnectionID, nil, score)
	})
	return written, err
}

func upsertShadowFinding(tx *gorm.DB, in ShadowConnectionApply, f *models.ShadowFinding) (uuid.UUID, error) {
	var row struct {
		ID uuid.UUID `gorm:"column:id"`
	}
	now := in.ScanStartedAt
	owner, err := ownerHintJSON(f.OwnerHint)
	if err != nil {
		return uuid.Nil, err
	}
	attrs, err := toJSON(nonNilMap(f.Attributes))
	if err != nil {
		return uuid.Nil, err
	}
	err = tx.Raw(`
		INSERT INTO shadow_findings (ou_id, connection_id, provider, kind, external_id, display_name, scope, state,
			owner_hint, attributes, provider_created_at, first_used_at, last_used_at, first_seen_at, last_seen_at,
			last_scan_id, status, verdict, related)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?, ?, 'new', 'llm_consumer', '[]'::jsonb)
		ON CONFLICT (ou_id, connection_id, kind, external_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			scope = EXCLUDED.scope,
			state = EXCLUDED.state,
			owner_hint = CASE WHEN EXCLUDED.owner_hint = '{}'::jsonb THEN shadow_findings.owner_hint ELSE EXCLUDED.owner_hint END,
			attributes = EXCLUDED.attributes,
			provider_created_at = COALESCE(EXCLUDED.provider_created_at, shadow_findings.provider_created_at),
			first_used_at = LEAST(shadow_findings.first_used_at, EXCLUDED.first_used_at),
			last_used_at = GREATEST(shadow_findings.last_used_at, EXCLUDED.last_used_at),
			last_seen_at = EXCLUDED.last_seen_at,
			last_scan_id = EXCLUDED.last_scan_id,
			updated_at = NOW()
		RETURNING id`,
		in.OUID, in.ConnectionID, f.Provider, f.Kind, f.ExternalID, f.DisplayName, f.Scope, f.State,
		owner, attrs, f.ProviderCreatedAt, f.FirstUsedAt, f.LastUsedAt,
		now, now, in.ScanID,
	).Scan(&row).Error
	if err != nil {
		return uuid.Nil, fmt.Errorf("writing finding: %w", err)
	}
	return row.ID, nil
}

func upsertShadowSignal(tx *gorm.DB, ouID string, findingID, scanID uuid.UUID, s *models.ShadowFindingSignal) error {
	observed, err := toJSON(nonNilMap(s.Observed))
	if err != nil {
		return err
	}
	var scan *uuid.UUID
	if scanID != uuid.Nil {
		scan = &scanID
	}
	err = tx.Exec(`
		INSERT INTO shadow_finding_signals (ou_id, finding_id, code, tier, weight, source, condition, observed, scan_id, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)
		ON CONFLICT (finding_id, code, source) DO UPDATE SET
			tier = EXCLUDED.tier, weight = EXCLUDED.weight, condition = EXCLUDED.condition,
			observed = EXCLUDED.observed, scan_id = EXCLUDED.scan_id, detected_at = EXCLUDED.detected_at`,
		ouID, findingID, s.Code, s.Tier, s.Weight, s.Source, s.Condition, observed, scan, s.DetectedAt,
	).Error
	if err != nil {
		return fmt.Errorf("writing signal: %w", err)
	}
	return nil
}

func upsertShadowUsage(tx *gorm.DB, ouID string, findingID uuid.UUID, u *models.ShadowUsageDaily) error {
	err := tx.Exec(`
		INSERT INTO shadow_usage_daily (ou_id, finding_id, key_id, model, day, requests, input_tokens, output_tokens, cost_amount, currency, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
		ON CONFLICT (finding_id, key_id, model, day) DO UPDATE SET
			requests = EXCLUDED.requests, input_tokens = EXCLUDED.input_tokens, output_tokens = EXCLUDED.output_tokens,
			cost_amount = EXCLUDED.cost_amount, currency = EXCLUDED.currency, updated_at = NOW()`,
		ouID, findingID, u.KeyID, u.Model, u.Day.Format(time.DateOnly), u.Requests, u.InputTokens, u.OutputTokens, u.CostAmount, u.Currency,
	).Error
	if err != nil {
		return fmt.Errorf("writing usage: %w", err)
	}
	return nil
}

func upsertShadowKey(tx *gorm.DB, in ShadowConnectionApply, findingID *uuid.UUID, k *models.ShadowAPIKey) error {
	owner, err := ownerHintJSON(k.OwnerHint)
	if err != nil {
		return err
	}
	err = tx.Exec(`
		INSERT INTO shadow_api_keys (ou_id, connection_id, finding_id, key_id, name, redacted_hint, status, scope,
			owner_hint, provider_created_at, last_used_at, last_seen_at, present)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, TRUE)
		ON CONFLICT (ou_id, connection_id, key_id) DO UPDATE SET
			finding_id = COALESCE(EXCLUDED.finding_id, shadow_api_keys.finding_id),
			name = EXCLUDED.name, redacted_hint = EXCLUDED.redacted_hint, status = EXCLUDED.status, scope = EXCLUDED.scope,
			owner_hint = CASE WHEN EXCLUDED.owner_hint = '{}'::jsonb THEN shadow_api_keys.owner_hint ELSE EXCLUDED.owner_hint END,
			provider_created_at = COALESCE(EXCLUDED.provider_created_at, shadow_api_keys.provider_created_at),
			last_used_at = GREATEST(shadow_api_keys.last_used_at, EXCLUDED.last_used_at),
			last_seen_at = EXCLUDED.last_seen_at, present = TRUE, updated_at = NOW()`,
		in.OUID, in.ConnectionID, findingID, k.KeyID, k.Name, k.RedactedHint, k.Status, k.Scope,
		owner, k.ProviderCreatedAt, k.LastUsedAt, in.ScanStartedAt,
	).Error
	if err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	return nil
}

// mergeShadowRelations replaces either the connector's own relations
// (correlation=false) or the correlation's (true) on a finding, keeping the
// other kind.
func mergeShadowRelations(tx *gorm.DB, id uuid.UUID, replacement []models.ShadowFindingRelation, correlation bool) error {
	var current models.ShadowFinding
	if err := tx.Select("id", "related").Where("id = ?", id).First(&current).Error; err != nil {
		return fmt.Errorf("reading relations: %w", err)
	}
	merged := make([]models.ShadowFindingRelation, 0, len(current.Related)+len(replacement))
	for _, rel := range current.Related {
		if (rel.Source == ShadowCorrelationSource) != correlation {
			merged = append(merged, rel)
		}
	}
	for _, rel := range replacement {
		if correlation {
			rel.Source = ShadowCorrelationSource
		} else {
			rel.Source = ""
		}
		merged = append(merged, rel)
	}
	encoded, err := toJSON(merged)
	if err != nil {
		return err
	}
	if err := tx.Exec(`UPDATE shadow_findings SET related = ?::jsonb WHERE id = ?`, encoded, id).Error; err != nil {
		return fmt.Errorf("writing relations: %w", err)
	}
	return nil
}

// rescoreShadowFindings recomputes score and verdict from the stored
// signals, for a connection's findings or for the given findings.
func rescoreShadowFindings(tx *gorm.DB, ouID string, connectionID *uuid.UUID, findingIDs []uuid.UUID, score ShadowScoreFunc) error {
	var rows []struct {
		ID    uuid.UUID `gorm:"column:id"`
		Kind  string    `gorm:"column:kind"`
		Codes string    `gorm:"column:codes"`
	}
	q := tx.Table("shadow_findings f").
		Select("f.id, f.kind, COALESCE(string_agg(s.code, ','), '') AS codes").
		Joins("LEFT JOIN shadow_finding_signals s ON s.finding_id = f.id").
		Where("f.ou_id = ?", ouID).
		Group("f.id, f.kind")
	switch {
	case connectionID != nil:
		q = q.Where("f.connection_id = ?", *connectionID)
	case len(findingIDs) > 0:
		q = q.Where("f.id IN ?", findingIDs)
	default:
		return nil
	}
	if err := q.Scan(&rows).Error; err != nil {
		return fmt.Errorf("reading signals to score: %w", err)
	}
	for _, row := range rows {
		var codes []string
		if row.Codes != "" {
			codes = strings.Split(row.Codes, ",")
		}
		sc, verdict := score(row.Kind, codes)
		if err := tx.Exec(`UPDATE shadow_findings SET score = ?, verdict = ?, updated_at = NOW() WHERE id = ?`,
			sc, verdict, row.ID).Error; err != nil {
			return fmt.Errorf("writing score: %w", err)
		}
	}
	return nil
}

func (r *shadowAgentRepository) ListOrgFindings(ctx context.Context, ouID string) ([]models.ShadowFinding, error) {
	var out []models.ShadowFinding
	err := r.db.WithContext(ctx).Where("ou_id = ?", ouID).Find(&out).Error
	return out, err
}

func (r *shadowAgentRepository) ApplyCorrelation(
	ctx context.Context, ouID string, relations map[uuid.UUID][]models.ShadowFindingRelation,
	signals map[uuid.UUID][]models.ShadowFindingSignal, score ShadowScoreFunc,
) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var touched []uuid.UUID
		if err := tx.Raw(`SELECT DISTINCT finding_id FROM shadow_finding_signals WHERE ou_id = ? AND source = ?`,
			ouID, ShadowCorrelationSource).Scan(&touched).Error; err != nil {
			return fmt.Errorf("reading correlation signals: %w", err)
		}
		if err := tx.Exec(`DELETE FROM shadow_finding_signals WHERE ou_id = ? AND source = ?`,
			ouID, ShadowCorrelationSource).Error; err != nil {
			return fmt.Errorf("clearing correlation signals: %w", err)
		}
		for id, list := range signals {
			for i := range list {
				list[i].Source = ShadowCorrelationSource
				if err := upsertShadowSignal(tx, ouID, id, uuid.Nil, &list[i]); err != nil {
					return err
				}
			}
			touched = append(touched, id)
		}
		// Clear stale correlation relations on every finding of the org that has
		// any, then write the new ones.
		var withRelations []uuid.UUID
		if err := tx.Raw(`SELECT id FROM shadow_findings WHERE ou_id = ? AND related <> '[]'::jsonb`, ouID).
			Scan(&withRelations).Error; err != nil {
			return fmt.Errorf("reading relations: %w", err)
		}
		seen := map[uuid.UUID]bool{}
		for _, id := range withRelations {
			seen[id] = true
			if err := mergeShadowRelations(tx, id, relations[id], true); err != nil {
				return err
			}
		}
		for id, rels := range relations {
			if !seen[id] {
				if err := mergeShadowRelations(tx, id, rels, true); err != nil {
					return err
				}
			}
		}
		return rescoreShadowFindings(tx, ouID, nil, touched, score)
	})
}

// ---- findings ----

const shadowFindingSelect = `f.*, c.name AS connection_name,
	COALESCE((SELECT SUM(u.requests) FROM shadow_usage_daily u WHERE u.finding_id = f.id), 0) AS requests`

func (r *shadowAgentRepository) ListFindings(
	ctx context.Context, ouID string, flt ShadowFindingFilter,
) ([]ShadowFindingRow, int, error) {
	q := r.db.WithContext(ctx).Table("shadow_findings f").
		Joins("JOIN shadow_connections c ON c.id = f.connection_id").
		Where("f.ou_id = ?", ouID)
	if flt.Provider != "" {
		q = q.Where("f.provider = ?", flt.Provider)
	}
	if flt.Verdict != "" {
		q = q.Where("f.verdict = ?", flt.Verdict)
	}
	if flt.Status != "" {
		q = q.Where("f.status = ?", flt.Status)
	}
	if flt.Kind != "" {
		q = q.Where("f.kind = ?", flt.Kind)
	}
	if flt.ConnectionID != nil {
		q = q.Where("f.connection_id = ?", *flt.ConnectionID)
	}
	if flt.ScanID != nil {
		q = q.Where("EXISTS (SELECT 1 FROM shadow_scan_findings sf WHERE sf.finding_id = f.id AND sf.scan_id = ?)", *flt.ScanID)
	}
	if s := strings.TrimSpace(flt.Search); s != "" {
		like := "%" + escapeLike(strings.ToLower(s)) + "%"
		q = q.Where(`(lower(f.display_name) LIKE ? ESCAPE '\' OR lower(f.external_id) LIKE ? ESCAPE '\'
			OR lower(f.owner_hint->>'email') LIKE ? ESCAPE '\' OR lower(f.owner_hint->>'name') LIKE ? ESCAPE '\'
			OR lower(f.owner_hint->>'username') LIKE ? ESCAPE '\')`, like, like, like, like, like)
	}
	var total int64
	if err := q.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []ShadowFindingRow
	err := q.Select(shadowFindingSelect).
		Order("f.score DESC, f.last_used_at DESC NULLS LAST, f.display_name ASC").
		Limit(flt.Limit).Offset(flt.Offset).
		Scan(&rows).Error
	return rows, int(total), err
}

func (r *shadowAgentRepository) GetFinding(ctx context.Context, ouID string, id uuid.UUID) (*ShadowFindingRow, error) {
	var rows []ShadowFindingRow
	err := r.db.WithContext(ctx).Table("shadow_findings f").
		Joins("JOIN shadow_connections c ON c.id = f.connection_id").
		Select(shadowFindingSelect).
		Where("f.ou_id = ? AND f.id = ?", ouID, id).
		Limit(1).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rows[0], nil
}

func (r *shadowAgentRepository) ListSignals(ctx context.Context, ouID string, findingID uuid.UUID) ([]models.ShadowFindingSignal, error) {
	var out []models.ShadowFindingSignal
	err := r.db.WithContext(ctx).Where("ou_id = ? AND finding_id = ?", ouID, findingID).
		Order("weight DESC, code ASC, source ASC").Find(&out).Error
	return out, err
}

func (r *shadowAgentRepository) ListFindingKeys(ctx context.Context, ouID string, findingID uuid.UUID) ([]models.ShadowAPIKey, error) {
	var out []models.ShadowAPIKey
	err := r.db.WithContext(ctx).Where("ou_id = ? AND finding_id = ?", ouID, findingID).
		Order("name ASC").Find(&out).Error
	return out, err
}

func (r *shadowAgentRepository) ListUsage(ctx context.Context, ouID string, findingID uuid.UUID) ([]models.ShadowUsageDaily, error) {
	var out []models.ShadowUsageDaily
	err := r.db.WithContext(ctx).Where("ou_id = ? AND finding_id = ?", ouID, findingID).
		Order("day ASC, key_id ASC, model ASC").Find(&out).Error
	return out, err
}

func (r *shadowAgentRepository) UpdateFindingStatus(ctx context.Context, ouID string, id uuid.UUID, status string) error {
	res := r.db.WithContext(ctx).Model(&models.ShadowFinding{}).
		Where("ou_id = ? AND id = ?", ouID, id).
		Updates(map[string]any{"status": status, "updated_at": time.Now().UTC()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *shadowAgentRepository) OnboardFinding(
	ctx context.Context, ouID string, id uuid.UUID, project, agent, by string, at time.Time,
) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var f models.ShadowFinding
		if err := tx.Select("id", "linked_agent").Where("ou_id = ? AND id = ?", ouID, id).First(&f).Error; err != nil {
			return err
		}
		// Atomic: only a finding that is not linked yet is linked. A project
		// finding has no credential of its own, so it is not watched for
		// retirement.
		res := tx.Exec(`UPDATE shadow_findings SET linked_project = ?, linked_agent = ?, onboarded_at = ?, onboarded_by = ?,
				status = ?, retirement_state = CASE WHEN kind = ? THEN '' ELSE ? END, updated_at = NOW()
			WHERE ou_id = ? AND id = ? AND linked_agent = ''`,
			project, agent, at, by, models.ShadowStatusOnboarded, models.ShadowKindProject, models.ShadowRetirementMonitoring, ouID, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return utils.ErrShadowAlreadyOnboarded
		}
		return nil
	})
}

func (r *shadowAgentRepository) SetRetirement(
	ctx context.Context, ouID string, id uuid.UUID, state string, markedBy string, markedAt, verifiedAt *time.Time,
) error {
	updates := map[string]any{"retirement_state": state, "updated_at": time.Now().UTC()}
	if markedAt != nil {
		updates["retirement_marked_at"] = *markedAt
		updates["retirement_marked_by"] = markedBy
	}
	if verifiedAt != nil {
		updates["retirement_verified_at"] = *verifiedAt
		updates["status"] = models.ShadowStatusRetired
	}
	res := r.db.WithContext(ctx).Model(&models.ShadowFinding{}).Where("ou_id = ? AND id = ?", ouID, id).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *shadowAgentRepository) ListOnboardedFindings(ctx context.Context, ouID string) ([]models.ShadowFinding, error) {
	var out []models.ShadowFinding
	err := r.db.WithContext(ctx).Where("ou_id = ? AND linked_agent <> ''", ouID).Find(&out).Error
	return out, err
}

func (r *shadowAgentRepository) Summary(ctx context.Context, ouID string) (ShadowSummary, error) {
	sum := ShadowSummary{ByVerdict: map[string]int{}, ByProvider: map[string]int{}, ByStatus: map[string]int{}}
	var rows []struct {
		Verdict  string `gorm:"column:verdict"`
		Provider string `gorm:"column:provider"`
		Status   string `gorm:"column:status"`
		N        int    `gorm:"column:n"`
	}
	if err := r.db.WithContext(ctx).Table("shadow_findings").
		Select("verdict, provider, status, COUNT(*) AS n").
		Where("ou_id = ?", ouID).Group("verdict, provider, status").Scan(&rows).Error; err != nil {
		return sum, err
	}
	for _, row := range rows {
		sum.Total += row.N
		sum.ByVerdict[row.Verdict] += row.N
		sum.ByProvider[row.Provider] += row.N
		sum.ByStatus[row.Status] += row.N
	}
	var conns int64
	if err := r.db.WithContext(ctx).Model(&models.ShadowConnection{}).Where("ou_id = ?", ouID).Count(&conns).Error; err != nil {
		return sum, err
	}
	sum.Connections = int(conns)
	return sum, nil
}

// ---- helpers ----

func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encoding JSON: %w", err)
	}
	return string(b), nil
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func ownerHintJSON(h models.ShadowOwnerHint) (string, error) {
	if h == (models.ShadowOwnerHint{}) {
		return "{}", nil
	}
	return toJSON(h)
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// IsShadowNotFound reports gorm's not-found error.
func IsShadowNotFound(err error) bool { return errors.Is(err, gorm.ErrRecordNotFound) }
