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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// Scan worker settings.
const (
	shadowScanTick        = 5 * time.Second
	shadowScanLease       = 5 * time.Minute
	shadowScanRenewEvery  = time.Minute
	shadowScanBatch       = 2
	shadowScanMaxAttempts = 3
	// shadowConnectionTimeout bounds one connection's scan; CloudTrail and
	// Cloud Logging are rate limited to a few requests a second.
	shadowConnectionTimeout = 30 * time.Minute
	shadowConnectionWorkers = 4
)

// Connection outcomes in a scan result.
const (
	shadowConnectionOK      = "ok"
	shadowConnectionPartial = "partial"
	shadowConnectionFailed  = "failed"
)

// ShadowAgentScanner runs queued Shadow Agent Discovery scans in the
// background. Scans are leased in the database, so several service replicas
// can run it; a scan whose worker died is picked up again when its lease
// runs out.
type ShadowAgentScanner interface {
	Start(ctx context.Context) error
	Stop() error
	// RunOnce claims due scans and runs them.
	RunOnce(ctx context.Context)
}

type shadowAgentScanner struct {
	repo          repositories.ShadowAgentRepository
	connectors    ShadowConnectors
	encryptionKey []byte
	logger        *slog.Logger
	now           func() time.Time

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewShadowAgentScanner creates the scan worker.
func NewShadowAgentScanner(
	repo repositories.ShadowAgentRepository, connectors ShadowConnectors, encryptionKey []byte, logger *slog.Logger,
) ShadowAgentScanner {
	return &shadowAgentScanner{
		repo: repo, connectors: connectors, encryptionKey: encryptionKey,
		logger: logger.With("component", "shadow-agent-scanner"), now: time.Now,
	}
}

func (s *shadowAgentScanner) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return errors.New("shadow agent scanner already started")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(shadowScanTick)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				s.RunOnce(runCtx)
			}
		}
	}()
	s.logger.Info("Shadow agent scanner started")
	return nil
}

func (s *shadowAgentScanner) Stop() error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel = nil
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	<-done
	return nil
}

func (s *shadowAgentScanner) RunOnce(ctx context.Context) {
	scans, err := s.repo.ClaimDueScans(ctx, s.now().UTC(), shadowScanLease, shadowScanBatch)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Error("Failed to claim shadow agent scans", "error", err)
		}
		return
	}
	for i := range scans {
		s.runScan(ctx, &scans[i])
	}
}

// runScan runs every connection of a scan, keeps its lease alive, and
// records the outcome.
func (s *shadowAgentScanner) runScan(ctx context.Context, scan *models.ShadowScan) {
	log := s.logger.With("orgId", scan.OUID, "scanId", scan.ID)
	// Record the outcome even when the worker is shutting down.
	record := context.WithoutCancel(ctx)
	if scan.Attempts > shadowScanMaxAttempts {
		scan.Status = models.ShadowScanFailed
		finished := s.now().UTC()
		scan.FinishedAt = &finished
		scan.Results = append(scan.Results, models.ShadowScanConnectionResult{
			Outcome: shadowConnectionFailed, Message: fmt.Sprintf("gave up after %d attempts", shadowScanMaxAttempts),
			Calls: []models.ShadowScanCallResult{},
		})
		if err := s.repo.FinishScan(record, scan); err != nil {
			log.Error("Failed to record an abandoned scan", "error", err)
		}
		return
	}
	log.Info("Shadow agent scan started", "connections", len(scan.ConnectionIDs), "lookbackDays", scan.LookbackDays)

	leaseCtx, stopLease := context.WithCancel(ctx)
	go s.keepLease(leaseCtx, scan.ID, log)
	defer stopLease()

	startedAt := s.now().UTC()
	if scan.StartedAt != nil {
		startedAt = *scan.StartedAt
	}
	window := sa.NewWindow(startedAt, scan.LookbackDays)

	results := make([]models.ShadowScanConnectionResult, len(scan.ConnectionIDs))
	sem := make(chan struct{}, shadowConnectionWorkers)
	var wg sync.WaitGroup
	for i, idStr := range scan.ConnectionIDs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, idStr string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = s.scanConnection(ctx, record, scan, idStr, window, startedAt, log)
		}(i, idStr)
	}
	wg.Wait()

	total := 0
	okCount, failCount := 0, 0
	for _, r := range results {
		total += r.FindingsCount
		switch r.Outcome {
		case shadowConnectionOK, models.ShadowCallSkipped:
			okCount++
		case shadowConnectionPartial:
		default:
			failCount++
		}
	}
	if err := s.correlate(record, scan.OUID); err != nil {
		log.Error("Failed to correlate findings across connections", "error", err)
	}
	finished := s.now().UTC()
	scan.FinishedAt = &finished
	scan.Results = results
	scan.FindingsCount = total
	switch {
	case okCount == len(results):
		scan.Status = models.ShadowScanSucceeded
	case failCount == len(results):
		scan.Status = models.ShadowScanFailed
	default:
		scan.Status = models.ShadowScanPartial
	}
	if err := s.repo.FinishScan(record, scan); err != nil {
		log.Error("Failed to record the scan outcome", "error", err)
		return
	}
	if err := s.updateRetirements(record, scan.OUID); err != nil {
		log.Error("Failed to update credential retirement states", "error", err)
	}
	log.Info("Shadow agent scan finished", "status", scan.Status, "findings", total)
}

func (s *shadowAgentScanner) keepLease(ctx context.Context, id uuid.UUID, log *slog.Logger) {
	t := time.NewTicker(shadowScanRenewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.repo.RenewScanLease(ctx, id, s.now().UTC().Add(shadowScanLease)); err != nil && ctx.Err() == nil {
				log.Warn("Failed to renew the scan lease", "error", err)
			}
		}
	}
}

// scanConnection runs one connection and writes what it found. A failure
// here fails only this connection's part of the scan.
func (s *shadowAgentScanner) scanConnection(
	ctx, record context.Context, scan *models.ShadowScan, idStr string, w sa.Window, startedAt time.Time, log *slog.Logger,
) models.ShadowScanConnectionResult {
	res := models.ShadowScanConnectionResult{ConnectionID: idStr, Outcome: shadowConnectionFailed, Calls: []models.ShadowScanCallResult{}}
	id, err := uuid.Parse(idStr)
	if err != nil {
		res.Message = "invalid connection ID"
		return res
	}
	c, err := s.repo.GetConnection(ctx, scan.OUID, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res.Message = "the connection was deleted"
		} else {
			res.Message = "failed to load the connection"
			log.Error("Failed to load a connection", "connectionId", id, "error", err)
		}
		return res
	}
	res.ConnectionName, res.Provider = c.Name, c.Provider
	connector, ok := s.connectors[c.Provider]
	if !ok {
		res.Message = "no connector for this provider"
		return res
	}
	conn, err := shadowRuntimeConnection(c, s.encryptionKey)
	if err != nil {
		res.Message = "the stored credential cannot be decrypted; enter it again"
		log.Error("Failed to decrypt a connection credential", "connectionId", id, "error", err)
		return res
	}
	cctx, cancel := context.WithTimeout(ctx, shadowConnectionTimeout)
	defer cancel()
	out := runConnector(cctx, connector, conn, w, log)
	res.Calls = sanitizeCalls(out.Calls)
	in := toShadowApply(scan, c, out, w, startedAt, s.now().UTC(), log)
	n, err := s.repo.ApplyConnectionResult(record, in, sa.Score)
	if err != nil {
		res.Message = "failed to save what the scan found"
		log.Error("Failed to save a connection's scan result", "connectionId", id, "error", err)
		return res
	}
	res.FindingsCount = n
	res.Outcome, res.Message = connectionOutcome(res.Calls)
	return res
}

// runConnector runs a connector, turning a panic into a failed result so one
// provider cannot take the worker down.
func runConnector(ctx context.Context, c sa.Connector, conn sa.Connection, w sa.Window, log *slog.Logger) (out *sa.Result) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Shadow agent connector panicked", "provider", conn.Provider, "connectionId", conn.ID)
			out = &sa.Result{Calls: []models.ShadowScanCallResult{{Call: "scan", Outcome: models.ShadowCallFailed, Message: "internal error in the connector"}}}
		}
	}()
	out = c.Scan(ctx, conn, w)
	if out == nil {
		out = &sa.Result{}
	}
	return out
}

func sanitizeCalls(calls []models.ShadowScanCallResult) []models.ShadowScanCallResult {
	out := make([]models.ShadowScanCallResult, 0, len(calls))
	for _, c := range calls {
		c.Call = sa.Truncate(c.Call, 200)
		c.Message = sa.ScrubText(c.Message)
		out = append(out, c)
	}
	return out
}

// connectionOutcome summarizes a connection's calls: skipped when every call
// was skipped on purpose (nothing read), ok when every call
// succeeded or was skipped on purpose, auth_failed when the credential was
// refused and nothing was read, failed when nothing succeeded, partial
// otherwise.
func connectionOutcome(calls []models.ShadowScanCallResult) (string, string) {
	okCalls, failed, authFailed, skipped := 0, 0, 0, 0
	var firstErr, firstSkip string
	for _, c := range calls {
		switch c.Outcome {
		case models.ShadowCallOK:
			okCalls++
		case models.ShadowCallSkipped:
			skipped++
			if firstSkip == "" {
				firstSkip = c.Call + ": " + c.Message
			}
		default:
			failed++
			if c.Outcome == models.ShadowCallAuthFailed {
				authFailed++
			}
			if firstErr == "" {
				firstErr = c.Call + ": " + c.Message
			}
		}
	}
	switch {
	case failed == 0 && okCalls == 0 && skipped > 0:
		// Nothing was read on purpose (a source host until its analysis
		// exists): skipped, which does not fail the scan.
		return models.ShadowCallSkipped, sa.ScrubText(firstSkip)
	case failed == 0:
		return shadowConnectionOK, ""
	case okCalls == 0 && authFailed > 0:
		return models.ShadowCallAuthFailed, sa.ScrubText(firstErr)
	case okCalls == 0:
		return shadowConnectionFailed, sa.ScrubText(firstErr)
	default:
		return shadowConnectionPartial, sa.ScrubText(fmt.Sprintf("%d of %d calls failed; %s", failed, failed+okCalls, firstErr))
	}
}

// toShadowApply converts a connector result into what the repository
// stores, applying the retention rules once more: attributes through the
// allow-list, owner hints minimised, names and hints scrubbed, signals
// re-weighted from the catalog (a connector cannot change a weight).
func toShadowApply(
	scan *models.ShadowScan, c *models.ShadowConnection, out *sa.Result, w sa.Window, startedAt, now time.Time, log *slog.Logger,
) repositories.ShadowConnectionApply {
	in := repositories.ShadowConnectionApply{
		OUID: scan.OUID, ConnectionID: c.ID, ScanID: scan.ID, ScanStartedAt: startedAt, WindowStart: w.Start,
		KeysListed: out.KeysListed, KeyScopesListed: out.KeyScopesListed,
	}
	for _, f := range out.Findings {
		if f == nil || strings.TrimSpace(f.ExternalID) == "" || !validShadowKind(f.Kind) {
			continue
		}
		fi := repositories.ShadowFindingInput{
			Finding: models.ShadowFinding{
				Provider:          c.Provider,
				Kind:              f.Kind,
				ExternalID:        sa.Truncate(f.ExternalID, 1024),
				DisplayName:       sa.SanitizeName(firstNonEmpty(f.DisplayName, f.ExternalID)),
				Scope:             sa.Truncate(f.Scope, 256),
				State:             sa.Truncate(f.State, 64),
				OwnerHint:         sa.MinimiseOwnerHint(f.OwnerHint),
				Attributes:        sa.SanitizeAttributes(f.Attributes),
				ProviderCreatedAt: f.ProviderCreatedAt,
				FirstUsedAt:       f.FirstUsedAt,
				LastUsedAt:        f.LastUsedAt,
			},
			KeyIDs: f.KeyIDs,
		}
		for _, sig := range f.Signals {
			d, ok := sa.Def(sig.Code)
			if !ok {
				log.Warn("Dropping an unknown signal code", "provider", c.Provider, "code", sig.Code)
				continue
			}
			fi.Signals = append(fi.Signals, models.ShadowFindingSignal{
				Code: d.Code, Tier: d.Tier, Weight: d.Weight, Condition: d.Condition,
				Source:     sa.Truncate(firstNonEmpty(sig.Source, "scan"), 200),
				Observed:   sanitizeObserved(sig.Observed),
				DetectedAt: now,
			})
		}
		for _, u := range f.Usage {
			fi.Usage = append(fi.Usage, models.ShadowUsageDaily{
				Day: sa.DayOf(u.Day), KeyID: sa.Truncate(u.KeyID, 256), Model: sa.Truncate(u.Model, 256),
				Requests: u.Requests, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
				CostAmount: finiteOrNil(u.CostAmount), Currency: sa.Truncate(u.Currency, 16),
			})
		}
		for _, rel := range f.Related {
			fi.Related = append(fi.Related, repositories.ShadowRelationInput{
				Kind: rel.Kind, ExternalID: rel.ExternalID, Relation: sa.Truncate(rel.Relation, 64), Reason: sa.Truncate(rel.Reason, 200),
			})
		}
		in.Findings = append(in.Findings, fi)
	}
	for _, k := range out.Keys {
		if strings.TrimSpace(k.KeyID) == "" {
			continue
		}
		in.Keys = append(in.Keys, models.ShadowAPIKey{
			KeyID: sa.Truncate(k.KeyID, 256), Name: sa.SanitizeName(k.Name),
			// A hint is a redacted form; scrubbing removes anything that looks
			// like a whole key, in case a provider ever returns one.
			RedactedHint: sa.Truncate(sa.ScrubText(k.RedactedHint), 64),
			Status:       sa.Truncate(k.Status, 32), Scope: sa.Truncate(k.Scope, 256),
			OwnerHint: sa.MinimiseOwnerHint(k.OwnerHint), ProviderCreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
		})
	}
	return in
}

func validShadowKind(kind string) bool {
	switch kind {
	case models.ShadowKindPlatformAgent, models.ShadowKindRuntime, models.ShadowKindAPIKey,
		models.ShadowKindPrincipal, models.ShadowKindToolInfra,
		models.ShadowKindProject:
		return true
	default:
		return false
	}
}

// sanitizeObserved keeps counts, flags and short labels only.
func sanitizeObserved(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		if len(out) == 20 {
			break
		}
		k = sa.Truncate(k, 64)
		switch x := v.(type) {
		case int, int32, int64, bool:
			out[k] = x
		case float64:
			if f := finiteOrNil(&x); f != nil {
				out[k] = *f
			}
		case float32:
			f64 := float64(x)
			if f := finiteOrNil(&f64); f != nil {
				out[k] = *f
			}
		case string:
			if len(x) <= 64 {
				out[k] = sa.ScrubText(x)
			}
		}
	}
	return out
}

func finiteOrNil(f *float64) *float64 {
	if f == nil || *f != *f || *f > 1e15 || *f < -1e15 {
		return nil
	}
	return f
}

// ---- correlation across connections ----

// correlate links findings of different connections about the same
// workload: a Foundry external agent and a same-named agent found elsewhere
// (Foundry stores no endpoint for external agents, so a name match is only a
// "possible duplicate", never merged).
func (s *shadowAgentScanner) correlate(ctx context.Context, ouID string) error {
	findings, err := s.repo.ListOrgFindings(ctx, ouID)
	if err != nil {
		return fmt.Errorf("listing findings: %w", err)
	}
	relations, signals := CorrelateShadowFindings(findings, s.now().UTC())
	return s.repo.ApplyCorrelation(ctx, ouID, relations, signals, sa.Score)
}

// CorrelateShadowFindings computes cross-connection relations and the
// signals they raise.
func CorrelateShadowFindings(
	findings []models.ShadowFinding, now time.Time,
) (map[uuid.UUID][]models.ShadowFindingRelation, map[uuid.UUID][]models.ShadowFindingSignal) {
	relations := map[uuid.UUID][]models.ShadowFindingRelation{}
	signals := map[uuid.UUID][]models.ShadowFindingSignal{}
	addSignal := func(id uuid.UUID, code string, observed map[string]any) {
		d, _ := sa.Def(code)
		for _, existing := range signals[id] {
			if existing.Code == code {
				return
			}
		}
		signals[id] = append(signals[id], models.ShadowFindingSignal{
			Code: d.Code, Tier: d.Tier, Weight: d.Weight, Condition: d.Condition,
			Source: repositories.ShadowCorrelationSource, Observed: observed, DetectedAt: now,
		})
	}

	// Foundry external agents: possible duplicates by normalized name.
	byName := map[string][]*models.ShadowFinding{}
	for i := range findings {
		f := &findings[i]
		if f.Provider == models.ShadowProviderFoundry {
			continue
		}
		if f.Kind != models.ShadowKindPlatformAgent && f.Kind != models.ShadowKindRuntime {
			continue
		}
		if n := normalizeShadowName(f.DisplayName); n != "" {
			byName[n] = append(byName[n], f)
		}
	}
	for i := range findings {
		f := &findings[i]
		if f.Provider != models.ShadowProviderFoundry {
			continue
		}
		if kind, _ := f.Attributes["agentKind"].(string); kind != "external" {
			continue
		}
		matches := byName[normalizeShadowName(f.DisplayName)]
		for _, m := range matches {
			relations[f.ID] = append(relations[f.ID], models.ShadowFindingRelation{
				FindingID: m.ID.String(), Relation: "possible_duplicate", Reason: "same name; Foundry stores no endpoint for external agents",
			})
			relations[m.ID] = append(relations[m.ID], models.ShadowFindingRelation{
				FindingID: f.ID.String(), Relation: "possible_duplicate", Reason: "registered in Foundry as an external agent with the same name",
			})
		}
		if len(matches) > 0 {
			addSignal(f.ID, sa.SigFoundryPossibleDupOf, map[string]any{"matches": len(matches)})
		}
	}
	return relations, signals
}

// normalizeShadowName lower-cases a name and keeps letters and digits only.
func normalizeShadowName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---- retirement ----

// updateRetirements moves onboarded findings through retirement after a
// scan: monitoring ⇄ ready_to_retire from the zero-usage days, and
// pending_verification → retired once the provider confirms it.
func (s *shadowAgentScanner) updateRetirements(ctx context.Context, ouID string) error {
	onboarded, err := s.repo.ListOnboardedFindings(ctx, ouID)
	if err != nil {
		return fmt.Errorf("listing onboarded findings: %w", err)
	}
	if len(onboarded) == 0 {
		return nil
	}
	latest, err := s.repo.LatestScan(ctx, ouID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("reading the latest scan: %w", err)
	}
	for i := range onboarded {
		f := &onboarded[i]
		if f.RetirementState == models.ShadowRetirementRetired || f.Kind == models.ShadowKindProject {
			continue
		}
		usage, err := s.repo.ListUsage(ctx, ouID, f.ID)
		if err != nil {
			return fmt.Errorf("reading usage: %w", err)
		}
		keys, err := s.repo.ListFindingKeys(ctx, ouID, f.ID)
		if err != nil {
			return fmt.Errorf("reading keys: %w", err)
		}
		view := EvaluateShadowRetirement(f, usage, keys, dataThrough(f, latest, false), dataThrough(f, latest, true))
		switch {
		case f.RetirementState == models.ShadowRetirementPendingVerify:
			verified, _ := verifyShadowRetirement(f, usage, keys, dataThrough(f, latest, true))
			if verified {
				now := s.now().UTC()
				if err := s.repo.SetRetirement(ctx, ouID, f.ID, models.ShadowRetirementRetired, "", nil, &now); err != nil {
					return fmt.Errorf("recording a verified retirement: %w", err)
				}
			}
		case view.State != f.RetirementState:
			if err := s.repo.SetRetirement(ctx, ouID, f.ID, view.State, "", nil, nil); err != nil {
				return fmt.Errorf("recording the retirement state: %w", err)
			}
		}
	}
	return nil
}
