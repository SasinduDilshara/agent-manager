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

// Package shadowagents is the provider-facing half of Shadow Agent Discovery
// (Method 1: provider and cloud admin APIs). Each provider has a Connector in
// a sub-package that calls the provider's read-only admin and management
// APIs and reports what it found as provider-neutral Findings, with signals,
// owner hints, keys and daily usage. This package holds what they share: the
// types, the signal catalog and scoring, the HTTP client and the cloud
// credentials, and the retention sanitiser everything passes before storage.
//
// Data retention: a connector never returns a secret, a prompt, a completion,
// a tool payload or an instruction text. Sources that hold such content are
// read in memory only (and only with deep inspection on) to derive counts
// and flags. See docs/shadow-agent-discovery.md.
package shadowagents

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/wso2/agent-manager/agent-manager-service/models"
)

// Connection is a connection ready to scan: its settings and its decrypted
// secret. It lives only in memory while a connector runs.
type Connection struct {
	ID       uuid.UUID
	OUID     string
	Name     string
	Provider string
	Config   models.ShadowConnectionConfig
	Secret   models.ShadowConnectionSecret
}

// Window is the time range a scan looks at. Start is a UTC midnight; End is
// the scan time.
type Window struct {
	Start time.Time
	End   time.Time
}

// Days is the number of calendar days the window touches.
func (w Window) Days() int {
	return int(w.End.Sub(w.Start).Hours()/24) + 1
}

// NewWindow returns the window of the last lookbackDays days ending at now.
func NewWindow(now time.Time, lookbackDays int) Window {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -lookbackDays)
	return Window{Start: start, End: now}
}

// Connector scans one provider. Implementations must be safe for concurrent
// use by several scans, each with its own Connection.
type Connector interface {
	// Provider is the provider this connector scans (models.ShadowProvider*).
	Provider() string
	// Scan runs every call the connection's settings enable over the window.
	// A failing call never fails the scan: it is recorded in the result's
	// calls and the scan goes on with what it has.
	Scan(ctx context.Context, conn Connection, w Window) *Result
	// Test checks the credential with one cheap read per capability and says
	// which signals each capability unlocks.
	Test(ctx context.Context, conn Connection) models.ShadowConnectionTestInfo
}

// Result is what one connection's scan found.
type Result struct {
	Findings []*Finding
	Keys     []Key
	Calls    []models.ShadowScanCallResult
	// KeysListed is true when the key listing succeeded for every scope, so
	// a stored key the listing no longer returns can be marked as gone.
	KeysListed bool
	// KeyScopesListed are the scopes (Key.Scope values) whose key listing
	// succeeded completely, when not every scope's did: stored keys of these
	// scopes that the listing no longer returns are marked as gone.
	KeyScopesListed []string
}

// Finding is a potential agent as a connector sees it. ExternalID is stable
// across scans for the same workload at the provider.
type Finding struct {
	Kind              string
	ExternalID        string
	DisplayName       string
	Scope             string
	State             string
	OwnerHint         models.ShadowOwnerHint
	Attributes        map[string]any
	ProviderCreatedAt *time.Time
	FirstUsedAt       *time.Time
	LastUsedAt        *time.Time
	Signals           []Signal
	Usage             []UsageDay
	// KeyIDs are the provider keys this workload uses.
	KeyIDs []string
	// Related links findings of the same connection, by ExternalID.
	Related []Relation
}

// Relation links a finding to another finding of the same connection.
type Relation struct {
	ExternalID string
	Kind       string
	Relation   string
	Reason     string
}

// Signal is one detected signal. Tier, weight and condition come from the
// catalog (see Catalog), never from the connector.
type Signal struct {
	Code string
	// Source names the call that produced it, e.g. "GET /v1/agents".
	Source string
	// Observed holds counts and flags only, e.g. {"numRequests": 42}.
	Observed map[string]any
}

// UsageDay is one day of usage, per key and model.
type UsageDay struct {
	Day          time.Time
	KeyID        string
	Model        string
	Requests     int64
	InputTokens  int64
	OutputTokens int64
	CostAmount   *float64
	Currency     string
}

// Key is a provider API key, as much of it as the retention rules allow.
type Key struct {
	KeyID        string
	Name         string
	RedactedHint string
	Status       string
	Scope        string
	OwnerHint    models.ShadowOwnerHint
	CreatedAt    *time.Time
	LastUsedAt   *time.Time
}

// AddSignal appends a signal unless one with the same code and source is
// already on the finding, in which case their observed counts are summed
// (numbers) or kept (anything else).
func (f *Finding) AddSignal(s Signal) {
	for i := range f.Signals {
		if f.Signals[i].Code == s.Code && f.Signals[i].Source == s.Source {
			f.Signals[i].Observed = mergeObserved(f.Signals[i].Observed, s.Observed)
			return
		}
	}
	if s.Observed == nil {
		s.Observed = map[string]any{}
	}
	f.Signals = append(f.Signals, s)
}

// ObserveUse widens the finding's first/last used times to include t.
func (f *Finding) ObserveUse(t time.Time) {
	t = t.UTC()
	if f.FirstUsedAt == nil || t.Before(*f.FirstUsedAt) {
		f.FirstUsedAt = &t
	}
	if f.LastUsedAt == nil || t.After(*f.LastUsedAt) {
		f.LastUsedAt = &t
	}
}

// AddUsage adds a day of usage, summing it into an existing entry for the
// same day, key and model so a workload's usage is never counted twice.
func (f *Finding) AddUsage(u UsageDay) {
	u.Day = DayOf(u.Day)
	for i := range f.Usage {
		e := &f.Usage[i]
		if e.Day.Equal(u.Day) && e.KeyID == u.KeyID && e.Model == u.Model {
			e.Requests += u.Requests
			e.InputTokens += u.InputTokens
			e.OutputTokens += u.OutputTokens
			if u.CostAmount != nil {
				sum := *u.CostAmount
				if e.CostAmount != nil {
					sum += *e.CostAmount
				}
				e.CostAmount = &sum
				if e.Currency == "" {
					e.Currency = u.Currency
				}
			}
			return
		}
	}
	f.Usage = append(f.Usage, u)
}

// AddKeyID records that the workload uses key id.
func (f *Finding) AddKeyID(id string) {
	if id == "" {
		return
	}
	for _, k := range f.KeyIDs {
		if k == id {
			return
		}
	}
	f.KeyIDs = append(f.KeyIDs, id)
}

// DayOf truncates t to its UTC calendar day.
func DayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func mergeObserved(a, b map[string]any) map[string]any {
	if a == nil {
		a = map[string]any{}
	}
	for k, v := range b {
		old, ok := a[k]
		if !ok {
			a[k] = v
			continue
		}
		if x, ok1 := toInt64(old); ok1 {
			if y, ok2 := toInt64(v); ok2 {
				a[k] = x + y
			}
		}
	}
	return a
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case int32:
		return int64(n), true
	default:
		return 0, false
	}
}

// Findings indexes findings by kind and external ID, so a connector can add
// evidence from several calls to the same finding.
type Findings struct {
	order []*Finding
	byKey map[string]*Finding
}

// NewFindings creates an empty index.
func NewFindings() *Findings {
	return &Findings{byKey: map[string]*Finding{}}
}

// Get returns the finding for kind and externalID, creating it if needed.
func (fs *Findings) Get(kind, externalID string) *Finding {
	k := kind + "\x00" + externalID
	if f, ok := fs.byKey[k]; ok {
		return f
	}
	f := &Finding{Kind: kind, ExternalID: externalID, Attributes: map[string]any{}}
	fs.byKey[k] = f
	fs.order = append(fs.order, f)
	return f
}

// Lookup returns the finding for kind and externalID, if there is one.
func (fs *Findings) Lookup(kind, externalID string) (*Finding, bool) {
	f, ok := fs.byKey[kind+"\x00"+externalID]
	return f, ok
}

// Remove drops a finding, e.g. after its evidence was merged into another.
func (fs *Findings) Remove(kind, externalID string) {
	k := kind + "\x00" + externalID
	f, ok := fs.byKey[k]
	if !ok {
		return
	}
	delete(fs.byKey, k)
	for i, o := range fs.order {
		if o == f {
			fs.order = append(fs.order[:i], fs.order[i+1:]...)
			break
		}
	}
}

// All returns the findings in the order they were first seen.
func (fs *Findings) All() []*Finding {
	out := make([]*Finding, len(fs.order))
	copy(out, fs.order)
	return out
}
