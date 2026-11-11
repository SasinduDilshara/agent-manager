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
	"fmt"
	"strings"
	"time"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// ShadowRetirementView is where an onboarded finding's direct credential is
// in retirement: Agent Manager watches the direct usage drop to zero for the
// observation window, then guides the user to revoke the credential and
// verifies it on the next scan. It never revokes anything itself.
type ShadowRetirementView struct {
	State           string
	ObservationDays int
	ZeroUsageDays   int
	LastDirectUseAt *time.Time
	DataThrough     *time.Time
	MarkedAt        *time.Time
	MarkedBy        string
	VerifiedAt      *time.Time
	Verification    string
	Guidance        ShadowRetirementGuidance
}

// ShadowRetirementGuidance tells the user how to revoke the direct
// credential at the provider.
type ShadowRetirementGuidance struct {
	Title   string
	Steps   []string
	DocsURL string
}

// Key statuses a provider reports for a key that no longer works.
var shadowRetiredKeyStatuses = map[string]bool{
	"inactive": true, "archived": true, "expired": true, "disabled": true, "revoked": true, "deleted": true,
}

// Finding states that mean the workload no longer runs.
var shadowRetiredStates = map[string]bool{
	"disabled": true, "archived": true, "deleted": true, "deleting": true,
}

// dataThrough is the latest time the stored data about a finding covers:
// the last scan that saw it, or a later scan that ran its connection
// without failing. With strict, only a connection result where every call
// succeeded counts: only then would a scan have seen the finding if it still
// existed, which is what verifying a revocation relies on.
func dataThrough(f *models.ShadowFinding, latest *models.ShadowScan, strict bool) *time.Time {
	t := f.LastSeenAt
	if latest != nil && latest.StartedAt != nil && latest.FinishedAt != nil && latest.StartedAt.After(t) {
		for _, r := range latest.Results {
			if r.ConnectionID != f.ConnectionID.String() {
				continue
			}
			ok := r.Outcome == shadowConnectionOK || (!strict && r.Outcome == shadowConnectionPartial)
			if ok {
				t = *latest.StartedAt
			}
			break
		}
	}
	if t.IsZero() {
		return nil
	}
	return &t
}

// lastDirectUse is the latest direct use the stored data shows: the latest
// day with requests, or the provider's last-used time if later.
func lastDirectUse(f *models.ShadowFinding, usage []models.ShadowUsageDaily) *time.Time {
	var last *time.Time
	for i := range usage {
		if usage[i].Requests <= 0 {
			continue
		}
		d := sa.DayOf(usage[i].Day)
		if last == nil || d.After(*last) {
			last = &d
		}
	}
	if f.LastUsedAt != nil && (last == nil || f.LastUsedAt.After(*last)) {
		t := f.LastUsedAt.UTC()
		last = &t
	}
	return last
}

// zeroUsageDays counts the complete days, after onboarding and after the
// last direct use, up to the day before the data's end (that day is not
// complete yet).
func zeroUsageDays(onboardedAt time.Time, last *time.Time, through *time.Time) int {
	if through == nil {
		return 0
	}
	start := sa.DayOf(onboardedAt).AddDate(0, 0, 1)
	if last != nil {
		if after := sa.DayOf(*last).AddDate(0, 0, 1); after.After(start) {
			start = after
		}
	}
	end := sa.DayOf(*through).AddDate(0, 0, -1)
	if end.Before(start) {
		return 0
	}
	return int(end.Sub(start).Hours()/24) + 1
}

// EvaluateShadowRetirement derives the retirement view of a finding from
// its stored state, usage and keys.
func EvaluateShadowRetirement(
	f *models.ShadowFinding, usage []models.ShadowUsageDaily, keys []models.ShadowAPIKey, through, strictThrough *time.Time,
) ShadowRetirementView {
	v := ShadowRetirementView{
		State:           "",
		ObservationDays: ShadowRetirementObservationDays,
		DataThrough:     through,
		MarkedAt:        f.RetirementMarkedAt,
		MarkedBy:        f.RetirementMarkedBy,
		VerifiedAt:      f.RetirementVerifiedAt,
		Guidance:        shadowRetirementGuidance(f),
	}
	if f.Kind == models.ShadowKindProject {
		// A project or workspace has no credential of its own to revoke;
		// the keys that may have made its calls are separate findings.
		v.Guidance = ShadowRetirementGuidance{}
		return v
	}
	if f.LinkedAgent == "" || f.OnboardedAt == nil {
		return v
	}
	last := lastDirectUse(f, usage)
	v.LastDirectUseAt = last
	v.ZeroUsageDays = zeroUsageDays(*f.OnboardedAt, last, through)
	switch f.RetirementState {
	case models.ShadowRetirementRetired:
		v.State = models.ShadowRetirementRetired
		v.Verification = "A scan confirmed the credential no longer works at the provider."
	case models.ShadowRetirementPendingVerify:
		v.State = models.ShadowRetirementPendingVerify
		_, v.Verification = verifyShadowRetirement(f, usage, keys, strictThrough)
	default:
		if v.ZeroUsageDays >= ShadowRetirementObservationDays {
			v.State = models.ShadowRetirementReady
		} else {
			v.State = models.ShadowRetirementMonitoring
		}
	}
	return v
}

// verifyShadowRetirement checks, after the user said they revoked the
// direct credential, whether the stored scan data confirms it.
func verifyShadowRetirement(
	f *models.ShadowFinding, usage []models.ShadowUsageDaily, keys []models.ShadowAPIKey, through *time.Time,
) (bool, string) {
	marked := f.RetirementMarkedAt
	if marked == nil {
		return false, "Not confirmed yet."
	}
	if through == nil || !through.After(*marked) {
		return false, "Run a scan to check the provider."
	}
	if last := lastDirectUse(f, usage); last != nil && sa.DayOf(*last).After(sa.DayOf(*marked)) {
		return false, fmt.Sprintf("Direct usage was seen on %s, after you confirmed the revocation.", last.Format(time.DateOnly))
	}
	if len(keys) > 0 {
		var active []string
		for _, k := range keys {
			gone := !k.Present || shadowRetiredKeyStatuses[strings.ToLower(k.Status)]
			if !gone {
				active = append(active, fmt.Sprintf("%s (%s)", firstNonEmpty(k.Name, k.KeyID), firstNonEmpty(k.Status, "listed")))
			}
		}
		if len(active) > 0 {
			return false, "The provider still lists the key as usable: " + strings.Join(active, ", ") + "."
		}
		return true, "The provider no longer lists the key as usable."
	}
	if f.Kind == models.ShadowKindPrincipal {
		// Agent Manager cannot read IAM; CloudTrail history keeps listing the
		// identity, so the evidence is a full day with no direct model call.
		if !sa.DayOf(*through).After(sa.DayOf(*marked).AddDate(0, 0, 1)) {
			return false, "Waiting for a full day of CloudTrail data after you confirmed."
		}
		return true, "CloudTrail shows no direct model calls from this identity since you confirmed."
	}
	if shadowRetiredStates[strings.ToLower(f.State)] {
		return true, fmt.Sprintf("The provider reports the workload as %s.", f.State)
	}
	if f.LastSeenAt.Before(*through) {
		return true, "The provider no longer returns this workload."
	}
	return false, "The provider still returns this workload; check that the credential was revoked."
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
