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

package azure

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

func findingByName(t *testing.T, res *sa.Result, name string) *sa.Finding {
	t.Helper()
	for _, f := range res.Findings {
		if f.DisplayName == name {
			return f
		}
	}
	t.Fatalf("no finding named %q", name)
	return nil
}

func signal(f *sa.Finding, code string) *sa.Signal {
	for i := range f.Signals {
		if f.Signals[i].Code == code {
			return &f.Signals[i]
		}
	}
	return nil
}

func callResult(res *sa.Result, call string) *models.ShadowScanCallResult {
	for i := range res.Calls {
		if res.Calls[i].Call == call {
			return &res.Calls[i]
		}
	}
	return nil
}

func assertNoMarkers(t *testing.T, res any, logs string) {
	t.Helper()
	b, err := json.Marshal(res)
	require.NoError(t, err)
	for _, m := range retentionMarkers {
		assert.NotContains(t, string(b), m, "result must not contain %q", m)
		assert.NotContains(t, logs, m, "logs must not contain %q", m)
	}
}

func TestMetricsEitherOr(t *testing.T) {
	d := &dayMetrics{aoaiRequests: 3, modelRequests: 5, promptTokens: 10, inputTokens: 7, genTokens: 1, outputTokens: 4}
	assert.Equal(t, int64(5), d.requests())
	assert.Equal(t, int64(10), d.input())
	assert.Equal(t, int64(4), d.output())
	u := deploymentUsage{
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC): {aoaiRequests: 2},
		time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC): {inputTokens: 9},
	}
	total, active := u.totals()
	assert.Equal(t, int64(2), total)
	assert.Equal(t, 1, active)
	assert.Len(t, u.days(), 2)
}

func TestBuildURL(t *testing.T) {
	got := buildURL("https://arm.example.com/", "/subscriptions/a b/x", qp{"api-version", "1"}, qp{"$filter", "a eq 'b'"})
	assert.Equal(t, "https://arm.example.com/subscriptions/a%20b/x?api-version=1&$filter=a%20eq%20%27b%27", got)
}
