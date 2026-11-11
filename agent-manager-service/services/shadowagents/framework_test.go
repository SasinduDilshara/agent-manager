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

package shadowagents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/agent-manager/agent-manager-service/models"
)

// ---- scoring ----

func TestScoreVerdicts(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		codes   []string
		score   int
		verdict string
	}{
		{"agent object alone is an agent", models.ShadowKindPlatformAgent, []string{SigOpenAIAgentObject}, 60, models.ShadowVerdictAgent},
		{"plain usage only", models.ShadowKindAPIKey, []string{SigOpenAIPlainUsage}, 5, models.ShadowVerdictLLMConsumer},
		{"tool call + plain usage is a possible agent", models.ShadowKindAPIKey, []string{SigOpenAIToolCallBatch, SigOpenAIPlainUsage}, 40, models.ShadowVerdictPossibleAgent},
		{"tool call + tool result + usage is an agent", models.ShadowKindAPIKey, []string{SigOpenAIToolCallBatch, SigOpenAIToolResultBatch, SigOpenAIPlainUsage}, 75, models.ShadowVerdictAgent},
		{"mediums without a high stay LLM consumer", models.ShadowKindAPIKey, []string{SigOpenAIHostedSearch, SigOpenAICodeInterpreter, SigOpenAIPlainUsage}, 25, models.ShadowVerdictLLMConsumer},
		{
			"three mediums at 60 without high or definitive are not an agent", models.ShadowKindRuntime,
			[]string{SigGoogleEngineInUse, SigFoundryUsesTools, SigOpenAIHostedSearch},
			60, models.ShadowVerdictLLMConsumer,
		},
		{
			"score is capped", models.ShadowKindPlatformAgent,
			[]string{SigFoundryAgentObject, SigFoundryToolCallResp, SigOpenAIToolResultBatch, SigFoundryUsesTools, SigFoundryPlainUsage},
			100, models.ShadowVerdictAgent,
		},
		{"info signals weigh nothing", models.ShadowKindPlatformAgent, []string{SigFoundryPossibleDupOf}, 0, models.ShadowVerdictLLMConsumer},
		{"unknown codes count nothing", models.ShadowKindAPIKey, []string{"made.up"}, 0, models.ShadowVerdictLLMConsumer},
		{"tool infrastructure is never an agent", models.ShadowKindToolInfra, []string{SigBedrockMCPGateway, SigBedrockRegistryTool}, 0, models.ShadowVerdictToolInfra},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, verdict := Score(tt.kind, tt.codes)
			assert.Equal(t, tt.score, score)
			assert.Equal(t, tt.verdict, verdict)
		})
	}
}

// Related evidence counts once per group: tool calls seen in a batch and in
// stored completions, or plain usage reported by two calls, are one kind of
// evidence about the same workload.
func TestScoreCountsEachGroupOnce(t *testing.T) {
	one, _ := Score(models.ShadowKindAPIKey, []string{SigOpenAIToolCallBatch})
	both, _ := Score(models.ShadowKindAPIKey, []string{SigOpenAIToolCallBatch, SigOpenAIToolCallCompletion})
	assert.Equal(t, one, both)
	dup, _ := Score(models.ShadowKindAPIKey, []string{SigOpenAIPlainUsage, SigOpenAIPlainUsage})
	assert.Equal(t, WeightLow, dup)
}

func TestCatalogIsConsistent(t *testing.T) {
	providers := map[string]bool{}
	for _, p := range models.ShadowProviders {
		providers[p] = true
	}
	for _, d := range Defs() {
		assert.True(t, providers[d.Provider], d.Code)
		assert.True(t, strings.HasPrefix(d.Code, d.Provider+"."), "code %s is prefixed by its provider", d.Code)
		assert.NotEmpty(t, d.Condition, d.Code)
		assert.Equal(t, tierWeight(d.Tier), d.Weight, d.Code)
		if d.Group == GroupInfo {
			assert.Equal(t, WeightInfo, d.Weight, d.Code)
		}
	}
	for _, p := range Providers() {
		assert.True(t, providers[p.Provider], p.Provider)
		assert.NotEmpty(t, p.Endpoints, p.Provider)
		assert.NotEmpty(t, p.Permissions, p.Provider)
		for _, e := range p.Endpoints {
			require.NoError(t, ValidateEndpoint(e, e.Default), "%s %s", p.Provider, e.Key)
			assert.True(t, IsOfficialHost(e, e.Default), "%s %s default is official", p.Provider, e.Key)
		}
		for _, perm := range p.Permissions {
			if perm.Policy != "" {
				assert.True(t, json.Valid([]byte(perm.Policy)), "%s policy is JSON", p.Provider)
			}
		}
		// The console renders a heading before the first field of a section,
		// so every field after it must belong to that section.
		section := ""
		for _, f := range p.Fields {
			if section != "" {
				assert.Equal(t, section, f.Section, "%s: field %s after section %q", p.Provider, f.Key, section)
			}
			if f.Section != "" {
				section = f.Section
			}
		}
	}
}

// ---- retention ----

// TestCapabilitiesAreConsistent checks the "What can Agent Manager
// analyze?" data against the catalog: every capability's signals exist and
// belong to the provider, every need is a field or option of the provider,
// every signal the provider can emit is covered by some capability, and the
// credential choices name optional credential fields.
func TestCapabilitiesAreConsistent(t *testing.T) {
	for _, p := range Providers() {
		caps := Capabilities(p.Provider)
		require.NotEmpty(t, caps, p.Provider)
		covered := map[string]bool{}
		keys := map[string]bool{}
		for _, c := range caps {
			assert.NotEmpty(t, c.Title, c.Key)
			assert.NotEmpty(t, c.Description, c.Key)
			assert.False(t, keys[c.Key], "duplicate capability key %s", c.Key)
			keys[c.Key] = true
			for _, code := range c.Signals {
				d, ok := Def(code)
				if assert.True(t, ok, "%s: unknown signal %s", c.Key, code) {
					assert.Equal(t, p.Provider, d.Provider, "%s: signal %s of another provider", c.Key, code)
				}
				covered[code] = true
			}
			for _, need := range c.Needs {
				_, ok := p.Field(need)
				assert.True(t, ok, "%s: need %q is not a field of %s", c.Key, need, p.Provider)
			}
		}
		for _, d := range Defs() {
			if d.Provider == p.Provider {
				assert.True(t, covered[d.Code], "%s: signal %s is in no capability", p.Provider, d.Code)
			}
		}
		if choice, ok := CredentialChoiceOf(p.Provider); ok {
			assert.NotEmpty(t, choice.Message)
			for _, k := range choice.Fields {
				f, ok := p.Field(k)
				if assert.True(t, ok, "%s: credential choice field %s", p.Provider, k) {
					assert.False(t, f.Required, "%s: a credential choice field must be optional", k)
					assert.Contains(t, []string{FieldSecret, FieldKeyMap, FieldCheckbox}, f.Kind, k)
					if f.Kind == FieldCheckbox {
						assert.True(t, IsServiceOption(k), "%s: a checkbox in a choice must be a service option", k)
					}
				}
			}
		}
	}
	for _, provider := range []string{models.ShadowProviderOpenAI, models.ShadowProviderAnthropic} {
		p, _ := Provider(provider)
		admin, _ := p.Field(FieldAPIKey)
		assert.False(t, admin.Required, "%s Admin key is optional", provider)
		assert.True(t, admin.Recommended, "%s Admin key is recommended", provider)
		_, ok := CredentialChoiceOf(provider)
		assert.True(t, ok, provider)
	}
}

func TestSanitizeAttributesAllowList(t *testing.T) {
	in := map[string]any{
		"model":        "gpt-4.1",
		"instructions": "SECRET-PROMPT-MARKER you are a bot",
		"system":       "SECRET-PROMPT-MARKER",
		"env":          map[string]string{"OPENAI_API_KEY": "sk-test-SECRETSECRETSECRET"},
		"tools":        []ToolRef{{Type: "function", Name: "lookup"}},
		"mcpServers":   []MCPServerRef{{Label: "github", Origin: "https://user:pw@mcp.example.com/sk-test-SECRETSECRETSECRET/sse?token=abc"}},
		"labels":       map[string]string{"team": "payments"},
		"description":  strings.Repeat("x", 1000),
		"unsupported":  struct{ A int }{1},
		"toolCount":    3,
	}
	out := SanitizeAttributes(in)
	b, err := json.Marshal(out)
	require.NoError(t, err)
	s := string(b)
	assert.NotContains(t, s, "SECRET-PROMPT-MARKER")
	assert.NotContains(t, s, "SECRETSECRET")
	assert.NotContains(t, s, "token=abc")
	assert.NotContains(t, s, "user:pw")
	assert.NotContains(t, out, "instructions")
	assert.NotContains(t, out, "env")
	assert.Equal(t, []MCPServerRef{{Label: "github", Origin: "https://mcp.example.com"}}, out["mcpServers"])
	assert.Len(t, out["description"], maxAttrString)
	assert.Equal(t, 3, out["toolCount"])
}

func TestOriginAndRepositoryURL(t *testing.T) {
	assert.Equal(t, "https://h.example.com:8443", Origin("https://u:p@h.example.com:8443/a/b?x=1#f"))
	assert.Equal(t, "", Origin("not a url"))
	assert.Equal(t, "https://github.com/acme/agent", RepositoryURL("https://token@github.com/acme/agent/?ref=main"))
	assert.Equal(t, "", RepositoryURL("git@github.com:acme/agent.git"))
}

func TestScrubTextRemovesCredentials(t *testing.T) {
	msg := "invalid key sk-proj-ABCDEFGH12345678 Authorization: Bearer abc.def.ghi " +
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig AKIAABCDEFGHIJKLMNOP url?api_key=topsecret&x=1"
	out := ScrubText(msg)
	for _, secret := range []string{"sk-proj-ABCDEFGH12345678", "abc.def.ghi", "eyJhbGciOiJIUzI1NiJ9", "AKIAABCDEFGHIJKLMNOP", "topsecret"} {
		assert.NotContains(t, out, secret)
	}
	assert.LessOrEqual(t, len([]rune(ScrubText(strings.Repeat("a ", 400)))), maxMessageChars)
}

func TestSecretHint(t *testing.T) {
	assert.Equal(t, "", SecretHint(""))
	assert.Equal(t, "••••", SecretHint("short"))
	assert.Equal(t, "sk-a…wxyz", SecretHint("sk-admin-1234567890wxyz"))
}

func TestMinimiseOwnerHint(t *testing.T) {
	h := MinimiseOwnerHint(models.ShadowOwnerHint{Name: "  Alice ", Email: strings.Repeat("a", 400) + "@x.com"})
	assert.Equal(t, "Alice", h.Name)
	assert.LessOrEqual(t, len(h.Email), 254)
}

// ---- endpoints ----

func TestValidateEndpoint(t *testing.T) {
	spec := EndpointSpec{Key: "x", Label: "X", Placeholders: []string{"region"}, OfficialHostSuffixes: []string{".amazonaws.com"}}
	require.NoError(t, ValidateEndpoint(spec, "https://svc.{region}.amazonaws.com"))
	require.NoError(t, ValidateEndpoint(spec, "http://localhost:9000"))
	for _, bad := range []string{"", "ftp://x.com", "https://u:p@x.com", "https://x.com?a=1", "https://x.com#f", "https://{location}.x.com", "notaurl"} {
		assert.Error(t, ValidateEndpoint(spec, bad), bad)
	}
	assert.True(t, IsOfficialHost(spec, "https://svc.{region}.amazonaws.com"))
	assert.False(t, IsOfficialHost(spec, "https://amazonaws.com.evil.example"))
	assert.False(t, IsOfficialHost(spec, "http://svc.us-east-1.amazonaws.com"), "official endpoints use https")
	assert.False(t, IsOfficialHost(spec, "https://localhost:9000"))
}

func TestExpand(t *testing.T) {
	got, err := Expand("https://{location}-aiplatform.googleapis.com/", map[string]string{"location": "us-central1"})
	require.NoError(t, err)
	assert.Equal(t, "https://us-central1-aiplatform.googleapis.com", got)
	_, err = Expand("https://svc.{region}.amazonaws.com", map[string]string{})
	assert.Error(t, err)
}

// ---- HTTP client ----

func newTestAPI(srv *httptest.Server) *API {
	return &API{HTTP: srv.Client(), Sleep: func(context.Context, time.Duration) error { return nil }}
}

func TestAPIRetriesOn429WithRetryAfter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	var out struct{ OK bool }
	require.NoError(t, newTestAPI(srv).GetJSON(context.Background(), srv.URL+"/x", nil, &out))
	assert.True(t, out.OK)
	assert.Equal(t, int32(2), calls.Load())
}

func TestAPIGivesUpOnLongRetryAfter(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	err := newTestAPI(srv).GetJSON(context.Background(), srv.URL, nil, nil)
	assert.Equal(t, models.ShadowCallRateLimited, OutcomeOf(err))
}

func TestAPIClassifiesErrorsAndScrubsMessages(t *testing.T) {
	tests := []struct {
		status  int
		body    string
		outcome string
	}{
		{401, `{"error":{"message":"Incorrect API key provided: sk-proj-ABCDEFGH12345678","type":"invalid_request_error"}}`, models.ShadowCallAuthFailed},
		{403, `{"error":"Your key does not have the api.usage.read scope"}`, models.ShadowCallPermissionDenied},
		{404, `{"type":"error","error":{"type":"not_found_error","message":"Not found"}}`, models.ShadowCallNotFound},
		{400, `{"error":{"code":"InvalidFilter","message":"bad filter"}}`, models.ShadowCallFailed},
	}
	for _, tt := range tests {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tt.status)
			_, _ = w.Write([]byte(tt.body))
		}))
		err := newTestAPI(srv).GetJSON(context.Background(), srv.URL, nil, nil)
		srv.Close()
		assert.Equal(t, tt.outcome, OutcomeOf(err), tt.body)
		assert.NotContains(t, MessageOf(err), "sk-proj-ABCDEFGH12345678")
	}
}

func TestAPIMalformedJSONIsUnsupported(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data": "not-a-list"`))
	}))
	defer srv.Close()
	var out struct{ Data []string }
	err := newTestAPI(srv).GetJSON(context.Background(), srv.URL, nil, &out)
	assert.Equal(t, models.ShadowCallUnsupported, OutcomeOf(err))
}

func TestHTTPClientRefusesCrossHostRedirect(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}))
	defer srv.Close()
	api := &API{HTTP: NewHTTPClient(nil), Header: func(h http.Header) { h.Set("Authorization", "Bearer secret") }}
	_, err := api.Do(context.Background(), Request{Method: http.MethodGet, URL: srv.URL})
	require.Error(t, err, "a 302 to another host is not followed and is not a success")
	assert.False(t, leaked.Load(), "the credential never reached the other host")
}

func TestEncodeQueryKeepsArrayBrackets(t *testing.T) {
	q := map[string][]string{"group_by[]": {"api_key_id", "model"}, "filter": {"a[b]"}}
	assert.Equal(t, "filter=a%5Bb%5D&group_by[]=api_key_id&group_by[]=model", encodeQuery(q))
}

func TestAuthorizeErrorIsAuthFailed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	api := newTestAPI(srv)
	api.Authorize = func(context.Context, *http.Request, []byte) error { return errors.New("token endpoint refused") }
	err := api.GetJSON(context.Background(), srv.URL, nil, nil)
	assert.Equal(t, models.ShadowCallAuthFailed, OutcomeOf(err))
}

// ---- calls, findings, usage ----

func TestCallsMergeScopesWorstOutcome(t *testing.T) {
	c := NewCalls()
	c.Record("GET /x", 2, nil)
	c.Record("GET /x", 3, &CallError{Outcome: models.ShadowCallPermissionDenied, Status: 403, Message: "no"})
	c.Record("GET /x", 1, nil)
	c.Skip("GET /y", "deep inspection is off")
	res := c.Results()
	require.Len(t, res, 2)
	assert.Equal(t, models.ShadowCallPermissionDenied, res[0].Outcome)
	assert.Equal(t, 6, res[0].Items)
	assert.Contains(t, res[0].Message, "1 of 3 scopes failed")
	assert.Equal(t, models.ShadowCallSkipped, res[1].Outcome)
	assert.False(t, c.OK("GET /x"))
}

func TestFindingAggregation(t *testing.T) {
	fs := NewFindings()
	f := fs.Get(models.ShadowKindAPIKey, "key_1")
	day := time.Date(2026, 11, 1, 15, 0, 0, 0, time.UTC)
	cost := 1.5
	f.AddUsage(UsageDay{Day: day, KeyID: "key_1", Model: "m", Requests: 2, CostAmount: &cost, Currency: "usd"})
	f.AddUsage(UsageDay{Day: day.Add(time.Hour), KeyID: "key_1", Model: "m", Requests: 3, CostAmount: &cost})
	require.Len(t, f.Usage, 1, "same day, key and model are one row")
	assert.Equal(t, int64(5), f.Usage[0].Requests)
	assert.InDelta(t, 3.0, *f.Usage[0].CostAmount, 1e-9)
	f.AddSignal(Signal{Code: SigOpenAIPlainUsage, Source: "s", Observed: map[string]any{"numModelRequests": int64(2)}})
	f.AddSignal(Signal{Code: SigOpenAIPlainUsage, Source: "s", Observed: map[string]any{"numModelRequests": int64(3)}})
	require.Len(t, f.Signals, 1)
	assert.Equal(t, int64(5), f.Signals[0].Observed["numModelRequests"])
	assert.Same(t, f, fs.Get(models.ShadowKindAPIKey, "key_1"))
	fs.Remove(models.ShadowKindAPIKey, "key_1")
	assert.Empty(t, fs.All())
}

func TestNewWindow(t *testing.T) {
	now := time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC)
	w := NewWindow(now, 30)
	assert.Equal(t, time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC), w.Start)
	assert.Equal(t, now, w.End)
	assert.Equal(t, 31, w.Days())
}
