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

package auditstoresvc

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, srv *httptest.Server, timeout time.Duration) AuditStoreClient {
	t.Helper()
	c, err := NewAuditStoreClient(Config{
		BaseURL: srv.URL, Username: "reader", Password: "pw", IndexPattern: "amp-audit-*", Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("NewAuditStoreClient: %v", err)
	}
	return c
}

func TestSearch_SendsAuthenticatedSearchToIndexPattern(t *testing.T) {
	var gotPath, gotQuery, gotUser, gotPass, gotBody, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		gotUser, gotPass, _ = r.BasicAuth()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer srv.Close()

	out, err := newTestClient(t, srv, time.Second).Search(context.Background(), []byte(`{"size":1}`))
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if string(out) != `{"hits":{"hits":[]}}` {
		t.Fatalf("unexpected body %q", out)
	}
	if gotMethod != http.MethodPost || gotPath != "/amp-audit-*/_search" {
		t.Fatalf("unexpected request %s %s", gotMethod, gotPath)
	}
	if !strings.Contains(gotQuery, "allow_partial_search_results=false") || !strings.Contains(gotQuery, "ignore_unavailable=true") {
		t.Fatalf("unexpected query %q", gotQuery)
	}
	if gotUser != "reader" || gotPass != "pw" {
		t.Fatalf("basic auth not sent")
	}
	if gotBody != `{"size":1}` {
		t.Fatalf("unexpected request body %q", gotBody)
	}
}

func TestSearch_ErrorsAreStoreUnavailable(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{
			name: "non-2xx status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
			},
		},
		{
			name: "oversized response",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("x", MaxResponseBytes+10)))
			},
		},
		{
			name: "timeout",
			handler: func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
			},
			timeout: 100 * time.Millisecond,
		},
		{
			name: "redirect is not followed",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			timeout := tt.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			_, err := newTestClient(t, srv, timeout).Search(context.Background(), []byte(`{}`))
			if !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("got %v, want ErrStoreUnavailable", err)
			}
		})
	}
}

func TestNewAuditStoreClient_RejectsUnsafeIndexPattern(t *testing.T) {
	for _, p := range []string{"", "a,b", "a/b", "a?b"} {
		if _, err := NewAuditStoreClient(Config{BaseURL: "https://os:9200", IndexPattern: p}); err == nil {
			t.Fatalf("pattern %q accepted", p)
		}
	}
}

// writeServerCA writes the TLS test server's certificate as a PEM CA bundle.
func writeServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return path
}

func TestSearch_TLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer srv.Close()
	base := Config{BaseURL: srv.URL, Username: "reader", Password: "pw", IndexPattern: "amp-audit-*", Timeout: time.Second}

	t.Run("an unknown CA is refused by default", func(t *testing.T) {
		c, err := NewAuditStoreClient(base)
		if err != nil {
			t.Fatalf("NewAuditStoreClient: %v", err)
		}
		if _, err := c.Search(context.Background(), []byte(`{}`)); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("expected a TLS failure wrapped as ErrStoreUnavailable, got %v", err)
		}
	})
	t.Run("a configured CA bundle is trusted, with verification on", func(t *testing.T) {
		cfg := base
		cfg.CAFile = writeServerCA(t, srv)
		c, err := NewAuditStoreClient(cfg)
		if err != nil {
			t.Fatalf("NewAuditStoreClient: %v", err)
		}
		if _, err := c.Search(context.Background(), []byte(`{}`)); err != nil {
			t.Fatalf("Search with the CA: %v", err)
		}
	})
	t.Run("a CA file without a certificate is rejected at startup", func(t *testing.T) {
		cfg := base
		cfg.CAFile = filepath.Join(t.TempDir(), "empty.crt")
		if err := os.WriteFile(cfg.CAFile, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewAuditStoreClient(cfg); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
			t.Fatalf("expected a no-certificate error, got %v", err)
		}
	})
	t.Run("a missing CA file is rejected at startup", func(t *testing.T) {
		cfg := base
		cfg.CAFile = filepath.Join(t.TempDir(), "missing.crt")
		if _, err := NewAuditStoreClient(cfg); err == nil {
			t.Fatal("expected an error for a missing CA file")
		}
	})
	t.Run("a CA file with skip-verify is rejected", func(t *testing.T) {
		cfg := base
		cfg.CAFile = writeServerCA(t, srv)
		cfg.InsecureSkipVerify = true
		if _, err := NewAuditStoreClient(cfg); err == nil {
			t.Fatal("expected mutually exclusive settings to be rejected")
		}
	})
}
