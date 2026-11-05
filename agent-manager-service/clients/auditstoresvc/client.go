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

// Package auditstoresvc reads audit records back from the log store
// (OpenSearch) that the platform's Fluent Bit ships them to.
//
// It is deliberately a thin search transport: it sends one _search request to
// a configured index pattern and returns the raw response body. Query
// construction and org scoping live in the service layer, where they are unit
// tested; nothing here decides which records a caller may see.
package auditstoresvc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

//go:generate moq -rm -fmt goimports -skip-ensure -pkg clientmocks -out ../clientmocks/audit_store_client_fake.go . AuditStoreClient:AuditStoreClientMock

// AuditStoreClient searches the audit indices.
type AuditStoreClient interface {
	// Search runs one _search request with the given JSON body against the
	// configured index pattern and returns the response body.
	Search(ctx context.Context, body []byte) ([]byte, error)
}

// MaxResponseBytes caps a search response. A page is at most 201 documents;
// gateway lines are a few KiB each, so this leaves an order of magnitude of
// headroom while bounding memory if the store misbehaves.
const MaxResponseBytes = 16 << 20

// maxErrorBodyBytes caps how much of an error response is read for the log.
const maxErrorBodyBytes = 4 << 10

// ErrStoreUnavailable wraps every failure to obtain a usable response:
// transport errors, timeouts, non-2xx statuses and oversized bodies. Callers
// map it to 502 without exposing the detail to the client.
var ErrStoreUnavailable = errors.New("audit store unavailable")

// Config configures the client.
type Config struct {
	BaseURL            string
	Username           string
	Password           string
	IndexPattern       string
	InsecureSkipVerify bool
	// CAFile is a PEM bundle trusted, alongside the system roots, for the
	// store's certificate. Empty uses the system roots only.
	CAFile  string
	Timeout time.Duration
}

type client struct {
	searchURL  string
	username   string
	password   string
	httpClient *http.Client
}

// NewAuditStoreClient builds a client. The configuration is validated at
// startup (config.validateAuditQueryConfig); this only re-checks what would
// otherwise produce a malformed request.
func NewAuditStoreClient(cfg Config) (AuditStoreClient, error) {
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("invalid audit store URL %q", cfg.BaseURL)
	}
	if cfg.IndexPattern == "" || strings.ContainsAny(cfg.IndexPattern, ",/?# ") {
		return nil, fmt.Errorf("invalid audit index pattern %q", cfg.IndexPattern)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if cfg.CAFile != "" && cfg.InsecureSkipVerify {
		return nil, errors.New("audit store CA file and insecure skip verify are mutually exclusive")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Only for local clusters whose store presents a self-signed
		// certificate; off unless AUDIT_OPENSEARCH_INSECURE_SKIP_VERIFY is set.
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // operator opt-in for self-signed local stores
	}
	if cfg.CAFile != "" {
		pool, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.ResponseHeaderTimeout = timeout
	transport.MaxIdleConnsPerHost = 4

	// Allow-listed query string: ignore a missing index (no audit record has
	// been shipped yet) rather than failing, and never let a partial result from
	// a failed shard pass as a complete answer.
	searchURL := fmt.Sprintf("%s/%s/_search?ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false",
		base.String(), url.PathEscape(cfg.IndexPattern))
	return &client{
		searchURL: searchURL,
		username:  cfg.Username,
		password:  cfg.Password,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// The store has no reason to redirect a search; following one would
			// resend the credentials to wherever it points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// loadCAPool returns the system roots plus every certificate in the PEM file.
// A file with no certificate is an error: trusting nothing new while the
// operator believes a CA is configured would fail every query with an
// unhelpful TLS error.
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read audit store CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("audit store CA file %q contains no PEM certificate", path)
	}
	return pool, nil
}

func (c *client) Search(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.searchURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build audit search request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, fmt.Errorf("%w: search returned HTTP %d: %s", ErrStoreUnavailable, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read search response: %w", ErrStoreUnavailable, err)
	}
	if len(data) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: search response exceeds %d bytes", ErrStoreUnavailable, MaxResponseBytes)
	}
	return data, nil
}
