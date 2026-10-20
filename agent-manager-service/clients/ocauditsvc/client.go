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

// Package ocauditsvc reads the audit trail through the OpenChoreo Observer's
// audit API (POST /api/v1alpha1/audit-logs/query and /filter-values).
//
// The Observer authorizes audit reads at cluster scope only, so this client
// holds a cluster-wide read. Confining a read to one organization is the
// caller's job, on every request: see services.AuditTrailService.
package ocauditsvc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	occlient "github.com/wso2/agent-manager/agent-manager-service/clients/openchoreosvc/client"
	"github.com/wso2/agent-manager/agent-manager-service/clients/requests"
)

const (
	queryPath        = "/api/v1alpha1/audit-logs/query"
	filterValuesPath = "/api/v1alpha1/audit-logs/filter-values"
)

// ErrNotSupported is returned when the Observer's logs backend cannot serve
// audit records (the Observer answers 501). Distinct from a failure: nothing is
// wrong, the installed logs module simply has no audit support.
var ErrNotSupported = errors.New("audit logs are not supported by the observability backend")

// ErrInvalidRequest is returned when the Observer rejects a query as invalid.
var ErrInvalidRequest = errors.New("audit log query rejected as invalid")

// ErrAccessDenied is returned when the Observer refuses this service's own
// identity — a deployment fault (missing role binding), never a caller's.
var ErrAccessDenied = errors.New("audit log read refused for agent-manager-service's identity")

// Client reads audit records from the OpenChoreo Observer.
//
//go:generate moq -rm -fmt goimports -skip-ensure -pkg clientmocks -out ../clientmocks/oc_audit_client_fake.go . Client:OCAuditClientMock
type Client interface {
	QueryAuditLogs(ctx context.Context, req QueryRequest) (*QueryResponse, error)
	QueryFilterValues(ctx context.Context, req FilterValuesRequest) (*FilterValuesResponse, error)
}

// Config configures the client.
type Config struct {
	// BaseURL is the Observer's public API base, e.g.
	// http://observer.openchoreo-observability-plane.svc.cluster.local:8080.
	BaseURL      string
	AuthProvider occlient.AuthProvider
	RetryConfig  requests.RequestRetryConfig
}

type client struct {
	baseURL      string
	httpClient   requests.HttpClient
	authProvider occlient.AuthProvider
}

// NewClient returns an Observer audit client.
func NewClient(cfg *Config) (Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if cfg.AuthProvider == nil {
		return nil, fmt.Errorf("auth provider is required")
	}
	return &client{
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		httpClient:   requests.NewRetryableHTTPClient(&http.Client{}, cfg.RetryConfig),
		authProvider: cfg.AuthProvider,
	}, nil
}

func (c *client) QueryAuditLogs(ctx context.Context, req QueryRequest) (*QueryResponse, error) {
	var out QueryResponse
	if err := c.post(ctx, queryPath, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *client) QueryFilterValues(ctx context.Context, req FilterValuesRequest) (*FilterValuesResponse, error) {
	var out FilterValuesResponse
	if err := c.post(ctx, filterValuesPath, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// post sends an authenticated JSON POST and decodes a 200 into out, retrying
// once with a fresh token on a 401 (the cached token may have been revoked or
// the identity provider's keys rotated).
func (c *client) post(ctx context.Context, path string, body, out any) error {
	name := "ocauditsvc" + path
	result, err := c.send(ctx, name, path, body)
	if err != nil {
		return err
	}
	scanErr := result.ScanResponse(out, http.StatusOK)
	var httpErr *requests.HttpError
	if errors.As(scanErr, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized {
		c.authProvider.InvalidateToken()
		if result, err = c.send(ctx, name, path, body); err != nil {
			return err
		}
		scanErr = result.ScanResponse(out, http.StatusOK)
	}
	return classify(name, scanErr)
}

func (c *client) send(ctx context.Context, name, path string, body any) (*requests.Result, error) {
	token, err := c.authProvider.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get auth token: %w", name, err)
	}
	req := (&requests.HttpRequest{
		Name:   name,
		URL:    c.baseURL + path,
		Method: http.MethodPost,
	}).SetJson(body)
	if strings.TrimSpace(token) != "" {
		req.SetHeader("Authorization", "Bearer "+token)
	}
	result := requests.SendRequest(ctx, c.httpClient, req)
	if result == nil {
		return nil, fmt.Errorf("%s: request returned nil result", name)
	}
	return result, nil
}

// classify maps the Observer's documented statuses onto sentinel errors.
func classify(name string, err error) error {
	if err == nil {
		return nil
	}
	var httpErr *requests.HttpError
	if !errors.As(err, &httpErr) {
		return fmt.Errorf("%s: %w", name, err)
	}
	switch httpErr.StatusCode {
	case http.StatusNotImplemented:
		return ErrNotSupported
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrInvalidRequest, httpErr.Body)
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w (status %d)", ErrAccessDenied, httpErr.StatusCode)
	default:
		return fmt.Errorf("%s: %w", name, err)
	}
}
