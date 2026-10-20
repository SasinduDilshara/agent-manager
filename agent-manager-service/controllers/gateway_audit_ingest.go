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

package controllers

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/wso2/agent-manager/agent-manager-service/middleware/logger"
	"github.com/wso2/agent-manager/agent-manager-service/services"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// auditIngestRetryAfterSeconds is how soon a gateway is asked to resend a batch
// that could not be written.
const auditIngestRetryAfterSeconds = 5

// IngestAuditEvents handles POST /api/internal/v1/audit/gateway-events.
//
// The body is an OTLP/HTTP JSON logs export request from the gateway's OTel
// analytics publisher: one log record per request the gateway handled. The
// answers follow that publisher's delivery rules — it retries 429 and 5xx and
// drops a batch on any other 4xx — so a batch that could not be written is a
// 503 (resent), and only a batch that can never be accepted is a 4xx.
func (c *gatewayInternalController) IngestAuditEvents(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger(r.Context())

	// Authenticated first, so only a gateway learns whether the ingest is on.
	identity, ok := c.authenticateGateway(w, r, "audit-ingest")
	if !ok {
		return
	}

	if c.auditIngest == nil {
		// Not a 5xx: the gateway would resend forever to a deployment that has
		// the feature turned off. Its own audit configuration is what to fix.
		http.Error(w, "Gateway audit ingest is not enabled on this deployment", http.StatusNotFound)
		return
	}

	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json (OTLP/HTTP JSON)", http.StatusUnsupportedMediaType)
		return
	}

	body, err := readAuditIngestBody(w, r, c.auditIngestMaxBodyBytes)
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge), errors.Is(err, errAuditBodyTooLarge):
			http.Error(w, fmt.Sprintf("Batch exceeds %d bytes", c.auditIngestMaxBodyBytes), http.StatusRequestEntityTooLarge)
		case errors.Is(err, errUnsupportedEncoding):
			http.Error(w, "Content-Encoding must be gzip or absent", http.StatusUnsupportedMediaType)
		default:
			http.Error(w, "Could not read the batch", http.StatusBadRequest)
		}
		return
	}

	result, err := c.auditIngest.Ingest(r.Context(), services.GatewayAuditCaller{
		GatewayID: identity.ID,
		OUID:      identity.OUID,
	}, body)
	if err != nil {
		switch {
		case errors.Is(err, utils.ErrMalformedAuditBatch):
			log.Warn("Rejected malformed gateway audit batch", "gatewayId", identity.ID, "error", err)
			http.Error(w, "The body is not an OTLP logs export request", http.StatusBadRequest)
		case errors.Is(err, utils.ErrAuditIngestUnavailable):
			log.Error("Gateway audit batch could not be written; asking the gateway to resend",
				"gatewayId", identity.ID, "error", err)
			w.Header().Set("Retry-After", strconv.Itoa(auditIngestRetryAfterSeconds))
			http.Error(w, "Audit ingest is temporarily unavailable", http.StatusServiceUnavailable)
		default:
			log.Error("Gateway audit ingest failed", "gatewayId", identity.ID, "error", err)
			http.Error(w, "Audit ingest failed", http.StatusInternalServerError)
		}
		return
	}

	writeOTLPExportResponse(w, result)
}

var (
	errAuditBodyTooLarge   = errors.New("batch too large")
	errUnsupportedEncoding = errors.New("unsupported content encoding")
)

// readAuditIngestBody reads the batch, decompressing gzip, and bounds both the
// bytes on the wire and the decompressed size by limit.
func readAuditIngestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	reader := io.Reader(http.MaxBytesReader(w, r.Body, limit))
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		defer func() { _ = gz.Close() }()
		reader = gz
	default:
		return nil, errUnsupportedEncoding
	}
	// One byte past the limit tells "exactly at the limit" from "over it".
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errAuditBodyTooLarge
	}
	return body, nil
}

// otlpExportResponse is the OTLP ExportLogsServiceResponse. A partial success
// tells the publisher records were refused even though the batch was accepted.
type otlpExportResponse struct {
	PartialSuccess *otlpPartialSuccess `json:"partialSuccess,omitempty"`
}

type otlpPartialSuccess struct {
	// Encoded as a string: proto3 JSON maps int64 to a string.
	RejectedLogRecords string `json:"rejectedLogRecords"`
	ErrorMessage       string `json:"errorMessage,omitempty"`
}

func writeOTLPExportResponse(w http.ResponseWriter, result *services.GatewayAuditIngestResult) {
	resp := otlpExportResponse{}
	if result != nil && result.Rejected > 0 {
		reasons := make([]string, 0, len(result.RejectReasons))
		for reason, n := range result.RejectReasons {
			reasons = append(reasons, fmt.Sprintf("%s=%d", reason, n))
		}
		sort.Strings(reasons)
		resp.PartialSuccess = &otlpPartialSuccess{
			RejectedLogRecords: strconv.Itoa(result.Rejected),
			ErrorMessage:       "records not accepted: " + strings.Join(reasons, ", "),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
