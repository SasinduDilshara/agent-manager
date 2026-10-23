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
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"

	"github.com/wso2/agent-manager/agent-manager-service/middleware/logger"
	"github.com/wso2/agent-manager/agent-manager-service/services"
	"github.com/wso2/agent-manager/agent-manager-service/utils"
)

// IngestTrafficAuditEvents handles POST /api/internal/v1/audit/traffic-events.
//
// The body is an NDJSON batch from the gateway's traffic-log HTTP sink: one
// traffic-log line per request the gateway handled. The sink's delivery rules
// match the OTel publisher's — it retries 429 and 5xx and drops a batch on any
// other 4xx — so the statuses follow IngestAuditEvents.
func (c *gatewayInternalController) IngestTrafficAuditEvents(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger(r.Context())

	// Authenticated first, so only a gateway learns whether the feed is on.
	identity, ok := c.authenticateGateway(w, r, "audit-traffic-ingest")
	if !ok {
		return
	}

	if c.trafficAuditIngest == nil {
		http.Error(w, "Gateway traffic-log ingest is not enabled on this deployment", http.StatusNotFound)
		return
	}

	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/x-ndjson" {
		http.Error(w, "Content-Type must be application/x-ndjson (traffic-log lines)", http.StatusUnsupportedMediaType)
		return
	}

	body, err := readAuditIngestBody(w, r, c.trafficAuditIngestMaxBodyBytes)
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge), errors.Is(err, errAuditBodyTooLarge):
			http.Error(w, fmt.Sprintf("Batch exceeds %d bytes", c.trafficAuditIngestMaxBodyBytes), http.StatusRequestEntityTooLarge)
		case errors.Is(err, errUnsupportedEncoding):
			http.Error(w, "Content-Encoding must be gzip or absent", http.StatusUnsupportedMediaType)
		default:
			http.Error(w, "Could not read the batch", http.StatusBadRequest)
		}
		return
	}

	result, err := c.trafficAuditIngest.Ingest(r.Context(), services.GatewayAuditCaller{
		GatewayID: identity.ID,
		OUID:      identity.OUID,
	}, body)
	if err != nil {
		switch {
		case errors.Is(err, utils.ErrMalformedAuditBatch):
			log.Warn("Rejected malformed gateway traffic-log batch", "gatewayId", identity.ID, "error", err)
			http.Error(w, "The body holds no traffic-log line", http.StatusBadRequest)
		case errors.Is(err, utils.ErrAuditIngestUnavailable):
			log.Error("Gateway traffic-log batch could not be written; asking the gateway to resend",
				"gatewayId", identity.ID, "error", err)
			w.Header().Set("Retry-After", strconv.Itoa(auditIngestRetryAfterSeconds))
			http.Error(w, "Audit ingest is temporarily unavailable", http.StatusServiceUnavailable)
		default:
			log.Error("Gateway traffic-log ingest failed", "gatewayId", identity.ID, "error", err)
			http.Error(w, "Audit ingest failed", http.StatusInternalServerError)
		}
		return
	}

	// The sink reads only the status; the counts are for an operator's curl.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted":      result.Accepted,
		"rejected":      result.Rejected,
		"rejectReasons": result.RejectReasons,
	})
}
