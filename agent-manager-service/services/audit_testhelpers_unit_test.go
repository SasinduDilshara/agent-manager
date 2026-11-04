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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/wso2/agent-manager/agent-manager-service/repositories"
	"github.com/wso2/agent-manager/agent-manager-service/repositories/repomocks"
)

// Identifiers below are the ones in the live fixture records (testdata/audit),
// captured from a local cluster in which org "default" ran three agents.
const (
	auditTestOUID      = "01900000-0000-7000-8000-000000000001"
	auditTestOrgHandle = "default"

	auditTestExtProxy     = "audit-llm-3dc9f0dbfb6c4d76-27f6b597-proxy"
	auditTestExtRespProxy = "audit-llm-2e466efd806c9a3e-27f6b597-proxy"
	auditTestIntProxy     = "int-llm-1382e9cebe5634a0-27f6b597-proxy"

	auditTestExtAgentID  = "01a1a364-bef0-7b63-bad3-f7f002d3e771"
	auditTestExtClientID = "8MrgYJLUzHxuGCysR_wQ0g"
	auditTestIntAgentID  = "01a1a370-9edf-76d9-b093-b19ff4c9383c"
	auditTestIntClientID = "XSEAcx4PKsuGH_oNsN4LkA"

	auditTestIntArtifact = "01a1a370-9a24-7d3c-a37f-f6bf20d1c4cc"
	auditTestA2AArtifact = "01a1a5fb-868f-752a-a6ef-f8ba3e8733d7"
	auditTestEnvUUID     = "ca151496-8f62-42de-b7df-d72ae7c4eaab"

	// The end user in the delegated (OBO) MCP calls.
	auditTestUserID = "01900000-0000-7000-8000-000000000030"
)

// auditTestRepo returns a fake attribution repository mirroring the live DB the
// fixtures were captured against.
func auditTestRepo() *repomocks.AuditAttributionRepositoryMock {
	return &repomocks.AuditAttributionRepositoryMock{
		ListLLMProxyAgentsFunc: func(_ context.Context, ouID string) ([]repositories.AuditLLMProxyAgent, error) {
			if ouID != auditTestOUID {
				return []repositories.AuditLLMProxyAgent{}, nil
			}
			return []repositories.AuditLLMProxyAgent{
				{ArtifactUUID: "66dfcb4f-2950-4318-be53-56bc4658ba5b", Handle: auditTestExtProxy, ProjectName: "default", AgentName: "ext-audit-agent"},
				{ArtifactUUID: "cc119718-b870-4ca8-a751-bf9845501588", Handle: auditTestExtRespProxy, ProjectName: "default", AgentName: "ext-audit-agent"},
				{ArtifactUUID: "25084105-65fe-4208-bd14-03cbd94ea604", Handle: auditTestIntProxy, ProjectName: "default", AgentName: "int-audit-agent"},
			}, nil
		},
		ListAgentIdentitiesFunc: func(_ context.Context, ouID string) ([]repositories.AuditAgentIdentity, error) {
			if ouID != auditTestOUID {
				return []repositories.AuditAgentIdentity{}, nil
			}
			return []repositories.AuditAgentIdentity{
				{ProjectName: "default", AgentName: "ext-audit-agent", EnvironmentName: "default", ThunderAgentID: auditTestExtAgentID, ThunderClientID: auditTestExtClientID},
				{ProjectName: "default", AgentName: "int-audit-agent", EnvironmentName: "default", ThunderAgentID: auditTestIntAgentID, ThunderClientID: auditTestIntClientID},
				{ProjectName: "default", AgentName: "a2a-notes-agent", EnvironmentName: "default", ThunderAgentID: "01a1a5fb-8b50-7c9d-9d2e-52a199247511", ThunderClientID: "cAAGTzPMSH0OBjaeVsztwg"},
			}, nil
		},
		ListAgentArtifactsFunc: func(_ context.Context, ouID string) ([]repositories.AuditAgentArtifact, error) {
			if ouID != auditTestOUID {
				return []repositories.AuditAgentArtifact{}, nil
			}
			return []repositories.AuditAgentArtifact{
				{ArtifactUUID: auditTestIntArtifact, Handle: "default/int-audit-agent/" + auditTestEnvUUID, Kind: "Agent", AgentUUID: "11111111-1111-1111-1111-111111111111"},
				{ArtifactUUID: auditTestA2AArtifact, Handle: "default/a2a-notes-agent/" + auditTestEnvUUID, Kind: "Agent"},
				// A user REST API artifact is not an agent's and must be ignored.
				{ArtifactUUID: "22222222-2222-2222-2222-222222222222", Handle: "orders-api", Kind: "RestApi"},
			}, nil
		},
		ListAPIKeysFunc: func(_ context.Context, _ string) ([]repositories.AuditAPIKey, error) {
			return []repositories.AuditAPIKey{}, nil
		},
	}
}

func auditTestIndex(t *testing.T) *AuditAgentIndex {
	t.Helper()
	idx, err := NewAuditAgentResolver(auditTestRepo(), "").Index(context.Background(), auditTestOUID)
	if err != nil {
		t.Fatalf("build index: %v", err)
	}
	return idx
}

// loadAuditFixture reads an NDJSON fixture and returns each line as the
// document Fluent Bit would index: the parsed line plus audit_source and the
// Kubernetes metadata.
func loadAuditFixture(t *testing.T, name, source, namespace string) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "audit", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	var docs []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		doc := map[string]any{}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("decode fixture line: %v", err)
		}
		doc["audit_source"] = source
		doc["kubernetes"] = map[string]any{"namespace_name": namespace}
		docs = append(docs, doc)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return docs
}

func loadGatewayFixture(t *testing.T) []map[string]any {
	t.Helper()
	return loadAuditFixture(t, "gateway_traffic.ndjson", auditSourceGateway, "default-default")
}

func loadControlPlaneFixture(t *testing.T) []map[string]any {
	t.Helper()
	return loadAuditFixture(t, "control_plane.ndjson", auditSourceControlPlane, "wso2-amp")
}
