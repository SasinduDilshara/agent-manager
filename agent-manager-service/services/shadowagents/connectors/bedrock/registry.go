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

package bedrock

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	reg "github.com/aws/aws-sdk-go-v2/service/agentregistrycontrol"
	regtypes "github.com/aws/aws-sdk-go-v2/service/agentregistrycontrol/types"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// scanRegistry lists the AWS Agent Registry registries of the region and
// their records, on the agent-registry-control service (the bedrock-agentcore
// registry namespace shut down on 2026-10-30; evidence §2.5).
func (s *scan) scanRegistry(ctx context.Context, rc *regionClients) {
	p := reg.NewListRegistriesPaginator(rc.registry, &reg.ListRegistriesInput{Filters: nil, MaxResults: aws.Int32(pageSize), NextToken: nil})
	var ids []string
	n, err := paginate(ctx, maxPages, p.HasMorePages, func(ctx context.Context) (int, error) {
		out, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, r := range out.Registries {
			if id := str(r.RegistryId); id != "" {
				ids = append(ids, id)
			}
		}
		return len(out.Registries), nil
	})
	s.calls.Record(callListRegistries, n, err)
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		s.registryRecords(ctx, rc, id)
	}
}

// registryRecords lists every record of a registry (no filters: every record
// type and status is evidence). The summary carries all that is needed
// (recordType, names, provenance), so GetRegistryRecord, whose descriptors
// and customMetadata are @sensitive, is not called.
func (s *scan) registryRecords(ctx context.Context, rc *regionClients, registryID string) {
	p := reg.NewListRegistryRecordsPaginator(rc.registry, &reg.ListRegistryRecordsInput{
		RegistryId: aws.String(registryID), Filters: nil, MaxResults: aws.Int32(pageSize), NextToken: nil,
	})
	n, err := paginate(ctx, maxPages, p.HasMorePages, func(ctx context.Context) (int, error) {
		out, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, r := range out.RegistryRecords {
			s.registryRecord(rc.region, r)
		}
		return len(out.RegistryRecords), nil
	})
	s.calls.Record(callListRecords, n, err)
}

func (s *scan) registryRecord(region string, r regtypes.RegistryRecordSummary) {
	arn := str(r.RecordArn)
	if arn == "" {
		return
	}
	code := sa.SigBedrockRegistryTool
	kind := models.ShadowKindToolInfra
	if r.RecordType == regtypes.RecordTypeAgent {
		code = sa.SigBedrockRegistryAgent
		kind = models.ShadowKindPlatformAgent
	}
	sig := sa.Signal{Code: code, Source: callListRecords, Observed: map[string]any{"recordType": string(r.RecordType)}}

	// A record detected from (or describing) an AgentCore runtime or gateway
	// is the same workload: its evidence goes to that finding.
	if f := s.provenanceTarget(region, r.ProvenanceSummaryList); f != nil {
		f.AddSignal(sig)
		f.Attributes["recordType"] = string(r.RecordType)
		return
	}

	f := s.fs.Get(kind, arn)
	name := str(r.DisplayName)
	if name == "" {
		name = str(r.Name)
	}
	f.DisplayName = sa.SanitizeName(name)
	f.Scope = region
	f.State = string(r.Status)
	f.ProviderCreatedAt = timePtr(r.CreatedAt)
	f.Attributes["region"] = region
	f.Attributes["resourceId"] = arn
	f.Attributes["recordType"] = string(r.RecordType)
	f.Attributes["status"] = string(r.Status)
	f.Attributes["agentVersion"] = str(r.RecordVersion)
	if dn := str(r.DisplayName); dn != "" {
		f.Attributes["displayName"] = dn
	}
	// description is @sensitive (evidence §2.5): never stored.
	f.AddSignal(sig)
}

// provenanceTarget returns the runtime or gateway finding a record's
// provenance names, if this scan found it.
func (s *scan) provenanceTarget(region string, prov []regtypes.ProvenanceSummary) *sa.Finding {
	for _, p := range prov {
		src := str(p.SourceId)
		if src == "" {
			continue
		}
		switch {
		case p.SourceType == regtypes.SourceTypeAwsBedrockAgentcoreRuntime || strings.Contains(src, ":runtime/"):
			if f := s.runtimeByARN[src]; f != nil {
				return f
			}
			if id := arnResourceID(src, "runtime/"); id != "" {
				if f := s.runtimeByID[arnRegion(src, region)+"|"+id]; f != nil {
					return f
				}
			}
		case p.SourceType == regtypes.SourceTypeAwsBedrockAgentcoreGateway || strings.Contains(src, ":gateway/"):
			if id := arnResourceID(src, "gateway/"); id != "" {
				if f := s.gatewayByID[arnRegion(src, region)+"|"+id]; f != nil {
					return f
				}
			}
		}
	}
	return nil
}

// arnResourceID returns the ID after prefix in an ARN's resource part,
// up to the next "/" (e.g. "runtime/<id>/runtime-endpoint/DEFAULT").
func arnResourceID(arn, prefix string) string {
	i := strings.Index(arn, prefix)
	if i < 0 {
		return ""
	}
	id := arn[i+len(prefix):]
	if j := strings.IndexByte(id, '/'); j >= 0 {
		id = id[:j]
	}
	return id
}

// arnRegion returns the region field of an ARN, or def.
func arnRegion(arn, def string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[3] != "" {
		return parts[3]
	}
	return def
}
