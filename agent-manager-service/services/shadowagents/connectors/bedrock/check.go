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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	reg "github.com/aws/aws-sdk-go-v2/service/agentregistrycontrol"
	awsbedrock "github.com/aws/aws-sdk-go-v2/service/bedrock"
	ba "github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	ac "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// requiredChecks are the capabilities of which at least one must pass for
// the connection to be usable: the inventory of agents or the model calls.
var requiredChecks = map[string]bool{callListRuntimes: true, callListAgents: true, callLookupEvents: true}

// Test implements sa.Connector: one cheap read per capability, in the first
// configured region. It never reads invocation log content.
func (c *Connector) Test(ctx context.Context, conn sa.Connection) models.ShadowConnectionTestInfo {
	regions := cleanRegions(conn.Config.Regions)
	if len(regions) == 0 {
		return models.ShadowConnectionTestInfo{OK: false, Checks: []models.ShadowConnectionCheck{{
			Name: callConfigure, Outcome: models.ShadowCallFailed, Message: "at least one region is required", Unlocks: nil,
		}}}
	}
	rc, err := newRegionClients(conn, c.http, regions[0], c.retryer)
	if err != nil {
		return models.ShadowConnectionTestInfo{OK: false, Checks: []models.ShadowConnectionCheck{{
			Name: callConfigure, Outcome: models.ShadowCallFailed, Message: sa.ScrubText(err.Error()), Unlocks: nil,
		}}}
	}
	now := time.Now().UTC()
	probes := []struct {
		name    string
		unlocks []string
		call    func(context.Context) error
	}{
		{callListRuntimes, []string{sa.SigBedrockAgentCoreRuntime, sa.SigBedrockRuntimeNotReady}, func(ctx context.Context) error {
			_, err := rc.agentCore.ListAgentRuntimes(ctx, &ac.ListAgentRuntimesInput{MaxResults: aws.Int32(1), NextToken: nil})
			return err
		}},
		{callListGateways, []string{sa.SigBedrockMCPGateway}, func(ctx context.Context) error {
			_, err := rc.agentCore.ListGateways(ctx, &ac.ListGatewaysInput{MaxResults: aws.Int32(1), NextToken: nil})
			return err
		}},
		{callListRegistries, []string{sa.SigBedrockRegistryAgent, sa.SigBedrockRegistryTool}, func(ctx context.Context) error {
			_, err := rc.registry.ListRegistries(ctx, &reg.ListRegistriesInput{Filters: nil, MaxResults: aws.Int32(1), NextToken: nil})
			return err
		}},
		{callListAgents, []string{sa.SigBedrockClassicAgent}, func(ctx context.Context) error {
			_, err := rc.agents.ListAgents(ctx, &ba.ListAgentsInput{MaxResults: aws.Int32(1), NextToken: nil})
			return err
		}},
		{callLoggingConfig, []string{sa.SigBedrockInvocationLogsOff, sa.SigBedrockToolCallLog, sa.SigBedrockToolResultLog}, func(ctx context.Context) error {
			_, err := rc.bedrock.GetModelInvocationLoggingConfiguration(ctx, &awsbedrock.GetModelInvocationLoggingConfigurationInput{})
			return err
		}},
		{callListMetrics, []string{sa.SigBedrockRuntimeInUse}, func(ctx context.Context) error {
			_, err := rc.cloudWatch.ListMetrics(ctx, &cloudwatch.ListMetricsInput{
				Namespace: aws.String(agentCoreNamespace), MetricName: aws.String(sessionCountMetric),
				Dimensions: nil, IncludeLinkedAccounts: nil, NextToken: nil, OwningAccount: nil, RecentlyActive: "",
			})
			return err
		}},
		{callLookupEvents, []string{sa.SigBedrockPlainModelUsage}, func(ctx context.Context) error {
			_, err := rc.cloudTrail.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
				LookupAttributes: []cttypes.LookupAttribute{{AttributeKey: cttypes.LookupAttributeKeyEventSource, AttributeValue: aws.String(bedrockEventSource)}},
				StartTime:        aws.Time(now.Add(-24 * time.Hour)), EndTime: aws.Time(now),
				MaxResults: aws.Int32(1), EventCategory: "", NextToken: nil,
			})
			return err
		}},
	}
	info := models.ShadowConnectionTestInfo{OK: false, Checks: nil}
	requiredOK, authFailed := false, false
	requiredOn, anyOK := false, false
	first := true
	for _, p := range probes {
		if opt := probeService[p.name]; opt != "" && !sa.ServiceEnabled(conn.Config, opt) {
			info.Checks = append(info.Checks, models.ShadowConnectionCheck{
				Name: p.name, Outcome: models.ShadowCallSkipped, Message: sa.ReasonServiceOff, Unlocks: p.unlocks,
			})
			continue
		}
		if requiredChecks[p.name] {
			requiredOn = true
		}
		isFirst := first
		first = false
		err := awsError(p.call(ctx))
		check := models.ShadowConnectionCheck{Name: p.name, Outcome: sa.OutcomeOf(err), Message: sa.MessageOf(err), Unlocks: p.unlocks}
		info.Checks = append(info.Checks, check)
		if isAuthFailure(err) {
			authFailed = true
			if isFirst {
				break
			}
		}
		if err == nil {
			anyOK = true
			if requiredChecks[p.name] {
				requiredOK = true
			}
		}
	}
	// With an inventory or model-call service selected, one of them must
	// work; otherwise any selected service must.
	info.OK = !authFailed && ((requiredOn && requiredOK) || (!requiredOn && anyOK))
	return info
}

// probeService is the optional service each check belongs to.
var probeService = map[string]string{
	callListRuntimes: sa.OptBedrockAgentCore, callListGateways: sa.OptBedrockAgentCore,
	callListRegistries: sa.OptBedrockRegistry, callListAgents: sa.OptBedrockClassicAgents,
	callLoggingConfig: sa.OptBedrockInvocationLogs, callListMetrics: sa.OptBedrockMetrics,
	callLookupEvents: sa.OptBedrockCloudTrail,
}
