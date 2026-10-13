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

// Validates that provisioning an environment with GATEWAY_TOPOLOGY=split
// installs a dedicated INGRESS gateway and a dedicated EGRESS gateway,
// instead of the single combined BOTH gateway a "single" topology gets.

package environment

import (
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/wso2/agent-manager/test/e2e/framework"
	envops "github.com/wso2/agent-manager/test/e2e/operations/environment"
	"github.com/wso2/agent-manager/test/e2e/operations/gateway"
)

var _ = Describe("Environment management: split gateway topology", Label("environment", "split-topology"), Ordered, func() {
	var (
		envName      string
		scriptParams *envops.ScriptParams
	)

	BeforeAll(func() {
		// Split topology tightens add-environment.sh's ENV_NAME length cap (it
		// reserves 7 more characters for the egress release's "-egress" suffix),
		// so keep this name short: E2EEnvPrefix ("e2e-", 4 chars) + a 4-char
		// suffix stays within the 8-char budget the script enforces for the
		// default org in split mode.
		suffix := uuid.New().String()[:4]
		envName = framework.E2EEnvPrefix + suffix
		scriptParams = envops.FromClient(Client)
		scriptParams.EnvName = envName
		scriptParams.DisplayName = "E2E Split Env " + suffix
		scriptParams.Topology = "split"
		// Split mode installs Thunder plus two gateways, each with its own
		// readiness wait; that takes longer than runScript's 6-minute default
		// (the script was killed mid-run in CI). Removal needs the same budget.
		scriptParams.Timeout = 12 * time.Minute
	})

	AfterAll(func() {
		if scriptParams == nil {
			return
		}
		err := envops.RemoveEnvironment(scriptParams)
		Expect(err).NotTo(HaveOccurred(), "remove-environment.sh failed for env %q", envName)
		GinkgoWriter.Printf("Split-topology environment removed: %s\n", envName)
	})

	It("provisions an environment with GATEWAY_TOPOLOGY=split", func() {
		envops.AddEnvironment(scriptParams)

		env := envops.GetEnvironment(Default, Client, Cfg.DefaultOrg, envName)
		Expect(env.Name).To(Equal(envName))
		GinkgoWriter.Printf("Split-topology environment created: %s\n", envName)
	})

	It("ends up with exactly one INGRESS gateway and one EGRESS gateway", func() {
		gateways := gateway.WaitForActiveGatewaysForEnv(Client, Cfg.DefaultOrg, envName, 2, 5*time.Minute)

		var ingress, egress int
		for _, gw := range gateways {
			switch gw.GatewayType {
			case "INGRESS":
				ingress++
			case "EGRESS":
				egress++
			}
		}

		Expect(gateways).To(HaveLen(2), "expected exactly 2 gateways for split env %q, got %d", envName, len(gateways))
		Expect(ingress).To(Equal(1), "expected exactly one INGRESS gateway for env %q", envName)
		Expect(egress).To(Equal(1), "expected exactly one EGRESS gateway for env %q", envName)
	})

	It("registers a cluster-local runtimeUrl for both roles", func() {
		gateways := gateway.WaitForActiveGatewaysForEnv(Client, Cfg.DefaultOrg, envName, 2, 5*time.Minute)

		for _, gw := range gateways {
			// The chart is the only producer; empty here means the POST body lost the field
			// or the exists-path PUT never ran, and sandboxed agents would silently fall
			// back to the unroutable vhost.
			Expect(gw.RuntimeUrl).NotTo(BeEmpty(),
				"gateway %q (%s) has no runtimeUrl", gw.Name, gw.GatewayType)
			Expect(gw.RuntimeUrl).To(HavePrefix("http://"+gw.Name+"-gw-gateway-gateway-runtime."),
				"gateway %q runtimeUrl does not address its own runtime Service: %s", gw.Name, gw.RuntimeUrl)
			Expect(gw.RuntimeUrl).To(HaveSuffix(":22893"),
				"gateway %q runtimeUrl is missing the runtime port: %s", gw.Name, gw.RuntimeUrl)
			GinkgoWriter.Printf("Gateway %s (%s) runtimeUrl: %s\n", gw.Name, gw.GatewayType, gw.RuntimeUrl)
		}
	})
})
