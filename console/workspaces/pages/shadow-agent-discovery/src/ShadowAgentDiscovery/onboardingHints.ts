/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**
 * Copy-ready hints for moving an externally hosted workload under Agent
 * Manager. Sources (Agent Manager docs): create-your-first-agent.mdx and
 * guides/amp-instrumentation.mdx (instrumentation), configure-agent-llm-
 * configuration.mdx and tutorials/govern-the-model.mdx (LLM gateway). The
 * values are placeholders: the console shows the real ones once, in the
 * Setup Agent and Connect to LLM Provider panels.
 */

/** Step 2: instrumentation, for a Python agent. */
export const INSTRUMENTATION_SHELL = [
  "pip install amp-instrumentation",
  'export AMP_OTEL_ENDPOINT="<OTel endpoint from the Setup Agent panel>"',
  'export AMP_AGENT_API_KEY="<agent API key from the Setup Agent panel>"',
  "amp-instrument python main.py",
].join("\n");

/** Other languages export traces over OTLP/HTTP themselves. */
export const INSTRUMENTATION_OTHER =
  "Other languages: send OTLP/HTTP traces to ${AMP_OTEL_ENDPOINT}/v1/traces with the header " +
  "x-amp-api-key: ${AMP_AGENT_API_KEY}.";

/** Step 3: the gateway values, exported for the workload. */
export const LLM_GATEWAY_SHELL = [
  'export LLM_PROVIDER_URL="<Endpoint URL from the Connect to LLM Provider panel>"',
  'export LLM_PROVIDER_KEY="<API key from the same panel; it is shown once>"',
].join("\n");

/**
 * The official client example (OpenAI Python SDK): the gateway expects the
 * key in the API-Key header, not as a bearer token.
 */
export const OPENAI_CLIENT_PYTHON = [
  "import os",
  "from openai import OpenAI",
  "",
  "client = OpenAI(",
  '    base_url=os.environ["LLM_PROVIDER_URL"],',
  '    api_key="",',
  '    default_headers={"API-Key": os.environ["LLM_PROVIDER_KEY"], "Authorization": ""},',
  ")",
].join("\n");

export interface DirectCredentialHint {
  /** The direct credential the workload uses today. */
  credential: string;
  /** The environment variable the provider's SDK reads it from by default, if there is one. */
  envVar?: string;
}

/** The direct credential of each provider, to stop using once traffic goes through the gateway. */
export function directCredentialHint(provider: string): DirectCredentialHint {
  switch (provider) {
    case "openai":
      return { credential: "the OpenAI API key", envVar: "OPENAI_API_KEY" };
    case "anthropic":
      return { credential: "the Anthropic API key", envVar: "ANTHROPIC_API_KEY" };
    case "bedrock":
      return { credential: "the AWS credentials it uses to call Bedrock" };
    case "google":
      return { credential: "the Google credentials it uses to call Agent Platform" };
    case "foundry":
      return { credential: "the credentials it uses to call the Foundry project" };
    default:
      return { credential: "the direct provider credential" };
  }
}

/** Shell lines that move the workload off its direct credential. */
export function moveOffDirectShell(provider: string): string {
  const hint = directCredentialHint(provider);
  const lines = hint.envVar
    ? [`unset ${hint.envVar}     # the workload no longer needs the direct key`]
    : [];
  lines.push("amp-instrument python main.py");
  return lines.join("\n");
}
