#!/usr/bin/env bash
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# Adds the amp:audit:read permission to an EXISTING Agent Manager install.
#
# The Thunder extension's bootstrap runs on install only, so `helm upgrade`
# does not add a new permission to a running ThunderID. This script makes the
# same three changes the bootstrap makes on a fresh install, through
# ThunderID's admin API. It is idempotent: each step is skipped when already
# done.
#
#   1. An "audit" resource with a "read" action on the amp resource server.
#   2. amp:audit:read on the "Agent Manager Admin" role (and nowhere else).
#   3. amp:audit:read in the allowed scopes of the interactive clients
#      (console, amctl, MCP) and of amp-api-client, so tokens can carry it.
#
# Afterwards users must sign in again (or refresh) to get a token with the
# new scope, and the console must request it (wso2-agent-manager chart
# console.config.auth.scopes, updated by the chart upgrade).
#
# Requires curl and jq. Environment:
#   THUNDER_URL            ThunderID base URL (default http://thunder.amp.localhost:8080)
#   THUNDER_CLIENT_ID      a client allowed the "system" scope (default amp-system-client)
#   THUNDER_CLIENT_SECRET  its secret (default: the chart's local default)
#   THUNDER_SYSTEM_RESOURCE  the System resource server identifier
#                          (default "$THUNDER_URL/mcp", as the chart configures it)
#   CLIENT_SECRETS         optional "id=secret,id=secret" for confidential clients,
#                          re-sent with their update so ThunderID keeps them
#                          (default: amp-api-client=amp-api-client-secret)
set -euo pipefail

THUNDER_URL="${THUNDER_URL:-http://thunder.amp.localhost:8080}"
THUNDER_URL="${THUNDER_URL%/}"
THUNDER_CLIENT_ID="${THUNDER_CLIENT_ID:-amp-system-client}"
THUNDER_CLIENT_SECRET="${THUNDER_CLIENT_SECRET:-amp-system-client-secret}"
THUNDER_SYSTEM_RESOURCE="${THUNDER_SYSTEM_RESOURCE:-${THUNDER_URL}/mcp}"
CLIENT_SECRETS="${CLIENT_SECRETS:-amp-api-client=amp-api-client-secret}"
RS_ID="amp-resource-server"
ROLE_ID="amp-role-admin"
SCOPE="amp:audit:read"
APPS=(amp-console-client amctl-client am-mcp-client amp-api-client)

TOKEN="$(curl -sS -f -u "${THUNDER_CLIENT_ID}:${THUNDER_CLIENT_SECRET}" "${THUNDER_URL}/oauth2/token" \
  -d grant_type=client_credentials --data-urlencode scope=system \
  --data-urlencode "resource=${THUNDER_SYSTEM_RESOURCE}" | jq -r .access_token)"
[[ -n "${TOKEN}" && "${TOKEN}" != "null" ]] || { echo "could not get a ThunderID system token" >&2; exit 1; }

api() { # method path [json-body]
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "${body}" ]]; then
    curl -sS -f -X "${method}" -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
      --data-binary "${body}" "${THUNDER_URL}${path}"
  else
    curl -sS -f -X "${method}" -H "Authorization: Bearer ${TOKEN}" "${THUNDER_URL}${path}"
  fi
}

# 1. Resource and action.
amp_id="$(api GET "/resource-servers/${RS_ID}/resources?limit=100" | jq -r '.resources[] | select(.handle=="amp") | .id')"
[[ -n "${amp_id}" ]] || { echo "the amp resource was not found on ${RS_ID}" >&2; exit 1; }
audit_id="$(api GET "/resource-servers/${RS_ID}/resources?parentId=${amp_id}&limit=100" | jq -r '.resources[] | select(.handle=="audit") | .id')"
if [[ -z "${audit_id}" ]]; then
  audit_id="$(api POST "/resource-servers/${RS_ID}/resources" "$(jq -n --arg p "${amp_id}" \
    '{name:"Audit", handle:"audit", parent:$p, description:"Organization audit trail"}')" | jq -r .id)"
  echo "created resource audit (${audit_id})"
fi
if ! api GET "/resource-servers/${RS_ID}/resources/${audit_id}/actions" | jq -e '.actions[]? | select(.handle=="read")' >/dev/null; then
  api POST "/resource-servers/${RS_ID}/resources/${audit_id}/actions" \
    '{"name":"Read","handle":"read","description":"Read the organization audit trail"}' >/dev/null
  echo "created action audit:read"
fi

# 2. Admin role.
role="$(api GET "/roles/${ROLE_ID}")"
if jq -e --arg rs "${RS_ID}" --arg s "${SCOPE}" '.permissions[] | select(.resourceServerId==$rs) | .permissions | index($s)' <<<"${role}" >/dev/null; then
  echo "role ${ROLE_ID} already holds ${SCOPE}"
else
  api PUT "/roles/${ROLE_ID}" "$(jq --arg rs "${RS_ID}" --arg s "${SCOPE}" \
    '{ouId, name, description, permissions: [.permissions[] | if .resourceServerId==$rs then .permissions += [$s] else . end]}' <<<"${role}")" >/dev/null
  echo "granted ${SCOPE} to role ${ROLE_ID}"
fi

# 3. Allowed scopes of the clients.
secret_of() {
  local id="$1" pair
  IFS=',' read -ra pairs <<<"${CLIENT_SECRETS}"
  for pair in "${pairs[@]}"; do
    if [[ "${pair%%=*}" == "${id}" ]]; then
      printf '%s' "${pair#*=}"
      return 0
    fi
  done
  return 0 # no secret for this client; under set -e a false test must not end the script
}
for app in "${APPS[@]}"; do
  if ! doc="$(api GET "/applications/${app}" 2>/dev/null)"; then
    echo "application ${app} not found, skipped"
    continue
  fi
  if jq -e --arg s "${SCOPE}" '.inboundAuthConfig[0].config.scopes | index($s)' <<<"${doc}" >/dev/null; then
    echo "application ${app} already allows ${SCOPE}"
    continue
  fi
  secret="$(secret_of "${app}")"
  api PUT "/applications/${app}" "$(jq --arg s "${SCOPE}" --arg secret "${secret}" '
    .inboundAuthConfig[0].config.scopes += [$s]
    | if $secret != "" then .inboundAuthConfig[0].config.clientSecret = $secret else . end' <<<"${doc}")" >/dev/null
  echo "application ${app} now allows ${SCOPE}"
done
echo "done: sign in again to get a token carrying ${SCOPE}"
