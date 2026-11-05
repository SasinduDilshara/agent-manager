#!/usr/bin/env bash
# Render assertions for wso2-amp-api-platform-gateway-extension.
# Run: bash deployments/helm-charts/wso2-amp-api-platform-gateway-extension/tests/render.sh
#
# Covers audit.trafficLogging: the tables it appends to config_toml, the env var
# that backs token_fingerprint_key, and — the property existing installs rely
# on — that turning it off leaves config_toml and extraEnv exactly as the
# operator wrote them.
set -uo pipefail

CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

render() {
  local out
  if ! out="$(helm template api-platform-default-default "$CHART_DIR" "$@" 2>&1)"; then
    printf 'helm template failed: %s\n' "$out" >&2
    return 1
  fi
  printf '%s\n' "$out"
}

# config_toml_of [helm args...] -> the config_toml block of the gateway values,
# de-indented.
config_toml_of() {
  render "$@" | awk '
    /^      config_toml: \|/ { on = 1; next }
    on && /^        / { sub(/^        /, ""); print; next }
    on && /^ *$/ { print ""; next }
    on { exit }
  '
}

pass() { printf 'ok   - %s\n' "$1"; }
fail() { printf 'FAIL - %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

expect_contains() { # label haystack needle
  if grep -qF -- "$3" <<<"$2"; then pass "$1"; else fail "$1 (missing: $3)"; fi
}
expect_absent() { # label haystack needle
  if grep -qF -- "$3" <<<"$2"; then fail "$1 (found: $3)"; else pass "$1"; fi
}

TOML_EXTRA=(
  --set-string 'apiGateway.config.config_toml=awsbedrock_guardrail_region = "us-east-1"'
  --set 'apiGateway.config.systemExtraEnv[0].name=APIP_GW_KEY'
  --set 'apiGateway.config.systemExtraEnv[0].valueFrom.secretKeyRef.name=gw-secret'
  --set 'apiGateway.config.systemExtraEnv[0].valueFrom.secretKeyRef.key=k'
)

# --- enabled (opt-in) --------------------------------------------------------
ON=(--set audit.trafficLogging.enabled=true)
on="$(config_toml_of "${ON[@]}")"
expect_contains "traffic logging can be turned on" "$on" "[traffic_logging]"
expect_contains "records go to stdout only" "$on" 'outputs = ["stdout"]'
expect_contains "no header or body capture" "$on" "request_body = false"
expect_contains "the AMP API key header is masked" "$on" '"x-amp-api-key"'
expect_contains "the gateway id is the APIGateway name" "$on" 'gateway_id = "api-platform-default-default"'
expect_contains "the organization is the AMP org" "$on" 'organization = "default"'
expect_contains "the environment is the gateway environment" "$on" 'environment = "default"'
expect_contains "only the act claim is copied" "$on" 'audit_claims = ["act"]'
expect_contains "the fingerprint key comes from the environment" "$on" \
  "token_fingerprint_key = '{{ env \"AMP_TRAFFIC_LOG_FINGERPRINT_KEY\" \"\" }}'"

all="$(render "${ON[@]}")"
expect_contains "a fingerprint key Secret is generated" "$all" "name: api-platform-default-default-traffic-log-fingerprint"
expect_contains "the key reaches the gateway as an env var" "$all" "- name: AMP_TRAFFIC_LOG_FINGERPRINT_KEY"
expect_absent "an operator-supplied key Secret is not generated" \
  "$(render "${ON[@]}" --set audit.trafficLogging.fingerprintKeySecret.name=shared-fp)" "traffic-log-fingerprint"

# Operator root keys must stay above the first [table]: TOML would otherwise
# file them under it.
with_root="$(config_toml_of "${ON[@]}" "${TOML_EXTRA[@]}")"
first_line="$(head -n1 <<<"$with_root")"
if [[ "$first_line" == 'awsbedrock_guardrail_region = "us-east-1"' ]]; then
  pass "operator root keys stay before the appended tables"
else
  fail "operator root keys moved (first line: $first_line)"
fi
expect_contains "operator env vars are kept alongside the key" "$(render "${ON[@]}" "${TOML_EXTRA[@]}")" "- name: APIP_GW_KEY"

# A second [traffic_logging] table would crash-loop the gateway; refuse it.
if out="$(helm template x "$CHART_DIR" "${ON[@]}" --set-string 'apiGateway.config.config_toml=[traffic_logging]
enabled = true' 2>&1)"; then
  fail "a duplicate [traffic_logging] table rendered"
else
  expect_contains "a duplicate [traffic_logging] table is refused" "$out" "defines [collector] or [traffic_logging]"
fi

# --- disabled (the default): exactly the operator's configuration -------------
# An upgrade of this chart must not switch traffic logging on by itself.
default_render="$(render)"
expect_absent "traffic logging is off by default" "$default_render" "[traffic_logging]"
expect_absent "off by default: no fingerprint Secret" "$default_render" "traffic-log-fingerprint"
expect_absent "off by default: no config_toml is invented" "$default_render" "config_toml:"
off_default="$(render --set audit.trafficLogging.enabled=false)"
expect_absent "disabled: no config_toml is invented" "$off_default" "config_toml:"
expect_absent "disabled: no extraEnv is invented" "$off_default" "extraEnv:"
expect_absent "disabled: no fingerprint Secret" "$off_default" "traffic-log-fingerprint"
off_toml="$(config_toml_of --set audit.trafficLogging.enabled=false "${TOML_EXTRA[@]}")"
if [[ "$off_toml" == 'awsbedrock_guardrail_region = "us-east-1"' ]]; then
  pass "disabled: config_toml is the operator's, unchanged"
else
  fail "disabled: config_toml changed: $off_toml"
fi
off_env="$(render --set audit.trafficLogging.enabled=false "${TOML_EXTRA[@]}")"
expect_absent "disabled: no fingerprint env var" "$off_env" "AMP_TRAFFIC_LOG_FINGERPRINT_KEY"
expect_contains "disabled: operator env vars still render" "$off_env" "- name: APIP_GW_KEY"

if ((FAILURES > 0)); then
  printf '\n%d assertion(s) failed\n' "$FAILURES"
  exit 1
fi
printf '\nAll render assertions passed\n'
