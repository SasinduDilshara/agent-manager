{{/*
Expand the name of the chart.
*/}}
{{- define "wso2-amp-gateway-extension.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "wso2-amp-gateway-extension.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "wso2-amp-gateway-extension.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "wso2-amp-gateway-extension.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wso2-amp-gateway-extension.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the K8s Secret holding the gateway registration token (created by bootstrap job).
Defaults to "<release-name>-token" when not explicitly set.
*/}}
{{- define "wso2-amp-gateway-extension.tokenSecretName" -}}
{{- if .Values.gateway.tokenSecret.name }}
{{- .Values.gateway.tokenSecret.name }}
{{- else }}
{{- printf "%s-token" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Name of the ConfigMap holding gateway Helm values (referenced by APIGateway CR configRef).
Defaults to "<release-name>-config" when not explicitly set.
*/}}
{{- define "wso2-amp-gateway-extension.configMapName" -}}
{{- if .Values.apiGateway.config.configMapName }}
{{- .Values.apiGateway.config.configMapName }}
{{- else }}
{{- printf "%s-config" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Name of the APIGateway CR.
Defaults to "api-platform-<orgName>-<environment>" when gateway.name is not explicitly set.
*/}}
{{- define "wso2-amp-gateway-extension.apiGatewayName" -}}
{{- if .Values.gateway.name }}
{{- .Values.gateway.name }}
{{- else }}
{{- printf "api-platform-%s-%s" .Values.agentManager.orgName .Values.gateway.environment | lower | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Hostname for routing traffic through kgateway to this gateway.
Defaults to "<environment>-<orgName>.gateway.localhost" when not explicitly set.
*/}}
{{- define "wso2-amp-gateway-extension.gatewayHostname" -}}
{{- if .Values.gateway.hostname }}
{{- .Values.gateway.hostname }}
{{- else }}
{{- printf "%s-%s.gateway.localhost" .Values.gateway.environment .Values.agentManager.orgName | lower | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Bare hostname MCP proxies are publicly served on — the mcp-auth policy's
gatewayhost system parameter (the policy adds scheme and request port itself).
Derived from gateway.vhost so OAuth challenge URLs agree with the Thunder
resource-server identifiers AMS registers from the same vhost; falls back to
the routed kgateway hostname.
*/}}
{{- define "wso2-amp-gateway-extension.mcpGatewayHost" -}}
{{- $vhost := .Values.gateway.vhost | default "" | trim -}}
{{- if $vhost -}}
{{- if not (contains "://" $vhost) -}}{{- $vhost = printf "https://%s" $vhost -}}{{- end -}}
{{- regexReplaceAll ":[0-9]+$" (urlParse $vhost).host "" -}}
{{- else -}}
{{- include "wso2-amp-gateway-extension.gatewayHostname" . -}}
{{- end -}}
{{- end }}

{{/*
Label value used to bind a RestApi to its APIGateway via the
`gateway.api-platform.wso2.com/restapi-target` label/selector. The APIGateway
name is already unique per environment (see apiGatewayName), so we reuse it
verbatim rather than re-appending the environment.
*/}}
{{- define "wso2-amp-gateway-extension.restApiTarget" -}}
{{- include "wso2-amp-gateway-extension.apiGatewayName" . }}
{{- end }}

{{/*
Bootstrap resource name prefix. All bootstrap resources (ServiceAccount, Role,
RoleBinding, Job) are derived from this to avoid collisions across releases.
*/}}
{{- define "wso2-amp-gateway-extension.bootstrapName" -}}
{{- printf "%s-bootstrap" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
In-cluster base URL of this release's gateway runtime, POSTed to AMS at registration and
stored verbatim. AMS no longer derives this from the gateway name, so this template is the
only producer. `-gw-gateway-gateway-runtime` and port 22893 are the gateway-operator's
Service convention — the same pair gateway-kgateway-route.yaml already depends on, and this
chart ships in lockstep with that operator where AMS config did not.
*/}}
{{- define "wso2-amp-gateway-extension.runtimeUrl" -}}
{{- if .Values.gateway.runtimeUrl }}
{{- /* AMS rejects any path, "/" included, so an override's trailing slash never reaches it. */}}
{{- .Values.gateway.runtimeUrl | trimSuffix "/" }}
{{- else }}
{{- printf "http://%s-gw-gateway-gateway-runtime.%s:22893" (include "wso2-amp-gateway-extension.apiGatewayName" .) .Values.apiGateway.namespace }}
{{- end }}
{{- end }}

{{/*
Resolve the IDP client ID from secret or direct value
*/}}
{{- define "wso2-amp-gateway-extension.idpClientIdEnv" -}}
{{- if .Values.agentManager.idp.existingSecret }}
- name: IDP_CLIENT_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.agentManager.idp.existingSecret }}
      key: {{ required "agentManager.idp.existingSecretClientIdKey is required when using existingSecret" .Values.agentManager.idp.existingSecretClientIdKey }}
{{- else }}
- name: IDP_CLIENT_ID
  value: {{ .Values.agentManager.idp.clientId | quote }}
{{- end }}
{{- end }}

{{/*
Resolve the IDP client secret from secret or direct value
*/}}
{{- define "wso2-amp-gateway-extension.idpClientSecretEnv" -}}
{{- if .Values.agentManager.idp.existingSecret }}
- name: IDP_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.agentManager.idp.existingSecret }}
      key: {{ required "agentManager.idp.existingSecretClientSecretKey is required when using existingSecret" .Values.agentManager.idp.existingSecretClientSecretKey }}
{{- else }}
- name: IDP_CLIENT_SECRET
  value: {{ .Values.agentManager.idp.clientSecret | quote }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding the traffic-log token fingerprint key: the operator's
audit.trafficLogging.fingerprintKeySecret.name, or the one this chart generates.
*/}}
{{- define "wso2-amp-gateway-extension.fingerprintSecretName" -}}
{{- if .Values.audit.trafficLogging.fingerprintKeySecret.name -}}
{{- .Values.audit.trafficLogging.fingerprintKeySecret.name -}}
{{- else -}}
{{- printf "%s-traffic-log-fingerprint" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{/*
config_toml as rendered into the gateway values: the operator's
apiGateway.config.config_toml, followed — when audit.trafficLogging.enabled —
by the traffic-logging tables the AMP audit trail needs. Appended, not
prepended: config_toml may start with bare root keys, which TOML only accepts
before the first [table] header.

With audit.trafficLogging.enabled=false this is exactly config_toml, so the
rendered ConfigMap is unchanged.
*/}}
{{- define "wso2-amp-gateway-extension.configToml" -}}
{{- $user := .Values.apiGateway.config.config_toml | default "" -}}
{{- $tl := .Values.audit.trafficLogging -}}
{{- if $tl.enabled -}}
{{- if regexMatch "(?m)^[ \t]*\\[(collector|traffic_logging)\\][ \t]*$" $user -}}
{{- fail "apiGateway.config.config_toml defines [collector] or [traffic_logging], which audit.trafficLogging.enabled also renders (TOML rejects a duplicate table). Remove them from config_toml, or set audit.trafficLogging.enabled=false to keep your own." -}}
{{- end -}}
{{- $lines := list -}}
{{- if $user -}}
{{- $lines = append $lines (trimSuffix "\n" $user) -}}
{{- $lines = append $lines "" -}}
{{- end -}}
{{- $lines = append $lines "# AMP audit trail: one JSON traffic record per request on stdout, collected" -}}
{{- $lines = append $lines "# by the platform's Fluent Bit (see deployments/AUDIT_LOGS.md). No headers" -}}
{{- $lines = append $lines "# or bodies are captured." -}}
{{- $lines = append $lines "[collector]" -}}
{{- $lines = append $lines "request_headers = false" -}}
{{- $lines = append $lines "response_headers = false" -}}
{{- $lines = append $lines "request_body = false" -}}
{{- $lines = append $lines "response_body = false" -}}
{{- $lines = append $lines "" -}}
{{- $lines = append $lines "[traffic_logging]" -}}
{{- $lines = append $lines "enabled = true" -}}
{{- $lines = append $lines "outputs = [\"stdout\"]" -}}
{{- $lines = append $lines (printf "masked_headers = %s" ($tl.maskedHeaders | toJson)) -}}
{{- $lines = append $lines (printf "gateway_id = %s" (include "wso2-amp-gateway-extension.apiGatewayName" . | toJson)) -}}
{{- $lines = append $lines (printf "organization = %s" (.Values.agentManager.orgName | toJson)) -}}
{{- $lines = append $lines (printf "environment = %s" (.Values.gateway.environment | toJson)) -}}
{{- $lines = append $lines (printf "audit_claims = %s" ($tl.auditClaims | toJson)) -}}
{{- $lines = append $lines (printf "token_fingerprint_key = '{{ env \"%s\" \"\" }}'" $tl.fingerprintKeyEnvVar) -}}
{{- join "\n" $lines -}}
{{- else -}}
{{- $user -}}
{{- end -}}
{{- end }}

{{/*
systemExtraEnv, plus — when audit.trafficLogging.enabled — the env var backing
token_fingerprint_key, read from a Secret. Unchanged when disabled.
*/}}
{{- define "wso2-amp-gateway-extension.extraEnv" -}}
{{- $env := .Values.apiGateway.config.systemExtraEnv | default list -}}
{{- $tl := .Values.audit.trafficLogging -}}
{{- if $tl.enabled -}}
{{- $ref := dict "name" (include "wso2-amp-gateway-extension.fingerprintSecretName" .) "key" $tl.fingerprintKeySecret.key -}}
{{- $env = append $env (dict "name" $tl.fingerprintKeyEnvVar "valueFrom" (dict "secretKeyRef" $ref)) -}}
{{- end -}}
{{- if $env -}}
{{- toYaml $env -}}
{{- end -}}
{{- end }}
