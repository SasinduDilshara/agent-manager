# AMP audit logs: operator notes

Agent Manager keeps an organization-level audit trail from two sources:

- **API gateway traffic records.** One JSON line per request, written to stdout by each gateway's runtime (`gateway-runtime` container, namespace `<org>-<env>`). Each line covers LLM, MCP, A2A, agent-endpoint and telemetry calls: who called, under which credential or delegation, which policy denied it, models and token counts, and MCP methods and tools. No headers or bodies are recorded.
- **Control-plane audit records.** Agent Manager writes these to stdout with `log_type=audit` (`agent-manager-service` container, namespace `wso2-amp`). See [`agent-manager-service/docs/audit-logging.md`](../agent-manager-service/docs/audit-logging.md).

Both are shipped by the OpenChoreo logs module's Fluent Bit into dedicated `amp-audit-YYYY-MM-DD` indices in its OpenSearch. You read them back through `GET /api/v1/orgs/{orgName}/audit/events` or on the console's org-level **Audit Logs** page. No new data store is deployed.

## How it works

```
gateway-runtime stdout ─┐                       ┌─> container-logs-*  (unchanged)
                        ├─> Fluent Bit (DaemonSet)
AMS stdout (audit) ─────┘   amp-fluent-bit       └─> amp-audit-*  ──> AMS audit query API ──> console
```

| Piece | Chart / script | What it does |
|---|---|---|
| `amp-fluent-bit` ConfigMap | `wso2-amp-observability-extension` (`audit.*`) | The logs module's own Fluent Bit configuration, kept verbatim, with additions. Gateway and audit lines are copied to an `audit.*` tag and the original still goes to `container-logs-*`. Grep filters keep only lines from the gateway runtime (container name and `openchoreo.dev/system-component` label) and from Agent Manager (container name and namespace). The lines are parsed as JSON, stamped with `audit_source` (`gateway` or `control-plane`), and written to `amp-audit-*` through a filesystem buffer with unlimited retries. |
| Setup Job (`*-audit-setup`) | same chart, post-install/post-upgrade hook | Creates the `amp-audit` index template (keyword mappings and `flat_object` for free-form fields), the `amp-audit-retention` ISM policy, and a read-only `amp_audit_reader` role and user. It is idempotent. |
| Gateway traffic logging | `wso2-amp-api-platform-gateway-extension` (`audit.trafficLogging.*`) | Appends `[collector]` (all capture off) and `[traffic_logging]` (stdout, `gateway_id`, `organization`, `environment`, `audit_claims`, `token_fingerprint_key`) to the gateway's `config.toml`. |
| Audit query API | `wso2-agent-manager` (`agentManagerService.config.auditQuery.*`) | `GET /orgs/{orgName}/audit/events`, permission `observability:log-read`. It is off by default. |
| Console page | `wso2-agent-manager` (`console.config.featureFlags.enableAuditLogs`) | Shows the Audit Logs page. It is off by default. |
| Installer | `quick-start/install.sh` | Turns all of the above on when log collection is installed. |

### Organization scoping

The organization always comes from the caller's token. It is never taken from the path or the query.

- Control-plane records are matched on `event.ouId`.
- Gateway records are matched on `gateway.organization`, which the gateway extension sets from `agentManager.orgName`.

Some records carry no organization: AMS `system:startup`, and gateway key-sync reads on the internal surface. These are platform-level records and are not returned to any organization.

`AUDIT_GATEWAY_NAMESPACE_FALLBACK=true` makes the API also accept gateway records that have no `gateway.organization` (written by a gateway configured before this feature) when they come from a namespace starting with `<org>-`. The fallback is off by default. A prefix cannot tell org `acme` from org `acme-labs`, so enable it only when no org handle is a hyphenated extension of another.

### Agent attribution

AMS maps the identifiers in each record to an agent, using its own database (cached for 60 seconds per org):

- **LLM proxy calls:** `api.name` or `api.id` gives the agent's model configuration and so the agent.
- **MCP calls:** `auth.subject` or `act.sub` is the agent's AgentID, and `auth.clientId` is its OAuth client. With delegation, `onBehalfOf.subject` is the user and `onBehalfOf.chain` lists the acting agents, outermost first.
- **Telemetry export:** `auth.subject` is the agent name. AMS attributes the record only when that name is unique in the org.
- **Agent endpoints and A2A:** `api.id` is the agent's API artifact. The agent recorded is the one being called.
- **API-key calls:** the actor is reported as `ANONYMOUS`, with `authMethod` and `tokenId` set. If `AUDIT_TOKEN_FINGERPRINT_KEY` is configured, the key fingerprint is joined to the stored key and its agent.

## Configuration

**Observability extension (`audit.*`):**

| Value | Default | Notes |
|---|---|---|
| `audit.enabled` | `true` | Renders the ConfigMap, setup Job, reader Secret and NetworkPolicy. |
| `audit.fluentBit.openSearchHost` / `openSearchPort` / `openSearchVHost` | `gateway-default.openchoreo-observability-plane.svc.cluster.local` / `11443` / `opensearch.observability.openchoreo.localhost` | Must match the logs module's `fluent-bit.openSearch*` values (`deployments/values/observability-logs-opensearch.yaml`). Releases that ship straight to the in-namespace service use `opensearch` / `9200` / `opensearch`. |
| `audit.fluentBit.storageTotalLimitSize` | `2G` | Disk buffer for undelivered audit records, per node. Beyond it, the oldest chunks are dropped. |
| `audit.sources.controlPlane.namespace` | `wso2-amp` | Namespace Agent Manager runs in. |
| `audit.retention.days` | `186` | Must be at least 186 (six calendar months). Lower values are refused. |
| `audit.retention.readOnlyAfter` | `""` | Optional read-only phase. It is off by default because, after a long store outage, Fluent Bit writes its backlog to older daily indices. |
| `audit.reader.create` / `existingSecret` | `true` / `""` | Read-only OpenSearch identity. When `existingSecret` is empty, the chart generates `amp-audit-opensearch-reader` and keeps it across upgrades. |
| `audit.networkPolicy.allowAgentManager` | `true` | Admits the Agent Manager API pods to OpenSearch on port 9200. |

**Gateway extension (`audit.trafficLogging.*`):**

- `enabled` (default `true`), `auditClaims` (default `["act"]`) and `maskedHeaders`.
- `fingerprintKeySecret.name`: when empty, a 48-character key is generated per gateway and kept.

With `enabled=false`, the rendered chart is byte-identical to the previous release. If your own `config_toml` defines `[collector]` or `[traffic_logging]`, the render fails. In that case, remove those tables or disable this setting.

**Agent Manager (`agentManagerService.config.auditQuery.*`, environment variable in brackets):**

| Value | Env var | Default |
|---|---|---|
| `enabled` | `AUDIT_QUERY_ENABLED` | `false` |
| `openSearchUrl` | `AUDIT_OPENSEARCH_URL` | `https://opensearch.openchoreo-observability-plane.svc.cluster.local:9200` |
| `insecureSkipVerify` | `AUDIT_OPENSEARCH_INSECURE_SKIP_VERIFY` | `true` in the chart (the bundled OpenSearch is self-signed), `false` in the service |
| `indexPattern` | `AUDIT_INDEX_PATTERN` | `amp-audit-*` |
| `timeoutSeconds` | `AUDIT_OPENSEARCH_TIMEOUT_SECONDS` | `15` |
| `gatewayNamespaceFallback` | `AUDIT_GATEWAY_NAMESPACE_FALLBACK` | `false` |
| `existingSecret` (keys `username`, `password`) | `AUDIT_OPENSEARCH_USERNAME` / `_PASSWORD` | `amp-audit-opensearch-reader` |
| `fingerprintKeySecret.name` / `.key` | `AUDIT_TOKEN_FINGERPRINT_KEY` | not set |

To join API-key calls back to their keys, give every gateway and Agent Manager the same fingerprint key. Set `audit.trafficLogging.fingerprintKeySecret.name` on each gateway release, and `agentManagerService.config.auditQuery.fingerprintKeySecret` on Agent Manager, each pointing at a copy of one Secret.

## Retention

The `amp-audit-retention` ISM policy deletes each daily index 186 days after creation, or after the configured number of days. The policy attaches to new `amp-audit-*` indices through its ISM template. The setup Job also attaches it to existing indices and moves them to the current policy version. Container logs keep the logs module's own 30-day policy.

## Security considerations

- The audit query API requires `observability:log-read` and is scoped to the caller's organization. Reading the trail is itself recorded, because the route is listed in `sensitiveReadPaths`.
- AMS reads OpenSearch with a dedicated identity that can only read and search `amp-audit-*`. Fluent Bit and the setup Job use the logs module's admin credentials, as the module already does.
- Only records from the expected containers are copied into the audit indices: the gateway runtime container with its system-component label, and the Agent Manager container in its namespace. The `audit_source` field is set by Fluent Bit, never taken from the line itself. Anyone who can create pods with those names and labels in the cluster is trusted to the same degree as the platform components.
- Traffic records carry no headers or bodies. Token claims are limited to `auditClaims`. API keys appear only as an HMAC fingerprint (`hmac-sha256:…`) when a fingerprint key is configured, and are omitted otherwise.
- The audit indices are not write-once: anyone with OpenSearch admin access can change or delete them. If you need tamper evidence or separation of duties, forward the records to a store the platform administrators do not control.
- The API returns `502` with a generic message when OpenSearch cannot be queried. Details go only to the service log.

## Existing installations (manual steps)

Run these steps in order. Set the following first:

```bash
OBS_NS=openchoreo-observability-plane
AMP_NS=wso2-amp
SECRET=amp-audit-opensearch-reader
```

1. **Reader Secret in both namespaces, with the same password:**

   ```bash
   PW="$(openssl rand -hex 24)"
   for ns in "$OBS_NS" "$AMP_NS"; do
     printf '%s' "$PW" | kubectl create secret generic "$SECRET" -n "$ns" \
       --from-literal=username=amp_audit_reader --from-file=password=/dev/stdin \
       --dry-run=client -o yaml | kubectl apply -f -
   done
   ```

2. **Observability extension.** This creates the ConfigMap, the index template, the retention policy and the reader user:

   ```bash
   helm upgrade amp-observability-traces oci://ghcr.io/wso2/helm-charts/wso2-amp-observability-extension \
     -n "$OBS_NS" --version <version> --reuse-values \
     --set audit.reader.existingSecret="$SECRET" --set audit.sources.controlPlane.namespace="$AMP_NS"
   # Releases whose Fluent Bit ships to opensearch:9200 directly (no TLS passthrough route):
   #   --set audit.fluentBit.openSearchHost=opensearch --set audit.fluentBit.openSearchPort=9200 \
   #   --set audit.fluentBit.openSearchVHost=opensearch
   kubectl logs -n "$OBS_NS" job/amp-observability-traces-audit-setup
   ```

3. **Switch Fluent Bit to the AMP configuration** (after step 2, so the index template exists before the first audit record arrives):

   ```bash
   helm upgrade observability-logs-opensearch oci://ghcr.io/openchoreo/helm-charts/observability-logs-opensearch \
     -n "$OBS_NS" --version <installed version> --reuse-values \
     --set fluent-bit.existingConfigMap=amp-fluent-bit
   kubectl rollout restart daemonset/fluent-bit -n "$OBS_NS"
   ```

   To roll back, set `fluent-bit.existingConfigMap=fluent-bit` and restart the DaemonSet.

4. **Gateways.** Upgrade each `wso2-amp-api-platform-gateway-extension` release with the new chart version. Traffic logging is on by default. The gateway operator rolls the gateway.

5. **Agent Manager:**

   ```bash
   helm upgrade amp oci://ghcr.io/wso2/helm-charts/wso2-agent-manager -n "$AMP_NS" --version <version> --reuse-values \
     --set agentManagerService.config.auditQuery.enabled=true \
     --set console.config.featureFlags.enableAuditLogs=true
   ```

### Check that it works

```bash
# Audit indices exist and grow:
kubectl exec -n "$OBS_NS" opensearch-master-0 -c opensearch -- sh -c \
  'curl -sk -u "admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD" "https://localhost:9200/_cat/indices/amp-audit-*?v"'
# Fluent Bit is not reporting delivery errors:
kubectl logs -n "$OBS_NS" daemonset/fluent-bit | grep -i "amp-audit\|error" | tail
# The API answers (with a token holding observability:log-read):
curl -H "Authorization: Bearer $TOKEN" "$AMP_API/api/v1/orgs/default/audit/events?limit=5"
```

## Not in this iteration

- A hash chain or signed checkpoints over the trail, an export API, and legal hold.
- Cloud wiring (alerting, dashboards and runbook live in the cloud repository).
- Upgrading the OpenChoreo logs module.
- Egress through the gateway only, so that every agent call is recorded.
