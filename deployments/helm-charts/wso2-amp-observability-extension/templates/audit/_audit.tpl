{{/*
Name of the Secret holding the read-only OpenSearch identity for the audit
query API: the operator's existingSecret, or the one this chart generates.
*/}}
{{- define "amp-observability-extension.auditReaderSecretName" -}}
{{- if .Values.audit.reader.existingSecret -}}
{{- .Values.audit.reader.existingSecret -}}
{{- else -}}
{{- .Values.audit.reader.secretName -}}
{{- end -}}
{{- end }}

{{/*
Retention below six calendar months is refused: the audit trail must cover the
evidence period, and a shorter value would silently delete records an audit
still needs.
*/}}
{{- define "amp-observability-extension.auditRetentionDays" -}}
{{- $days := int .Values.audit.retention.days -}}
{{- if lt $days 186 -}}
{{- fail (printf "audit.retention.days must be at least 186 (six calendar months), got %d" $days) -}}
{{- end -}}
{{- $days -}}
{{- end }}

{{/*
Name of the setup Job and its ConfigMap. Kept to 63 characters: a Job's name
becomes the job-name label on its pods, and the installer's release name plus
the chart name is already 57.
*/}}
{{- define "amp-observability-extension.auditSetupName" -}}
{{- printf "%s-audit-setup" (.Release.Name | trunc 50 | trimSuffix "-") -}}
{{- end }}
