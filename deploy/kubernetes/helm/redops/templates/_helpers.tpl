{{/*
Expand the name of the chart.
*/}}
{{- define "redops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "redops.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "redops.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "redops.labels" -}}
helm.sh/chart: {{ include "redops.chart" . }}
{{ include "redops.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "redops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "redops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "redops.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "redops.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
API component labels
*/}}
{{- define "redops.api.labels" -}}
{{ include "redops.labels" . }}
app.kubernetes.io/component: api
{{- end }}

{{- define "redops.api.selectorLabels" -}}
{{ include "redops.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Dashboard component labels
*/}}
{{- define "redops.dashboard.labels" -}}
{{ include "redops.labels" . }}
app.kubernetes.io/component: dashboard
{{- end }}

{{- define "redops.dashboard.selectorLabels" -}}
{{ include "redops.selectorLabels" . }}
app.kubernetes.io/component: dashboard
{{- end }}

{{/*
Worker component labels
*/}}
{{- define "redops.worker.labels" -}}
{{ include "redops.labels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{- define "redops.worker.selectorLabels" -}}
{{ include "redops.selectorLabels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{/*
Get the image tag
*/}}
{{- define "redops.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Redis host
*/}}
{{- define "redops.redisHost" -}}
{{- if .Values.redis.external.enabled }}
{{- .Values.redis.external.host }}
{{- else }}
{{- printf "%s-redis-master" (include "redops.fullname" .) }}
{{- end }}
{{- end }}

{{/*
PostgreSQL host
*/}}
{{- define "redops.postgresqlHost" -}}
{{- if .Values.postgresql.external.enabled }}
{{- .Values.postgresql.external.host }}
{{- else }}
{{- printf "%s-postgresql" (include "redops.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secret name for credentials
*/}}
{{- define "redops.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "redops.fullname" .) }}
{{- end }}
{{- end }}
