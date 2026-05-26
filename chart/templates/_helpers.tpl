{{/*
Expand the name of the chart.
*/}}
{{- define "appsec-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Common labels
*/}}
{{- define "appsec-gateway.labels" -}}
app.kubernetes.io/name: {{ include "appsec-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "appsec-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "appsec-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
