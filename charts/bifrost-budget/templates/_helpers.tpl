{{- define "bifrost-budget.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "bifrost-budget.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "bifrost-budget.labels" -}}
app.kubernetes.io/name: {{ include "bifrost-budget.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}
