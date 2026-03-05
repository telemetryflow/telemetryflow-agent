{{/*
Expand the name of the chart.
*/}}
{{- define "tfo-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncate at 63 chars (Kubernetes name limit).
*/}}
{{- define "tfo-agent.fullname" -}}
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
Create chart label value (name-version).
*/}}
{{- define "tfo-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "tfo-agent.labels" -}}
helm.sh/chart: {{ include "tfo-agent.chart" . }}
{{ include "tfo-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels (used in matchLabels and pod selectors — must be stable).
*/}}
{{- define "tfo-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tfo-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component label for the node DaemonSet.
*/}}
{{- define "tfo-agent.nodeCollector.labels" -}}
{{ include "tfo-agent.labels" . }}
app.kubernetes.io/component: node-collector
{{- end }}

{{/*
Selector labels for the node DaemonSet.
*/}}
{{- define "tfo-agent.nodeCollector.selectorLabels" -}}
{{ include "tfo-agent.selectorLabels" . }}
app.kubernetes.io/component: node-collector
{{- end }}

{{/*
Component label for the K8s cluster collector Deployment.
*/}}
{{- define "tfo-agent.k8sCollector.labels" -}}
{{ include "tfo-agent.labels" . }}
app.kubernetes.io/component: k8s-collector
{{- end }}

{{/*
Selector labels for the K8s cluster collector Deployment.
*/}}
{{- define "tfo-agent.k8sCollector.selectorLabels" -}}
{{ include "tfo-agent.selectorLabels" . }}
app.kubernetes.io/component: k8s-collector
{{- end }}

{{/*
ServiceAccount name — use custom name if provided, else generate from fullname.
*/}}
{{- define "tfo-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tfo-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Container image reference — tag defaults to appVersion.
*/}}
{{- define "tfo-agent.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Name of the credentials Secret.
*/}}
{{- define "tfo-agent.secretName" -}}
{{- printf "%s-credentials" (include "tfo-agent.fullname" .) }}
{{- end }}

{{/*
Name of the ConfigMap for the cluster collector config.
*/}}
{{- define "tfo-agent.k8sConfigMapName" -}}
{{- printf "%s-k8s-config" (include "tfo-agent.fullname" .) }}
{{- end }}

{{/*
Name of the ConfigMap for the node collector config.
*/}}
{{- define "tfo-agent.nodeConfigMapName" -}}
{{- printf "%s-node-config" (include "tfo-agent.fullname" .) }}
{{- end }}
