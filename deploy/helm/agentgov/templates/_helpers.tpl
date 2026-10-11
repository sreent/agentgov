{{/* Names */}}

{{- define "agentgov.fullname" -}}
{{- if contains "agentgov" .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-agentgov" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* A component's name: include "agentgov.name" (list . "opa") */}}
{{- define "agentgov.name" -}}
{{- printf "%s-%s" (include "agentgov.fullname" (index . 0)) (index . 1) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agentgov.labels" -}}
{{- $ctx := index . 0 -}}
helm.sh/chart: {{ printf "%s-%s" $ctx.Chart.Name $ctx.Chart.Version }}
app.kubernetes.io/name: agentgov
app.kubernetes.io/instance: {{ $ctx.Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
app.kubernetes.io/version: {{ $ctx.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ $ctx.Release.Service }}
{{- end -}}

{{- define "agentgov.selector" -}}
app.kubernetes.io/name: agentgov
app.kubernetes.io/instance: {{ (index . 0).Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}

{{- define "agentgov.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{- define "agentgov.secretName" -}}
{{- .Values.secrets.existingSecret | default (include "agentgov.fullname" .) -}}
{{- end -}}

{{- define "agentgov.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- .Values.serviceAccount.name | default (include "agentgov.fullname" .) -}}
{{- else -}}
{{- .Values.serviceAccount.name | default "default" -}}
{{- end -}}
{{- end -}}

{{/* The host of a URL, for ingress rules. */}}
{{- define "agentgov.host" -}}
{{- (urlParse .).host | splitList ":" | first -}}
{{- end -}}

{{/* In-cluster addresses */}}

{{- define "agentgov.controlPlaneUrl" -}}
http://{{ include "agentgov.name" (list . "control-plane") }}:{{ .Values.controlPlane.service.port }}
{{- end -}}

{{- define "agentgov.keycloakUrl" -}}
{{- if .Values.keycloak.enabled -}}
http://{{ include "agentgov.name" (list . "keycloak") }}:8080
{{- else -}}
{{- required "keycloak.enabled=false needs externalKeycloak.url" .Values.externalKeycloak.url | trimSuffix "/" -}}
{{- end -}}
{{- end -}}

{{- define "agentgov.realm" -}}
{{- if .Values.keycloak.enabled }}agentgov{{ else }}{{ .Values.externalKeycloak.realm }}{{ end -}}
{{- end -}}

{{- define "agentgov.keycloakIssuer" -}}
{{- if .Values.keycloak.enabled -}}
{{- printf "%s/realms/agentgov" (trimSuffix "/" .Values.urls.keycloak) -}}
{{- else -}}
{{- .Values.externalKeycloak.issuer | default (printf "%s/realms/%s" (include "agentgov.keycloakUrl" .) .Values.externalKeycloak.realm) -}}
{{- end -}}
{{- end -}}

{{/* Pod and container hardening shared by AgentGov's pods. */}}

{{- define "agentgov.podSecurity" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "agentgov.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}

{{/* The settings the AgentGov containers share. */}}
{{- define "agentgov.commonEnv" -}}
- name: AGENTGOV_SERVICE_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "agentgov.secretName" . }}
      key: service-token
- name: AGENTGOV_OPA_URL
  value: http://{{ include "agentgov.name" (list . "opa") }}:8181
{{- end -}}

{{- define "agentgov.scheduling" -}}
{{- with .nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Pinned features as AGENTGOV_FEATURES ("feature=mode,..."). YAML reads an unquoted
off or on as a boolean: take it as the mode it was meant to be. */}}
{{- define "agentgov.features" -}}
{{- $pins := list -}}
{{- range $feature, $mode := .Values.features -}}
{{- if kindIs "bool" $mode -}}
{{- $mode = ternary "on" "off" $mode -}}
{{- end -}}
{{- $pins = append $pins (printf "%s=%s" $feature $mode) -}}
{{- end -}}
{{- join "," $pins -}}
{{- end -}}

{{/* The Secret holding destinations' credentials. */}}
{{- define "agentgov.destinationSecretsSecret" -}}
{{- .Values.destinationSecrets.existingSecret | default (printf "%s-destination-secrets" (include "agentgov.fullname" .)) -}}
{{- end -}}

{{/* The Secret holding model providers' API keys. */}}
{{- define "agentgov.modelKeysSecret" -}}
{{- .Values.modelKeys.existingSecret | default (printf "%s-model-keys" (include "agentgov.fullname" .)) -}}
{{- end -}}
