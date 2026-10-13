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

{{- define "agentgov.bundleSigningSecret" -}}
{{- .Values.bundleSigning.existingSecret | default (printf "%s-bundle-signing" (include "agentgov.fullname" .)) -}}
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

{{- /* Where AgentGov's other components reach the control plane: its internal port,
  over mutual TLS, while internalTLS is on. */}}
{{- define "agentgov.internalControlPlaneUrl" -}}
{{- if .Values.internalTLS.enabled -}}
https://{{ include "agentgov.name" (list . "control-plane") }}:8443
{{- else -}}
{{ include "agentgov.controlPlaneUrl" . }}
{{- end -}}
{{- end -}}

{{- /* A component's certificate for mutual TLS (tls.crt, tls.key, ca.crt). */}}
{{- define "agentgov.tlsSecret" -}}
{{- printf "%s-tls-%s" (include "agentgov.fullname" (index . 0)) (index . 1) -}}
{{- end -}}

{{- define "agentgov.tlsVolume" -}}
{{- $ctx := index . 0 }}
{{- if $ctx.Values.internalTLS.enabled }}
{{- if $ctx.Values.internalTLS.spire.enabled }}
# Its X.509-SVID from SPIRE, as spiffe-helper writes it: tls.crt, tls.key and ca.crt.
- name: tls
  emptyDir: {medium: Memory, sizeLimit: 1Mi}
- name: spiffe-workload-api
  csi: {driver: {{ $ctx.Values.internalTLS.spire.csiDriver }}, readOnly: true}
- name: spiffe-helper
  configMap:
    name: {{ printf "%s-spiffe-helper" (include "agentgov.fullname" $ctx) }}
{{- else }}
- name: tls
  secret:
    secretName: {{ include "agentgov.tlsSecret" . }}
{{- end }}
{{- end }}
{{- end -}}

{{/* With SPIRE, a component's SPIFFE ID. */}}
{{- define "agentgov.spiffeId" -}}
{{- $ctx := index . 0 -}}
{{- printf "spiffe://%s/ns/%s/agentgov/%s" $ctx.Values.internalTLS.spire.trustDomain $ctx.Release.Namespace (include "agentgov.name" .) -}}
{{- end -}}

{{/* With SPIRE, which gives every workload an SVID, the callers a component's TLS
listeners take: the components (list . "processor" ...) that call it. */}}
{{- define "agentgov.tlsPeersEnv" -}}
{{- $ctx := index . 0 -}}
{{- if and $ctx.Values.internalTLS.enabled $ctx.Values.internalTLS.spire.enabled -}}
{{- $ids := list -}}
{{- range (index . 1) -}}
{{- $ids = append $ids (include "agentgov.spiffeId" (list $ctx .)) -}}
{{- end }}
- name: AGENTGOV_TLS_PEERS
  value: {{ join "," $ids | quote }}
{{- end -}}
{{- end -}}

{{/* With SPIRE: spiffe-helper writes the pod's SVID into /tls before the component starts
(an init container), and keeps it current beside it as SPIRE renews it. */}}
{{- define "agentgov.spireContainer" -}}
{{- $ctx := index . 0 -}}
{{- $daemon := index . 1 -}}
{{- if and $ctx.Values.internalTLS.enabled $ctx.Values.internalTLS.spire.enabled -}}
- name: {{ ternary "spiffe-helper" "spiffe-helper-init" $daemon }}
  image: {{ $ctx.Values.internalTLS.spire.helper.image }}
  args: ["-config", "/config/{{ ternary "daemon" "once" $daemon }}.conf"]
  resources:
    {{- toYaml $ctx.Values.internalTLS.spire.helper.resources | nindent 4 }}
  securityContext:
    {{- include "agentgov.containerSecurity" $ctx | nindent 4 }}
  volumeMounts:
    - {name: tls, mountPath: /tls}
    - {name: spiffe-workload-api, mountPath: /spiffe-workload-api, readOnly: true}
    - {name: spiffe-helper, mountPath: /config, readOnly: true}
{{- end }}
{{- end -}}

{{- define "agentgov.tlsMount" -}}
{{- if .Values.internalTLS.enabled }}
- {name: tls, mountPath: /tls, readOnly: true}
{{- end }}
{{- end -}}

{{- /* Keycloak's address in the cluster: the bundled one's, or yours. Empty without either,
  which only a release without the gateway may be: the gateway checks agents' tokens. */}}
{{- define "agentgov.keycloakUrl" -}}
{{- if .Values.keycloak.enabled -}}
http://{{ include "agentgov.name" (list . "keycloak") }}:8080
{{- else if .Values.externalKeycloak.url -}}
{{- .Values.externalKeycloak.url | trimSuffix "/" -}}
{{- else if .Values.gateway.enabled -}}
{{- fail "keycloak.enabled=false needs externalKeycloak.url: the gateway checks agents' tokens with Keycloak (or set gateway.enabled=false for an inventory without the gateway)" -}}
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
{{- /* AgentGov's own components this release runs, each with a certificate for mutual TLS,
  space-separated. */}}
{{- define "agentgov.parts" -}}
{{- if and .Values.gateway.enabled (not .Values.opa.enabled) -}}
{{- fail "gateway.enabled needs opa.enabled: the gateway's processor asks OPA about every call" -}}
{{- end -}}
{{- $parts := list "control-plane" -}}
{{- if .Values.gateway.enabled -}}{{- $parts = append $parts "processor" -}}{{- end -}}
{{- if .Values.opa.enabled -}}{{- $parts = append $parts "opa" -}}{{- end -}}
{{- if .Values.gateway.enabled -}}{{- $parts = append $parts "gateway" -}}{{- end -}}
{{- if .Values.otelCollector.enabled -}}{{- $parts = append $parts "otel-collector" -}}{{- end -}}
{{- join " " $parts -}}
{{- end -}}

{{- define "agentgov.commonEnv" -}}
- name: AGENTGOV_SERVICE_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "agentgov.secretName" . }}
      key: service-token
{{- if .Values.opa.enabled }}
- name: AGENTGOV_OPA_URL
  value: {{ if .Values.internalTLS.enabled }}https{{ else }}http{{ end }}://{{ include "agentgov.name" (list . "opa") }}:8181
{{- end }}
{{- /* The control plane configures the gateway with it; the processor acts on it. */}}
- name: AGENTGOV_GATEWAY_FAILURE_MODE
  value: {{ .Values.gatewayFailureMode | default "modes" | quote }}
{{- if .Values.internalTLS.enabled }}
- name: AGENTGOV_TLS_DIR
  value: /tls
- name: AGENTGOV_TLS_RELOAD_SECONDS
  value: {{ .Values.internalTLS.reloadSeconds | quote }}
{{- end }}
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

{{- /* IBM Granite Guardian, for the control plane and the processor (guardian.*). */}}
{{- define "agentgov.guardianEnv" -}}
{{- if .Values.guardian.url }}
- name: AGENTGOV_GUARDIAN_URL
  value: {{ .Values.guardian.url | quote }}
- name: AGENTGOV_GUARDIAN_MODEL
  value: {{ .Values.guardian.model | quote }}
{{- if .Values.guardian.existingSecret }}
- name: AGENTGOV_GUARDIAN_API_KEY
  valueFrom:
    secretKeyRef: {name: {{ .Values.guardian.existingSecret }}, key: api-key}
{{- end }}
{{- end }}
{{- end -}}
