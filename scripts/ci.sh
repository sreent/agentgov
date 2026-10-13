#!/usr/bin/env bash
# shellcheck disable=SC2329  # check functions are called through run()
# Runs this repository's checks. The GitHub workflows call this script too, so a
# local run matches CI.
#
#   scripts/ci.sh             lint, Rego checks, tests, the Helm chart and the image build (ci.yml)
#   scripts/ci.sh --e2e       all of the above, then the full stack and the demo, with
#                             Compose and from the Helm chart's pods on Docker (e2e.yml)
#   scripts/ci.sh --e2e-only  only the end-to-end run
#   scripts/ci.sh --kind      also install the Helm chart on a kind cluster and run the demo
#   scripts/ci.sh --kind-only only that (e2e.yml)
#   scripts/ci.sh --spire     --kind, with SPIRE on the cluster issuing the components'
#                             certificates (e2e.yml, with --kind-only)
#   scripts/ci.sh --quick     lint, Rego checks and tests; no Docker
#   scripts/ci.sh --matrix    also run the tests on each Python 3.11-3.13 found
#   scripts/ci.sh --postgres  also run the tests on PostgreSQL (a throwaway container)
#   scripts/ci.sh --keep      leave the end-to-end stack running afterwards
#   scripts/ci.sh --setup     only prepare the toolchain (.venv and opa)
#
# Python dependencies go into .venv, and opa (and, for the chart, helm,
# kubeconform, kind and kubectl) into .venv/bin; they are fetched on first use. Docker steps need a Docker daemon. Behind an HTTPS proxy
# (HTTPS_PROXY, and SSL_CERT_FILE for a TLS-inspecting one), image builds go
# through it. The end-to-end run uses its own Compose project ("agentgov-ci")
# and the stack's usual host ports, so stop a running local stack first.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
OPA_VERSION=1.21.1
HELM_VERSION=3.19.0
KUBECONFORM_VERSION=0.7.0
KIND_VERSION=0.30.0
# Schemas of custom resources (External Secrets, the clouds' load balancer settings), for
# kubeconform: https://github.com/datreeio/CRDs-catalog
CRDS_CATALOG='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
KUBECTL_VERSION=1.34.1
CHART=deploy/helm/agentgov
AGENTGATEWAY_IMAGE=ghcr.io/agentgateway/agentgateway:v1.6.0
# Keycloak, as the authorization server of a server outside the gateway, takes AgentGov's
# identity assertions in a test (tests/test_assertions.py).
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.8.0
POSTGRES_IMAGE=postgres:17-alpine
# SPIRE 1.15.3 for the kind run with --spire, from the SPIFFE project's charts.
SPIRE_CHARTS=https://spiffe.github.io/helm-charts-hardened/
SPIRE_CRDS_CHART_VERSION=0.6.1
SPIRE_CHART_VERSION=0.30.3
COMPOSE=(docker compose -p agentgov-ci -f deploy/compose/docker-compose.yml)
E2E_PORTS=(8000 8080 8180 8181 4317 4318 9200 9300)

lint=1 tests=1 chart=1 image=1 e2e=0 kind=0 spire=0 matrix=0 postgres=0 keep=0 setup_only=0
for arg in "$@"; do
  case "$arg" in
    --e2e) e2e=1 postgres=1 ;;
    --e2e-only) lint=0 tests=0 chart=0 image=0 e2e=1 ;;
    --kind) kind=1 ;;
    --kind-only) lint=0 tests=0 chart=0 image=0 kind=1 ;;
    --spire) kind=1 spire=1 ;;
    --quick) chart=0 image=0 ;;
    --matrix) matrix=1 ;;
    --postgres) postgres=1 ;;
    --keep) keep=1 ;;
    --setup) setup_only=1 ;;
    -h | --help) awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  bold=$'\033[1m' red=$'\033[31m' green=$'\033[32m' yellow=$'\033[33m' reset=$'\033[0m'
else
  bold='' red='' green='' yellow='' reset=''
fi
results=()

heading() { printf '\n%s==> %s%s\n' "$bold" "$1" "$reset"; }

# run <name> <command...>: run one check and record the outcome; later checks still run.
run() {
  local name=$1
  shift
  heading "$name"
  if "$@"; then results+=("pass|$name"); else results+=("FAIL|$name"); fi
}

skip() {
  heading "$1"
  echo "skipped: $2"
  results+=("skip|$1 ($2)")
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# ------------------------------------------------------------------- toolchain

# setup_python <venv> <python>: a virtualenv with the project and its dev extras,
# reinstalled only when pyproject.toml changes.
setup_python() {
  local venv=$1 python=$2 stamp want
  [ -x "$venv/bin/python" ] || "$python" -m venv "$venv" || return 1
  stamp="$venv/.agentgov-deps"
  want=$(sha256 pyproject.toml)
  if [ ! -f "$stamp" ] || [ "$(cat "$stamp")" != "$want" ]; then
    echo "installing Python dependencies into $venv"
    "$venv/bin/python" -m pip --version >/dev/null 2>&1 ||
      "$venv/bin/python" -m ensurepip --upgrade >/dev/null || return 1
    "$venv/bin/python" -m pip install --quiet --disable-pip-version-check -e ".[dev,postgres]" ||
      return 1
    echo "$want" >"$stamp"
  fi
}

# platform: "<os> <arch>" as release downloads name them.
platform() {
  local os arch
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) echo "no downloads for $(uname -s): install the tools yourself" >&2; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "no downloads for $(uname -m)" >&2; return 1 ;;
  esac
  echo "$os $arch"
}

# fetch <url> <checksums url> <file>: download a release file and check its SHA-256
# against the published checksums (a bare hash, or "<hash>  <name>" lines).
fetch() {
  local url=$1 sums=$2 dest=$3 name tmp want
  name=$(basename "$url")
  tmp=$(mktemp -d)
  if curl -fsSL -o "$tmp/file" "$url" && curl -fsSL -o "$tmp/sums" "$sums"; then
    want=$(awk -v f="$name" 'NF == 1 || $2 == f || $2 == "*" f { print $1; exit }' "$tmp/sums")
    if [ -n "$want" ] && [ "$(sha256 "$tmp/file")" = "$want" ]; then
      mv "$tmp/file" "$dest"
      rm -rf "$tmp"
      return 0
    fi
  fi
  echo "could not download or verify $url" >&2
  rm -rf "$tmp"
  return 1
}

# The chart's tools, into .venv/bin, at the versions above.
setup_chart_tools() {
  local os arch tmp
  read -r os arch < <(platform) || return 1
  tmp=$(mktemp -d)
  if ! helm version --short 2>/dev/null | grep -q "^v$HELM_VERSION"; then
    echo "downloading helm $HELM_VERSION into .venv/bin"
    if ! { fetch "https://get.helm.sh/helm-v$HELM_VERSION-$os-$arch.tar.gz" \
      "https://get.helm.sh/helm-v$HELM_VERSION-$os-$arch.tar.gz.sha256sum" "$tmp/helm.tgz" &&
      tar -xzf "$tmp/helm.tgz" -C "$tmp" &&
      install -m 0755 "$tmp/$os-$arch/helm" .venv/bin/helm; }; then
      rm -rf "$tmp"
      return 1
    fi
  fi
  if ! kubeconform -v 2>/dev/null | grep -qx "v$KUBECONFORM_VERSION"; then
    echo "downloading kubeconform $KUBECONFORM_VERSION into .venv/bin"
    if ! { fetch "https://github.com/yannh/kubeconform/releases/download/v$KUBECONFORM_VERSION/kubeconform-$os-$arch.tar.gz" \
      "https://github.com/yannh/kubeconform/releases/download/v$KUBECONFORM_VERSION/CHECKSUMS" \
      "$tmp/kubeconform.tgz" &&
      tar -xzf "$tmp/kubeconform.tgz" -C "$tmp" kubeconform &&
      install -m 0755 "$tmp/kubeconform" .venv/bin/kubeconform; }; then
      rm -rf "$tmp"
      return 1
    fi
  fi
  rm -rf "$tmp"
}

setup_kind_tools() {
  local os arch
  read -r os arch < <(platform) || return 1
  if ! kind version 2>/dev/null | grep -q "^kind v$KIND_VERSION "; then
    echo "downloading kind $KIND_VERSION into .venv/bin"
    fetch "https://github.com/kubernetes-sigs/kind/releases/download/v$KIND_VERSION/kind-$os-$arch" \
      "https://github.com/kubernetes-sigs/kind/releases/download/v$KIND_VERSION/kind-$os-$arch.sha256sum" \
      .venv/bin/kind && chmod 0755 .venv/bin/kind || return 1
  fi
  if ! kubectl version --client 2>/dev/null | grep -qx "Client Version: v$KUBECTL_VERSION"; then
    echo "downloading kubectl $KUBECTL_VERSION into .venv/bin"
    fetch "https://dl.k8s.io/release/v$KUBECTL_VERSION/bin/$os/$arch/kubectl" \
      "https://dl.k8s.io/release/v$KUBECTL_VERSION/bin/$os/$arch/kubectl.sha256" .venv/bin/kubectl &&
      chmod 0755 .venv/bin/kubectl || return 1
  fi
}

setup_opa() {
  if command -v opa >/dev/null 2>&1 && opa version 2>/dev/null | grep -qx "Version: $OPA_VERSION"; then
    return 0
  fi
  local os arch asset url tmp
  read -r os arch < <(platform) || return 1
  asset="opa_${os}_${arch}"
  [ "$os/$arch" = darwin/amd64 ] || asset="${asset}_static"
  url="https://github.com/open-policy-agent/opa/releases/download/v$OPA_VERSION/$asset"
  echo "downloading opa $OPA_VERSION into .venv/bin"
  tmp=$(mktemp -d)
  if curl -fsSL -o "$tmp/opa" "$url" && curl -fsSL -o "$tmp/opa.sha256" "$url.sha256" &&
    [ "$(sha256 "$tmp/opa")" = "$(cut -d' ' -f1 "$tmp/opa.sha256")" ]; then
    install -m 0755 "$tmp/opa" .venv/bin/opa
    rm -rf "$tmp"
  else
    echo "could not download or verify $url" >&2
    rm -rf "$tmp"
    return 1
  fi
}

docker_ready() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

# Claude Code cloud sessions include dockerd but do not start it.
ensure_docker() {
  docker_ready && return 0
  if [ "${CLAUDE_CODE_REMOTE:-}" = true ] && [ "$(id -u)" = 0 ] && command -v dockerd >/dev/null 2>&1; then
    echo "starting dockerd (log: /tmp/agentgov-dockerd.log)"
    setsid nohup dockerd >/tmp/agentgov-dockerd.log 2>&1 </dev/null &
    for _ in $(seq 1 30); do
      docker_ready && return 0
      sleep 1
    done
  fi
  return 1
}

# first_line <command...>: the command's first line of output. Piping into `head -1`
# instead races: head exits early, the command dies of a broken pipe, and pipefail
# turns that into a failure.
first_line() {
  local out
  out=$("$@") || return
  printf '%s\n' "${out%%$'\n'*}"
}

# docker_build <tag> <context>: builds through the HTTPS proxy and its CA, if any.
docker_build() {
  local args=() proxy=${HTTPS_PROXY:-${https_proxy:-}}
  if [ -n "$proxy" ]; then
    args+=(--network host --build-arg "HTTPS_PROXY=$proxy"
      --build-arg "HTTP_PROXY=${HTTP_PROXY:-${http_proxy:-$proxy}}")
  fi
  if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "$SSL_CERT_FILE" ]; then
    args+=(--secret "id=extra_ca,src=$SSL_CERT_FILE")
  fi
  echo "building $1"
  DOCKER_BUILDKIT=1 docker build --quiet ${args[@]+"${args[@]}"} -t "$1" "$2" >/dev/null
}

# ---------------------------------------------------------------------- checks

lint_python() {
  ruff check src tests examples scripts && ruff format --check src tests examples scripts
}

# The docs: links between pages, and the settings reference generated from config.py.
lint_docs() {
  python scripts/check-docs.py && python scripts/settings-doc.py --check
}

# The Compose files, alone and with each override: they parse, and their variables resolve.
lint_compose() {
  local file
  for file in docker-compose.yml docker-compose.inventory.yml; do
    # The inventory stack refuses to start without an admin token of its own.
    AGENTGOV_ADMIN_TOKEN=lint docker compose -f "deploy/compose/$file" config --quiet ||
      return 1
  done
  for file in deploy/compose/docker-compose.*.yml; do
    case "$file" in */docker-compose.inventory.yml) continue ;; esac
    docker compose -f deploy/compose/docker-compose.yml -f "$file" config --quiet || return 1
  done
}

lint_rego() {
  local unformatted
  unformatted=$(opa fmt --list src/agentgov/policies examples/manifests/policies) || return 1
  if [ -n "$unformatted" ]; then
    printf 'not formatted with opa fmt:\n%s\n' "$unformatted"
    return 1
  fi
  opa check --strict src/agentgov/policies && opa test src/agentgov/policies
}

# run_tests <venv>: pytest as CI runs it; with Docker, generated agentgateway
# configs are also validated by the real binary.
run_tests() {
  local image
  if docker_ready; then
    for image in "$AGENTGATEWAY_IMAGE" "$KEYCLOAK_IMAGE"; do
      docker image inspect "$image" >/dev/null 2>&1 || docker pull --quiet "$image" >/dev/null ||
        echo "${yellow}could not pull $image; the tests that run it will be skipped${reset}"
    done
  fi
  "$1/bin/pytest" -rs
}

# matrix_tests <version>: the tests in a separate virtualenv for that Python.
matrix_tests() {
  setup_python ".venv-ci/py$1" "python$1" && run_tests ".venv-ci/py$1"
}

# postgres_tests <venv>: the tests again, each on a database of its own in a throwaway
# PostgreSQL, the database production runs on (tests/conftest.py).
postgres_tests() {
  local name=agentgov-ci-postgres port="" rc=0
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" -e POSTGRES_PASSWORD=ci -p 127.0.0.1::5432 "$POSTGRES_IMAGE" \
    -c fsync=off -c synchronous_commit=off -c full_page_writes=off >/dev/null || return 1
  # Over TCP: the image's first, initialising server listens on its socket only.
  for _ in $(seq 1 60); do
    if docker exec "$name" pg_isready -q -h 127.0.0.1 -U postgres; then
      port=$(docker port "$name" 5432/tcp | head -1 | sed 's/.*://')
      break
    fi
    sleep 1
  done
  if [ -z "$port" ]; then
    echo "PostgreSQL didn't start"
    rc=1
  else
    AGENTGOV_TEST_POSTGRES_URL="postgresql+psycopg://postgres:ci@127.0.0.1:$port/postgres" \
      "$1/bin/pytest" -rs || rc=1
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  return "$rc"
}

# The chart: lint, render the default, a production-like configuration and the profiles,
# and validate every manifest against the Kubernetes API schemas.
lint_chart() {
  local out rc=0
  setup_chart_tools || return 1
  if ! cmp -s deploy/compose/keycloak/agentgov-realm.json "$CHART/files/agentgov-realm.json"; then
    echo "$CHART/files/agentgov-realm.json differs from deploy/compose/keycloak/agentgov-realm.json"
    return 1
  fi
  out=$(mktemp -d)
  mkdir -p .venv/kubeconform-cache
  helm lint --strict "$CHART" &&
    helm template agentgov "$CHART" >"$out/default.yaml" &&
    helm template agentgov "$CHART" --set postgresql.enabled=false --set keycloak.enabled=false \
      --set externalDatabase.existingSecret=agentgov-db \
      --set externalKeycloak.url=https://keycloak.example.com \
      --set secrets.existingSecret=agentgov --set networkPolicy.enabled=true \
      --set controlPlane.ingress.enabled=true --set gateway.ingress.enabled=true \
      --set urls.controlPlane=https://agentgov.example.com \
      --set urls.gateway=https://mcp.example.com \
      --set controlPlane.transparencyLog.url=https://log2025-1.rekor.sigstore.dev \
      --set controlPlane.transparencyLog.signingKeySecret=agentgov-rekor \
      --set controlPlane.transparencyLog.logKey=placeholder >"$out/production.yaml" &&
    helm template agentgov "$CHART" --set postgresql.enabled=false \
      --set externalDatabase.existingSecret=agentgov-db \
      --set keycloak.externalDatabase.url=jdbc:postgresql://db.example.com:5432/keycloak \
      --set keycloak.externalDatabase.existingSecret=agentgov-db --set keycloak.mode=production \
      --set keycloak.replicas=2 --set keycloak.ingress.enabled=true \
      --set networkPolicy.enabled=true --set urls.keycloak=https://auth.example.com \
      >"$out/production-keycloak.yaml" &&
    helm lint --strict "$CHART" -f "$CHART/profiles/inventory.yaml" >/dev/null &&
    helm template agentgov "$CHART" -f "$CHART/profiles/inventory.yaml" \
      --set networkPolicy.enabled=true >"$out/inventory.yaml" &&
    helm lint --strict "$CHART" -f "$CHART/profiles/monitor.yaml" >/dev/null &&
    helm template agentgov "$CHART" -f "$CHART/profiles/monitor.yaml" \
      --set networkPolicy.enabled=true >"$out/monitor.yaml" &&
    kubeconform -strict -summary -cache .venv/kubeconform-cache -kubernetes-version 1.30.0 \
      "$out/default.yaml" "$out/production.yaml" "$out/production-keycloak.yaml" \
      "$out/inventory.yaml" "$out/monitor.yaml" || rc=1
  # The profiles run what they say: no gateway, OPA, Presidio or Keycloak in the inventory;
  # no Presidio when monitoring.
  if grep -qE 'name: agentgov-(gateway|processor|opa|presidio|keycloak)$' "$out/inventory.yaml" ||
    grep -qE 'name: agentgov-presidio$' "$out/monitor.yaml"; then
    echo "a profile renders a part it leaves out"
    rc=1
  fi
  # cert-manager issuing the components' certificates, from an authority of the release's
  # own, against the CRDs catalog's schemas of its resources.
  helm template agentgov "$CHART" --set internalTLS.certManager.enabled=true \
    >"$out/cert-manager.yaml" &&
    kubeconform -strict -summary -cache .venv/kubeconform-cache -kubernetes-version 1.30.0 \
      -schema-location default -schema-location "$CRDS_CATALOG" "$out/cert-manager.yaml" || rc=1
  # SPIRE issuing them (ClusterSPIFFEIDs), against the schema in deploy/helm/schemas: the
  # catalog has none for SPIRE's resources.
  helm lint --strict "$CHART" --set internalTLS.spire.enabled=true >/dev/null &&
    helm template agentgov "$CHART" --set internalTLS.spire.enabled=true >"$out/spire.yaml" &&
    kubeconform -strict -summary -cache .venv/kubeconform-cache -kubernetes-version 1.30.0 \
      -schema-location default \
      -schema-location 'deploy/helm/schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
      "$out/spire.yaml" || rc=1
  # The cloud guides' values (docs/deploy), and the manifests they apply beside the chart,
  # against the Kubernetes schemas and, for their custom resources, the CRDs catalog.
  local cloud
  for cloud in deploy/kubernetes/*/; do
    [ -f "$cloud/values.yaml" ] || continue
    helm template agentgov "$CHART" -f "$cloud/values.yaml" >"$out/cloud.yaml" &&
      kubeconform -strict -summary -cache .venv/kubeconform-cache -kubernetes-version 1.30.0 \
        -schema-location default -schema-location "$CRDS_CATALOG" "$out/cloud.yaml" || rc=1
    # The catalog's schemas of the External Secrets Operator's stores don't compile as
    # JSON Schema draft 4, which kubeconform uses (a boolean where a schema should be).
    if compgen -G "$cloud/manifests/*.yaml" >/dev/null; then
      kubeconform -strict -summary -cache .venv/kubeconform-cache -kubernetes-version 1.30.0 \
        -schema-location default -schema-location "$CRDS_CATALOG" \
        -skip SecretStore,ClusterSecretStore "$cloud"manifests/*.yaml || rc=1
    fi
  done
  # Examples applied beside AgentGov, such as the NetworkPolicy that lets only the gateway
  # reach an agent (docs/agent-to-agent.md).
  kubeconform -strict -summary -cache .venv/kubeconform-cache -kubernetes-version 1.30.0 \
    examples/kubernetes/*.yaml || rc=1
  rm -rf "$out"
  return "$rc"
}

image_smoke() {
  docker_build agentgov:ci . &&
    docker run --rm agentgov:ci version &&
    first_line docker run --rm --entrypoint opa agentgov:ci version
}

port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

e2e_logs() {
  echo "${yellow}--- last 100 log lines per service ---${reset}"
  "${COMPOSE[@]}" logs --no-color --tail 100 || true
}

# The control plane's image and the demo's stand-ins: a tool server, a model provider,
# a workload identity issuer, the security team's tools and an agent other agents call.
build_demo_images() {
  docker_build agentgov:local . && docker_build agentgov-demo-crm:local examples/mcp-servers/crm &&
    docker_build agentgov-demo-model:local examples/models/mock &&
    docker_build agentgov-demo-issuer:local examples/identity/workload-issuer &&
    docker_build agentgov-demo-sink:local examples/secops/sink &&
    docker_build agentgov-demo-billing:local examples/agents/billing
}

# The demo's stand-in for IBM Granite Guardian (examples/models/mock), which the control
# plane and the processor ask for a second opinion (docs/detection.md).
DEMO_GUARDIAN_URL=http://demo-model:9100/guardian/v1

# What the demo needs from the chart: the destinations' secrets
# (examples/manifests/secops.yaml), the sink's Slack and Teams webhook URLs and its Splunk
# token; and the sink as the authority that time-stamps the ledger's checkpoints.
DEMO_DESTINATION_SECRETS=(
  --set controlPlane.env.AGENTGOV_LEDGER_TSA_URL=http://demo-sink:9300/tsa
  --set destinationSecrets.values.soc-slack=http://demo-sink:9300/slack/T0000/B0000/demo-only
  --set destinationSecrets.values.soc-teams=http://demo-sink:9300/teams/workflows/demo-only
  --set destinationSecrets.values.soc-splunk=demo-hec-token
  --set destinationSecrets.values.cx-slack=http://demo-sink:9300/slack/T0000/B0001/cx-platform
  --set destinationSecrets.values.governance-teams=http://demo-sink:9300/teams/workflows/governance
)

# Each component's certificate renewed, as cert-manager or SPIRE would: the components take
# their new ones without a restart (AGENTGOV_TLS_RELOAD_SECONDS, OPA's
# --tls-cert-refresh-period), and the gateway's rewrites agentgateway's configuration.
renewed_certificates() {
  local before after i
  before=$("${COMPOSE[@]}" exec -T gateway-config tail -n 1 /gateway/config.yaml) || return 1
  "${COMPOSE[@]}" run --rm --no-deps -T --entrypoint sh certs -c \
    "agentgov internal-certs /certs --renew >/dev/null && chmod a+r /certs/*/tls.key" || return 1
  echo "certificates renewed; waiting for the components to take them"
  for i in $(seq 30); do
    sleep 5
    after=$("${COMPOSE[@]}" exec -T gateway-config tail -n 1 /gateway/config.yaml) || continue
    [ "$after" != "$before" ] || continue
    # Which certificate each one serves (shown a certificate each takes, the gateway's).
    "${COMPOSE[@]}" run --rm --no-deps -T --entrypoint python certs - $((i * 5)) <<'EOF' && return 0
import socket
import ssl
import sys
from pathlib import Path

from cryptography import x509

stale = []
for host, port, alpn in [("control-plane", 8443, []), ("processor", 50051, ["h2"]),
                         ("processor", 8091, []), ("opa", 8181, [])]:
    context = ssl.create_default_context(cafile="/certs/ca/ca.crt")
    context.load_cert_chain("/certs/gateway/tls.crt", "/certs/gateway/tls.key")
    context.set_alpn_protocols(alpn or ["http/1.1"])
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                served = x509.load_der_x509_certificate(conn.getpeercert(binary_form=True))
    except OSError as exc:
        stale.append(f"{host}:{port} ({exc})")
        continue
    held = x509.load_pem_x509_certificate(Path(f"/certs/{host}/tls.crt").read_bytes())
    if served.serial_number != held.serial_number:
        stale.append(f"{host}:{port}")
print(f"not yet renewed: {', '.join(stale)}" if stale else
      f"each serves its renewed certificate, within {sys.argv[1]} seconds")
sys.exit(1 if stale else 0)
EOF
  done
  echo "the components didn't take their renewed certificates"
  return 1
}

end_to_end() {
  local port busy=() rc=0
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  for port in "${E2E_PORTS[@]}"; do
    if port_in_use "$port"; then busy+=("$port"); fi
  done
  if [ ${#busy[@]} -gt 0 ]; then
    echo "ports in use: ${busy[*]}. Stop the local stack first:"
    echo "  docker compose -f deploy/compose/docker-compose.yml down"
    return 1
  fi
  build_demo_images || return 1
  echo "starting the stack (project agentgov-ci)"
  if ! AGENTGOV_GUARDIAN_URL=$DEMO_GUARDIAN_URL \
    "${COMPOSE[@]}" up -d --no-build --wait --wait-timeout 600 >/dev/null; then
    e2e_logs
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    return 1
  fi
  export AGENTGOV_URL=http://localhost:8000 AGENTGOV_TOKEN=dev-admin-token
  # The demo runs on renewed certificates.
  agentgov apply -f examples/manifests &&
    renewed_certificates &&
    python examples/agents/demo_agent.py &&
    agentgov ledger verify || rc=1
  [ "$rc" = 0 ] || e2e_logs
  if [ "$keep" = 1 ]; then
    echo "stack left running; remove it with: ${COMPOSE[*]} down -v"
  else
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  return "$rc"
}

# The inventory stack (docker-compose.inventory.yml): the control plane and PostgreSQL
# alone start, apply the inventory starting point, and keep a ledger that verifies.
inventory_end_to_end() {
  local compose=(docker compose -p agentgov-ci-inventory -f deploy/compose/docker-compose.inventory.yml)
  local rc=0
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if port_in_use 8000; then
    echo "port 8000 in use. Stop the stack that has it first"
    return 1
  fi
  # It has no token everybody knows: without one of its own, it doesn't start.
  if AGENTGOV_ADMIN_TOKEN= "${compose[@]}" config --quiet >/dev/null 2>&1; then
    echo "the inventory stack starts without an admin token"
    return 1
  fi
  local token
  token=$(python -c 'import secrets; print(secrets.token_hex(16))')
  if ! AGENTGOV_ADMIN_TOKEN=$token "${compose[@]}" up -d --no-build --wait --wait-timeout 300 >/dev/null; then
    "${compose[@]}" logs --no-color --tail 100 || true
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    return 1
  fi
  AGENTGOV_URL=http://localhost:8000 AGENTGOV_TOKEN=$token python scripts/check-inventory.py &&
    AGENTGOV_URL=http://localhost:8000 AGENTGOV_TOKEN=$token agentgov ledger verify ||
    rc=1
  [ "$rc" = 0 ] || "${compose[@]}" logs --no-color --tail 100 || true
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  return "$rc"
}

# The chart's pods, run by scripts/chart-on-docker.py where Kubernetes can't run
# (as in containers without cgroup v2), and the same demo against them.
chart_on_docker() {
  local rendered rc=0 busy=() port
  setup_chart_tools || return 1
  for port in 8000 8080 8180 4318 9200 9300; do
    if port_in_use "$port"; then busy+=("$port"); fi
  done
  if [ ${#busy[@]} -gt 0 ]; then
    echo "ports in use: ${busy[*]}; stop what uses them first"
    return 1
  fi
  build_demo_images || return 1
  rendered=$(mktemp)
  # Keycloak in production mode here (Compose runs it in development mode), and two
  # control-plane replicas: the demo's requests alternate between them.
  helm template agentgov "$CHART" --set image.repository=agentgov --set image.tag=local \
    --set image.pullPolicy=Never --set presidio.image.tag=2.2.364 --set keycloak.mode=production \
    --set controlPlane.replicas=2 --set guardian.url="$DEMO_GUARDIAN_URL" \
    --set modelKeys.keys.demo=demo-model-key "${DEMO_DESTINATION_SECRETS[@]}" >"$rendered" || return 1
  python scripts/chart-on-docker.py down
  if python scripts/chart-on-docker.py up "$rendered" --demo; then
    AGENTGOV_TOKEN=$(python scripts/chart-on-docker.py secret "$rendered" admin-token)
    AGENTGOV_DEMO_PASSWORD=$(python scripts/chart-on-docker.py secret "$rendered" demo-password)
    export AGENTGOV_URL=http://localhost:8000 AGENTGOV_TOKEN AGENTGOV_DEMO_PASSWORD
    agentgov apply -f examples/manifests &&
      python examples/agents/demo_agent.py &&
      agentgov ledger verify || rc=1
  else
    rc=1
  fi
  [ "$rc" = 0 ] || python scripts/chart-on-docker.py logs
  if [ "$keep" = 1 ]; then
    echo "pods left running; remove them with: python scripts/chart-on-docker.py down"
  else
    python scripts/chart-on-docker.py down
  fi
  rm -f "$rendered"
  return "$rc"
}

# The chart on a real cluster: kind, with every image loaded from the local
# Docker, the demo MCP server and model beside it, and the same demo as the
# Compose run.
KIND_CLUSTER=agentgov-ci
KIND_NAMESPACE=agentgov
# With --spire: SPIRE's quick install, as its chart's readme has it, whose controller
# manager's class is <namespace>-<release>.
SPIRE_NAMESPACE="spire-server"

kind_logs() {
  local namespace pod namespaces=("$KIND_NAMESPACE") stats=.status.stats
  [ "$spire" = 0 ] || namespaces+=("$SPIRE_NAMESPACE")
  echo "${yellow}--- pods and their last 60 log lines ---${reset}"
  for namespace in "${namespaces[@]}"; do
    kubectl -n "$namespace" get pods -o wide || true
    kubectl -n "$namespace" get events --sort-by=.lastTimestamp | tail -30 || true
    for pod in $(kubectl -n "$namespace" get pods -o name 2>/dev/null); do
      echo "--- $namespace/$pod"
      kubectl -n "$namespace" logs "$pod" --all-containers --tail 60 || true
    done
  done
  # What SPIRE's controller manager made of each ClusterSPIFFEID.
  [ "$spire" = 0 ] || kubectl get clusterspiffeids -o custom-columns="NAME:.metadata.name,\
PODS:$stats.podsSelected,ENTRIES:$stats.entriesToSet,FAILED:$stats.entryFailures" || true
}

# With --spire, after the demo: the control plane serves an X.509-SVID from SPIRE with its
# SPIFFE ID, and one SPIRE issued after the control plane started, so renewed in place. The
# run's SVIDs last minutes, so SPIRE renews them as the demo runs. The processor connects,
# with its own SVID: the control plane takes it.
spire_renewed() {
  local started probe out='' i
  local want="spiffe://example.org/ns/$KIND_NAMESPACE/agentgov/agentgov-control-plane"
  probe=$(
    cat <<'EOF'
import socket
import ssl
import sys
from datetime import datetime

from cryptography import x509

want, started = sys.argv[1], datetime.fromisoformat(sys.argv[2])
context = ssl.create_default_context(cafile="/tls/ca.crt")
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
with socket.create_connection(("agentgov-control-plane", 8443), timeout=5) as raw:
    with context.wrap_socket(raw, server_hostname="agentgov-control-plane") as conn:
        served = x509.load_der_x509_certificate(conn.getpeercert(binary_form=True))
names = served.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
ids = names.get_values_for_type(x509.UniformResourceIdentifier)
if ids != [want]:
    print(f"the control plane's certificate names {ids}, not {want}")
    sys.exit(2)
if served.not_valid_before_utc <= started:
    sys.exit(f"the control plane serves the SVID it started with, from {served.not_valid_before_utc}")
print(f"the control plane serves {want}, an SVID from SPIRE renewed in place")
EOF
  )
  started=$(kubectl -n "$KIND_NAMESPACE" get pods \
    -l app.kubernetes.io/instance=agentgov,app.kubernetes.io/component=control-plane \
    -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="control-plane")].state.running.startedAt}')
  [ -n "$started" ] || { echo "the control plane isn't running" >&2; return 1; }
  for i in $(seq 72); do
    out=$(kubectl -n "$KIND_NAMESPACE" exec deploy/agentgov-processor -c processor -- \
      python -c "$probe" "$want" "$started" 2>&1) && { echo "$out"; return 0; }
    [ $? = 1 ] || break
    sleep 5
  done
  echo "$out" >&2
  return 1
}

# wait_port <port>: until something accepts connections on localhost:<port>.
wait_port() {
  local _
  for _ in $(seq 1 60); do
    port_in_use "$1" && return 0
    sleep 1
  done
  echo "nothing listening on port $1" >&2
  return 1
}

kind_end_to_end() {
  local rc=0 image pids=() values=(
    --set image.repository=agentgov --set image.tag=local --set image.pullPolicy=Never
    # kind loads images by tag: the digest pin would make the node pull it.
    --set presidio.image.tag=2.2.364
    --set modelKeys.keys.demo=demo-model-key
    --set guardian.url="$DEMO_GUARDIAN_URL"
    "${DEMO_DESTINATION_SECRETS[@]}"
  )
  if [ "$spire" = 1 ]; then
    # SVIDs that last minutes: SPIRE renews them as the demo runs.
    values+=(--set internalTLS.spire.enabled=true --set internalTLS.spire.ttl=6m
      --set internalTLS.spire.className="$SPIRE_NAMESPACE-spire")
  fi
  setup_chart_tools && setup_kind_tools || return 1
  kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
  build_demo_images || return 1
  kind create cluster --name "$KIND_CLUSTER" --wait 180s || return 1
  for image in agentgov-demo-crm:local agentgov-demo-model:local agentgov-demo-issuer:local \
    agentgov-demo-sink:local agentgov-demo-billing:local \
    $(helm template agentgov "$CHART" "${values[@]}" |
    awk '$1 == "image:" { gsub(/"/, "", $2); print $2 }' | sort -u); do
    if ! { docker image inspect "$image" >/dev/null 2>&1 || docker pull --quiet "$image" >/dev/null; } ||
      ! kind load docker-image --name "$KIND_CLUSTER" "$image" >/dev/null; then
      rc=1
      break
    fi
  done
  if [ "$rc" = 0 ] && [ "$spire" = 1 ]; then
    echo "installing SPIRE"
    helm install spire-crds spire-crds --repo "$SPIRE_CHARTS" --version "$SPIRE_CRDS_CHART_VERSION" \
      -n "$SPIRE_NAMESPACE" --create-namespace --wait &&
      helm install spire spire --repo "$SPIRE_CHARTS" --version "$SPIRE_CHART_VERSION" \
        -n "$SPIRE_NAMESPACE" --set spiffe-oidc-discovery-provider.enabled=false \
        --wait --timeout 10m || rc=1
  fi
  if [ "$rc" = 0 ]; then
    kubectl create namespace "$KIND_NAMESPACE" >/dev/null &&
      kubectl -n "$KIND_NAMESPACE" apply -f - >/dev/null <<'EOF' || rc=1
apiVersion: apps/v1
kind: Deployment
metadata: {name: crm-mcp}
spec:
  selector: {matchLabels: {app: crm-mcp}}
  template:
    metadata: {labels: {app: crm-mcp}}
    spec:
      containers:
        - {name: crm, image: "agentgov-demo-crm:local", imagePullPolicy: Never, ports: [{containerPort: 9000}]}
---
apiVersion: v1
kind: Service
metadata: {name: crm-mcp}
spec:
  selector: {app: crm-mcp}
  ports: [{port: 9000}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: demo-model}
spec:
  selector: {matchLabels: {app: demo-model}}
  template:
    metadata: {labels: {app: demo-model}}
    spec:
      containers:
        - name: model
          image: "agentgov-demo-model:local"
          imagePullPolicy: Never
          ports: [{containerPort: 9100}]
          env: [{name: MOCK_MODEL_KEY, value: demo-model-key}]
---
apiVersion: v1
kind: Service
metadata: {name: demo-model}
spec:
  selector: {app: demo-model}
  ports: [{port: 9100}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: workload-issuer}
spec:
  selector: {matchLabels: {app: workload-issuer}}
  template:
    metadata: {labels: {app: workload-issuer}}
    spec:
      containers:
        - name: issuer
          image: "agentgov-demo-issuer:local"
          imagePullPolicy: Never
          ports: [{containerPort: 9200}]
          env: [{name: ISSUER, value: "http://workload-issuer:9200"}]
---
apiVersion: v1
kind: Service
metadata: {name: workload-issuer}
spec:
  selector: {app: workload-issuer}
  ports: [{port: 9200}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: demo-sink}
spec:
  selector: {matchLabels: {app: demo-sink}}
  template:
    metadata: {labels: {app: demo-sink}}
    spec:
      containers:
        - name: sink
          image: "agentgov-demo-sink:local"
          imagePullPolicy: Never
          ports: [{containerPort: 9300}]
          env: [{name: HEC_TOKEN, value: demo-hec-token}]
---
apiVersion: v1
kind: Service
metadata: {name: demo-sink}
spec:
  selector: {app: demo-sink}
  ports: [{port: 9300}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: billing-agent}
spec:
  selector: {matchLabels: {app: billing-agent}}
  template:
    metadata: {labels: {app: billing-agent}}
    spec:
      containers:
        - name: agent
          image: "agentgov-demo-billing:local"
          imagePullPolicy: Never
          ports: [{containerPort: 9600}]
          env:
            - {name: GATEWAY_URL, value: "http://agentgov-gateway:8080"}
            - {name: TOKEN_URL, value: "http://agentgov-keycloak:8080/realms/agentgov/protocol/openid-connect/token"}
            - {name: ASSERTION_AUDIENCE, value: "http://localhost:8180/realms/agentgov"}
            - {name: WORKLOAD_ISSUER, value: "http://workload-issuer:9200"}
            - {name: DELEGATION_JWKS_URL, value: "http://agentgov-control-plane:8000/v1/delegations/jwks"}
---
apiVersion: v1
kind: Service
metadata: {name: billing-agent}
spec:
  selector: {app: billing-agent}
  ports: [{port: 9600}]
EOF
  fi
  if [ "$rc" = 0 ]; then
    echo "installing the chart"
    helm install agentgov "$CHART" -n "$KIND_NAMESPACE" "${values[@]}" --wait --timeout 15m || rc=1
  fi
  if [ "$rc" = 0 ]; then
    for forward in agentgov-control-plane:8000:8000 agentgov-gateway:8080:8080 \
      agentgov-keycloak:8180:8080 agentgov-otel-collector:4318:4318 workload-issuer:9200:9200 \
      demo-sink:9300:9300; do
      IFS=: read -r service local remote <<<"$forward"
      kubectl -n "$KIND_NAMESPACE" port-forward "svc/$service" "$local:$remote" >/dev/null &
      pids+=($!)
    done
    for port in 8000 8080 8180 4318 9200 9300; do wait_port "$port" || rc=1; done
  fi
  if [ "$rc" = 0 ]; then
    AGENTGOV_TOKEN=$(kubectl -n "$KIND_NAMESPACE" get secret agentgov \
      -o jsonpath='{.data.admin-token}' | base64 -d)
    AGENTGOV_DEMO_PASSWORD=$(kubectl -n "$KIND_NAMESPACE" get secret agentgov \
      -o jsonpath='{.data.demo-password}' | base64 -d)
    export AGENTGOV_URL=http://localhost:8000 AGENTGOV_TOKEN AGENTGOV_DEMO_PASSWORD
    agentgov apply -f examples/manifests &&
      python examples/agents/demo_agent.py &&
      agentgov ledger verify &&
      helm test agentgov -n "$KIND_NAMESPACE" || rc=1
  fi
  if [ "$rc" = 0 ] && [ "$spire" = 1 ]; then
    spire_renewed || rc=1
  fi
  [ "$rc" = 0 ] || kind_logs
  [ ${#pids[@]} -eq 0 ] || kill "${pids[@]}" 2>/dev/null || true
  if [ "$keep" = 1 ]; then
    echo "cluster left running; remove it with: kind delete cluster --name $KIND_CLUSTER"
  else
    kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
  fi
  return "$rc"
}

# ------------------------------------------------------------------------ main

heading "Toolchain"
setup_python .venv "${PYTHON:-python3}" || { echo "${red}Python setup failed${reset}"; exit 1; }
export PATH="$ROOT/.venv/bin:$PATH"
setup_opa || { echo "${red}opa setup failed${reset}"; exit 1; }
echo "$(python --version), $(first_line opa version), ruff $(ruff --version | cut -d' ' -f2)"
[ "$setup_only" = 1 ] && exit 0

# Docker is started when a step needs it; tests use it only if it is already up.
if [ "$image" = 1 ] || [ "$e2e" = 1 ] || [ "$kind" = 1 ] || [ "$postgres" = 1 ]; then
  ensure_docker || true
fi

if [ "$lint" = 1 ]; then
  run "Lint (ruff)" lint_python
  run "Docs (links, settings reference)" lint_docs
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    run "Compose files (config)" lint_compose
  else
    skip "Compose files (config)" "no docker compose"
  fi
  run "Rego (opa fmt, check --strict, test)" lint_rego
fi
if [ "$tests" = 1 ]; then
  run "Tests ($(python --version))" run_tests .venv
  if [ "$matrix" = 1 ]; then
    for version in 3.11 3.12 3.13; do
      if command -v "python$version" >/dev/null 2>&1; then
        run "Tests (Python $version)" matrix_tests "$version"
      else
        skip "Tests (Python $version)" "python$version not found"
      fi
    done
  fi
  if [ "$postgres" = 1 ]; then
    if docker_ready; then run "Tests on PostgreSQL" postgres_tests .venv; else
      skip "Tests on PostgreSQL" "no Docker daemon"
    fi
  fi
fi
if [ "$chart" = 1 ]; then
  run "Helm chart (lint, render, kubeconform)" lint_chart
fi
if [ "$image" = 1 ]; then
  if docker_ready; then run "Image build and smoke test" image_smoke; else
    skip "Image build and smoke test" "no Docker daemon"
  fi
fi
if [ "$e2e" = 1 ]; then
  if docker_ready; then
    run "End to end (stack + demo + ledger)" end_to_end
    run "End to end (Helm chart's pods on Docker + demo + ledger)" chart_on_docker
    run "End to end (inventory stack + ledger)" inventory_end_to_end
  else
    skip "End to end (stack + demo + ledger)" "no Docker daemon"
  fi
fi

if [ "$kind" = 1 ]; then
  name="Kubernetes (Helm chart on kind$([ "$spire" = 0 ] || echo " with SPIRE") + demo + ledger)"
  if docker_ready; then run "$name" kind_end_to_end; else skip "$name" "no Docker daemon"; fi
fi

heading "Summary"
failed=0
for result in "${results[@]}"; do
  status=${result%%|*} name=${result#*|}
  case "$status" in
    pass) echo "  ${green}pass${reset}  $name" ;;
    skip) echo "  ${yellow}skip${reset}  $name" ;;
    *) echo "  ${red}FAIL${reset}  $name"; failed=1 ;;
  esac
done
exit "$failed"
