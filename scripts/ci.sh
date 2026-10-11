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
#   scripts/ci.sh --quick     lint, Rego checks and tests; no Docker
#   scripts/ci.sh --matrix    also run the tests on each Python 3.11-3.13 found
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
KUBECTL_VERSION=1.34.1
CHART=deploy/helm/agentgov
AGENTGATEWAY_IMAGE=ghcr.io/agentgateway/agentgateway:v1.6.0
COMPOSE=(docker compose -p agentgov-ci -f deploy/compose/docker-compose.yml)
E2E_PORTS=(8000 8080 8180 8181 4317 4318 9200)

lint=1 tests=1 chart=1 image=1 e2e=0 kind=0 matrix=0 keep=0 setup_only=0
for arg in "$@"; do
  case "$arg" in
    --e2e) e2e=1 ;;
    --e2e-only) lint=0 tests=0 chart=0 image=0 e2e=1 ;;
    --kind) kind=1 ;;
    --kind-only) lint=0 tests=0 chart=0 image=0 kind=1 ;;
    --quick) chart=0 image=0 ;;
    --matrix) matrix=1 ;;
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
  if docker_ready && ! docker image inspect "$AGENTGATEWAY_IMAGE" >/dev/null 2>&1; then
    docker pull --quiet "$AGENTGATEWAY_IMAGE" >/dev/null ||
      echo "${yellow}could not pull $AGENTGATEWAY_IMAGE; its validation test will be skipped${reset}"
  fi
  "$1/bin/pytest" -rs
}

# matrix_tests <version>: the tests in a separate virtualenv for that Python.
matrix_tests() {
  setup_python ".venv-ci/py$1" "python$1" && run_tests ".venv-ci/py$1"
}

# The chart: lint, render the default and a production-like configuration, and
# validate every manifest against the Kubernetes API schemas.
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
      --set urls.gateway=https://mcp.example.com >"$out/production.yaml" &&
    kubeconform -strict -summary -cache .venv/kubeconform-cache -kubernetes-version 1.30.0 \
      "$out/default.yaml" "$out/production.yaml" || rc=1
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

# The control plane's image and the demo's stand-ins: a tool server, a model provider
# and a workload identity issuer.
build_demo_images() {
  docker_build agentgov:local . && docker_build agentgov-demo-crm:local examples/mcp-servers/crm &&
    docker_build agentgov-demo-model:local examples/models/mock &&
    docker_build agentgov-demo-issuer:local examples/identity/workload-issuer
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
  if ! "${COMPOSE[@]}" up -d --no-build --wait --wait-timeout 600 >/dev/null; then
    e2e_logs
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    return 1
  fi
  export AGENTGOV_URL=http://localhost:8000 AGENTGOV_TOKEN=dev-admin-token
  agentgov apply -f examples/manifests &&
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

# The chart's pods, run by scripts/chart-on-docker.py where Kubernetes can't run
# (as in containers without cgroup v2), and the same demo against them.
chart_on_docker() {
  local rendered rc=0 busy=() port
  setup_chart_tools || return 1
  for port in 8000 8080 8180 4318 9200; do
    if port_in_use "$port"; then busy+=("$port"); fi
  done
  if [ ${#busy[@]} -gt 0 ]; then
    echo "ports in use: ${busy[*]}; stop what uses them first"
    return 1
  fi
  build_demo_images || return 1
  rendered=$(mktemp)
  helm template agentgov "$CHART" --set image.repository=agentgov --set image.tag=local \
    --set image.pullPolicy=Never --set presidio.image.tag=2.2.364 \
    --set modelKeys.keys.demo=demo-model-key >"$rendered" || return 1
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

kind_logs() {
  echo "${yellow}--- pods and their last 60 log lines ---${reset}"
  kubectl -n "$KIND_NAMESPACE" get pods -o wide || true
  kubectl -n "$KIND_NAMESPACE" get events --sort-by=.lastTimestamp | tail -30 || true
  local pod
  for pod in $(kubectl -n "$KIND_NAMESPACE" get pods -o name 2>/dev/null); do
    echo "--- $pod"
    kubectl -n "$KIND_NAMESPACE" logs "$pod" --all-containers --tail 60 || true
  done
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
  )
  setup_chart_tools && setup_kind_tools || return 1
  kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
  build_demo_images || return 1
  kind create cluster --name "$KIND_CLUSTER" --wait 180s || return 1
  for image in agentgov-demo-crm:local agentgov-demo-model:local agentgov-demo-issuer:local \
    $(helm template agentgov "$CHART" "${values[@]}" |
    awk '$1 == "image:" { gsub(/"/, "", $2); print $2 }' | sort -u); do
    if ! { docker image inspect "$image" >/dev/null 2>&1 || docker pull --quiet "$image" >/dev/null; } ||
      ! kind load docker-image --name "$KIND_CLUSTER" "$image" >/dev/null; then
      rc=1
      break
    fi
  done
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
EOF
  fi
  if [ "$rc" = 0 ]; then
    echo "installing the chart"
    helm install agentgov "$CHART" -n "$KIND_NAMESPACE" "${values[@]}" --wait --timeout 15m || rc=1
  fi
  if [ "$rc" = 0 ]; then
    for forward in agentgov-control-plane:8000:8000 agentgov-gateway:8080:8080 \
      agentgov-keycloak:8180:8080 agentgov-otel-collector:4318:4318 workload-issuer:9200:9200; do
      IFS=: read -r service local remote <<<"$forward"
      kubectl -n "$KIND_NAMESPACE" port-forward "svc/$service" "$local:$remote" >/dev/null &
      pids+=($!)
    done
    for port in 8000 8080 8180 4318 9200; do wait_port "$port" || rc=1; done
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
if [ "$image" = 1 ] || [ "$e2e" = 1 ] || [ "$kind" = 1 ]; then ensure_docker || true; fi

if [ "$lint" = 1 ]; then
  run "Lint (ruff)" lint_python
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
  else
    skip "End to end (stack + demo + ledger)" "no Docker daemon"
  fi
fi

if [ "$kind" = 1 ]; then
  if docker_ready; then run "Kubernetes (Helm chart on kind + demo + ledger)" kind_end_to_end; else
    skip "Kubernetes (Helm chart on kind + demo + ledger)" "no Docker daemon"
  fi
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
