#!/usr/bin/env bash
# shellcheck disable=SC2329  # check functions are called through run()
# Runs this repository's checks. The GitHub workflows call this script too, so a
# local run matches CI.
#
#   scripts/ci.sh             lint, Rego checks, tests and the image build (ci.yml)
#   scripts/ci.sh --e2e       all of the above, then the full stack and the demo (e2e.yml)
#   scripts/ci.sh --e2e-only  only the end-to-end run
#   scripts/ci.sh --quick     lint, Rego checks and tests; no Docker
#   scripts/ci.sh --matrix    also run the tests on each Python 3.11-3.13 found
#   scripts/ci.sh --keep      leave the end-to-end stack running afterwards
#   scripts/ci.sh --setup     only prepare the toolchain (.venv and opa)
#
# Python dependencies go into .venv and opa into .venv/bin; both are created on
# first use. Docker steps need a Docker daemon. Behind an HTTPS proxy
# (HTTPS_PROXY, and SSL_CERT_FILE for a TLS-inspecting one), image builds go
# through it. The end-to-end run uses its own Compose project ("agentgov-ci")
# and the stack's usual host ports, so stop a running local stack first.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
OPA_VERSION=1.21.1
AGENTGATEWAY_IMAGE=ghcr.io/agentgateway/agentgateway:v1.6.0
COMPOSE=(docker compose -p agentgov-ci -f deploy/compose/docker-compose.yml)
E2E_PORTS=(8000 8080 8180 8181 4317 4318)

lint=1 tests=1 image=1 e2e=0 matrix=0 keep=0 setup_only=0
for arg in "$@"; do
  case "$arg" in
    --e2e) e2e=1 ;;
    --e2e-only) lint=0 tests=0 image=0 e2e=1 ;;
    --quick) image=0 ;;
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

setup_opa() {
  if command -v opa >/dev/null 2>&1 && opa version 2>/dev/null | grep -qx "Version: $OPA_VERSION"; then
    return 0
  fi
  local os arch asset url tmp
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) echo "install opa $OPA_VERSION yourself and put it on PATH" >&2; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "no opa build for $(uname -m)" >&2; return 1 ;;
  esac
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
  ruff check src tests examples && ruff format --check src tests examples
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
  docker_build agentgov:local . && docker_build agentgov-demo-crm:local examples/mcp-servers/crm ||
    return 1
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

# ------------------------------------------------------------------------ main

heading "Toolchain"
setup_python .venv "${PYTHON:-python3}" || { echo "${red}Python setup failed${reset}"; exit 1; }
export PATH="$ROOT/.venv/bin:$PATH"
setup_opa || { echo "${red}opa setup failed${reset}"; exit 1; }
echo "$(python --version), $(first_line opa version), ruff $(ruff --version | cut -d' ' -f2)"
[ "$setup_only" = 1 ] && exit 0

# Docker is started when a step needs it; tests use it only if it is already up.
if [ "$image" = 1 ] || [ "$e2e" = 1 ]; then ensure_docker || true; fi

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
if [ "$image" = 1 ]; then
  if docker_ready; then run "Image build and smoke test" image_smoke; else
    skip "Image build and smoke test" "no Docker daemon"
  fi
fi
if [ "$e2e" = 1 ]; then
  if docker_ready; then run "End to end (stack + demo + ledger)" end_to_end; else
    skip "End to end (stack + demo + ledger)" "no Docker daemon"
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
