# Contributing to AgentGov

Thanks for helping. AgentGov is young, so issues describing how you govern agents today
(and where that hurts) are as valuable as code.

## The one design rule

AgentGov composes established open-source projects and writes only what none of them
provides ([ADR 0001](docs/adr/0001-compose-established-projects.md)). Before adding a
feature, check whether Keycloak, OPA, agentgateway, Presidio or the OpenTelemetry Collector
already does it. If one does, configure or generate configuration for it instead of
reimplementing it. Policy logic belongs in Rego (`src/agentgov/policies`), not in Python.

Significant decisions get a short ADR in `docs/adr/`.

## Development setup

You need Python 3.11 or later and the [OPA](https://www.openpolicyagent.org/docs/#running-opa)
binary (1.21) on your `PATH`. Docker is optional; with it, the tests also validate the
generated gateway configuration with the real agentgateway binary.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,postgres]"
docker pull ghcr.io/agentgateway/agentgateway:v1.6.0   # optional
```

For API or UI work, the control plane runs on its own against a local SQLite file
(`agentgov.db`); Keycloak, OPA and the gateway are optional and their reconcilers stay
idle when they are not configured:

```bash
AGENTGOV_ADMIN_TOKEN=dev agentgov server     # then open http://localhost:8000/ui
```

For end-to-end work, use the Compose stack in [`deploy/compose`](deploy/compose/README.md)
and rebuild the image with `docker compose up -d --build control-plane processor`.

## Checks

Run what CI runs before you open a pull request:

```bash
ruff check src tests examples
ruff format --check src tests examples
opa fmt --list src/agentgov/policies examples/manifests/policies   # must print nothing
opa check --strict src/agentgov/policies
opa test -v src/agentgov/policies
pytest -q
```

The `e2e` workflow brings up the full stack and runs `examples/agents/demo_agent.py`; run
it locally (see `deploy/compose/README.md`) when you change the processor, the Rego
library, the gateway configuration or the identity reconciler.

## Where things live

| Path | What |
|---|---|
| `src/agentgov/registry` | Registry and lifecycle: agents, blueprints, tool servers, approvals, findings, risk, discovery |
| `src/agentgov/policies` | The Rego library and its tests |
| `src/agentgov/opa` | Bundle building and serving, Rego validation |
| `src/agentgov/identity` | Keycloak reconciler |
| `src/agentgov/gateway.py` | agentgateway configuration generator |
| `src/agentgov/processor` | ExtMcp governance processor and detectors |
| `src/agentgov/api` | HTTP API |
| `src/agentgov/ui` | Admin UI (static files, no build step) |

If you change the ExtMcp protocol definition, regenerate the stubs with
`scripts/gen-protos.sh`.

## Pull requests

* Keep each pull request focused, with tests for behaviour changes and docs for
  user-visible changes (including `docs/baseline-agent365.md` when parity changes).
* Write commit messages in the imperative mood ("Add …", "Fix …") and explain why.
* By contributing you agree that your contributions are licensed under the
  [Apache License 2.0](LICENSE).

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.
