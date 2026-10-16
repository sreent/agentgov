"""OPA bundle contents, long polling, and the Rego library evaluated by real OPA."""

from __future__ import annotations

import asyncio
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from agentgov.opa import WHAT_IF, rego
from agentgov.opa import bundle as opa_bundle
from agentgov.registry import agents, blueprints, policies, toolservers
from agentgov.registry.errors import ValidationError
from tests.conftest import requires_opa


def _seed(rt, settings) -> None:
    with rt.db.transaction() as tx:
        blueprints.create(
            tx,
            {
                "name": "support",
                "labels": {"pii-access": "true"},
                "permissions": [{"server": "crm", "tools": ["get_*", "delete_*"]}],
            },
            actor="t",
        )
        toolservers.create(
            tx,
            {"name": "crm", "url": "http://crm/mcp", "trust_level": "verified"},
            actor="t",
            approve=True,
        )
        agents.register(
            tx,
            settings,
            {"name": "bot", "blueprint": "support", "sponsors": ["a"]},
            actor="t",
            approve=True,
        )


def _files(body: bytes) -> dict[str, str]:
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        return {m.name.lstrip("/"): tar.extractfile(m).read().decode() for m in tar.getmembers()}


def test_bundle_layout(rt, settings) -> None:
    _seed(rt, settings)
    bundle = rt.bundles.current()
    files = _files(bundle.body)
    manifest = json.loads(files[".manifest"])
    assert manifest["roots"] == ["agentgov", "agentos", "registry", "system/log"]
    assert manifest["revision"] == bundle.revision
    assert {
        "agentgov/mcp.rego",
        "agentgov/context.rego",
        "agentos/agentos.rego",
        "system/log.rego",
    } <= set(files)
    assert not any("_test" in name for name in files)
    data = json.loads(files["registry/data.json"])
    agent = next(iter(data["agents"].values()))
    assert agent["grants"] == [{"server": "crm", "tools": ["get_*", "delete_*"]}]
    assert agent["labels"] == {"pii-access": "true"}  # inherited from the blueprint
    assert data["clients"] == {"agent-bot": agent["id"]}
    assert data["toolservers"]["crm"]["status"] == "approved"


def test_etag_is_stable_and_tracks_changes(rt, settings) -> None:
    _seed(rt, settings)
    first = rt.bundles.current()
    rt.bundles.notify()
    assert rt.bundles.current().etag == first.etag  # rebuilt, same content
    with rt.db.transaction() as tx:
        agents.transition(tx, settings, agents.get(tx, "bot"), "block", actor="t")
    assert rt.bundles.current().etag != first.etag  # commit hook marked it stale


def test_deleted_agents_are_not_published(rt, settings) -> None:
    _seed(rt, settings)
    with rt.db.transaction() as tx:
        agents.transition(tx, settings, agents.get(tx, "bot"), "delete", actor="t")
    data = json.loads(_files(rt.bundles.current().body)["registry/data.json"])
    assert data["agents"] == {}


def test_long_poll_wakes_on_change(rt, settings) -> None:
    _seed(rt, settings)

    async def scenario() -> float:
        rt.bundles.bind_loop(asyncio.get_running_loop())
        etag = (await asyncio.to_thread(rt.bundles.current)).etag
        loop = asyncio.get_running_loop()
        started = loop.time()
        waiter = asyncio.create_task(rt.bundles.wait_for_change(etag, timeout=10))
        await asyncio.sleep(0.2)

        def block() -> None:
            with rt.db.transaction() as tx:
                agents.transition(tx, settings, agents.get(tx, "bot"), "block", actor="t")

        await asyncio.to_thread(block)
        result = await waiter
        assert result is not None and result.etag != etag
        return loop.time() - started

    assert asyncio.run(scenario()) < 2


def test_long_poll_times_out_without_change(rt, settings) -> None:
    _seed(rt, settings)

    async def scenario():
        rt.bundles.bind_loop(asyncio.get_running_loop())
        current = await asyncio.to_thread(rt.bundles.current)
        return await rt.bundles.wait_for_change(current.etag, timeout=0.3)

    assert asyncio.run(scenario()) is None


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("modes=snapshot,delta;wait=30", 30.0),
        ("wait=5", 5.0),
        (None, None),
        ("modes=snapshot", None),
    ],
)
def test_prefer_header(header, expected) -> None:
    assert opa_bundle.parse_prefer_wait(header) == expected


@requires_opa
def test_rego_library_unit_tests() -> None:
    proc = subprocess.run(
        ["opa", "test", str(opa_bundle.library_dir())], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@requires_opa
@pytest.mark.parametrize(
    ("tool", "detections", "effect"),
    [
        ("get_customer", [], "allow"),
        ("export_customers", [], "deny"),
        ("get_customer", ["secret"], "deny"),
    ],
)
def test_python_snapshot_matches_rego_expectations(
    rt, settings, tmp_path: Path, tool, detections, effect
) -> None:
    """Evaluate the real bundle with real OPA: Python data shapes and Rego must agree."""
    _seed(rt, settings)
    bundle_path = tmp_path / "bundle.tar.gz"
    bundle_path.write_bytes(rt.bundles.current().body)
    inp = {
        "phase": "request",
        "method": "tools/call",
        "agent": {"client_id": "agent-bot"},
        "resource": {"server": "crm", "name": tool},
        "arguments": {},
        "detections": {"categories": detections},
    }
    (tmp_path / "input.json").write_text(json.dumps(inp))
    proc = subprocess.run(
        [
            "opa",
            "eval",
            "--format",
            "json",
            "--bundle",
            str(bundle_path),
            "--input",
            str(tmp_path / "input.json"),
            "data.agentgov.mcp.decision",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    decision = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    assert decision["effect"] == effect, decision


def _decide(rt, tmp_path: Path, inp: dict, path: str = "data.agentgov.mcp.decision") -> dict:
    """What the real bundle decides, evaluated by real OPA."""
    bundle_path = tmp_path / "bundle.tar.gz"
    bundle_path.write_bytes(rt.bundles.current().body)
    (tmp_path / "input.json").write_text(json.dumps(inp))
    proc = subprocess.run(
        ["opa", "eval", "--format", "json", "--bundle", str(bundle_path),
         "--input", str(tmp_path / "input.json"), path],
        capture_output=True,
        text=True,
        check=True,
    )  # fmt: skip
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


@requires_opa
@pytest.mark.parametrize(
    ("path", "what_if", "logged"),
    [
        ("agentos/allow", False, True),
        ("agentos/allow", True, False),
        ("agentgov/mcp/decision", False, False),
        ("agentgov/authzen/evaluation", False, False),
        ("agentgov/copilotstudio/decision", False, False),
        ("registry/features", False, False),
        ("agentgov/context/caller_modes", False, False),
    ],
)
def test_opa_logs_only_agents_own_decisions(
    rt, settings, tmp_path: Path, path: str, what_if: bool, logged: bool
) -> None:
    """OPA sends the control plane only what the Agent Governance Toolkit asked, and not a
    what-if question: the processor and the control plane record their own decisions."""
    _seed(rt, settings)
    bundle_path = tmp_path / "bundle.tar.gz"
    bundle_path.write_bytes(rt.bundles.current().body)
    event = {"path": path, "input": {"agent_id": "bot", **({WHAT_IF: True} if what_if else {})}}
    (tmp_path / "event.json").write_text(json.dumps(event))
    proc = subprocess.run(
        ["opa", "eval", "--format", "json", "--bundle", str(bundle_path),
         "--input", str(tmp_path / "event.json"), "data.system.log.drop"],
        capture_output=True,
        text=True,
        check=True,
    )  # fmt: skip
    dropped = bool(json.loads(proc.stdout).get("result"))
    assert dropped is not logged


@requires_opa
def test_who_agents_act_for_reaches_policy(rt, settings, tmp_path: Path) -> None:
    """Blueprints' acts_for and people_groups, and the person in organisation policies."""
    _seed(rt, settings)
    with rt.db.transaction() as tx:
        blueprints.update(
            tx,
            blueprints.get(tx, "support"),
            {"acts_for": "people", "people_groups": ["support"]},
            actor="t",
        )
        policies.create(
            tx,
            {
                "name": "no-deletes-for-contractors",
                "rego": "package agentgov.custom.no_deletes_for_contractors\n\n"
                'deny contains "Contractors may not delete" if {\n'
                '  "/contractors" in input.user.groups\n'
                '  startswith(input.resource.name, "delete_")\n}\n',
            },
            actor="t",
        )
    call = {
        "phase": "request",
        "method": "tools/call",
        "agent": {"client_id": "agent-bot"},
        "resource": {"server": "crm", "name": "get_customer"},
        "detections": {"categories": []},
    }
    alice = {"id": "u-1", "username": "alice", "groups": ["/support"], "via": "exchange"}
    assert _decide(rt, tmp_path, {**call, "user": alice})["effect"] == "allow"
    alone = _decide(rt, tmp_path, call)
    assert alone["reasons"] == [
        "Agent bot acts only for people, and this call is on no one's behalf"
    ]
    bob = {"id": "u-2", "username": "bob", "groups": ["/sales"], "via": "exchange"}
    assert _decide(rt, tmp_path, {**call, "user": bob})["reasons"] == [
        "Agent bot acts only for people in support, and bob is in none of them"
    ]
    contractor = {**alice, "groups": ["/support", "/contractors"]}
    delete = {**call, "resource": {"server": "crm", "name": "delete_customer"}}
    assert _decide(rt, tmp_path, {**delete, "user": contractor})["reasons"] == [
        "Contractors may not delete"
    ]


@requires_opa
def test_custom_policy_is_validated_and_shipped(rt, settings) -> None:
    _seed(rt, settings)
    source = (
        "package agentgov.custom.weekend\n\n"
        'deny contains "no deletes" if {\n  input.phase == "request"\n'
        '  startswith(input.resource.name, "delete_")\n}\n'
    )
    with rt.db.transaction() as tx:
        policies.create(tx, {"name": "weekend", "rego": source}, actor="t")
    assert "agentgov/custom/weekend.rego" in _files(rt.bundles.current().body)


@requires_opa
@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("package agentgov.custom.other\n", "must declare"),
        (
            "package agentgov.custom.bad\n\ndeny contains msg if {\n  input.x ==\n}\n",
            "does not compile",
        ),
        ('package agentgov.custom.bad\n\ndeny := "not a set"\n', "must be a set"),
        # Breaks only Copilot Studio's decisions (two values for one rule).
        (
            "package agentgov.custom.bad\n\n"
            'limit := 1 if input.platform == "copilot-studio"\n\n'
            'limit := 2 if input.platform == "copilot-studio"\n\n'
            'deny contains "over the limit" if limit > 5\n',
            "fails at evaluation time",
        ),
    ],
)
def test_broken_custom_policies_are_rejected(rt, settings, source, message) -> None:
    _seed(rt, settings)
    with rt.db.transaction() as tx, pytest.raises(ValidationError, match=message):
        policies.create(tx, {"name": "bad", "rego": source}, actor="t")


def test_policies_need_the_opa_binary(rt, monkeypatch) -> None:
    monkeypatch.setattr(rego, "opa_binary", lambda: None)
    with rt.db.transaction() as tx, pytest.raises(ValidationError, match="opa binary"):
        policies.create(tx, {"name": "x", "rego": "package agentgov.custom.x\n"}, actor="t")


@requires_opa
def test_opa_keeps_an_authorization_policy_of_its_own(rt, settings, tmp_path: Path) -> None:
    """OPA can have an authorization policy of its own, from a file (system.authz: the
    chart's, with SPIRE, takes only the processor and the control plane). OPA erases the
    policies under a bundle's roots as it activates the bundle, so AgentGov's leave it
    be."""
    import socket
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    import httpx

    _seed(rt, settings)
    body = rt.bundles.current().body

    class ControlPlane(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    web = ThreadingHTTPServer(("127.0.0.1", 0), ControlPlane)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    config = tmp_path / "config.yaml"
    config.write_text(
        f"services:\n  agentgov:\n    url: http://127.0.0.1:{web.server_address[1]}\n"
        "bundles:\n  agentgov:\n    service: agentgov\n    resource: bundles/agentgov.tar.gz\n"
    )
    authz = tmp_path / "authz.rego"
    authz.write_text(
        "package system.authz\n\nimport rego.v1\n\ndefault allow := false\n\n"
        'allow if input.path[0] == "v1"\n'
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    opa = subprocess.Popen(
        [rego.opa_binary(), "run", "--server", f"--addr=127.0.0.1:{port}",
         "--authorization=basic", f"--config-file={config}", str(authz)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        clients = f"http://127.0.0.1:{port}/v1/data/registry/clients"
        answer = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                answer = httpx.get(clients)
            except httpx.HTTPError:
                time.sleep(0.1)
                continue
            if answer.status_code != 200 or answer.json().get("result"):
                break  # the bundle is active, or OPA lost its authorization policy
            time.sleep(0.1)
        assert answer is not None and answer.status_code == 200, answer and answer.text
        assert list(answer.json()["result"]) == ["agent-bot"]
        # And its policy still decides: it takes nothing but the v1 API.
        assert httpx.post(f"http://127.0.0.1:{port}/v0/data/registry", json={}).status_code == 401
    finally:
        opa.terminate()
        opa.wait(10)
        web.shutdown()
