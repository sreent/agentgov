"""OPA bundle contents, long polling, and the Rego library evaluated by real OPA."""

from __future__ import annotations

import asyncio
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from agentgov.opa import bundle as opa_bundle
from agentgov.opa import rego
from agentgov.registry import agents, blueprints, policies, toolservers
from agentgov.registry.errors import ValidationError
from tests.conftest import requires_opa


def _seed(rt, settings) -> None:
    with rt.db.session() as s:
        blueprints.create(
            s,
            {
                "name": "support",
                "labels": {"pii-access": "true"},
                "permissions": [{"server": "crm", "tools": ["get_*", "delete_*"]}],
            },
            actor="t",
        )
        toolservers.create(
            s,
            {"name": "crm", "url": "http://crm/mcp", "trust_level": "verified"},
            actor="t",
            approve=True,
        )
        agents.register(
            s,
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
    assert manifest["roots"] == ["agentgov", "agentos", "registry", "system"]
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
    with rt.db.session() as s:
        agents.transition(s, settings, agents.get(s, "bot"), "block", actor="t")
    assert rt.bundles.current().etag != first.etag  # commit hook marked it stale


def test_deleted_agents_are_not_published(rt, settings) -> None:
    _seed(rt, settings)
    with rt.db.session() as s:
        agents.transition(s, settings, agents.get(s, "bot"), "delete", actor="t")
    data = json.loads(_files(rt.bundles.current().body)["registry/data.json"])
    assert data["agents"] == {}


def test_long_poll_wakes_on_change(rt, settings) -> None:
    _seed(rt, settings)

    async def scenario() -> float:
        rt.bundles.bind_loop(asyncio.get_running_loop())
        etag = rt.bundles.current().etag
        loop = asyncio.get_running_loop()
        started = loop.time()
        waiter = asyncio.create_task(rt.bundles.wait_for_change(etag, timeout=10))
        await asyncio.sleep(0.2)

        def block() -> None:
            with rt.db.session() as s:
                agents.transition(s, settings, agents.get(s, "bot"), "block", actor="t")

        await asyncio.to_thread(block)
        result = await waiter
        assert result is not None and result.etag != etag
        return loop.time() - started

    assert asyncio.run(scenario()) < 2


def test_long_poll_times_out_without_change(rt, settings) -> None:
    _seed(rt, settings)

    async def scenario():
        rt.bundles.bind_loop(asyncio.get_running_loop())
        return await rt.bundles.wait_for_change(rt.bundles.current().etag, timeout=0.3)

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


@requires_opa
def test_custom_policy_is_validated_and_shipped(rt, settings) -> None:
    _seed(rt, settings)
    source = (
        "package agentgov.custom.weekend\n\n"
        'deny contains "no deletes" if {\n  input.phase == "request"\n'
        '  startswith(input.resource.name, "delete_")\n}\n'
    )
    with rt.db.session() as s:
        policies.create(s, {"name": "weekend", "rego": source}, actor="t")
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
    ],
)
def test_broken_custom_policies_are_rejected(rt, settings, source, message) -> None:
    _seed(rt, settings)
    with rt.db.session() as s, pytest.raises(ValidationError, match=message):
        policies.create(s, {"name": "bad", "rego": source}, actor="t")


def test_policies_need_the_opa_binary(rt, monkeypatch) -> None:
    monkeypatch.setattr(rego, "opa_binary", lambda: None)
    with rt.db.session() as s, pytest.raises(ValidationError, match="opa binary"):
        policies.create(s, {"name": "x", "rego": "package agentgov.custom.x\n"}, actor="t")
