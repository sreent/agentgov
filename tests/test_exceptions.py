"""A control's exceptions: its mode for the agents in a scope, and the label that exempts
one agent (docs/features.md#exceptions)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from starlette.testclient import TestClient

from agentgov import cli
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.gateway import render
from agentgov.models import LedgerEntry
from agentgov.opa.bundle import registry_snapshot
from agentgov.opa.client import OpaError
from agentgov.processor.modes import FeatureModes
from agentgov.registry import features
from tests.conftest import ADMIN, seed
from tests.test_api import key
from tests.test_cli import _Shared, ok, runner
from tests.test_gateway import SETTINGS as GATEWAY_SETTINGS
from tests.test_gateway import routes, servers
from tests.test_processor import FakeOpa, call_request, run

DEV = [{"mode": "monitor", "scope": {"environments": ["dev"]}, "note": "not ready yet"}]


def put(client: TestClient, key_: str, body: dict[str, Any], headers=ADMIN) -> Any:
    return client.put(f"/v1/features/{key_}", json=body, headers=headers)


def agent(client: TestClient, name: str, **fields: Any) -> dict[str, Any]:
    resp = client.post(
        "/v1/agents",
        json={
            "name": name,
            "blueprint": "support",
            "owner": "cx",
            "sponsors": ["alice@example.com"],
            "approve": True,
            **fields,
        },
        headers=ADMIN,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def team(client: TestClient, *names: str) -> None:
    for name in names:
        resp = client.post("/v1/teams", json={"name": name}, headers=ADMIN)
        assert resp.status_code == 201, resp.text


def snapshot(client: TestClient) -> dict[str, Any]:
    with client.app.state.rt.db.session() as s:
        return registry_snapshot(s)


# ----------------------------------------------------------------------------- choosing


class TestChoosing:
    def test_a_control_takes_exceptions_and_says_what_they_are(self, client) -> None:
        resp = put(client, "least-privilege", {"scopes": DEV})
        assert resp.status_code == 200, resp.text
        found = resp.json()
        assert found["mode"] == "enforce" and found["scopable"] is True
        [exception] = found["scopes"]
        assert exception["mode"] == "monitor" and exception["note"] == "not ready yet"
        assert exception["describe"] == "environment dev"
        # Weaker for some agents than for the others: a warning in the ledger.
        with client.app.state.rt.db.session() as s:
            entry = (
                s.query(LedgerEntry)
                .filter(LedgerEntry.type == "feature.changed")
                .order_by(LedgerEntry.seq.desc())
                .first()
            )
            assert entry.severity == "warning" and "monitor for environment dev" in entry.reason
            assert entry.details["scopes_to"] == DEV
        # Mode and exceptions together; an empty list removes them.
        both = put(client, "least-privilege", {"mode": "monitor", "scopes": []}).json()
        assert both["mode"] == "monitor" and both["scopes"] == []

    @pytest.mark.parametrize(
        ("feature", "scopes", "message"),
        [
            ("unknown-callers", DEV, "takes no exceptions"),
            ("discovery", DEV, "takes no exceptions"),
            ("least-privilege", [{"mode": "loud", "scope": {"teams": ["a"]}}], "takes off"),
            ("least-privilege", [{"mode": "monitor", "scope": {}}], "names no agents"),
            ("least-privilege", [{"mode": "monitor", "scope": {"owners": ["x"]}}], "unknown"),
            ("least-privilege", [{"mode": "monitor", "teams": ["a"]}], "unknown key"),
            ("least-privilege", [DEV[0]] * 21, "20 exceptions at most"),
            ("least-privilege", {"mode": "monitor"}, "a list"),
            (
                "external-decision-point",
                [{"mode": "enforce", "scope": {"teams": ["a"]}}],
                "AGENTGOV_AUTHZEN_URL",
            ),
        ],
    )
    def test_exceptions_are_checked(self, client, feature: str, scopes: Any, message: str) -> None:
        resp = put(client, feature, {"scopes": scopes})
        assert resp.status_code == 422, resp.text
        assert message in resp.text

    def test_only_administrators_and_not_while_pinned(self, settings: Settings) -> None:
        pinned = settings.with_overrides(features="least-privilege=enforce")
        with TestClient(create_app(pinned, background=False)) as client:
            auditor = key(client, "auditor")
            assert put(client, "tool-integrity", {"scopes": DEV}, auditor).status_code == 403
            resp = put(client, "least-privilege", {"scopes": DEV})
            assert resp.status_code == 409 and "AGENTGOV_FEATURES" in resp.text
            assert put(client, "least-privilege", {}).status_code == 422


class TestNames:
    """A scope names teams, blueprints and platforms there are: a misspelt one would match
    no agent, and nobody would know."""

    def test_a_name_there_isnt_is_refused(self, client) -> None:
        for scope, says in (
            ({"teams": ["cx-platfrom"]}, "there is no team cx-platfrom"),
            ({"blueprints": ["suport"]}, "there is no blueprint suport"),
            ({"platforms": ["copilot"]}, "the platforms are gateway, microsoft-365"),
        ):
            resp = put(client, "least-privilege", {"scopes": [{"mode": "monitor", "scope": scope}]})
            assert resp.status_code == 422 and says in resp.json()["detail"], resp.text
        team(client, "cx-platform")
        scope = {"teams": ["cx-platform"], "platforms": ["entra-agent-id"]}
        assert put(
            client, "least-privilege", {"scopes": [{"mode": "monitor", "scope": scope}]}
        ).status_code == 200  # fmt: skip

    def test_each_says_how_many_agents_it_applies_to(self, client) -> None:
        seed(client)
        agent(client, "dev-bot", environment="dev")
        agent(client, "pay-bot", environment="dev", labels={"tier": "payments"})
        scopes = [
            {"mode": "enforce", "scope": {"labels": {"tier": "payments"}}},
            # pay-bot is in dev too, but the first exception takes it.
            {"mode": "monitor", "scope": {"environments": ["dev"]}},
            {"mode": "monitor", "scope": {"environments": ["prod"]}},
        ]
        put(client, "least-privilege", {"mode": "enforce", "scopes": scopes})
        listed = client.get("/v1/features/least-privilege", headers=ADMIN).json()["scopes"]
        assert [(e["agents"], e["missing"]) for e in listed] == [(1, []), (1, []), (0, [])]
        # What the listing gives can be sent back as it is.
        again = put(client, "least-privilege", {"scopes": listed})
        assert again.status_code == 200, again.text
        assert [e["scope"] for e in again.json()["scopes"]] == [e["scope"] for e in scopes]

    def test_a_name_from_before_doesnt_stop_editing_the_others(self, client) -> None:
        from agentgov.db.models import FeatureSetting

        with client.app.state.rt.db.transaction():
            FeatureSetting.objects.create(
                key="least-privilege",
                mode="enforce",
                changed_by="admin:test",
                scopes=[{"mode": "monitor", "scope": {"teams": ["gone"]}}],
            )
        listed = client.get("/v1/features/least-privilege", headers=ADMIN).json()["scopes"]
        assert listed[0]["missing"] == ["team gone"] and listed[0]["agents"] == 0
        resp = put(client, "least-privilege", {"scopes": [*listed, *DEV]})
        assert resp.status_code == 200, resp.text

    def test_a_team_or_blueprint_they_name_stays(self, client) -> None:
        seed(client)
        team(client, "pay")
        scopes = [
            {"mode": "monitor", "scope": {"teams": ["pay"]}},
            {"mode": "monitor", "scope": {"blueprints": ["unused"]}},
        ]
        client.post("/v1/blueprints", json={"name": "unused"}, headers=ADMIN).raise_for_status()
        put(client, "least-privilege", {"scopes": scopes}).raise_for_status()
        refused = client.delete("/v1/teams/pay", headers=ADMIN)
        assert refused.status_code == 409, refused.text
        assert "the exceptions to least-privilege name team 'pay'" in refused.json()["detail"]
        named = client.get("/v1/teams/pay", headers=ADMIN).json()["named_by"]
        assert named == ["the exceptions to least-privilege"]
        refused = client.delete("/v1/blueprints/unused", headers=ADMIN)
        assert refused.status_code == 409 and "least-privilege" in refused.json()["detail"]
        put(client, "least-privilege", {"scopes": []}).raise_for_status()
        assert client.delete("/v1/teams/pay", headers=ADMIN).status_code == 200
        assert client.delete("/v1/blueprints/unused", headers=ADMIN).status_code == 200

    def test_a_manifest_says_which_document_names_what_there_isnt(self, client) -> None:
        doc = (
            "apiVersion: agentgov/v1alpha1\nkind: Feature\nmetadata:\n  name: tool-integrity\n"
            "spec:\n  scopes:\n  - mode: monitor\n    scope:\n      teams: [reserach]\n"
        )
        resp = client.post(
            "/v1/apply", content=doc, headers={**ADMIN, "content-type": "application/yaml"}
        )
        assert resp.status_code == 422
        assert resp.json()["detail"].startswith(
            "feature tool-integrity: scopes[0].scope: there is no team reserach"
        )

    def test_the_platforms_are_those_agentgov_reads(self) -> None:
        from agentgov.registry import platforms, scopes

        assert set(scopes.PLATFORMS) == {"gateway", *platforms.SOURCES}


# ------------------------------------------------------------------- which agents


class TestWhichAgents:
    def test_each_agent_takes_the_first_exception_it_is_in(self, client) -> None:
        seed(client)
        agent(client, "dev-bot", environment="dev")
        agent(client, "pay-bot", environment="dev", labels={"tier": "payments"})
        scopes = [
            {"mode": "enforce", "scope": {"labels": {"tier": "payments"}}},
            {"mode": "monitor", "scope": {"environments": ["dev"]}},
        ]
        put(client, "least-privilege", {"mode": "enforce", "scopes": scopes})
        put(
            client, "approvals", {"scopes": [{"mode": "off", "scope": {"blueprints": ["support"]}}]}
        )
        agents = {a["name"]: a for a in snapshot(client)["agents"].values()}
        assert agents["dev-bot"]["modes"] == {"least-privilege": "monitor", "approvals": "off"}
        # The first that matches: enforced, as the feature is, so not its own.
        assert agents["pay-bot"]["modes"] == {"approvals": "off"}
        assert agents["support-bot"]["modes"] == {"approvals": "off"}
        assert agents["dev-bot"]["team"] is None and agents["dev-bot"]["platform"] == "gateway"
        assert snapshot(client)["scoped_modes"] is True

    def test_an_administrator_exempts_one_agent(self, client) -> None:
        seed(client)
        exempt = {"agentgov/exempt-controls": "tool-integrity, unknown-callers"}
        agent(client, "legacy-bot", labels=exempt)
        agent(client, "old-bot", labels={"agentgov/exempt-controls": "*"})
        put(client, "approvals", {"mode": "monitor"})
        agents = {a["name"]: a for a in snapshot(client)["agents"].values()}
        # Enforced controls are monitored for it; unknown-callers isn't one an agent has.
        assert agents["legacy-bot"]["modes"] == {"tool-integrity": "monitor"}
        old = agents["old-bot"]["modes"]
        assert old["least-privilege"] == "monitor" and "approvals" not in old
        assert "unknown-callers" not in old
        view = client.get("/v1/agents/legacy-bot", headers=ADMIN).json()
        assert view["control_modes"] == {
            "tool-integrity": {"mode": "monitor", "why": "label agentgov/exempt-controls"}
        }

    def test_only_administrators_set_agentgovs_labels(self, client) -> None:
        seed(client)
        registrar = key(client, "registrar")
        for label in ("agentgov/exempt-controls", "agentgov/exempt-rules"):
            resp = client.post(
                "/v1/agents",
                json={"name": "sneaky", "owner": "cx", "labels": {label: "*"}},
                headers=registrar,
            )
            assert resp.status_code == 422 and "set by administrators" in resp.text
        resp = client.post(
            "/v1/agents",
            json={"name": "honest", "owner": "cx", "labels": {"tier": "a"}},
            headers=registrar,
        )
        assert resp.status_code == 201, resp.text

    def test_the_automatic_block_follows_an_agents_mode(self, client) -> None:
        from agentgov.registry import agents as agents_svc

        seed(client)
        put(client, "risk-based-access", {"scopes": DEV})
        bot = agent(client, "dev-bot", environment="dev")
        rt = client.app.state.rt
        with rt.db.session() as s:
            row = agents_svc.get(s, bot["id"])
            assert features.mode_for(s, row, "risk-based-access") == "monitor"
            other = agents_svc.get(s, "support-bot")
            assert features.mode_for(s, other, "risk-based-access") == "enforce"


# --------------------------------------------------------- what the gateway is set up for


def test_the_gateway_is_ready_for_the_strictest_mode(client) -> None:
    put(client, "least-privilege", {"mode": "monitor"})
    for key_ in features.GATEWAY_CONTROLS:
        if key_ != "least-privilege" and features.BY_KEY[key_].default == "enforce":
            put(client, key_, {"mode": "monitor"})
    put(client, "unknown-callers", {"mode": "monitor"})
    with client.app.state.rt.db.session() as s:
        assert features.fails_open("modes", features.strictest_modes(s))
    # Enforced for some agents: what the gateway can't check is refused.
    team(client, "pay", "a")
    put(client, "least-privilege", {"scopes": [{"mode": "enforce", "scope": {"teams": ["pay"]}}]})
    with client.app.state.rt.db.session() as s:
        strictest = features.strictest_modes(s)
        assert strictest["least-privilege"] == "enforce"
        assert not features.fails_open("modes", strictest)
    processor = routes(render(servers(), GATEWAY_SETTINGS, strictest))["mcp-crm"]["policies"][
        "mcpGuardrails"
    ]["processors"][0]
    assert processor["failureMode"] == "failClosed"
    # The page judges it by its strictest mode: off, but enforced for some, it isn't off.
    put(client, "jailbreak-detection", {"mode": "off"})
    put(client, "jailbreak-detection", {"scopes": [{"mode": "monitor", "scope": {"teams": ["a"]}}]})
    found = client.get("/v1/features/jailbreak-detection", headers=ADMIN).json()
    assert found["mode"] == "off" and found["status"] != "off"


# --------------------------------------------------------------------- the processor


class CallerOpa(FakeOpa):
    """OPA with modes of its own for some callers (data.agentgov.context.caller_modes)."""

    def __init__(self, own: dict[str, dict[str, str]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.own = own
        self.asked: list[dict[str, Any]] = []
        self.down = False

    async def evaluate(self, path: str, input_doc: dict[str, Any]):
        if path == "agentgov/context/caller_modes":
            self.asked.append(input_doc)
            if self.down:
                raise OpaError("down")
            client_id = input_doc["agent"].get("client_id")
            return {**self.modes, **self.own.get(client_id, {})}, None
        return await super().evaluate(path, input_doc)


def test_the_processor_applies_each_callers_modes() -> None:
    # Data protection is off for agent-bot: what it sends isn't looked at.
    opa = CallerOpa({"agent-bot": {"data-protection": "off"}})
    secret = {"note": "AKIAIOSFODNN7EXAMPLE"}
    run(opa, request=call_request("note", secret))
    assert opa.inputs[0][1]["detections"].get("categories") in (None, [])
    # Another caller's is looked at.
    opa = CallerOpa({"someone-else": {"data-protection": "off"}})
    run(opa, request=call_request("note", secret))
    assert "secret" in opa.inputs[0][1]["detections"]["categories"]


def test_a_callers_modes_are_kept_and_outlive_opa() -> None:
    opa = CallerOpa({"agent-bot": {"least-privilege": "monitor"}}, modes={})
    modes = FeatureModes(opa)  # type: ignore[arg-type]
    caller = {"client_id": "agent-bot"}

    async def go() -> list[dict[str, str]]:
        first = await modes.for_caller(caller)
        again = await modes.for_caller(caller)  # read again only after MAX_AGE
        unknown = await modes.for_caller({})  # nobody to ask about
        modes._callers[("", "agent-bot")] = (-1e9, first)  # stale
        opa.down = True
        stale = await modes.for_caller(caller)  # OPA down: what was known stands
        return [first, again, unknown, stale]

    first, again, unknown, stale = asyncio.run(go())
    assert first["least-privilege"] == "monitor" and again == first
    assert unknown["least-privilege"] == "enforce"
    assert stale == first and modes.last(caller) == first
    assert len(opa.asked) == 2
    assert modes.last({"client_id": "never-seen"})["least-privilege"] == "enforce"


def test_callers_kept_at_most() -> None:
    modes = FeatureModes(CallerOpa({}))  # type: ignore[arg-type]
    modes.MAX_CALLERS = 3

    async def go() -> None:
        for i in range(5):
            await modes.for_caller({"client_id": f"agent-{i}"})

    asyncio.run(go())
    assert [k[1] for k in modes._callers] == ["agent-2", "agent-3", "agent-4"]


# ------------------------------------------------------------ CLI, manifests, presets


def test_the_cli(client, monkeypatch) -> None:
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
    out = ok(
        runner.invoke(
            cli.app,
            [
                "features",
                "scope",
                "least-privilege",
                "monitor",
                "--environment",
                "dev",
                "--label",
                "tier=pilot",
                "--note",
                "pilot",
                "--yes",
            ],
        )
    )
    assert "monitor for environment dev, label tier=pilot" in out
    team(client, "pay")
    ok(runner.invoke(cli.app, ["features", "scope", "least-privilege", "enforce", "--team", "pay"]))
    out = ok(runner.invoke(cli.app, ["features", "list"]))
    assert "EXCEPTIONS" in out
    out = ok(runner.invoke(cli.app, ["features", "unscope", "least-privilege", "1", "--yes"]))
    assert "1 exception(s) left" in out
    found = client.get("/v1/features/least-privilege", headers=ADMIN).json()
    assert [e["describe"] for e in found["scopes"]] == ["team pay"]
    result = runner.invoke(cli.app, ["features", "scope", "least-privilege", "monitor", "--yes"])
    assert result.exit_code == 2
    result = runner.invoke(cli.app, ["features", "unscope", "least-privilege", "5", "--yes"])
    assert result.exit_code == 2


def test_manifests_apply_and_export_them(client) -> None:
    # The team the exception names is in the same manifest: exceptions are set last.
    doc = (
        "apiVersion: agentgov/v1alpha1\nkind: Feature\nmetadata:\n  name: tool-integrity\n"
        "spec:\n  scopes:\n  - mode: monitor\n    scope:\n"
        "      teams: [research]\n"
        "---\napiVersion: agentgov/v1alpha1\nkind: Team\nmetadata:\n  name: research\n"
        "spec:\n  emails: [research@example.com]\n"
    )
    resp = client.post(
        "/v1/apply", content=doc, headers={**ADMIN, "content-type": "application/yaml"}
    )
    assert resp.status_code == 200, resp.text
    assert [r["action"] for r in resp.json()["results"]] == ["configured", "created"]
    exported = client.get("/v1/export", headers=ADMIN).text
    assert "teams:\n      - research" in exported or "- research" in exported
    found = client.get("/v1/features/tool-integrity", headers=ADMIN).json()
    assert found["scopes"][0]["scope"] == {"teams": ["research"]}


def test_the_monitor_starting_point_monitors_exceptions_too(client) -> None:
    team(client, "a")
    put(client, "jailbreak-detection", {"scopes": [{"mode": "enforce", "scope": {"teams": ["a"]}}]})
    view = client.get("/v1/feature-presets", headers=ADMIN).json()
    monitor = next(p for p in view["presets"] if p["preset"] == "monitor")
    scoped = [c for c in monitor["changes"] if "scope" in c]
    assert scoped == [
        {
            "key": "jailbreak-detection",
            "title": "Jailbreak detection",
            "scope": "team a",
            "from": "enforce",
            "to": "monitor",
        }
    ]
    client.post("/v1/feature-presets/monitor", headers=ADMIN).raise_for_status()
    found = client.get("/v1/features/jailbreak-detection", headers=ADMIN).json()
    assert found["scopes"][0]["mode"] == "monitor"
    with client.app.state.rt.db.session() as s:
        assert features.fails_open("modes", features.strictest_modes(s))


def test_compliance_reports_say_what_is_enforced_for_some_agents_only(client) -> None:
    import io
    import zipfile

    seed(client)
    put(client, "least-privilege", {"scopes": DEV})
    agent(client, "legacy-bot", labels={"agentgov/exempt-controls": "tool-integrity"})
    report = client.get("/v1/evidence/report", params={"framework": "eu-ai-act"}, headers=ADMIN)
    assert report.status_code == 200, report.text
    text = report.text
    assert (
        "Enforced, but not for some agents: least-privilege (monitor for environment dev)" in text
    )
    assert "Exempt from enforcement by their agentgov/exempt-controls label: legacy-bot" in text
    pack = client.get("/v1/evidence/pack", params={"days": 7}, headers=ADMIN)
    with zipfile.ZipFile(io.BytesIO(pack.content)) as z:
        assert '"least-privilege"' in z.read("feature-exceptions.json").decode()
