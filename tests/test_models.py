"""Model providers, model access, usage metering and daily token budgets."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import select

from agentgov import cli, ids
from agentgov.db.models import Finding
from agentgov.models import Agent, LedgerEntry, ModelUsage
from agentgov.opa import bundle as opa_bundle
from agentgov.registry import agents, blueprints, decisions, manifests, model_providers, model_usage
from agentgov.registry.errors import Conflict, InvalidTransition, ValidationError
from tests.conftest import ADMIN, SERVICE
from tests.test_api import key
from tests.test_cli import _Shared, ok, runner


def access_log(
    route: str = "default/llm-openai",
    *,
    agent_id: str | None = None,
    client_id: str | None = None,
    model: str = "gpt-4o-mini",
    tokens: tuple[int, int] = (100, 20),
    status: int = 200,
    when_ns: int | None = None,
) -> dict[str, Any]:
    """One record as agentgateway exports it (OTLP/JSON through the collector)."""
    attrs: dict[str, Any] = {
        "route": route,
        "http.response.status_code": str(status),
        "gen_ai.operation.name": "chat",
        "gen_ai.provider.name": "openai",
        "gen_ai.request.model": model,
        "gen_ai.usage.input_tokens": str(tokens[0]),
        "gen_ai.usage.output_tokens": str(tokens[1]),
    }
    if agent_id:
        attrs["agentgov.agent_id"] = agent_id
    if client_id:
        attrs["agentgov.client_id"] = client_id
    return {
        "observedTimeUnixNano": str(when_ns or int(ids.utcnow().timestamp() * 1e9)),
        "attributes": [{"key": k, "value": {"stringValue": v}} for k, v in attrs.items()],
    }


def logs(*records: dict[str, Any]) -> dict[str, Any]:
    return {"resourceLogs": [{"scopeLogs": [{"logRecords": list(records)}]}]}


@pytest.fixture
def provider(rt) -> str:
    with rt.db.session() as s:
        model_providers.create(
            s,
            {
                "name": "openai",
                "kind": "openai",
                "prices": {"gpt-4o*": {"input": 2.5, "output": 10}},
            },
            actor="admin:a",
        )
    return "openai"


@pytest.fixture
def bot(rt, settings, provider) -> str:
    with rt.db.session() as s:
        blueprints.create(
            s,
            {
                "name": "chat",
                "model_access": [{"provider": "openai", "models": ["gpt-4o*"]}],
                "daily_token_budget": 1000,
            },
            actor="a",
        )
        agent = agents.register(
            s, settings, {"name": "bot", "blueprint": "chat", "sponsors": ["a"]}, actor="a",
            approve=True,
        )  # fmt: skip
        return agent.id


class TestProviders:
    def test_validation(self, rt) -> None:
        cases = [
            ({"name": "x"}, "kind is required"),
            ({"name": "x", "kind": "cohere"}, "kind must be one of"),
            ({"name": "x", "kind": "openai-compatible"}, "needs base_url"),
            ({"name": "x", "kind": "openai", "base_url": "http://a"}, "only for openai-compat"),
            ({"name": "x", "kind": "openai-compatible", "base_url": "ftp://a"}, "must be an http"),
            ({"name": "x", "kind": "openai", "key_file": "keys/x"}, "a file in /model-keys"),
            ({"name": "x", "kind": "openai", "prices": {"m": {"input": -1}}}, "USD per million"),
            ({"name": "Bad Name", "kind": "openai"}, "lowercase"),
        ]
        for data, message in cases:
            with rt.db.session() as s, pytest.raises(ValidationError, match=message):
                model_providers.create(s, data, actor="a")

    def test_a_key_is_a_file_in_the_model_keys_directory(self, rt) -> None:
        """The gateway sends the file as the provider's key: no other file it holds can be
        one (its own TLS key, its service account's token)."""
        for path in (
            "/tls/tls.key",
            "/model-keys/../tls/tls.key",
            "/model-keys",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ):
            data = {"name": "x", "kind": "openai", "key_file": path}
            with (
                rt.db.session() as s,
                pytest.raises(ValidationError, match="a file in /model-keys"),
            ):
                model_providers.create(s, data, actor="a")
        with rt.db.session() as s:
            data = {"name": "x", "kind": "openai", "key_file": "/model-keys/team-a//x"}
            assert model_providers.create(s, data, actor="a").key_file == "/model-keys/team-a/x"

    def test_a_key_goes_only_to_the_hosts_listed(self, rt, settings) -> None:
        listed = settings.with_overrides(credential_hosts="vllm,*.groq.com")
        data = {"name": "x", "kind": "openai-compatible", "base_url": "https://evil.example/v1"}
        refused = "AGENTGOV_CREDENTIAL_HOSTS doesn't list evil.example"
        with rt.db.session() as s, pytest.raises(ValidationError, match=refused):
            model_providers.create(s, data, actor="a", settings=listed)
        with rt.db.session() as s:
            ok = {**data, "base_url": "https://api.groq.com/openai/v1"}
            p = model_providers.create(s, ok, actor="a", settings=listed)
            with pytest.raises(ValidationError, match=refused):
                model_providers.update(s, p, data, actor="a", settings=listed)
            model_providers.update(
                s, p, {"base_url": "http://vllm:8000/v1"}, actor="a", settings=listed
            )

    def test_lifecycle_is_recorded(self, rt, provider) -> None:
        with rt.db.session() as s:
            p = model_providers.get(s, provider)
            assert model_providers.to_dict(p)["key_file"] == "/model-keys/openai"
            assert model_providers.to_dict(p)["route"] == "/llm/openai"
            with pytest.raises(Conflict):
                model_providers.create(s, {"name": "openai", "kind": "openai"}, actor="a")
            model_providers.set_status(s, p, "block", actor="a")
            with pytest.raises(InvalidTransition):
                model_providers.set_status(s, p, "block", actor="a")
            model_providers.set_status(s, p, "unblock", actor="a")
            model_providers.delete(s, p, actor="a")
        with rt.db.session() as s:
            types = [e.type for e in s.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))]
        assert [t for t in types if t.startswith("model_provider.")] == [
            "model_provider.registered",
            "model_provider.block",
            "model_provider.unblock",
            "model_provider.deleted",
        ]

    def test_prices_take_the_most_specific_glob(self, rt) -> None:
        with rt.db.session() as s:
            p = model_providers.create(
                s,
                {
                    "name": "openai",
                    "kind": "openai",
                    "prices": {"*": {"input": 1}, "gpt-4o*": {"input": 2.5, "output": 10}},
                },
                actor="a",
            )
            assert model_providers.price_of(p, "gpt-4o-mini") == {"input": 2.5, "output": 10}
            assert model_providers.price_of(p, "o3") == {"input": 1.0, "output": 0.0}

    def test_api_and_roles(self, client) -> None:
        auditor = key(client, "auditor")
        body = {
            "name": "groq",
            "kind": "openai-compatible",
            "base_url": "https://api.groq.com/openai/v1",
        }
        assert client.post("/v1/models/providers", json=body, headers=auditor).status_code == 403
        created = client.post("/v1/models/providers", json=body, headers=ADMIN)
        assert created.status_code == 201 and created.json()["status"] == "approved"
        assert [p["name"] for p in client.get("/v1/models/providers", headers=auditor).json()] == [
            "groq"
        ]
        patched = client.patch(
            "/v1/models/providers/groq", json={"trust_level": "verified"}, headers=ADMIN
        )
        assert patched.json()["trust_level"] == "verified"
        assert client.post("/v1/models/providers/groq/block", headers=ADMIN).json()["status"] == (
            "blocked"
        )
        assert client.post("/v1/models/providers/groq/explode", headers=ADMIN).status_code == 404
        assert client.delete("/v1/models/providers/groq", headers=ADMIN).status_code == 204
        assert client.get("/v1/models/providers/groq", headers=ADMIN).status_code == 404


class TestModelAccess:
    def test_blueprint_and_agent_grants_merge(self, rt, bot) -> None:
        with rt.db.session() as s:
            agent = s.get(Agent, bot)
            agents.update(
                s,
                agent,
                {
                    "model_access": [{"provider": "openai", "models": ["o3"]}],
                    "daily_token_budget": 5,
                },
                actor="a",
            )
            assert model_providers.effective_model_access(agent) == [
                {"provider": "openai", "models": ["gpt-4o*", "o3"]}
            ]
            assert model_providers.effective_budget(agent) == 5
            assert model_providers.may_call(agent, "openai", "o3")
            assert not model_providers.may_call(agent, "openai", "o1")
            shown = agents.to_dict(agent)
            assert shown["effective_daily_token_budget"] == 5
            assert shown["effective_model_access"][0]["models"] == ["gpt-4o*", "o3"]

    def test_invalid_grants_and_budgets(self, rt, bot) -> None:
        for data in (
            {"model_access": [{"provider": "openai"}, "x"]},
            {"model_access": [{"provider": "Open AI", "models": ["*"]}]},
            {"model_access": [{"provider": "openai", "models": []}]},
            {"daily_token_budget": -1},
            {"daily_token_budget": "lots"},
        ):
            with rt.db.session() as s, pytest.raises(ValidationError):
                agents.update(s, s.get(Agent, bot), data, actor="a")

    def test_opa_gets_providers_grants_and_budgets(self, rt, bot) -> None:
        with rt.db.session() as s:
            data = opa_bundle.registry_snapshot(s)
        assert data["model_providers"]["openai"]["status"] == "approved"
        snapshot = data["agents"][bot]
        assert snapshot["model_access"] == [{"provider": "openai", "models": ["gpt-4o*"]}]
        assert (snapshot["daily_token_budget"], snapshot["over_budget"]) == (1000, False)


class TestMetering:
    def test_calls_are_metered_and_priced(self, rt, bot) -> None:
        with rt.db.session() as s:
            stats = model_usage.ingest_logs(
                s,
                logs(
                    access_log(agent_id=bot),
                    access_log(agent_id=bot, tokens=(0, 0), status=403),
                    access_log(route="default/mcp-crm"),  # a tool call: not metered
                    access_log(client_id="agent-nobody"),
                ),
            )
        assert stats == {"records": 4, "model_calls": 3, "unidentified": 1}
        with rt.db.session() as s:
            [row] = s.scalars(select(ModelUsage).where(ModelUsage.agent_id == bot)).all()
            assert (row.calls, row.refused, row.input_tokens, row.output_tokens) == (2, 1, 100, 20)
            assert row.cost_usd == pytest.approx((100 * 2.5 + 20 * 10) / 1e6)
            assert s.get(ModelUsage, ("", model_usage.today(), "openai", "gpt-4o-mini")).calls == 1
            assert model_usage.tokens_used(s) == {bot: 120}
            assert s.get(Agent, bot).last_seen_at is not None

    def test_reaching_the_budget_is_recorded_and_reaches_opa(self, rt, bot) -> None:
        with rt.db.session() as s:
            model_usage.ingest_logs(s, logs(access_log(agent_id=bot, tokens=(500, 100))))
        with rt.db.session() as s:
            assert not opa_bundle.registry_snapshot(s)["agents"][bot]["over_budget"]
            model_usage.ingest_logs(s, logs(access_log(agent_id=bot, tokens=(300, 200))))
        with rt.db.session() as s:
            assert opa_bundle.registry_snapshot(s)["agents"][bot]["over_budget"] is True
            [entry] = s.scalars(
                select(LedgerEntry).where(LedgerEntry.type == "model.budget_reached")
            ).all()
            assert entry.reason == "1100 of 1000 tokens used today"
            # Further calls don't record it again.
            model_usage.ingest_logs(s, logs(access_log(agent_id=bot, tokens=(10, 10))))
        with rt.db.session() as s:
            count = len(
                s.scalars(
                    select(LedgerEntry).where(LedgerEntry.type == "model.budget_reached")
                ).all()
            )
            assert count == 1

    def test_budgets_start_again_each_day(self, rt, bot) -> None:
        yesterday = int((ids.utcnow().timestamp() - 86400) * 1e9)
        with rt.db.session() as s:
            model_usage.ingest_logs(
                s, logs(access_log(agent_id=bot, tokens=(5000, 0), when_ns=yesterday))
            )
        with rt.db.session() as s:
            assert not opa_bundle.registry_snapshot(s)["agents"][bot]["over_budget"]
            assert model_usage.tokens_used(s) == {}

    def test_the_collector_posts_access_logs(self, client) -> None:
        resp = client.post("/v1/otlp/v1/logs", json=logs(access_log()), headers=SERVICE)
        assert resp.status_code == 200
        auditor = key(client, "auditor")
        assert client.post("/v1/otlp/v1/logs", json=logs(), headers=auditor).status_code == 403

    def test_usage_api(self, client, bot) -> None:
        client.post("/v1/otlp/v1/logs", json=logs(access_log(agent_id=bot)), headers=SERVICE)
        view = client.get("/v1/models/usage", headers=ADMIN).json()
        assert view["totals"]["calls"] == 1 and view["totals"]["input_tokens"] == 100
        assert view["rows"][0]["agent_name"] == "bot"
        assert view["today"] == [
            {
                "agent_id": bot,
                "agent_name": "bot",
                "used_today": 120,
                "daily_token_budget": 1000,
                "over_budget": False,
            }
        ]
        only = client.get("/v1/models/usage", params={"agent": "bot"}, headers=ADMIN).json()
        assert len(only["rows"]) == 1

    def test_spend_per_owner_and_sponsor(self, rt, settings, client, bot) -> None:
        with rt.db.session() as s:
            other = agents.register(
                s, settings,
                {"name": "bot2", "blueprint": "chat", "owner": "cx", "sponsors": ["a", "b"]},
                actor="a", approve=True,
            ).id  # fmt: skip
        records = [access_log(agent_id=bot), access_log(agent_id=other, tokens=(10, 10))]
        records.append(access_log())  # an unidentified caller counts for nobody
        client.post("/v1/otlp/v1/logs", json=logs(*records), headers=SERVICE)
        view = client.get("/v1/models/usage", headers=ADMIN).json()
        assert {g["owner"]: (g["agents"], g["calls"]) for g in view["by_owner"]} == {
            None: (1, 1),
            "cx": (1, 1),
        }
        assert [(g["sponsor"], g["agents"]) for g in view["by_sponsor"]] == [("a", 2), ("b", 1)]
        assert view["by_sponsor"][0]["cost_usd"] == pytest.approx((450 + 125) / 1e6)


class TestDecisions:
    def test_model_decisions_are_ledgered_with_findings(self, rt, settings, bot) -> None:
        record = {
            "kind": "model",
            "phase": "request",
            "method": "chat",
            "resource": "openai/gpt-4o-mini",
            "agent": {"id": bot},
            "identity": {"agent_id": bot},
            "effect": "deny",
            "reasons": ["The prompt contains credentials"],
            "detections": {"categories": ["secret"], "entities": ["AWS_ACCESS_KEY"]},
        }
        with rt.db.session() as s:
            decisions.record_mcp_decisions(s, settings, [record])
        with rt.db.session() as s:
            entry = s.scalars(
                select(LedgerEntry).where(LedgerEntry.type == "decision.model.request")
            ).one()
            assert (entry.decision, entry.resource) == ("deny", "openai/gpt-4o-mini")
            finding = Finding.objects.get(type="agent.credential_exfiltration_attempt")
            assert "model provider" in finding.title
            # Model calls' activity comes from the access logs, not from decisions.
            assert model_usage.tokens_used(s) == {}

    def test_jailbreak_attempts_raise_a_finding(self, rt, settings, bot) -> None:
        record = {
            "kind": "model",
            "phase": "request",
            "method": "chat",
            "resource": "openai/gpt-4o-mini",
            "agent": {"id": bot},
            "identity": {"agent_id": bot},
            "effect": "allow",
            "reasons": [],
            "monitored": ["jailbreak-detection: The prompt looks like a jailbreak"],
            "detections": {
                "categories": [],
                "jailbreak": True,
                "jailbreak_reasons": ["instruction_override"],
            },
        }
        with rt.db.session() as s:
            decisions.record_mcp_decisions(s, settings, [record])
        with rt.db.session() as s:
            finding = Finding.objects.get(type="agent.jailbreak_attempts")
            assert finding.title == "People tried to jailbreak bot"
            assert "went through: jailbreak detection is not enforced" in finding.description
            entry = s.scalars(
                select(LedgerEntry).where(LedgerEntry.type == "decision.model.request")
            ).one()
            assert entry.reason.startswith("monitored: jailbreak-detection")


class TestManifestsAndCli:
    def test_apply_and_export(self, rt, settings) -> None:
        doc = {
            "apiVersion": manifests.API_VERSION,
            "kind": "ModelProvider",
            "metadata": {"name": "vllm"},
            "spec": {
                "kind": "openai-compatible",
                "base_url": "http://vllm:8000/v1",
                "trust_level": "verified",
                "prices": {"*": {"input": 0.1, "output": 0.2}},
            },
        }
        with rt.db.session() as s:
            assert manifests.apply(s, settings, [doc], actor="ci")[0]["action"] == "created"
        with rt.db.session() as s:
            assert manifests.apply(s, settings, [doc], actor="ci")[0]["action"] == "unchanged"
            blocked = {**doc, "spec": {**doc["spec"], "status": "blocked"}}
            assert manifests.apply(s, settings, [blocked], actor="ci")[0]["action"] == "configured"
        with rt.db.session() as s:
            [exported] = [d for d in manifests.export(s) if d["kind"] == "ModelProvider"]
        assert exported["spec"] == {**doc["spec"], "status": "blocked"}

    def test_what_if_for_model_calls(self, monkeypatch) -> None:
        sent = []

        def fake_call(method: str, path: str, **kwargs: Any) -> Any:
            if path == "/v1/agents/bot":
                return {"id": "agt_1", "identity": {"client_id": "agent-bot"}}
            sent.append(kwargs["json"])
            return {
                "result": {
                    "effect": "deny",
                    "reasons": ["Model openai/o3 is not granted to agent bot"],
                    "redact": [],
                    "monitored": ["jailbreak-detection: The prompt looks like a jailbreak"],
                }
            }

        monkeypatch.setattr(cli, "_call", fake_call)
        args = ["policies", "evaluate", "--provider", "openai", "--model", "o3", "--agent", "bot"]
        out = ok(runner.invoke(cli.app, [*args, "--jailbreak", "--tool-calls"]))
        assert out.splitlines()[0] == "deny"
        assert "monitored: jailbreak-detection: The prompt looks like a jailbreak" in out
        body = sent[0]
        assert body["path"] == "agentgov/models/decision"
        assert body["input"]["kind"] == "model" and body["input"]["tool_calls"] is True
        assert body["input"]["detections"]["jailbreak"] is True
        assert body["input"]["agent"] == {"agent_id": "agt_1", "client_id": "agent-bot"}
        assert "user" not in body["input"]  # the agent acts on its own
        # On behalf of a person.
        ok(runner.invoke(cli.app, [*args, "--user", "alice", "--groups", "support,/emea/sales"]))
        assert sent[-1]["input"]["user"] == {
            "id": "alice",
            "username": "alice",
            "groups": ["support", "/emea/sales"],
            "roles": [],
            "via": "exchange",
        }
        assert runner.invoke(cli.app, [*args, "--user", "alice", "--via", "magic"]).exit_code == 2
        # A tool call or a model call, not half of one, nor both.
        assert runner.invoke(cli.app, ["policies", "evaluate", "--server", "crm"]).exit_code == 2
        both = [*args, "--server", "crm", "--tool", "get_customer"]
        assert runner.invoke(cli.app, both).exit_code == 2

    def test_cli(self, client, monkeypatch) -> None:
        def agentgov(*args: str):
            monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
            return runner.invoke(cli.app, list(args))

        out = ok(agentgov("models", "create", "openai", "--kind", "openai",
                          "--price", "gpt-4o*=2.5,10", "--trust", "verified"))  # fmt: skip
        assert "agents call it at /llm/openai" in out
        assert "openai" in ok(agentgov("models", "list"))
        assert json.loads(ok(agentgov("models", "get", "openai")))["prices"] == {
            "gpt-4o*": {"input": 2.5, "output": 10.0}
        }
        assert ok(agentgov("models", "block", "openai")).strip().endswith("blocked")
        ok(agentgov("blueprints", "create", "chat", "--model-access", "openai:gpt-4o*,o3",
                    "--token-budget", "5000"))  # fmt: skip
        bp = client.get("/v1/blueprints/chat", headers=ADMIN).json()
        assert bp["model_access"] == [{"provider": "openai", "models": ["gpt-4o*", "o3"]}]
        assert bp["daily_token_budget"] == 5000
        ok(agentgov("blueprints", "update", "chat", "--no-token-budget"))
        assert client.get("/v1/blueprints/chat", headers=ADMIN).json()["daily_token_budget"] is None
        assert ok(agentgov("models", "usage")).startswith("DAY")
        assert ok(agentgov("models", "usage", "--by", "sponsor")).startswith("SPONSOR")
        assert agentgov("models", "usage", "--by", "team").exit_code == 2
        bad = agentgov("models", "create", "x", "--kind", "openai", "--price", "gpt=lots")
        assert bad.exit_code == 2
