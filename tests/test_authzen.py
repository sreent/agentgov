"""AuthZEN (agentgov.authzen): AgentGov's decisions as an AuthZEN decision point, and an
organisation's own decision point asked beside AgentGov's policies by the processor."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentgov import authzen
from agentgov.api import authzen_routes
from agentgov.config import Settings
from agentgov.processor.control_plane import DecisionRecorder
from agentgov.processor.server import GovernanceProcessor
from agentgov.registry import features
from tests.conftest import ADMIN, requires_opa
from tests.test_opa import _decide, _seed
from tests.test_processor import AGENT, FakeControlPlane, FakeOpa, call_request, run

TOOL_INPUT = {
    "phase": "request",
    "method": "tools/call",
    "agent": {"agent_id": "agt_1", "client_id": "agent-bot"},
    "resource": {"server": "crm", "name": "get_customer"},
    "arguments": {"id": "c-1", "email": "ada@example.com"},
    "detections": {"categories": ["pii"], "prompt_injection": False},
    "chain": [{"type": "person", "id": "u-1", "name": "sam"}],
}


# ------------------------------------------------------------------ the mapping


class TestWhatIsAsked:
    def test_a_tool_call_by_an_agent_on_its_own(self) -> None:
        inp = {k: v for k, v in TOOL_INPUT.items() if k != "chain"}
        req = authzen.request_for("tool", inp, agent=AGENT)
        assert req["subject"] == {
            "type": "agent",
            "id": AGENT["id"],
            "properties": {"client_id": "agent-bot", "name": AGENT["name"]},
        }
        assert req["action"] == {"name": "tools/call"}
        assert req["resource"] == {
            "type": "tool",
            "id": "crm/get_customer",
            "properties": {"server": "crm", "name": "get_customer"},
        }
        assert req["context"]["detections"] == {"categories": ["pii"], "prompt_injection": False}
        assert req["context"]["supported_obligations"] == ["custom"]
        # What the call carries never goes.
        assert "ada@example.com" not in json.dumps(req)

    def test_a_person_is_the_subject_when_the_agent_acts_for_one(self) -> None:
        person = {"id": "u-1", "username": "sam", "groups": ["/support"], "via": "exchange"}
        req = authzen.request_for("tool", {**TOOL_INPUT, "user": person}, agent=AGENT)
        assert req["subject"] == {
            "type": "user",
            "id": "u-1",
            "properties": {"username": "sam", "groups": ["/support"]},
        }
        assert req["context"]["agent"]["client_id"] == "agent-bot"
        assert req["context"]["chain"] == ["sam"]

    def test_models_and_agents(self) -> None:
        model = authzen.request_for(
            "model", {"kind": "model", "provider": "openai", "model": "gpt-4o", "agent": {}}
        )
        assert model["action"] == {"name": "chat"}
        assert model["resource"]["id"] == "openai/gpt-4o"
        called = authzen.request_for(
            "agent", {"kind": "a2a", "method": "SendMessage", "target": "billing", "agent": {}}
        )
        assert (called["action"], called["resource"]) == (
            {"name": "SendMessage"},
            {"type": "agent", "id": "billing"},
        )


class TestWhatItAnswers:
    @pytest.mark.parametrize(
        ("answer", "effect", "reasons", "redact"),
        [
            ({"decision": True}, "allow", [], set()),
            (
                {"decision": False, "context": {"reasons": ["after hours"]}},
                "deny",
                ["after hours"],
                set(),
            ),
            (
                {"decision": False, "context": {"reason_admin": {"en": "not on call"}}},
                "deny",
                ["not on call"],
                set(),
            ),
            ({"decision": False}, "deny", ["it denied the call"], set()),
            (
                {"decision": False, "context": {"reason": "approval_required"}},
                "require_approval",
                ["it asks for approval"],
                set(),
            ),
            (
                {
                    "decision": True,
                    "context": {
                        "obligations": [
                            {
                                "id": "o-1",
                                "type": "custom",
                                "properties": {
                                    "vendor": "agentgov",
                                    "action": "redact",
                                    "categories": ["pii"],
                                },
                            }
                        ]
                    },
                },
                "allow",
                [],
                {"pii"},
            ),
            # An obligation AgentGov can't fulfil, on a permit: denied (Obligations profile).
            (
                {"decision": True, "context": {"obligations": [{"id": "o", "type": "step-up"}]}},
                "deny",
                ["it asks for an obligation AgentGov can't fulfil (step-up)"],
                set(),
            ),
        ],
    )
    def test_answers(self, answer, effect, reasons, redact) -> None:
        verdict = authzen.interpret(answer)
        assert (verdict.effect, verdict.reasons, verdict.redact) == (effect, reasons, redact)

    def test_an_answer_without_a_decision(self) -> None:
        for bad in ({}, {"decision": "yes"}, None):
            with pytest.raises(authzen.AuthZenError, match="no decision"):
                authzen.interpret(bad)  # type: ignore[arg-type]

    def test_batches(self) -> None:
        batch = {
            "subject": {"type": "agent", "id": "a"},
            "action": {"name": "tools/call"},
            "evaluations": [
                {"resource": {"type": "tool", "id": "crm/x"}},
                {"resource": {"type": "tool", "id": "crm/y"}, "action": {"name": "tools/list"}},
            ],
            "options": {"evaluations_semantic": "deny_on_first_deny"},
        }
        listed, semantic = authzen.items(batch)
        assert semantic == "deny_on_first_deny"
        assert [i["action"]["name"] for i in listed] == ["tools/call", "tools/list"]
        assert all(i["subject"]["id"] == "a" for i in listed)
        assert authzen.stops("deny_on_first_deny", False)
        assert not authzen.stops("deny_on_first_deny", True)
        assert authzen.stops("permit_on_first_permit", True)
        assert not authzen.stops("execute_all", False)
        with pytest.raises(authzen.AuthZenError, match="evaluations_semantic"):
            authzen.items({**batch, "options": {"evaluations_semantic": "whatever"}})
        assert authzen.items({"subject": {"id": "a"}}) == (
            [{"subject": {"id": "a"}}],
            "execute_all",
        )


# ------------------------------------------------- the organisation's decision point


class FakePdp:
    def __init__(self, answer: Any = None, status: int = 200) -> None:
        self.answer = {"decision": True} if answer is None else answer
        self.status = status
        self.asked: list[tuple[dict[str, Any], httpx.Headers]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/access/v1/evaluation"
        self.asked.append((json.loads(request.content), request.headers))
        return httpx.Response(self.status, json=self.answer)

    def client(self) -> authzen.AuthZenClient:
        http = httpx.AsyncClient(transport=httpx.MockTransport(self))
        return authzen.AuthZenClient("https://pdp.example.com", token="pdp-token", http=http)


def decide(
    pdp: FakePdp | None,
    mode: str,
    *,
    opa: FakeOpa | None = None,
    inp: dict[str, Any] | None = None,
) -> dict[str, Any]:
    opa = opa or FakeOpa(modes={"external-decision-point": mode})

    async def go() -> dict[str, Any]:
        cp = FakeControlPlane()
        processor = GovernanceProcessor(
            Settings(),
            opa=opa,
            control_plane=cp,
            recorder=DecisionRecorder(cp),
            decision_point=pdp.client() if pdp else None,
        )
        decision, _ = await processor.decide(
            "agentgov/mcp/decision", inp or TOOL_INPUT, kind="tool"
        )
        return decision

    return asyncio.run(go())


class TestYourDecisionPoint:
    def test_off_it_isnt_asked(self) -> None:
        pdp = FakePdp({"decision": False})
        assert decide(pdp, "off")["effect"] == "allow"
        assert pdp.asked == []

    def test_enforced_its_denial_stands(self) -> None:
        pdp = FakePdp({"decision": False, "context": {"reasons": ["crm is closed at night"]}})
        decision = decide(pdp, "enforce")
        assert decision["effect"] == "deny"
        assert decision["reasons"] == ["Your decision point denied it: crm is closed at night"]
        asked, headers = pdp.asked[0]
        assert asked["resource"]["id"] == "crm/get_customer"
        assert headers["authorization"] == "Bearer pdp-token" and headers["x-request-id"]

    def test_monitored_its_denial_is_recorded_and_the_call_goes(self) -> None:
        pdp = FakePdp({"decision": False, "context": {"reasons": ["crm is closed at night"]}})
        decision = decide(pdp, "monitor")
        assert decision["effect"] == "allow"
        assert decision["monitored"] == [
            "external-decision-point: would deny: crm is closed at night"
        ]

    def test_approval_and_masking(self) -> None:
        pdp = FakePdp({"decision": False, "context": {"reason": "approval_required"}})
        decision = decide(pdp, "enforce")
        assert decision["effect"] == "require_approval"
        assert decision["reasons"] == [
            "Your decision point asks for approval: it asks for approval"
        ]
        masks = {
            "decision": True,
            "context": {
                "obligations": [
                    {
                        "type": "custom",
                        "properties": {
                            "vendor": "agentgov",
                            "action": "redact",
                            "categories": ["pii"],
                        },
                    }
                ]
            },
        }
        assert decide(FakePdp(masks), "enforce")["redact"] == ["pii"]
        assert decide(FakePdp(masks), "monitor")["monitored"] == [
            "external-decision-point: would mask pii"
        ]

    def test_unreachable_enforced_it_refuses_monitored_it_says_so(self) -> None:
        down = FakePdp(status=503)
        decision = decide(down, "enforce")
        assert decision["effect"] == "deny"
        assert "can't be asked" in decision["reasons"][0]
        decision = decide(FakePdp(status=503), "monitor")
        assert decision["effect"] == "allow"
        assert "couldn't be asked" in decision["monitored"][0]

    def test_what_agentgov_denies_or_answers_isnt_asked(self) -> None:
        pdp = FakePdp({"decision": False})
        denied = FakeOpa(
            lambda inp: {"effect": "deny", "reasons": ["no"], "agent": AGENT},
            modes={"external-decision-point": "enforce"},
        )
        assert decide(pdp, "enforce", opa=denied)["reasons"] == ["no"]
        assert decide(pdp, "enforce", inp={**TOOL_INPUT, "phase": "response"})["effect"] == "allow"
        assert pdp.asked == []

    def test_a_tool_call_through_the_processor(self) -> None:
        pdp = FakePdp({"decision": False, "context": {"reasons": ["not today"]}})
        opa = FakeOpa(modes={"external-decision-point": "enforce"})
        reply, cp = run(
            opa,
            settings=Settings(),
            request=call_request("get_customer", {"id": "c-1"}),
            decision_point=pdp.client(),
        )
        assert reply.WhichOneof("result") == "error"
        assert "Your decision point denied it: not today" in reply.error.reason
        assert cp.records[0]["effect"] == "deny"

    def test_the_feature_needs_the_url(self) -> None:
        settings = Settings()
        assert "AGENTGOV_AUTHZEN_URL" in (
            features.unmet("external-decision-point", "monitor", settings) or ""
        )
        configured = dataclasses.replace(settings, authzen_url="https://pdp.example.com")
        assert features.unmet("external-decision-point", "enforce", configured) is None


# ---------------------------------------------------- AgentGov as a decision point


@requires_opa
class TestAgentGovAsADecisionPoint:
    def test_evaluations_with_the_real_policies(
        self, rt, settings, client, tmp_path: Path, monkeypatch
    ) -> None:
        _seed(client.app.state.rt, settings)
        app_rt = client.app.state.rt

        def opa_post(url: str, *, json: dict[str, Any], **kw: Any) -> httpx.Response:
            assert url.endswith("/v1/data/agentgov/authzen/evaluation")
            result = _decide(app_rt, tmp_path, json["input"], "data.agentgov.authzen.evaluation")
            return httpx.Response(200, json={"result": result})

        monkeypatch.setattr(authzen_routes.httpx, "post", opa_post)
        app_rt.settings = dataclasses.replace(app_rt.settings, opa_url="http://opa:8181")
        ask = {
            "subject": {"type": "agent", "id": "agent-bot"},
            "action": {"name": "tools/call"},
            "resource": {"type": "tool", "id": "crm/get_customer"},
            "context": {"detections": {"categories": []}},
        }
        # Off by default: AgentGov isn't one.
        assert client.post("/access/v1/evaluation", json=ask, headers=ADMIN).status_code == 404
        client.put("/v1/features/authzen-decision-point", json={"mode": "on"}, headers=ADMIN)
        meta = client.get("/.well-known/authzen-configuration").json()
        assert meta["access_evaluation_endpoint"].endswith("/access/v1/evaluation")
        resp = client.post(
            "/access/v1/evaluation", json=ask, headers={**ADMIN, "X-Request-ID": "req-7"}
        )
        assert resp.status_code == 200 and resp.headers["x-request-id"] == "req-7"
        assert resp.json()["decision"] is True
        assert resp.json()["context"]["agentgov"]["agent"]["name"] == "bot"
        # Not granted: false, with why.
        denied = client.post(
            "/access/v1/evaluation",
            json={**ask, "resource": {"type": "tool", "id": "crm/export_all"}},
            headers=ADMIN,
        ).json()
        assert denied["decision"] is False
        assert "crm/export_all is not granted to agent bot" in denied["context"]["reasons"]
        # A batch, stopping at the first denial.
        batch = client.post(
            "/access/v1/evaluations",
            json={
                **{k: ask[k] for k in ("subject", "action", "context")},
                "evaluations": [
                    {"resource": {"type": "tool", "id": "crm/get_customer"}},
                    {"resource": {"type": "tool", "id": "crm/export_all"}},
                    {"resource": {"type": "tool", "id": "crm/get_orders"}},
                ],
                "options": {"evaluations_semantic": "deny_on_first_deny"},
            },
            headers=ADMIN,
        ).json()
        assert [e["decision"] for e in batch["evaluations"]] == [True, False]
        # Whoever can't read AgentGov can't ask it.
        assert client.post("/access/v1/evaluation", json=ask).status_code == 401
