"""What the people an issue reaches answer: it isn't theirs, an exception, or that they
fixed it (docs/issues.md#answering-an-issue)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.platforms.base import Inventory
from agentgov.registry import findings
from tests.conftest import ADMIN
from tests.test_issues import _raise, _rt, agent  # noqa: F401 (the agent fixture)
from tests.test_other_platforms import NO_GUARDRAIL, FakeConnector, found


def person(client: TestClient, name: str, role: str = "auditor") -> dict[str, str]:
    """Someone signed in as ``name``: an API key of that name (a role that reads)."""
    resp = client.post("/v1/apikeys", json={"name": name, "role": role}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def finding(client: TestClient, fid: str) -> dict[str, Any]:
    return client.get(f"/v1/findings/{fid}", headers=ADMIN).json()


def answer(client: TestClient, fid: str, what: str, headers: dict[str, str], **body: Any):
    return client.post(f"/v1/findings/{fid}/{what}", json=body, headers=headers)


@pytest.fixture
def issue(client: TestClient, agent: dict[str, Any]) -> str:  # noqa: F811
    """An issue about support-bot, with its owner, team cx (cx-team@example.com)."""
    fid = _raise(client, agent["id"])
    _rt(client).run_issues()
    return fid


class TestNotMine:
    def test_it_goes_on_at_once_saying_why(self, client, issue) -> None:
        cx = person(client, "cx-team@example.com")
        resp = answer(client, issue, "not-mine", cx, reason="Payments took it over in June")
        assert resp.status_code == 200, resp.text
        assert resp.json()["went_to"] == ["alice@example.com", "bob"]
        now = finding(client, issue)
        assert now["level"] == "sponsors"
        assert [e["type"] for e in now["history"]][:2] == ["finding.escalated", "finding.declined"]
        declined = now["history"][1]["details"]
        assert (declined["why"], declined["by"]) == (
            "Payments took it over in June",
            "cx-team@example.com",
        )

    def test_at_the_last_step_it_stays_there(self, client, issue) -> None:
        cx, alice = person(client, "cx-team@example.com"), person(client, "alice@example.com")
        answer(client, issue, "not-mine", cx, reason="Not ours").raise_for_status()
        answer(client, issue, "not-mine", alice, reason="Not mine").raise_for_status()
        gov = person(client, "gov@example.com")
        assert answer(client, issue, "not-mine", gov, reason="?").json()["went_to"] == []
        assert finding(client, issue)["level"] == "team"

    def test_from_an_earlier_step_it_is_only_recorded(self, client, issue) -> None:
        cx = person(client, "cx-team@example.com")
        answer(client, issue, "not-mine", cx, reason="Not ours").raise_for_status()
        again = answer(client, issue, "not-mine", cx, reason="Still not ours")
        assert again.json()["went_to"] == [] and finding(client, issue)["level"] == "sponsors"

    def test_it_says_what_it_takes(self, client, issue) -> None:
        cx, mallory = person(client, "cx-team@example.com"), person(client, "mallory@example.com")
        assert answer(client, issue, "not-mine", mallory, reason="x").status_code == 403
        missing = answer(client, issue, "not-mine", cx)
        assert missing.status_code == 422 and "why it isn't yours" in missing.json()["detail"]


class TestAnException:
    def test_asked_for_then_accepted(self, client, issue) -> None:
        cx = person(client, "cx-team@example.com")
        asked = answer(client, issue, "exception", cx, reason="Retiring it in May", until=60)
        assert asked.status_code == 200, asked.text
        request = asked.json()["details"]["exception_request"]
        assert (request["by"], request["reason"]) == ("cx-team@example.com", "Retiring it in May")
        # It stays with whoever asked: acknowledged, it goes no further.
        assert asked.json()["acknowledged_by"] == "auditor:cx-team@example.com"
        listed = client.get("/v1/findings", params={"asked": "true"}, headers=ADMIN).json()
        assert [f["id"] for f in listed] == [issue]
        # Whoever owns the agent doesn't decide; an approver does.
        cx_approver = person(client, "cx-team@example.com", role="approver")
        refused = answer(client, issue, "accept", cx_approver, reason="ok", until=60)
        assert refused.status_code == 403
        approver = person(client, "dana@example.com", role="approver")
        accepted = answer(client, issue, "accept", approver, reason="Until May", until=60)
        assert accepted.status_code == 200 and accepted.json()["status"] == "accepted"
        assert "exception_request" not in accepted.json()["details"]
        assert client.get("/v1/findings", params={"asked": "true"}, headers=ADMIN).json() == []

    def test_declined_it_stays_with_whoever_asked(self, client, issue) -> None:
        cx, approver = (
            person(client, "cx-team@example.com"),
            person(client, "dana@example.com", role="approver"),
        )
        answer(client, issue, "exception", cx, reason="Soon", until=30).raise_for_status()
        refused = answer(client, issue, "exception/decline", cx, reason="no")
        assert refused.status_code == 403
        declined = answer(client, issue, "exception/decline", approver, reason="Fix it first")
        assert declined.status_code == 200, declined.text
        assert declined.json()["status"] == "open"
        assert "exception_request" not in declined.json()["details"]
        types = [e["type"] for e in finding(client, issue)["history"]]
        assert types[:2] == ["finding.exception_declined", "finding.exception_requested"]
        nothing = answer(client, issue, "exception/decline", approver, reason="again")
        assert nothing.status_code == 409

    def test_it_says_what_it_takes(self, client, issue) -> None:
        cx, mallory = person(client, "cx-team@example.com"), person(client, "mallory@example.com")
        for body, says in (
            ({"until": 30}, "why its risk is acceptable"),
            ({"reason": "x", "until": 400}, "a year at most"),
            ({"reason": "x", "until": 30, "who": "me"}, "unknown field"),
        ):
            resp = answer(client, issue, "exception", cx, **body)
            assert resp.status_code == 422 and says in resp.json()["detail"], (body, resp.text)
        assert answer(client, issue, "exception", mallory, reason="x", until=3).status_code == 403


class TestFixed:
    def test_a_posture_finding_is_checked_again_at_once(self, client, issue) -> None:
        # support-bot has an owner: the scan finds it gone.
        cx = person(client, "cx-team@example.com")
        resp = answer(client, issue, "recheck", cx)
        assert resp.status_code == 200, resp.text
        assert (resp.json()["fixed"], resp.json()["checked"]) == (True, "posture")
        now = finding(client, issue)
        assert now["status"] == "resolved"
        assert [e["type"] for e in now["history"]][:2] == [
            "finding.fix_claimed",
            "finding.resolved",
        ]

    def test_still_there_it_says_so(self, client, agent) -> None:  # noqa: F811
        client.patch(f"/v1/agents/{agent['id']}", json={"owner": None}, headers=ADMIN)
        client.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        rows = client.get("/v1/findings", params={"type": "agent.no_owner"}, headers=ADMIN)
        [row] = rows.json()
        approver = person(client, "dana@example.com", role="approver")
        out = answer(client, row["id"], "recheck", approver).json()
        assert (out["fixed"], out["finding"]["status"]) == (False, "open")

    def test_what_cant_be_checked_on_demand(self, client, agent) -> None:  # noqa: F811
        with _rt(client).db.session() as s:
            raised, _ = findings.raise_finding(
                s,
                type="defender.alert",
                severity="high",
                subject=agent["id"],
                agent_id=agent["id"],
                title="Jailbreak attempt",
            )
            fid = raised.id
        resp = answer(client, fid, "recheck", ADMIN)
        assert resp.status_code == 409 and "can't check this kind" in resp.json()["detail"]
        mallory = person(client, "mallory@example.com")
        assert answer(client, fid, "recheck", mallory).status_code == 403


@pytest.fixture
def aws(settings: Settings) -> Iterator[tuple[TestClient, FakeConnector]]:
    connector = FakeConnector()
    app = create_app(settings, background=False)
    with TestClient(app) as test_client:
        app.state.rt.platforms["aws"] = connector
        yield test_client, connector


def test_a_platforms_finding_resolves_after_one_check_asked_for(aws) -> None:
    client, connector = aws
    part = "111122223333/us-east-1"
    connector.next = Inventory(found=[found("billing-helper", part, NO_GUARDRAIL)], read={part})
    client.post("/v1/platforms/aws/sync", headers=ADMIN).raise_for_status()
    [row] = client.get(
        "/v1/findings", params={"type": "platform.no_guardrail"}, headers=ADMIN
    ).json()  # fmt: skip
    connector.next = Inventory(found=[found("billing-helper", part)], read={part})
    out = answer(client, row["id"], "recheck", ADMIN).json()
    # A scheduled sync takes two clean checks; one asked for is enough.
    assert (out["fixed"], out["checked"]) == (True, "platform")
    assert connector.calls == 2


def test_the_cli(client, issue, monkeypatch) -> None:
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    bearer = person(client, "cx-team@example.com")["Authorization"].removeprefix("Bearer ")
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, bearer))
    out = runner.invoke(
        cli.app, ["findings", "ask-exception", issue, "--reason", "Retiring it", "--until", "30"]
    )
    assert out.exit_code == 0 and "asked to accept its risk" in out.output, out.output
    out = runner.invoke(cli.app, ["findings", "not-mine", issue, "--reason", "Payments'"])
    assert "passed on to alice@example.com, bob" in out.output, out.output
    out = runner.invoke(cli.app, ["findings", "recheck", issue])
    assert out.exit_code == 0 and "gone: resolved" in out.output, out.output
