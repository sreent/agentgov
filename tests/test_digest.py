"""A daily digest of their open issues, for each address and team chat that has some
(docs/issues.md#a-daily-digest)."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentgov.config import Settings
from agentgov.models import Finding, IntegrationState, LedgerEntry
from agentgov.notify import Notifier
from agentgov.registry import destinations, digest, features, findings, issues, teams
from agentgov.secops.delivery import Delivery
from tests.test_issues import _SMTP, _raise, _rt, agent  # noqa: F401 (the agent fixture)

# A Monday, at 08:05 in UTC.
MONDAY = datetime(2026, 10, 19, 8, 5, tzinfo=UTC)


def at(settings: Settings, **digest_settings: str) -> Settings:
    return dataclasses.replace(
        settings,
        smtp_url="smtp://mail:25",
        smtp_from="agentgov@example.com",
        issues_digest_at="08:00",
        **{f"issues_digest_{k}": v for k, v in digest_settings.items()},
    )


class TestWhen:
    def test_once_its_time_has_come_on_a_day_it_goes_out(self, settings) -> None:
        s = at(settings)
        assert digest.due(s, MONDAY) == "2026-10-19"
        assert digest.due(s, MONDAY - timedelta(minutes=6)) is None  # 07:59
        assert digest.due(s, MONDAY + timedelta(days=5)) is None  # Saturday
        assert digest.due(dataclasses.replace(s, issues_digest_at=None), MONDAY) is None

    def test_in_its_time_zone(self, settings) -> None:
        s = at(settings, timezone="America/New_York")  # UTC-4 in October
        assert digest.due(s, MONDAY) is None  # 04:05 there
        assert digest.due(s, MONDAY + timedelta(hours=4)) == "2026-10-19"
        # Sunday evening in UTC is still Sunday there: none.
        assert digest.due(s, MONDAY - timedelta(hours=10)) is None

    def test_it_says_what_it_takes(self) -> None:
        for env, says in (
            ({"AGENTGOV_ISSUES_DIGEST_AT": "8"}, "HH:MM"),
            (
                {"AGENTGOV_ISSUES_DIGEST_AT": "08:00", "AGENTGOV_ISSUES_DIGEST_TIMEZONE": "Moon"},
                "time zone",
            ),
            (
                {"AGENTGOV_ISSUES_DIGEST_AT": "08:00", "AGENTGOV_ISSUES_DIGEST_DAYS": "mon,fun"},
                "days of the week",
            ),
        ):
            with pytest.raises(ValueError, match=says):
                Settings.from_env(env)


def _notifier(client: TestClient, settings: Settings, **kw: Any) -> Notifier:
    rt = _rt(client)
    return Notifier(rt.db, settings, Delivery(rt.db, settings, http=kw.pop("http", None)), **kw)


def _issues(client: TestClient, agent_id: str, settings: Settings) -> tuple[str, str]:
    """Two issues about support-bot, with its owner (team cx), found an hour before MONDAY:
    one medium, one low (below the severity sent one by one)."""
    rt = _rt(client)
    medium = _raise(client, agent_id)
    with rt.db.session() as s:
        low, _ = findings.raise_finding(
            s,
            type="agent.attestation_overdue",
            severity="low",
            subject=agent_id,
            agent_id=agent_id,
            title="Its review is overdue",
        )
        for f in s.scalars(select(Finding)):
            f.first_seen = MONDAY - timedelta(hours=1)
        issues.route(s, settings, MONDAY - timedelta(hours=1))
        return medium, low.id


def _ledger(client: TestClient, type_: str) -> list[dict[str, Any]]:
    with _rt(client).db.session() as s:
        return [e.details for e in s.scalars(select(LedgerEntry).where(LedgerEntry.type == type_))]


class TestTheDigest:
    def test_each_address_gets_its_issues_once_a_day(self, client, agent) -> None:  # noqa: F811
        outbox: list[Any] = []
        settings = at(_rt(client).settings)
        notifier = _notifier(client, settings, smtp=lambda: _SMTP(outbox))
        medium, low = _issues(client, agent["id"], settings)
        assert notifier.digest(MONDAY) == {"digests_sent": 1, "digests_failed": 0}
        (message,) = outbox
        assert message["To"] == "cx-team@example.com"
        assert message["Subject"] == (
            "[AgentGov] 2 open issues with you, 2 waiting for someone to take them on"
        )
        body = message.get_content()
        # The most severe first; the low one, not sent on its own, is in it.
        assert body.index("Medium: Agent support-bot has no owner") < body.index(
            "Low: Its review is overdue"
        )
        assert "agent support-bot (new). It goes further in 3 days unless someone" in body
        assert f"/ui/#/findings/{low}" in body and "/ui/#/findings?status=mine" in body
        assert _ledger(client, "issues.digest_sent") == [
            {"channel": "email", "to": "cx-team@example.com", "issues": 2, "waiting": 2}
        ]
        # Once a day.
        assert notifier.digest(MONDAY + timedelta(hours=3)) == {}
        # The next day: what was taken on says so, and nothing is new.
        with _rt(client).db.session() as s:
            issues.acknowledge(s, findings.get(s, medium), actor="person:cx-team@example.com")
        assert notifier.digest(MONDAY + timedelta(days=1))["digests_sent"] == 1
        body = outbox[1].get_content()
        assert outbox[1]["Subject"] == (
            "[AgentGov] 2 open issues with you, 1 waiting for someone to take it on"
        )
        assert "Taken on, not fixed yet:\n\n- Medium: Agent support-bot has no owner" in body
        assert "(new)" not in body

    def test_it_follows_the_issue_up_its_chain(self, client, agent) -> None:  # noqa: F811
        outbox: list[Any] = []
        settings = at(_rt(client).settings)
        notifier = _notifier(client, settings, smtp=lambda: _SMTP(outbox))
        _issues(client, agent["id"], settings)
        with _rt(client).db.session() as s:
            # A week on, nobody took them on: they are with the sponsors. bob has no
            # address: AgentGov lists them for him.
            issues.route(s, settings, MONDAY + timedelta(days=7))
        notifier.digest(MONDAY + timedelta(days=7))
        assert [m["To"] for m in outbox] == ["alice@example.com"]

    def test_a_failure_is_tried_again_then_given_up_for_the_day(self, client, agent) -> None:  # noqa: F811
        settings = at(_rt(client).settings)
        notifier = _notifier(client, settings, smtp=lambda: _SMTP([], fail=True))
        _issues(client, agent["id"], settings)
        assert notifier.digest(MONDAY) == {"digests_sent": 0, "digests_failed": 1}
        assert notifier.digest(MONDAY) == {}  # it waits a little first
        now = MONDAY
        for _ in range(digest.MAX_TRIES - 1):
            now += timedelta(hours=1)
            assert notifier.digest(now)["digests_failed"] == 1
        assert notifier.digest(now + timedelta(hours=1)) == {}
        (failed,) = _ledger(client, "issues.digest_failed")
        assert failed["to"] == "cx-team@example.com" and "connection refused" in failed["error"]

    def test_team_chats_get_one_too(self, client, agent, tmp_path: Path) -> None:  # noqa: F811
        rt = _rt(client)
        posted: list[httpx.Request] = []
        http = httpx.Client(
            transport=httpx.MockTransport(lambda r: posted.append(r) or httpx.Response(200))
        )
        rt.settings = dataclasses.replace(rt.settings, destination_secrets_dir=str(tmp_path))
        (tmp_path / "cx-slack").write_text("https://hooks.slack.example/T/B/x")
        with rt.db.session() as s:
            destinations.create(s, {"name": "cx-slack", "kind": "slack"}, actor="admin:test")
            teams.update_team(
                s, teams.get(s, "cx"), {"destinations": ["cx-slack"]}, actor="admin:test"
            )
        settings = dataclasses.replace(at(rt.settings), smtp_url=None)
        _issues(client, agent["id"], settings)
        assert _notifier(client, settings, http=http).digest(MONDAY)["digests_sent"] == 1
        (request,) = posted
        assert b"2 open issues with this team" in request.content
        assert b"Its review is overdue" in request.content

    def test_nothing_without_it_or_while_issues_are_off(self, client, agent) -> None:  # noqa: F811
        rt = _rt(client)
        outbox: list[Any] = []
        settings = at(rt.settings)
        _issues(client, agent["id"], settings)
        off = dataclasses.replace(settings, issues_digest_at=None)
        assert _notifier(client, off, smtp=lambda: _SMTP(outbox)).digest(MONDAY) == {}
        with rt.db.session() as s:
            features.set_mode(s, rt.settings, "issues", "off", actor="admin:test")
        assert _notifier(client, settings, smtp=lambda: _SMTP(outbox)).digest(MONDAY) == {}
        assert outbox == []
        with rt.db.session() as s:
            assert s.get(IntegrationState, digest.STATE) is None
