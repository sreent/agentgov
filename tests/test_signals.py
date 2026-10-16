"""What a finding says over time: why it was dismissed and until when, a threat that happens
again, and a severity that rises (docs/issues.md#dismissing-an-issue)."""

from __future__ import annotations

from datetime import timedelta

from agentgov import ids
from agentgov.registry import findings, issues
from tests.conftest import ADMIN
from tests.test_issues import _raise, _rt, agent  # noqa: F401 (the agent fixture)


def history(client, fid: str) -> list[str]:
    return [e["type"] for e in client.get(f"/v1/findings/{fid}", headers=ADMIN).json()["history"]]


def dismiss(client, fid: str, **body):
    return client.post(f"/v1/findings/{fid}/dismiss", json=body, headers=ADMIN)


class TestDismissing:
    def test_it_says_why_and_can_be_for_a_while(self, client, agent) -> None:  # noqa: F811
        fid = _raise(client, agent["id"])
        assert dismiss(client, fid).status_code == 422
        assert dismiss(client, fid, reason="x", until=400).status_code == 422
        done = dismiss(client, fid, reason="Its owner is being changed", until=14)
        assert done.status_code == 200, done.text
        dismissal = done.json()["details"]["dismissal"]
        assert (dismissal["reason"], dismissal["by"]) == (
            "Its owner is being changed",
            "admin:bootstrap",
        )
        assert dismiss(client, fid, reason="again").status_code == 409
        rt = _rt(client)
        with rt.db.transaction() as tx:
            assert issues.reopen_accepted(tx, ids.utcnow() + timedelta(days=13)) == 0
            assert issues.reopen_accepted(tx, ids.utcnow() + timedelta(days=15)) == 1
            again = findings.get(tx, fid)
            assert again.status == "open" and "dismissal" not in again.details
        assert history(client, fid)[0] == "finding.reopened"

    def test_for_good_it_stays_dismissed(self, client, agent) -> None:  # noqa: F811
        fid = _raise(client, agent["id"])
        dismiss(client, fid, reason="A test agent").raise_for_status()
        _raise(client, agent["id"])  # found again: a posture finding stays dismissed
        with _rt(client).db.transaction() as tx:
            assert issues.reopen_accepted(tx, ids.utcnow() + timedelta(days=400)) == 0
            assert findings.get(tx, fid).status == "dismissed"


def _threat(client, agent_id: str, severity: str = "high") -> str:
    with _rt(client).db.transaction() as tx:
        finding, _ = findings.raise_finding(
            tx,
            type="threat.prompt_injection",
            severity=severity,
            subject=agent_id,
            agent_id=agent_id,
            title="Prompt injection in a tool result",
            category=findings.THREAT,
        )
        return finding.id


def test_a_dismissed_threat_that_happens_again_opens_again(client, agent) -> None:  # noqa: F811
    fid = _threat(client, agent["id"])
    dismiss(client, fid, reason="A red-team exercise").raise_for_status()
    _threat(client, agent["id"])
    f = client.get(f"/v1/findings/{fid}", headers=ADMIN).json()
    assert f["status"] == "open" and f["occurrences"] == 2
    reopened = f["history"][0]
    assert reopened["type"] == "finding.reopened"
    assert reopened["details"]["why"] == (
        "it happened again after admin:bootstrap dismissed it: A red-team exercise"
    )


def test_people_are_told_again_when_it_gets_worse(client, agent) -> None:  # noqa: F811
    rt = _rt(client)
    fid = _raise(client, agent["id"], severity="medium")
    rt.run_issues()
    with rt.db.transaction() as tx:
        issues.acknowledge(tx, findings.get(tx, fid), actor="person:cx-team@example.com")
    # Worse: its chain starts over, and its first step is told again.
    _raise(client, agent["id"], severity="high")
    with rt.db.transaction() as tx:
        f = findings.get(tx, fid)
        assert (f.level, f.acknowledged_at, f.round) == (None, None, 1)
    rt.run_issues()
    assert history(client, fid)[:2] == ["finding.assigned", "finding.severity_raised"]
    # As bad as they were told, or back down and up again: not again.
    _raise(client, agent["id"], severity="high")
    _raise(client, agent["id"], severity="medium")
    _raise(client, agent["id"], severity="high")
    assert history(client, fid).count("finding.severity_raised") == 1


def test_the_cli_dismisses_with_a_reason(client, agent, monkeypatch) -> None:  # noqa: F811
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    fid = _raise(client, agent["id"])
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
    refused = runner.invoke(cli.app, ["findings", "dismiss", fid])
    assert refused.exit_code != 0
    out = runner.invoke(cli.app, ["findings", "dismiss", fid, "--reason", "Wrong", "--until", "30"])
    assert out.exit_code == 0 and "dismissed" in out.output, out.output
