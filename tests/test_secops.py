"""Security operations: the ledger as OCSF events, destinations (SIEMs, Teams and Slack),
and how much the security team's secops role may do at each hand-off level
(agentgov.secops)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentgov import ids, ledger
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.models import Destination, LedgerEntry
from agentgov.registry import destinations, findings, manifests, posture
from agentgov.registry.errors import ValidationError
from agentgov.runtime import Runtime
from agentgov.secops import delivery, formats, ocsf
from tests.conftest import ADMIN, SERVICE, seed
from tests.test_api import key
from tests.test_cli import _Shared, ok, runner

ADMIN_TOKEN = ADMIN["Authorization"].removeprefix("Bearer ")


def level(client: TestClient, mode: str) -> None:
    client.put(
        "/v1/features/security-operations", json={"mode": mode}, headers=ADMIN
    ).raise_for_status()


class Sink:
    """Stands in for the SIEMs and chats: records what is sent, answers ``status``."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.body = "ok"

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, text=self.body)

    def json(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)


@pytest.fixture
def sink() -> Sink:
    return Sink()


@pytest.fixture
def secrets(tmp_path: Path) -> Path:
    path = tmp_path / "destination-secrets"
    path.mkdir()
    return path


@pytest.fixture
def secops(settings: Settings, sink: Sink, secrets: Path) -> Iterator[TestClient]:
    """A control plane whose destinations' requests go to ``sink``."""
    settings = settings.with_overrides(
        destination_secrets_dir=str(secrets), public_url="https://agentgov.example.com"
    )
    rt = Runtime(settings, destinations_http=httpx.Client(transport=httpx.MockTransport(sink)))
    app = create_app(settings, runtime=rt, background=False)
    with TestClient(app) as client:
        yield client


def rt_of(client: TestClient) -> Runtime:
    return client.app.state.rt  # type: ignore[attr-defined,no-any-return]


def destination(client: TestClient, **body: Any) -> dict[str, Any]:
    resp = client.post("/v1/destinations", json=body, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[no-any-return]


def unverified_server(client: TestClient) -> dict[str, Any]:
    """A posture finding: an approved tool server nobody verified."""
    seed(client)
    client.post(
        "/v1/toolservers", json={"name": "wiki", "url": "http://wiki:9000/mcp"}, headers=ADMIN
    ).raise_for_status()
    client.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
    found = client.get("/v1/findings", params={"type": "toolserver.unverified"}, headers=ADMIN)
    return found.json()[0]  # type: ignore[no-any-return]


def entry(type_: str, **fields: Any) -> LedgerEntry:
    """A ledger entry, as the ledger would hold it."""
    values: dict[str, Any] = {
        "seq": 7,
        "id": ids.new_id(ids.EVENT),
        "ts": ids.utcnow(),
        "type": type_,
        "severity": "info",
        "actor": "admin:ada",
        "details": {},
        "hash": "ab" * 32,
    }
    return LedgerEntry(**{**values, **fields})


# ------------------------------------------------------------------------- OCSF


class TestOcsf:
    def test_a_tool_call_is_api_activity_with_the_agent_and_the_control(self) -> None:
        event = ocsf.event(
            entry(
                "decision.request",
                actor="agent:support-bot",
                agent_id="agt_1",
                agent_name="support-bot",
                action="tools/call",
                resource="crm/delete_customer",
                decision="deny",
                reason="not granted",
                on_behalf_of="alice",
                trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
            )
        )
        assert (event["class_uid"], event["activity_id"], event["type_uid"]) == (6003, 99, 600399)
        assert event["type_name"] == "API Activity: Other"
        assert event["api"] == {"operation": "tools/call", "service": {"name": "crm"}}
        assert event["actor"]["application"] == {"name": "support-bot", "uid": "agt_1"}
        assert event["actor"]["user"]["name"] == "alice"
        assert (event["action_id"], event["disposition_id"], event["disposition"]) == (
            2,
            2,
            "Blocked",
        )
        assert event["is_alert"] and event["severity_id"] == 3
        assert event["ai_agent"] == {"uid": "agt_1", "name": "support-bot"}
        assert event["metadata"]["profiles"] == ["security_control", "ai_operation"]
        assert event["metadata"]["correlation_uid"] == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert event["metadata"]["product"]["name"] == "AgentGov"
        # Nothing of the entry is lost.
        assert event["unmapped"]["agentgov"]["type"] == "decision.request"
        assert event["unmapped"]["agentgov"]["hash"] == "ab" * 32

    def test_a_model_call_names_the_model(self) -> None:
        event = ocsf.event(
            entry(
                "decision.model.request",
                agent_id="agt_1",
                agent_name="support-bot",
                action="chat",
                resource="openai/gpt-4o",
                decision="allow",
            )
        )
        assert event["ai_model"] == {"name": "gpt-4o", "ai_provider": "openai"}
        assert event["resources"] == [{"name": "gpt-4o", "type": "AI Model"}]
        assert (event["disposition_id"], event["status"]) == (1, "Success")

    def test_approvals_are_delayed_then_approved_or_rejected(self) -> None:
        requested = ocsf.event(entry("approval.requested", decision="require_approval"))
        approved = ocsf.event(entry("approval.approved", actor="approver:alice"))
        denied = ocsf.event(entry("approval.denied", actor="secops:soar"))
        assert (requested["disposition_id"], requested["is_alert"]) == (14, True)
        assert approved["disposition_id"] == 8
        assert approved["actor"]["user"]["name"] == "alice"
        assert (denied["disposition_id"], denied["action_id"]) == (25, 2)

    def test_sign_ins_are_authentication(self) -> None:
        login = ocsf.event(entry("admin.login", actor="admin:ada", details={"subject": "s-1"}))
        refused = ocsf.event(entry("admin.login_denied", actor="admin:eve"))
        logout = ocsf.event(entry("admin.logout"))
        assert (login["class_uid"], login["activity_id"]) == (3002, 1)
        assert login["user"]["uid"] == "s-1" and login["user"]["type"] == "Admin"
        assert refused["status"] == "Failure"
        assert logout["activity_id"] == 2

    def test_findings_are_compliance_or_detection_findings(self) -> None:
        posture_finding = ocsf.event(
            entry(
                "finding.raised",
                agent_id="agt_1",
                agent_name="support-bot",
                resource="agt_1",
                reason="Agent support-bot has no sponsor",
                details={
                    "finding_id": "fnd_1",
                    "type": "agent.no_sponsor",
                    "category": "posture",
                    "severity": "medium",
                    "remediation": "Add a sponsor.",
                },
            )
        )
        threat = ocsf.event(
            entry(
                "finding.raised",
                details={
                    "finding_id": "fnd_2",
                    "type": "agent.prompt_injection",
                    "category": "threat",
                    "severity": "high",
                },
            )
        )
        resolved = ocsf.event(
            entry("finding.resolved", details={"type": "agent.no_owner", "category": "posture"})
        )
        assert posture_finding["class_uid"] == 2003
        assert posture_finding["compliance"]["status"] == "Fail"
        assert posture_finding["finding_info"]["uid"] == "fnd_1"
        assert posture_finding["remediation"] == {"desc": "Add a sponsor."}
        assert posture_finding["resources"][0]["type"] == "AI Agent"
        assert "ai_agent" not in posture_finding and "is_alert" not in posture_finding
        assert (threat["class_uid"], threat["is_alert"], threat["severity_id"]) == (2004, True, 4)
        assert (resolved["activity_id"], resolved["status"]) == (3, "Resolved")
        assert resolved["compliance"]["status"] == "Pass"

    def test_changes_are_entity_management(self) -> None:
        registered = ocsf.event(
            entry("agent.registered", agent_id="agt_1", agent_name="support-bot")
        )
        blocked = ocsf.event(entry("toolserver.block", resource="toolserver/crm"))
        paused = ocsf.event(entry("destination.pause", resource="destination/siem"))
        other = ocsf.event(entry("feature.changed", resource="feature/approvals"))
        assert (registered["class_uid"], registered["activity_name"]) == (3004, "Create")
        assert registered["entity"] == {
            "type": "AI Agent",
            "type_id": 99,
            "name": "support-bot",
            "uid": "agt_1",
        }
        assert (blocked["activity_id"], blocked["entity"]["name"]) == (9, "crm")
        assert paused["activity_id"] == 9
        assert (other["activity_id"], other["type_name"]) == (3, "Entity Management: Update")
        assert registered["actor"]["user"] == {
            "name": "ada",
            "uid": "admin:ada",
            "type_id": 2,
            "type": "Admin",
        }


class TestFormats:
    def test_otlp_logs_carry_each_event_as_a_record(self) -> None:
        event = ocsf.event(entry("agent.registered", trace_id="4bf92f3577b34da6a3ce929d0e0e4736"))
        body = formats.otlp_logs([event])
        resource = body["resourceLogs"][0]
        assert resource["resource"]["attributes"][0] == {
            "key": "service.name",
            "value": {"stringValue": "agentgov-control-plane"},
        }
        record = resource["scopeLogs"][0]["logRecords"][0]
        assert record["severityText"] == "INFO"
        assert record["traceId"] == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert record["timeUnixNano"] == str(event["time"] * 1_000_000)
        attributes = {a["key"]: a["value"] for a in record["attributes"]}
        assert attributes["event.name"] == {"stringValue": "ocsf.Entity Management"}
        assert attributes["ocsf.class_uid"] == {"intValue": "3004"}
        fields = {kv["key"]: kv["value"] for kv in record["body"]["kvlistValue"]["values"]}
        assert fields["class_uid"] == {"intValue": "3004"}

    def test_splunk_and_json_lines(self) -> None:
        events = [ocsf.event(entry("agent.registered")), ocsf.event(entry("agent.updated"))]
        lines = formats.splunk_hec(events).splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert (first["sourcetype"], first["source"]) == ("ocsf:agentgov", "agentgov")
        assert first["time"] == events[0]["time"] / 1000
        assert [json.loads(x)["class_uid"] for x in formats.json_lines(events).splitlines()] == [
            3004,
            3004,
        ]

    def test_chat_messages_escape_what_agents_control(self) -> None:
        alert = formats.Alert(
            title="Agent <@U123> blocked",
            text="see <https://evil.example|here> & [click](https://evil.example)",
            severity="high",
            facts=[("Agent", "*bold*")],
            link="javascript:alert(1)",
        )
        slack = formats.slack_message(alert)
        # Headers are plain text, which Slack never parses; the rest is escaped.
        assert slack["blocks"][0]["text"] == {"type": "plain_text", "text": alert.title}
        text = json.dumps([slack["text"], slack["blocks"][1:]])
        assert "<@U123>" not in text and "&lt;@U123&gt;" in text
        assert "<https://evil.example|here>" not in text
        assert not [b for b in slack["blocks"] if b["type"] == "actions"]  # no javascript: link
        teams = formats.teams_message(alert)
        card = teams["attachments"][0]["content"]
        assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
        assert "](" not in json.dumps(card) and "[click]\u200b(" in card["body"][1]["text"]
        assert "actions" not in card
        assert card["body"][0]["color"] == "Attention"


# ------------------------------------------------------------------- hand-off


class TestHandoff:
    def test_the_secops_role_reads_like_an_auditor(self, client) -> None:
        soc = key(client, "secops", "soc")
        assert client.get("/v1/agents", headers=soc).status_code == 200
        assert client.get("/v1/ledger", headers=soc).status_code == 200
        assert client.post("/v1/agents", json={"name": "x"}, headers=soc).status_code == 403
        # Only administrators choose the level.
        resp = client.put("/v1/features/security-operations", json={"mode": "decide"}, headers=soc)
        assert resp.status_code == 403
        me = client.get("/v1/me", headers=soc).json()
        assert me["handoff"] == {"level": "off", "reached": []}
        level(client, "contain")
        me = client.get("/v1/me", headers=soc).json()
        assert me["handoff"] == {"level": "contain", "reached": ["inform", "triage", "contain"]}
        assert "handoff" not in client.get("/v1/me", headers=ADMIN).json()

    def test_triage_lets_it_resolve_findings(self, client) -> None:
        finding = unverified_server(client)
        soc = key(client, "secops", "soc")
        path = f"/v1/findings/{finding['id']}/resolve"
        level(client, "inform")
        refused = client.post(path, headers=soc)
        assert refused.status_code == 403
        assert "triage" in refused.json()["detail"]
        level(client, "triage")
        assert client.post(path, headers=soc).json()["resolved_by"] == "secops:soc"
        assert client.post(f"/v1/findings/{finding['id']}/reopen", headers=soc).status_code == 200
        # Approvers triage whatever the level.
        level(client, "off")
        approver = key(client, "approver", "bob")
        assert client.post(path, headers=approver).status_code == 200
        entries = client.get("/v1/ledger", params={"type": "finding.resolved"}, headers=ADMIN)
        assert {e["actor"] for e in entries.json()} >= {"secops:soc", "approver:bob"}

    def test_contain_lets_it_block_and_unblock(self, client) -> None:
        agent = seed(client)
        client.post(
            "/v1/models/providers",
            json={
                "name": "groq",
                "kind": "openai-compatible",
                "base_url": "https://api.groq.com/openai/v1",
            },
            headers=ADMIN,
        ).raise_for_status()
        client.post(
            "/v1/identity-issuers",
            json={"name": "cluster", "kind": "kubernetes", "issuer": "https://k8s.example.com"},
            headers=ADMIN,
        ).raise_for_status()
        soc = key(client, "secops", "soc")
        switches = [
            f"/v1/agents/{agent['id']}",
            "/v1/toolservers/crm",
            "/v1/models/providers/groq",
            "/v1/identity-issuers/cluster",
        ]
        level(client, "triage")
        for path in switches:
            refused = client.post(f"{path}/block", headers=soc)
            assert refused.status_code == 403, path
            assert "contain" in refused.json()["detail"]
        level(client, "contain")
        for path in switches:
            assert client.post(f"{path}/block", headers=soc).json()["status"] == "blocked", path
            assert client.post(f"{path}/unblock", headers=soc).status_code == 200, path
        # Block and unblock, nothing else: not even at decide.
        level(client, "decide")
        for action in ("delete", "restore", "adopt"):
            resp = client.post(f"/v1/agents/{agent['id']}/{action}", headers=soc)
            assert resp.status_code == 403, action
        assert client.delete("/v1/toolservers/crm", headers=soc).status_code == 403
        blocked = client.get("/v1/ledger", params={"type": "agent.block"}, headers=ADMIN).json()
        assert blocked[0]["actor"] == "secops:soc"

    def test_decide_lets_it_decide_approvers_requests(self, client) -> None:
        agent = seed(client)
        check = {
            "agent_id": agent["id"],
            "action": "tools/call",
            "resource": "crm/delete_customer",
            "arguments": {"id": "c-1"},
            "reasons": ["destructive"],
        }
        held = client.post("/v1/internal/approvals/check", json=check, headers=SERVICE).json()
        soc = key(client, "secops", "soc")
        path = f"/v1/approvals/{held['approval']['id']}/deny"
        level(client, "contain")
        refused = client.post(path, json={}, headers=soc)
        assert refused.status_code == 403 and "decide" in refused.json()["detail"]
        level(client, "decide")
        denied = client.post(path, json={"note": "SOC: not now"}, headers=soc).json()
        assert (denied["status"], denied["decided_by"]) == ("denied", "secops:soc")

    def test_requests_sent_to_the_person_stay_theirs(self, client) -> None:
        seed(client)
        client.put(
            "/v1/features/approvals-by-person", json={"mode": "on"}, headers=ADMIN
        ).raise_for_status()
        client.patch(
            "/v1/blueprints/support", json={"approvals_by": "person"}, headers=ADMIN
        ).raise_for_status()
        agent = client.get("/v1/agents/support-bot", headers=ADMIN).json()
        held = client.post(
            "/v1/internal/approvals/check",
            json={
                "agent_id": agent["id"],
                "action": "tools/call",
                "resource": "crm/delete_customer",
                "arguments": {},
                "reasons": ["destructive"],
                "user": {"id": "u-1", "username": "alice", "via": "exchange"},
            },
            headers=SERVICE,
        ).json()
        assert held["approval"]["deciders"] == "person"
        level(client, "decide")
        soc = key(client, "secops", "soc")
        resp = client.post(f"/v1/approvals/{held['approval']['id']}/approve", json={}, headers=soc)
        assert resp.status_code == 403


# --------------------------------------------------------------- the events API


class TestEventsApi:
    def test_off_until_inform(self, client) -> None:
        seed(client)
        soc = key(client, "secops", "soc")
        assert client.get("/v1/secops/events", headers=soc).status_code == 409
        level(client, "inform")
        page = client.get("/v1/secops/events", params={"limit": 2}, headers=soc).json()
        assert len(page["events"]) == 2 and page["more"]
        seen = page["events"]
        while page["more"]:
            page = client.get(
                "/v1/secops/events", params={"after": page["next"], "limit": 2}, headers=soc
            ).json()
            seen += page["events"]
        head = client.get("/v1/ledger/verify", headers=ADMIN).json()["checked"]
        assert [e["metadata"]["sequence"] for e in seen] == list(range(1, head + 1))
        assert len({e["metadata"]["uid"] for e in seen}) == head

    def test_choose_what_and_how_severe(self, client) -> None:
        unverified_server(client)
        level(client, "inform")
        found = client.get(
            "/v1/secops/events", params={"events": "findings"}, headers=ADMIN
        ).json()["events"]
        assert found and {e["class_uid"] for e in found} <= {2003, 2004}
        changes = client.get(
            "/v1/secops/events",
            params={"events": "changes", "min_severity": "medium"},
            headers=ADMIN,
        ).json()["events"]
        assert all(e["severity_id"] >= 3 for e in changes)
        assert (
            client.get(
                "/v1/secops/events", params={"events": "everything"}, headers=ADMIN
            ).status_code
            == 422
        )

    def test_status(self, client) -> None:
        level(client, "triage")
        view = client.get("/v1/secops", headers=key(client, "auditor")).json()
        assert (view["level"], view["sending"]) == ("triage", True)
        assert view["secops_may"] == ["resolve, dismiss and reopen findings"]
        assert view["destinations"] == [] and view["ledger_head"] > 0


# ---------------------------------------------------------------- destinations


class TestDestinations:
    def test_what_each_kind_takes(self, client) -> None:
        def refused(**body: Any) -> str:
            resp = client.post("/v1/destinations", json=body, headers=ADMIN)
            assert resp.status_code == 422, resp.text
            return resp.json()["detail"]  # type: ignore[no-any-return]

        assert "credential" in refused(name="soc", kind="slack", url="https://hooks.slack.com/x")
        assert "needs url" in refused(name="otel", kind="otlp")
        assert "needs url" in refused(name="splunk", kind="splunk-hec")
        assert "must not hold credentials" in refused(
            name="otel", kind="otlp", url="https://user:pw@collector:4318"
        )
        assert "gets findings, approvals, blocks" in refused(
            name="soc", kind="teams", events=["decisions"]
        )
        assert "format is for webhook" in refused(
            name="otel", kind="otlp", url="http://c:4318", format="ndjson"
        )
        assert "unknown field" in refused(name="otel", kind="otlp", url="http://c", sevrity="x")
        assert "backfill is for SIEMs" in refused(name="soc", kind="slack", backfill=True)
        assert "kind must be one of" in refused(name="x", kind="email")

    def test_lifecycle(self, client, secrets) -> None:
        seed(client)
        head = client.get("/v1/ledger/verify", headers=ADMIN).json()["checked"]
        soc = destination(client, name="soc", kind="slack", description="SOC channel")
        assert soc["events"] == ["findings", "approvals", "blocks"]
        assert soc["min_severity"] == "high"
        assert soc["delivery"]["cursor"] == head  # from now on
        assert soc["secret"] == {
            "file": str(Path("/destination-secrets") / "soc"),
            "present": False,
            "need": "required",
        }
        siem = destination(
            client, name="siem", kind="webhook", url="https://siem.example.com/in", backfill=True
        )
        assert (siem["delivery"]["cursor"], siem["format"], siem["min_severity"]) == (
            0,
            "json",
            "info",
        )
        assert siem["secret"]["need"] == "optional"
        assert (
            client.post(
                "/v1/destinations",
                json={"name": "siem", "kind": "otlp", "url": "http://c"},
                headers=ADMIN,
            ).status_code
            == 409
        )
        changed = client.patch(
            "/v1/destinations/siem",
            json={"format": "ndjson", "events": ["findings", "approvals"]},
            headers=ADMIN,
        ).json()
        assert (changed["format"], changed["events"]) == ("ndjson", ["findings", "approvals"])
        assert (
            client.patch("/v1/destinations/siem", json={"kind": "otlp"}, headers=ADMIN).status_code
            == 422
        )
        assert (
            client.post("/v1/destinations/siem/pause", headers=ADMIN).json()["status"] == "paused"
        )
        assert client.post("/v1/destinations/siem/pause", headers=ADMIN).status_code == 409
        assert (
            client.post("/v1/destinations/siem/resume", headers=ADMIN).json()["status"] == "active"
        )
        replayed = client.post("/v1/destinations/siem/replay", json={"after": 3}, headers=ADMIN)
        assert replayed.json()["delivery"]["cursor"] == 3
        assert client.post("/v1/destinations/soc/replay", json={}, headers=ADMIN).status_code == 422
        # Auditors and the secops role read them; only administrators change them.
        soc_key = key(client, "secops", "soc")
        assert [d["name"] for d in client.get("/v1/destinations", headers=soc_key).json()] == [
            "siem",
            "soc",
        ]
        assert client.post("/v1/destinations/siem/pause", headers=soc_key).status_code == 403
        assert client.delete("/v1/destinations/soc", headers=ADMIN).status_code == 204
        types = [
            e["type"]
            for e in client.get(
                "/v1/ledger", params={"type": "destination.*"}, headers=ADMIN
            ).json()
        ]
        assert {
            "destination.created",
            "destination.updated",
            "destination.pause",
            "destination.resume",
            "destination.replay",
            "destination.deleted",
        } <= set(types)

    def test_manifests_round_trip_without_credentials(self, client, rt) -> None:
        docs = manifests.parse(
            """
apiVersion: agentgov/v1alpha1
kind: Destination
metadata: {name: soc}
spec: {kind: teams, events: [findings, blocks], min_severity: critical}
---
apiVersion: agentgov/v1alpha1
kind: Destination
metadata: {name: collector}
spec: {kind: otlp, url: "http://otel-collector:4318", status: paused, backfill: true}
"""
        )
        with rt.db.session() as s:
            results = manifests.apply(s, rt.settings, docs, actor="admin:ada")
            assert [r["action"] for r in results] == ["created", "created"]
            assert destinations.get(s, "collector").cursor == 0
            again = manifests.apply(s, rt.settings, docs, actor="admin:ada")
            assert [r["action"] for r in again] == ["unchanged", "unchanged"]
            exported = [d for d in manifests.export(s) if d["kind"] == "Destination"]
        assert exported == [
            {
                "apiVersion": "agentgov/v1alpha1",
                "kind": "Destination",
                "metadata": {"name": "collector"},
                "spec": {"kind": "otlp", "url": "http://otel-collector:4318", "status": "paused"},
            },
            {
                "apiVersion": "agentgov/v1alpha1",
                "kind": "Destination",
                "metadata": {"name": "soc"},
                "spec": {
                    "kind": "teams",
                    "events": ["findings", "blocks"],
                    "min_severity": "critical",
                    "status": "active",
                },
            },
        ]

    def test_secret_files(self, settings, secrets) -> None:
        settings = settings.with_overrides(destination_secrets_dir=str(secrets))
        webhook = Destination(name="siem", kind="webhook", url="https://siem.example.com/in")
        assert destinations.credentials(settings, webhook).headers == {}  # optional
        # Without a URL, its secret file must hold it.
        with pytest.raises(destinations.SecretError, match="no secret file"):
            destinations.credentials(settings, Destination(name="siem", kind="webhook"))
        (secrets / "siem").write_text(
            "# Sumo Logic: the URL is the credential\n"
            "https://collectors.example.com/receiver/v1/http/c2VjcmV0\n"
            "X-Sumo-Category: agentgov\n"
        )
        creds = destinations.credentials(settings, webhook)
        assert creds.url == "https://collectors.example.com/receiver/v1/http/c2VjcmV0"
        assert creds.headers == {"X-Sumo-Category": "agentgov"}
        (secrets / "siem").write_text("not a header\n")
        with pytest.raises(destinations.SecretError, match="line 1"):
            destinations.credentials(settings, webhook)
        hec = Destination(name="splunk", kind="splunk-hec")
        with pytest.raises(destinations.SecretError, match="no secret file"):
            destinations.credentials(settings, hec)
        (secrets / "splunk").write_text("Splunk 1234-abcd\n")
        assert destinations.credentials(settings, hec).headers == {
            "Authorization": "Splunk 1234-abcd"
        }
        (secrets / "soc").write_text("not a url")
        with pytest.raises(destinations.SecretError, match="webhook URL") as raised:
            destinations.credentials(settings, Destination(name="soc", kind="slack"))
        assert "not a url" not in str(raised.value)  # never the contents

    def test_validation_helpers(self) -> None:
        assert destinations.category("decision.model.request") == "decisions"
        assert destinations.category("telemetry.ungranted_tool_use") == "decisions"
        assert destinations.category("approval.used") == "approvals"
        assert destinations.category("admin.login") == "access"
        assert destinations.category("apikey.created") == "access"
        assert destinations.category("agent.block") == "changes"
        with pytest.raises(ValidationError):
            destinations._events([], "otlp")


# --------------------------------------------------------------------- delivery


class TestDelivery:
    def test_nothing_is_sent_while_the_handoff_is_off(self, secops, sink) -> None:
        destination(
            secops, name="siem", kind="webhook", url="https://siem.example.com/in", backfill=True
        )
        assert rt_of(secops).delivery.run() == {}
        assert sink.requests == []

    def test_otlp_gets_every_entry_once_with_its_headers(self, secops, sink, secrets) -> None:
        destination(
            secops, name="collector", kind="otlp", url="http://otel-collector:4318", backfill=True
        )
        (secrets / "collector").write_text("Authorization: Bearer t0ken\n")
        seed(secops)
        level(secops, "inform")
        rt = rt_of(secops)
        outcome = rt.delivery.run()
        head = secops.get("/v1/ledger/verify", headers=ADMIN).json()["checked"]
        assert outcome == {"collector": {"sent": head}}
        request = sink.requests[0]
        assert str(request.url) == "http://otel-collector:4318/v1/logs"
        assert request.headers["authorization"] == "Bearer t0ken"
        assert request.headers["content-type"] == "application/json"
        records = sink.json()["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        assert len(records) == head
        # Up to date: nothing more to send.
        assert rt.delivery.run() == {}
        view = secops.get("/v1/destinations/collector", headers=ADMIN).json()["delivery"]
        assert (view["cursor"], view["behind"], view["delivered"], view["failures"]) == (
            head,
            0,
            head,
            0,
        )
        # What happens next goes too: from where it got to.
        secops.post("/v1/toolservers/crm/block", headers=ADMIN).raise_for_status()
        rt.delivery.run()
        sent = sink.json()["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        assert [r["body"]["kvlistValue"]["values"] for r in sent]
        assert len(sent) == 1

    def test_splunk_and_webhooks(self, secops, sink, secrets) -> None:
        destination(
            secops,
            name="splunk",
            kind="splunk-hec",
            url="https://splunk:8088",
            backfill=True,
            events=["findings", "changes"],
        )
        (secrets / "splunk").write_text("1234-abcd")
        destination(
            secops,
            name="sumo",
            kind="webhook",
            format="ndjson",
            backfill=True,
            events=["changes"],
            min_severity="medium",
        )
        (secrets / "sumo").write_text("https://collectors.example.com/receiver/v1/http/c2VjcmV0")
        seed(secops)
        secops.post("/v1/toolservers/crm/block", headers=ADMIN).raise_for_status()
        level(secops, "inform")
        rt_of(secops).delivery.run()
        by_host = {r.url.host: r for r in sink.requests}
        hec = by_host["splunk"]
        assert str(hec.url) == "https://splunk:8088/services/collector/event"
        assert hec.headers["authorization"] == "Splunk 1234-abcd"
        assert {json.loads(x)["event"]["class_uid"] for x in hec.content.decode().splitlines()} <= {
            3004,
            2003,
            2004,
        }
        sumo = by_host["collectors.example.com"]
        assert sumo.headers["content-type"] == "application/x-ndjson"
        events = [json.loads(x) for x in sumo.content.decode().splitlines()]
        # Only warnings and up: the tool server blocked, among the changes.
        assert events and all(e["severity_id"] >= 3 for e in events)
        assert "toolserver.block" in {e["unmapped"]["agentgov"]["type"] for e in events}

    def test_chats_get_alerts(self, secops, sink, secrets) -> None:
        destination(secops, name="soc", kind="slack")
        (secrets / "soc").write_text("https://hooks.slack.com/services/T0/B0/s3cret")
        destination(secops, name="teams", kind="teams", events=["approvals"])
        (secrets / "teams").write_text("https://example.webhook.office.com/workflows/s3cret")
        agent = seed(secops)
        rt = rt_of(secops)
        with rt.db.session() as s:
            findings.raise_finding(
                s,
                type="agent.prompt_injection",
                severity="high",
                subject=agent["id"],
                agent_id=agent["id"],
                title="Prompt injection in a tool result",
                category=findings.THREAT,
            )
            findings.raise_finding(
                s,
                type="agent.stale",
                severity="low",
                subject=agent["id"],
                agent_id=agent["id"],
                title="Stale",
            )
        secops.post(
            "/v1/internal/approvals/check",
            json={
                "agent_id": agent["id"],
                "action": "tools/call",
                "resource": "crm/delete_customer",
                "arguments": {},
                "reasons": ["destructive"],
            },
            headers=SERVICE,
        ).raise_for_status()
        secops.post(
            f"/v1/agents/{agent['id']}/block", json={"reason": "SOC"}, headers=ADMIN
        ).raise_for_status()
        level(secops, "inform")
        rt.delivery.run()
        slack = [json.loads(r.content) for r in sink.requests if r.url.host == "hooks.slack.com"]
        titles = [m["blocks"][0]["text"]["text"] for m in slack]
        assert titles == [
            "High finding: Prompt injection in a tool result",
            "Approval needed: support-bot wants to call crm/delete_customer",
            "Agent support-bot blocked",
        ]
        button = slack[0]["blocks"][-2]["elements"][0]
        assert button["url"] == "https://agentgov.example.com/ui/#/findings"
        teams = [json.loads(r.content) for r in sink.requests if r.url.host != "hooks.slack.com"]
        assert len(teams) == 1
        card = teams[0]["attachments"][0]["content"]
        assert card["body"][0]["text"].startswith("Approval needed")

    def test_a_failing_destination_waits_keeps_its_place_and_is_a_finding(
        self, secops, sink, secrets
    ) -> None:
        destination(secops, name="soc", kind="teams", events=["blocks"])
        url = "https://example.webhook.office.com/workflows/s3cret-sig"
        (secrets / "soc").write_text(url)
        agent = seed(secops)
        level(secops, "inform")
        secops.post(f"/v1/agents/{agent['id']}/block", headers=ADMIN).raise_for_status()
        rt = rt_of(secops)
        sink.status, sink.body = 500, f"workflow failed for {url}"
        outcome = rt.delivery.run()
        assert outcome["soc"]["sent"] == 0
        view = secops.get("/v1/destinations/soc", headers=ADMIN).json()["delivery"]
        assert view["failures"] == 1 and view["retry_at"] is not None
        assert "HTTP 500" in view["last_error"] and "s3cret-sig" not in view["last_error"]
        assert view["behind"] > 0
        # It waits before it tries again.
        assert rt.delivery.run() == {}
        assert len(sink.requests) == 1
        with rt.db.session() as s:
            row = destinations.get(s, "soc")
            row.retry_at, row.failures = None, posture.FAILING - 1
        rt.delivery.run()
        with rt.db.session() as s:
            assert destinations.get(s, "soc").failures == posture.FAILING
            posture.scan(s, rt.settings)
        failing = secops.get(
            "/v1/findings", params={"type": "destination.failing"}, headers=ADMIN
        ).json()
        assert failing[0]["severity"] == "high" and "s3cret" not in failing[0]["description"]
        # Once it works again it catches up, and the finding resolves.
        sink.status = 202
        with rt.db.session() as s:
            destinations.get(s, "soc").retry_at = None
        assert rt.delivery.run()["soc"] == {"sent": 1}
        with rt.db.session() as s:
            posture.scan(s, rt.settings)
        assert (
            secops.get("/v1/findings", params={"type": "destination.failing"}, headers=ADMIN).json()
            == []
        )

    def test_a_missing_secret_is_an_error_not_a_request(self, secops, sink) -> None:
        destination(secops, name="soc", kind="slack", events=["blocks"])
        agent = seed(secops)
        secops.post(f"/v1/agents/{agent['id']}/block", headers=ADMIN).raise_for_status()
        level(secops, "inform")
        outcome = rt_of(secops).delivery.run()
        assert "no secret file" in outcome["soc"]["error"]
        assert sink.requests == []

    def test_chats_get_ten_alerts_at_most_and_none_that_are_old(
        self, secops, sink, secrets
    ) -> None:
        destination(secops, name="soc", kind="slack", events=["findings"])
        (secrets / "soc").write_text("https://hooks.slack.com/services/T0/B0/s3cret")
        rt = rt_of(secops)
        with rt.db.session() as s:
            ledger.append(
                s,
                type="finding.raised",
                actor="system:agentgov",
                reason="old news",
                ts=ids.utcnow() - timedelta(hours=2),
                details={"type": "x", "severity": "critical"},
            )
            for n in range(14):
                findings.raise_finding(
                    s,
                    type="agent.prompt_injection",
                    severity="critical",
                    subject=f"s-{n}",
                    title=f"Injection {n}",
                    category=findings.THREAT,
                )
        level(secops, "inform")
        assert rt.delivery.run() == {"soc": {"sent": 10}}
        titles = [json.loads(r.content)["blocks"][0]["text"]["text"] for r in sink.requests]
        assert titles[0] == "Critical finding: Injection 0"
        assert titles[-1] == "5 more alerts"
        assert not [t for t in titles if "old news" in t]
        with rt.db.session() as s:
            assert destinations.get(s, "soc").cursor == destinations.head(s)

    def test_a_partial_failure_resumes_at_the_alert_that_failed(
        self, secops, sink, secrets
    ) -> None:
        destination(secops, name="soc", kind="slack", events=["findings"])
        (secrets / "soc").write_text("https://hooks.slack.com/services/T0/B0/s3cret")
        rt = rt_of(secops)
        with rt.db.session() as s:
            for n in range(3):
                findings.raise_finding(
                    s,
                    type="agent.prompt_injection",
                    severity="high",
                    subject=f"s-{n}",
                    title=f"Injection {n}",
                    category=findings.THREAT,
                )
        level(secops, "inform")
        answers = iter([200, 500])

        def flaky(request: httpx.Request) -> httpx.Response:
            sink.requests.append(request)
            return httpx.Response(next(answers, 200), text="ok")

        rt.delivery.http = httpx.Client(transport=httpx.MockTransport(flaky))
        assert rt.delivery.run()["soc"]["sent"] == 1
        with rt.db.session() as s:
            destinations.get(s, "soc").retry_at = None
        assert rt.delivery.run() == {"soc": {"sent": 2}}
        titles = [json.loads(r.content)["blocks"][0]["text"]["text"] for r in sink.requests]
        assert titles == [
            "High finding: Injection 0",
            "High finding: Injection 1",  # refused
            "High finding: Injection 1",
            "High finding: Injection 2",
        ]

    def test_replicas_dont_send_the_same_entries_at_once(self, secops, sink) -> None:
        destination(
            secops, name="siem", kind="webhook", url="https://siem.example.com/in", backfill=True
        )
        level(secops, "inform")
        rt = rt_of(secops)
        with rt.db.session() as s:
            destination_id = destinations.get(s, "siem").id
        first = rt.delivery._claim(destination_id)
        assert first is not None and first.events
        assert rt.delivery._claim(destination_id) is None  # claimed

    def test_a_test_message(self, secops, sink, secrets) -> None:
        destination(secops, name="soc", kind="teams")
        resp = secops.post("/v1/destinations/soc/test", headers=ADMIN).json()
        assert resp == {"ok": False, "error": f"no secret file {secrets / 'soc'}"}
        (secrets / "soc").write_text("https://example.webhook.office.com/workflows/x")
        sink.status = 202
        assert secops.post("/v1/destinations/soc/test", headers=ADMIN).json() == {
            "ok": True,
            "error": None,
        }
        card = sink.json()["attachments"][0]["content"]
        assert card["body"][0]["text"] == r"AgentGov test message"
        destination(secops, name="siem", kind="otlp", url="http://otel-collector:4318")
        assert secops.post("/v1/destinations/siem/test", headers=ADMIN).json()["ok"]
        record = sink.json()["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        assert record["attributes"][0]["value"] == {"stringValue": "ocsf.Entity Management"}
        tested = secops.get(
            "/v1/ledger", params={"type": "destination.tested"}, headers=ADMIN
        ).json()
        assert [e["details"]["ok"] for e in tested] == [True, True, False]
        assert (
            secops.post("/v1/destinations/soc/test", headers=key(secops, "secops")).status_code
            == 403
        )

    def test_ledger_writes_wake_delivery(self, settings, monkeypatch) -> None:
        rt = Runtime(settings.with_overrides(delivery_interval_seconds=60))
        woken: list[str] = []
        assert rt._delivery_worker is not None
        monkeypatch.setattr(rt._delivery_worker, "trigger", lambda: woken.append("delivery"))
        monkeypatch.setattr(rt.bundles, "notify", lambda: woken.append("bundle"))
        rt.init_db()
        with rt.db.session() as s:
            ledger.append(s, type="agent.updated", actor="admin:ada")
        assert woken == ["delivery"]  # OPA's data didn't change
        rt.db.dispose()


class TestCli:
    def test_destinations_and_events(self, secops, sink, secrets, monkeypatch) -> None:
        from agentgov import cli

        def agentgov(*args: str, token: str = ADMIN_TOKEN):  # type: ignore[no-untyped-def]
            monkeypatch.setattr(cli, "_client", lambda: _Shared(secops, token))
            return runner.invoke(cli.app, list(args))

        out = ok(
            agentgov(
                "destinations", "create", "soc", "--kind", "slack", "--events", "findings,blocks"
            )
        )
        assert "destination/soc: active" in out and "needs a secret file" in out
        ok(
            agentgov(
                "destinations",
                "create",
                "siem",
                "--kind",
                "webhook",
                "--url",
                "https://siem.example.com/in",
                "--backfill",
                "--format",
                "ndjson",
            )
        )
        ok(agentgov("destinations", "update", "siem", "--min-severity", "low"))
        listing = ok(agentgov("destinations", "list"))
        assert "no secret file" in listing and "siem" in listing
        ok(agentgov("destinations", "pause", "siem"))
        ok(agentgov("destinations", "resume", "siem"))
        assert "from after entry 0" in ok(agentgov("destinations", "replay", "siem", "--yes"))
        failed = agentgov("destinations", "test", "soc")
        assert failed.exit_code != 0 and "no secret file" in failed.output
        assert "hand-off: off" in ok(agentgov("secops", "status"))
        refused = agentgov("secops", "events")
        assert refused.exit_code != 0 and "409" in refused.output
        ok(agentgov("secops", "level", "inform"))
        events = ok(agentgov("secops", "events", "--events", "changes"))
        lines = [json.loads(line) for line in events.splitlines() if line.startswith("{")]
        assert lines and {e["class_uid"] for e in lines} == {3004}
        ok(agentgov("destinations", "delete", "soc", "--yes"))
        assert "soc" not in ok(agentgov("destinations", "list"))

    def test_the_old_alert_webhook_setting_is_refused(self) -> None:
        with pytest.raises(ValueError, match="destination of kind slack or teams"):
            Settings.from_env({"AGENTGOV_ALERT_WEBHOOK_URL": "https://hooks.slack.com/x"})
        with pytest.raises(ValueError, match="DELIVERY_INTERVAL"):
            Settings.from_env({"AGENTGOV_DELIVERY_INTERVAL_SECONDS": "-1"})


def test_siem_events_skip_what_was_not_chosen(rt) -> None:
    with rt.db.session() as s:
        ledger.append(s, type="admin.login", actor="admin:ada")
        ledger.append(s, type="agent.updated", actor="admin:ada", severity="warning")
        entries = list(s.scalars(select(LedgerEntry).order_by(LedgerEntry.seq)))
        assert [e["class_uid"] for e in delivery.siem_events(s, entries, ["access"], "info")] == [
            3002
        ]
        assert delivery.siem_events(s, entries, ["changes"], "high") == []
