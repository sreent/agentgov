"""Issues' tickets in service desks: ServiceNow, Jira and Freshservice (docs/tickets.md)."""

from __future__ import annotations

import base64
import itertools
import json
import re
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentgov import ids
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.models import Destination, Finding, Ticket
from agentgov.registry import desks, destinations, findings, issues, teams
from agentgov.registry.errors import ValidationError
from agentgov.runtime import Runtime
from tests.conftest import ADMIN, seed

SNOW = "https://acme.service-now.com"
JIRA = "https://acme.atlassian.net"
FRESH = "https://acme.freshservice.com"


class FakeDesks:
    """Stands in for a ServiceNow instance, a Jira site and a Freshservice helpdesk: keeps
    their tickets and answers their APIs, as far as AgentGov uses them."""

    SNOW_STATES = {"1": "New", "2": "In Progress", "3": "On Hold", "6": "Resolved", "7": "Closed"}

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.numbers = itertools.count(1)
        self.snow: dict[str, dict[str, Any]] = {}
        self.jira: dict[str, dict[str, Any]] = {}
        self.fresh: dict[int, dict[str, Any]] = {}
        # Answers to give before anything else: (method, path prefix, response), once each.
        self.next: list[tuple[str, str, httpx.Response]] = []
        self.jira_takes_priority = True

    def sent(self, method: str, prefix: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and r.url.path.startswith(prefix)]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for i, (method, prefix, response) in enumerate(self.next):
            if request.method == method and request.url.path.startswith(prefix):
                del self.next[i]
                return response
        host = request.url.host
        body = json.loads(request.content) if request.content else {}
        query = {k: v[0] for k, v in parse_qs(urlsplit(str(request.url)).query).items()}
        if host == "acme.service-now.com":
            return self._snow(request, body, query)
        if host == "acme.atlassian.net":
            return self._jira(request, body, query)
        return self._fresh(request, body, query)

    # -- ServiceNow -----------------------------------------------------------------
    def _snow(self, request: httpx.Request, body: Any, query: dict[str, str]) -> httpx.Response:
        parts = request.url.path.split("/")  # /api/now/table/<table>[/<sys_id>]
        sys_id = parts[5] if len(parts) > 5 else None
        if request.method == "POST":
            n = next(self.numbers)
            record = {
                **body,
                "sys_id": f"sys{n}",
                "number": f"INC{n:07d}",
                "state": "1",
                "active": "true",
                "assigned_to": "",
                "notes": [],
            }
            self.snow[record["sys_id"]] = record
            return httpx.Response(
                201, json={"result": {"sys_id": record["sys_id"], "number": record["number"]}}
            )
        if request.method == "GET" and sys_id is None:
            wanted = query.get("sysparm_query", "").removeprefix("correlation_id=")
            rows = [
                {"sys_id": r["sys_id"], "number": r["number"]}
                for r in self.snow.values()
                if wanted and r.get("correlation_id") == wanted
            ]
            return httpx.Response(200, json={"result": rows})
        record = self.snow.get(sys_id or "")
        if record is None:
            return httpx.Response(404, json={"error": {"message": "No Record found"}})
        if request.method == "GET":

            def both(value: str, shown: str | None = None) -> dict[str, str]:
                return {"value": value, "display_value": shown if shown is not None else value}

            return httpx.Response(
                200,
                json={
                    "result": {
                        "number": both(record["number"]),
                        "state": both(record["state"], self.SNOW_STATES.get(record["state"])),
                        "active": both(record["active"]),
                        "assigned_to": both(
                            "x" if record["assigned_to"] else "", record["assigned_to"]
                        ),
                        "close_code": both(record.get("close_code", "")),
                    }
                },
            )
        # PATCH
        if "work_notes" in body:
            record["notes"].append(body.pop("work_notes"))
        record.update(body)
        return httpx.Response(200, json={"result": {"sys_id": record["sys_id"]}})

    # -- Jira -------------------------------------------------------------------------
    def _jira(self, request: httpx.Request, body: Any, query: dict[str, str]) -> httpx.Response:
        path = request.url.path
        if path == "/rest/api/2/myself":
            return httpx.Response(200, json={"displayName": "AgentGov"})
        if path.startswith("/rest/api/2/project/"):
            return httpx.Response(200, json={"key": path.rsplit("/", 1)[-1]})
        if path == "/rest/api/2/issue" and request.method == "POST":
            fields = body["fields"]
            if "priority" in fields and not self.jira_takes_priority:
                return httpx.Response(
                    400,
                    json={
                        "errorMessages": [],
                        "errors": {
                            "priority": "Field 'priority' cannot be set. It is not on the "
                            "appropriate screen, or unknown."
                        },
                    },
                )
            n = next(self.numbers)
            key = f"{fields['project']['key']}-{n}"
            self.jira[key] = {
                "id": str(10000 + n),
                "key": key,
                "fields": fields,
                "status": ("To Do", "new"),
                "assignee": None,
                "comments": [],
            }
            return httpx.Response(201, json={"id": str(10000 + n), "key": key})
        if path == "/rest/api/2/search/jql":
            label = query["jql"].split('"')[1]
            found = [
                {"id": i["id"], "key": i["key"]}
                for i in self.jira.values()
                if label in i["fields"].get("labels", [])
            ]
            return httpx.Response(200, json={"issues": found})
        key = path.split("/")[5]
        issue = self.jira.get(key)
        if issue is None:
            return httpx.Response(404, json={"errorMessages": ["Issue does not exist"]})
        if path.endswith("/comment"):
            issue["comments"].append(body)
            return httpx.Response(201, json={"id": "1"})
        if path.endswith("/transitions"):
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json={
                        "transitions": [
                            {
                                "id": "21",
                                "name": "Start",
                                "to": {"statusCategory": {"key": "indeterminate"}},
                            },
                            {"id": "31", "name": "Done", "to": {"statusCategory": {"key": "done"}}},
                        ]
                    },
                )
            issue["status"] = (
                ("Done", "done")
                if body["transition"]["id"] == "31"
                else ("In Progress", "indeterminate")
            )
            return httpx.Response(204)
        if request.method == "PUT":
            issue["fields"].update(body["fields"])
            return httpx.Response(204)
        name, category = issue["status"]
        return httpx.Response(
            200,
            json={
                "key": key,
                "fields": {
                    "status": {"name": name, "statusCategory": {"key": category}},
                    "assignee": {"displayName": issue["assignee"]} if issue["assignee"] else None,
                    "resolution": {"name": "Done"} if category == "done" else None,
                },
            },
        )

    # -- Freshservice -------------------------------------------------------------------
    def _fresh(self, request: httpx.Request, body: Any, query: dict[str, str]) -> httpx.Response:
        path = request.url.path
        if path == "/api/v2/tickets" and request.method == "POST":
            n = next(self.numbers)
            ticket = {**body, "id": n, "responder_id": None, "notes": []}
            self.fresh[n] = ticket
            return httpx.Response(201, json={"ticket": ticket})
        if path == "/api/v2/tickets" and request.method == "GET":
            return httpx.Response(200, json={"tickets": []})
        if path == "/api/v2/tickets/filter":
            tag = query["query"].split("'")[1]
            found = [t for t in self.fresh.values() if tag in t.get("tags", [])]
            return httpx.Response(200, json={"tickets": found, "total": len(found)})
        if path.startswith("/api/v2/agents/"):
            return httpx.Response(200, json={"agent": {"first_name": "Dana", "last_name": "Lee"}})
        number = int(path.split("/")[4])
        ticket = self.fresh.get(number)
        if ticket is None:
            return httpx.Response(404, json={"code": "access_denied"})
        if path.endswith("/notes"):
            ticket["notes"].append(body)
            return httpx.Response(201, json={"conversation": body})
        if request.method == "PUT":
            ticket.update(body)
        return httpx.Response(200, json={"ticket": ticket})


@pytest.fixture
def fake() -> FakeDesks:
    return FakeDesks()


@pytest.fixture
def secrets(tmp_path: Path) -> Path:
    path = tmp_path / "destination-secrets"
    path.mkdir()
    return path


@pytest.fixture
def desks_client(settings: Settings, fake: FakeDesks, secrets: Path) -> Iterator[TestClient]:
    """A control plane whose service desks are ``fake``."""
    settings = settings.with_overrides(
        destination_secrets_dir=str(secrets), public_url="https://agentgov.example.com"
    )
    rt = Runtime(settings, destinations_http=httpx.Client(transport=httpx.MockTransport(fake)))
    app = create_app(settings, runtime=rt, background=False)
    with TestClient(app) as client:
        yield client


def rt_of(client: TestClient) -> Runtime:
    return client.app.state.rt  # type: ignore[attr-defined,no-any-return]


def desk(
    client: TestClient, secrets: Path, name: str, kind: str, url: str, **body: Any
) -> dict[str, Any]:
    (secrets / name).write_text(
        {"servicenow": "agentgov:pa55", "jira": "bot@example.com:tok", "freshservice": "key123"}[
            kind
        ]
    )
    resp = client.post(
        "/v1/destinations", json={"name": name, "kind": kind, "url": url, **body}, headers=ADMIN
    )
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[no-any-return]


def issue(
    client: TestClient,
    agent_id: str,
    *,
    severity: str = "high",
    type_: str = "agent.no_owner",
    category: str = findings.POSTURE,
    title: str = "Agent support-bot has no owner",
    description: str = "Nobody owns it.",
) -> str:
    """A finding, routed to its people: an issue."""
    rt = rt_of(client)
    with rt.db.session() as s:
        finding, _ = findings.raise_finding(
            s,
            type=type_,
            severity=severity,
            subject=agent_id,
            agent_id=agent_id,
            title=title,
            description=description,
            remediation="Give it an owner.",
            category=category,
        )
        fid = finding.id
    with rt.db.session() as s:
        issues.route(s, rt.settings)
    return fid


def run(client: TestClient) -> dict[str, int]:
    return rt_of(client).ticketing.run()


def ticket_of(client: TestClient, fid: str) -> dict[str, Any]:
    found = client.get(f"/v1/findings/{fid}", headers=ADMIN).json()["tickets"]
    return found[-1]  # type: ignore[no-any-return]


def history(client: TestClient, fid: str) -> list[str]:
    entries = client.get(f"/v1/findings/{fid}", headers=ADMIN).json()["history"]
    return [e["type"].removeprefix("finding.") for e in entries]


def basic(pair: str) -> str:
    return "Basic " + base64.b64encode(pair.encode()).decode()


@pytest.fixture
def agent(desks_client: TestClient) -> dict[str, Any]:
    """support-bot, its team cx (with a ServiceNow group), and the default team."""
    created = seed(desks_client, sponsors=["alice@example.com"])
    with rt_of(desks_client).db.session() as s:
        teams.create(s, {"name": "cx", "emails": ["cx@example.com"]}, actor="admin:test")
        teams.create(s, {"name": "ai-governance", "default": True}, actor="admin:test")
    desks_client.patch(
        f"/v1/agents/{created['id']}", json={"owner": "cx"}, headers=ADMIN
    ).raise_for_status()
    return created


class TestSettings:
    def test_each_desk_says_what_it_needs(self, desks_client: TestClient, secrets: Path) -> None:
        for body, says in (
            ({"kind": "servicenow"}, "needs url"),
            ({"kind": "servicenow", "url": "http://acme.service-now.com"}, "https URL"),
            ({"kind": "jira", "url": JIRA}, "tickets.group"),
            ({"kind": "jira", "url": JIRA, "tickets": {"group": "ops"}}, "project's key"),
            ({"kind": "freshservice", "url": FRESH}, "tickets.requester"),
            (
                {
                    "kind": "freshservice",
                    "url": FRESH,
                    "tickets": {"requester": "a@b.c", "group": "x"},
                },
                "group's ID",
            ),
            (
                {
                    "kind": "servicenow",
                    "url": SNOW,
                    "tickets": {"fields": {"short_description": "x"}},
                },
                "AgentGov writes it",
            ),
            (
                {
                    "kind": "servicenow",
                    "url": SNOW,
                    "tickets": {"fields": {"assignment_group": "x"}},
                },
                "use group instead",
            ),
            (
                {"kind": "servicenow", "url": SNOW, "tickets": {"issue_type": "Task"}},
                "no issue_type",
            ),
            (
                {"kind": "servicenow", "url": SNOW, "tickets": {"only_listed_teams": True}},
                "needs tickets.groups",
            ),
            ({"kind": "servicenow", "url": SNOW, "events": ["findings"]}, "gets issues"),
            (
                {
                    "kind": "jira",
                    "url": "https://api.atlassian.com/ex/jira/abc",
                    "tickets": {"group": "OPS"},
                },
                "tickets.site",
            ),
            ({"kind": "teams", "tickets": {"group": "x"}}, "for service desks"),
        ):
            resp = desks_client.post("/v1/destinations", json={"name": "d", **body}, headers=ADMIN)
            assert resp.status_code == 422 and says in resp.json()["detail"], (body, resp.text)

    def test_changing_one_setting_keeps_the_others(
        self, desks_client: TestClient, secrets: Path
    ) -> None:
        made = desk(
            desks_client,
            secrets,
            "itsm",
            "servicenow",
            SNOW,
            tickets={"group": "AI Governance", "groups": {"cx": "CX Platform"}},
        )
        assert made["min_severity"] == "high" and made["events"] == []
        changed = desks_client.patch(
            "/v1/destinations/itsm", json={"tickets": {"group": "Security"}}, headers=ADMIN
        ).json()
        assert changed["tickets"] == {"group": "Security", "groups": {"cx": "CX Platform"}}
        cleared = desks_client.patch(
            "/v1/destinations/itsm", json={"tickets": {"groups": None}}, headers=ADMIN
        ).json()
        assert cleared["tickets"] == {"group": "Security"}

    def test_the_secret_file(self) -> None:
        assert desks.headers("servicenow", "agentgov:pa55") == {
            "Authorization": basic("agentgov:pa55")
        }
        assert desks.headers("jira", "bot@example.com:tok\n") == {
            "Authorization": basic("bot@example.com:tok")
        }
        assert desks.headers("freshservice", "key123") == {"Authorization": basic("key123:X")}
        assert desks.headers("servicenow", "x-sn-apikey: abc") == {"x-sn-apikey": "abc"}
        assert desks.headers("jira", "Authorization: Bearer pat") == {"Authorization": "Bearer pat"}
        with pytest.raises(ValueError, match="email:api-token"):
            desks.headers("jira", "just-a-token")

    def test_settings_by_kind(self) -> None:
        with pytest.raises(ValidationError, match="by severity"):
            desks.normalize("servicenow", {"priorities": {"urgent": {}}}, SNOW)
        assert desks.priorities("jira", {}, "critical") == {"priority": {"name": "Highest"}}
        assert desks.priorities("jira", {"priorities": {}}, "critical") == {}
        assert desks.resolve_fields("servicenow", {"table": "sn_si_incident"}) == {"state": "3"}
        assert desks.group_for({"group": "A", "groups": {"cx": "B"}}, "cx") == "B"
        assert desks.group_for({"group": "A", "groups": {"cx": "B"}}, "ops") == "A"
        assert not desks.takes({"only_listed_teams": True, "groups": {"cx": "B"}}, "ops")


class TestServiceNow:
    def test_an_issue_opens_an_incident_and_ends_with_it(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(
            desks_client,
            secrets,
            "itsm",
            "servicenow",
            SNOW,
            tickets={
                "group": "AI Governance",
                "groups": {"cx": "CX Platform"},
                "fields": {"category": "security"},
            },
        )
        fid = issue(desks_client, agent["id"])
        assert run(desks_client)["tickets_opened"] == 1
        (sent,) = fake.sent("POST", "/api/now/table/incident")
        assert sent.headers["Authorization"] == basic("agentgov:pa55")
        assert parse_qs(sent.url.query.decode())["sysparm_input_display_value"] == ["true"]
        record = fake.snow["sys1"]
        assert record["assignment_group"] == "CX Platform"  # its team's group
        assert record["category"] == "security"
        assert (record["impact"], record["urgency"]) == ("1", "2")  # high
        assert record["short_description"] == "[AgentGov] High: Agent support-bot has no owner"
        assert "Give it an owner." in record["description"]
        assert "https://agentgov.example.com/ui/#/findings/" in record["description"]
        assert record["correlation_id"].startswith("agentgov-tkt_")
        t = ticket_of(desks_client, fid)
        assert (t["key"], t["status"], t["desk"], t["team"]) == ("INC0000001", "open", "itsm", "cx")
        assert t["url"] == f"{SNOW}/nav_to.do?uri=incident.do%3Fsys_id%3Dsys1"
        assert "ticket_opened" in history(desks_client, fid)
        # Read back once; then, with nothing changed, nothing more is sent or read.
        run(desks_client)
        assert len(fake.sent("GET", "/api/now/table/incident/sys1")) == 1
        before = len(fake.requests)
        run(desks_client)
        assert len(fake.requests) == before
        # AgentGov's check no longer finds it: the incident is resolved.
        with rt_of(desks_client).db.session() as s:
            findings.set_status(s, fid, "resolved", "system:posture-scan")
        run(desks_client)
        assert record["state"] == "6" and record["close_code"] == "Solution provided"
        assert "no longer finds the problem" in record["close_notes"]
        assert ticket_of(desks_client, fid)["status"] == "closed"
        assert "ticket_closed" in history(desks_client, fid)

    def test_taken_on_there_it_goes_no_further(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        fid = issue(desks_client, agent["id"])
        run(desks_client)
        fake.snow["sys1"].update(state="2", assigned_to="Dana Lee")
        with rt_of(desks_client).db.session() as s:
            for t in s.scalars(select(Ticket)):
                t.synced_at = ids.utcnow() - timedelta(minutes=10)
        run(desks_client)
        f = desks_client.get(f"/v1/findings/{fid}", headers=ADMIN).json()
        assert f["acknowledged_by"] == "Dana Lee (itsm INC0000001)"
        assert f["escalate_at"] is None
        t = ticket_of(desks_client, fid)
        assert (t["state"], t["phase"], t["assignee"]) == ("In Progress", "active", "Dana Lee")
        # Its own acknowledgement isn't sent back to it.
        assert fake.snow["sys1"]["notes"] == []

    def test_what_changes_goes_as_work_notes(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        fid = issue(desks_client, agent["id"])
        run(desks_client)
        rt = rt_of(desks_client)
        with rt.db.session() as s:
            issues.route(s, rt.settings, ids.utcnow() + timedelta(hours=30))  # nobody took it on
        run(desks_client)
        assert (
            "Nobody took it on in time: it now goes to alice@example.com"
            in fake.snow["sys1"]["notes"][-1]
        )
        with rt.db.session() as s:
            issues.acknowledge(s, findings.get(s, fid), actor="person:alice@example.com")
        run(desks_client)
        assert "person:alice@example.com took it on in AgentGov." in fake.snow["sys1"]["notes"][-1]

    def test_resolved_there_while_it_still_holds(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        fid = issue(desks_client, agent["id"])
        run(desks_client)
        fake.snow["sys1"].update(state="6", close_code="Solution provided")
        rt = rt_of(desks_client)

        def read_again() -> None:
            with rt.db.session() as s:
                for t in s.scalars(select(Ticket)):
                    t.synced_at = ids.utcnow() - timedelta(minutes=10)
            run(desks_client)

        read_again()
        f = desks_client.get(f"/v1/findings/{fid}", headers=ADMIN).json()
        assert f["status"] == "open" and f["acknowledged_by"] == "itsm INC0000001"
        assert "ticket_done" in history(desks_client, fid)
        # The next check still finds it: another incident says so.
        issue(desks_client, agent["id"])
        read_again()
        run(desks_client)
        assert len(fake.snow) == 2
        assert "It takes over from INC0000001" in fake.snow["sys2"]["description"]
        assert ticket_of(desks_client, fid)["replaces"] == "INC0000001"

    def test_a_threat_resolved_there_is_resolved(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        fid = issue(desks_client, agent["id"], type_="platform.threat", category=findings.THREAT)
        run(desks_client)
        fake.snow["sys1"].update(state="7")
        with rt_of(desks_client).db.session() as s:
            for t in s.scalars(select(Ticket)):
                t.synced_at = None
        run(desks_client)
        f = desks_client.get(f"/v1/findings/{fid}", headers=ADMIN).json()
        assert (f["status"], f["resolved_by"]) == ("resolved", "itsm INC0000001")
        assert ticket_of(desks_client, fid)["status"] == "closed"


class TestWhatGoes:
    def test_from_its_severity_and_for_its_teams(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(
            desks_client,
            secrets,
            "itsm",
            "servicenow",
            SNOW,
            tickets={"groups": {"ops": "Ops"}, "only_listed_teams": True},
        )
        issue(desks_client, agent["id"])  # its team is cx, which this desk doesn't take
        issue(desks_client, agent["id"], severity="medium", type_="agent.stale")
        assert run(desks_client).get("tickets_opened", 0) == 0
        assert desks_client.get("/v1/tickets", headers=ADMIN).json() == []

    def test_issues_open_before_the_desk_get_none_unless_backfilled(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        issue(desks_client, agent["id"])
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        assert run(desks_client).get("tickets_opened", 0) == 0
        desk(desks_client, secrets, "itsm2", "servicenow", SNOW, backfill=True)
        assert run(desks_client)["tickets_opened"] == 1

    def test_a_paused_desk_or_issues_off_gets_nothing(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW, status="paused")
        issue(desks_client, agent["id"])
        assert run(desks_client) == {}
        assert fake.requests == []


class TestFailures:
    def test_a_refused_ticket_is_tried_again_and_the_desk_says_why(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        fid = issue(desks_client, agent["id"])
        refusal = {"error": {"message": "Data Policy Exception", "detail": "Caller is mandatory"}}
        fake.next.append(("POST", "/api/now/table", httpx.Response(403, json=refusal)))
        assert run(desks_client)["tickets_failing"] == 1
        t = ticket_of(desks_client, fid)
        assert t["status"] == "pending" and "Caller is mandatory" in t["last_error"]
        state = desks_client.get("/v1/destinations/itsm", headers=ADMIN).json()["delivery"]
        assert "Caller is mandatory" in state["last_error"] and state["tickets"]["erring"] == 1
        # Fixing the desk's settings tries it again at once; it looks for it first.
        desks_client.patch(
            "/v1/destinations/itsm",
            json={"tickets": {"fields": {"caller_id": "agentgov"}}},
            headers=ADMIN,
        ).raise_for_status()
        assert run(desks_client)["tickets_opened"] == 1
        assert (
            fake.sent("GET", "/api/now/table/incident")[0]
            .url.params["sysparm_query"]
            .startswith("correlation_id=agentgov-")
        )
        assert fake.snow["sys1"]["caller_id"] == "agentgov"

    def test_opened_without_hearing_back_is_not_opened_twice(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        fid = issue(desks_client, agent["id"])
        real = fake.__call__

        def lost(request: httpx.Request) -> httpx.Response:
            answer = real(request)
            if request.method == "POST":
                raise httpx.ReadTimeout("timed out", request=request)
            return answer

        rt = rt_of(desks_client)
        rt.delivery.http = httpx.Client(transport=httpx.MockTransport(lost))
        assert run(desks_client)["desk_failures"] == 1
        with rt.db.session() as s:
            row = s.scalar(select(Destination).where(Destination.name == "itsm"))
            assert "ReadTimeout" in (row.last_error or "") and row.retry_at is not None
            row.retry_at = None
        rt.delivery.http = httpx.Client(transport=httpx.MockTransport(fake))
        assert run(desks_client)["tickets_opened"] == 1
        assert len(fake.snow) == 1 and ticket_of(desks_client, fid)["key"] == "INC0000001"

    def test_slow_down_is_honoured(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        issue(desks_client, agent["id"])
        fake.next.append(("POST", "/api/now", httpx.Response(429, headers={"Retry-After": "120"})))
        run(desks_client)
        rt = rt_of(desks_client)
        with rt.db.session() as s:
            row = s.scalar(select(Destination).where(Destination.name == "itsm"))
            wait = (row.retry_at - ids.utcnow()).total_seconds()
            assert 100 < wait <= 120
        assert run(desks_client).get("tickets_opened", 0) == 0  # not yet

    def test_no_secret_file(
        self, desks_client: TestClient, secrets: Path, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        (secrets / "itsm").unlink()
        issue(desks_client, agent["id"])
        run(desks_client)
        state = desks_client.get("/v1/destinations/itsm", headers=ADMIN).json()
        assert (
            state["secret"]["need"] == "required"
            and "no secret file" in state["delivery"]["last_error"]
        )

    def test_the_test_signs_in_and_changes_nothing(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks
    ) -> None:
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        out = desks_client.post("/v1/destinations/itsm/test", headers=ADMIN).json()
        assert out == {
            "ok": True,
            "error": None,
            "message": "AgentGov signs in, and can read the incident table",
        }
        assert [r.method for r in fake.requests] == ["GET"]
        fake.next.append(("GET", "/api/now", httpx.Response(401)))
        out = desks_client.post("/v1/destinations/itsm/test", headers=ADMIN).json()
        assert not out["ok"] and "refused AgentGov's credential" in out["error"]


def test_a_desk_on_a_host_not_listed_gets_nothing(
    settings: Settings, fake: FakeDesks, secrets: Path
) -> None:
    """With AGENTGOV_CREDENTIAL_HOSTS, a desk must be on a host it lists: when it is set up,
    and again when AgentGov signs in to it."""
    settings = settings.with_overrides(
        destination_secrets_dir=str(secrets),
        public_url="https://agentgov.example.com",
        credential_hosts="*.service-now.com",
    )
    rt = Runtime(settings, destinations_http=httpx.Client(transport=httpx.MockTransport(fake)))
    with TestClient(create_app(settings, runtime=rt, background=False)) as client:
        (secrets / "jsm").write_text("bot@example.com:tok")
        body = {"name": "jsm", "kind": "jira", "url": JIRA, "tickets": {"group": "OPS"}}
        refused = client.post("/v1/destinations", json=body, headers=ADMIN)
        assert refused.status_code == 422
        assert "AGENTGOV_CREDENTIAL_HOSTS doesn't list acme.atlassian.net" in refused.text
        with rt.db.session() as s:
            # Set up before the deployment listed the hosts.
            destinations.create(s, body, actor="admin:test")
        created = seed(client, sponsors=["alice@example.com"])
        with rt.db.session() as s:
            teams.create(s, {"name": "ai-governance", "default": True}, actor="admin:test")
        issue(client, created["id"])
        run(client)
        state = client.get("/v1/destinations/jsm", headers=ADMIN).json()["delivery"]
        assert "doesn't list acme.atlassian.net" in state["last_error"]
        assert fake.requests == []
        tested = client.post("/v1/destinations/jsm/test", headers=ADMIN).json()
        assert not tested["ok"] and "acme.atlassian.net" in tested["error"]
        assert fake.requests == []


class TestJira:
    def test_issue_comment_and_transition(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(
            desks_client,
            secrets,
            "jsm",
            "jira",
            JIRA,
            tickets={"group": "OPS", "issue_type": "Incident", "fields": {"labels": ["ai"]}},
        )
        fake.jira_takes_priority = False  # its screens have none: it goes without
        fid = issue(desks_client, agent["id"])
        assert run(desks_client)["tickets_opened"] == 1
        (made,) = fake.jira.values()
        assert made["fields"]["project"] == {"key": "OPS"}
        assert made["fields"]["issuetype"] == {"name": "Incident"}
        assert made["fields"]["labels"][:2] == ["ai", "agentgov"]
        assert "priority" not in made["fields"]
        t = ticket_of(desks_client, fid)
        assert t["url"] == f"{JIRA}/browse/{made['key']}"
        # Taken on there.
        made["status"], made["assignee"] = ("In Progress", "indeterminate"), "Dana Lee"
        with rt_of(desks_client).db.session() as s:
            for row in s.scalars(select(Ticket)):
                row.synced_at = None
        run(desks_client)
        assert desks_client.get(f"/v1/findings/{fid}", headers=ADMIN).json()["acknowledged_at"]
        # Dismissed in AgentGov: resolved there, with an internal comment.
        with rt_of(desks_client).db.session() as s:
            findings.dismiss(s, s.get(Finding, fid), actor="admin:ada", reason="a test agent")
        run(desks_client)
        assert made["status"] == ("Done", "done")
        (comment,) = made["comments"]
        assert "dismissed the issue in AgentGov" in comment["body"]
        assert comment["properties"] == [{"key": "sd.public.comment", "value": {"internal": True}}]


class TestWhatOthersWrote:
    """Tickets carry what agents, platforms and people wrote: a Copilot Studio maker names
    the agent, anyone an issue reaches gives a reason. In the desk, it shows as written."""

    # Jira's wiki markup, which its REST API 2 renders in descriptions and comments.
    JIRA = {
        "link": "[Sign in again|https://evil.example/sso]",
        "mention": "[~accountid:5b10ac8d82e05b22cc7d4ef5]",
        "image": "!https://evil.example/pixel.png!",
        "macro": "{color:red}urgent{color} {html}<b>x</b>{html}",
        "formatting": "*bold* _italic_ +under+ ^sup^ {{mono}}\nh1. Heading\n* item",
        "line break": "C:\\\\temp \\[x|https://evil.example\\]",
        "end of the block": "{noformat}[x|https://evil.example]{NoFormat:title=y}",
    }
    BLOCK = re.compile(r"\{noformat(?::[^}]*)?\}", re.IGNORECASE)

    def split(self, text: str) -> tuple[str, str]:
        """What Jira renders as markup (outside {noformat} blocks), and what it shows as it
        is (inside them, zero-width spaces aside)."""
        parts = self.BLOCK.split(text)
        assert len(parts) % 2 == 1, f"a block left open: {text!r}"
        return "".join(parts[0::2]), "".join(parts[1::2]).replace("\u200b", "")

    @pytest.mark.parametrize("construct", JIRA)
    def test_jira_shows_markup_as_text(
        self,
        desks_client: TestClient,
        secrets: Path,
        fake: FakeDesks,
        agent: dict[str, Any],
        construct: str,
    ) -> None:
        written = self.JIRA[construct]
        desk(desks_client, secrets, "jsm", "jira", JIRA, tickets={"group": "OPS"})
        fid = issue(
            desks_client,
            agent["id"],
            title=f"{written} is published without user authentication",
            description=f"Its description: {written}",
        )
        run(desks_client)
        (made,) = fake.jira.values()
        rendered, shown = self.split(made["fields"]["description"])
        assert written not in rendered and "evil.example" not in rendered
        assert f"{written} is published" in shown and f"Its description: {written}" in shown
        # AgentGov's own link stays a link.
        assert f"In AgentGov: https://agentgov.example.com/ui/#/findings/{fid}" in rendered
        assert "[~" not in made["fields"]["description"]
        # A reason someone gives goes as a comment, as written too.
        rt = rt_of(desks_client)
        with rt.db.session() as s:
            issues.ask_exception(
                s,
                findings.get(s, fid),
                actor="person:alice@example.com",
                name="alice@example.com",
                reason=written,
                until=30,
            )
        run(desks_client)
        rendered, shown = self.split(made["comments"][-1]["body"])
        assert written not in rendered and "evil.example" not in rendered
        assert written in shown and "[~" not in made["comments"][-1]["body"]
        assert f"https://agentgov.example.com/ui/#/findings/{fid}" in rendered

    def test_a_summary_is_one_line(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(desks_client, secrets, "jsm", "jira", JIRA, tickets={"group": "OPS"})
        issue(desks_client, agent["id"], title="support-bot\nis published\r\nwithout auth")
        run(desks_client)
        (made,) = fake.jira.values()
        assert made["fields"]["summary"] == (
            "[AgentGov] High: support-bot is published without auth"
        )

    # Between [code] and [/code], ServiceNow renders HTML in work notes.
    SNOW = {
        "code": "[code]<a href='https://evil.example/sso'>Sign in again</a>[/code]",
        "any case": "[CODE]<img src='https://evil.example/p.png'>[/Code]",
        "spaces": "[ code ]<b>x</b>[ / code ]",
    }
    CODE_TAG = re.compile(r"\[\s*/?\s*code\s*\]", re.IGNORECASE)

    @pytest.mark.parametrize("construct", SNOW)
    def test_servicenow_opens_no_code_tag(
        self,
        desks_client: TestClient,
        secrets: Path,
        fake: FakeDesks,
        agent: dict[str, Any],
        construct: str,
    ) -> None:
        written = self.SNOW[construct]
        desk(desks_client, secrets, "itsm", "servicenow", SNOW)
        fid = issue(desks_client, agent["id"], title=f"{written} has no owner")
        run(desks_client)
        rt = rt_of(desks_client)
        with rt.db.session() as s:
            issues.ask_exception(
                s,
                findings.get(s, fid),
                actor="person:alice@example.com",
                name="alice@example.com",
                reason=written,
                until=30,
            )
        run(desks_client)
        with rt.db.session() as s:
            findings.dismiss(s, s.get(Finding, fid), actor="admin:ada", reason=written)
        run(desks_client)
        record = fake.snow["sys1"]
        texts = [
            record["short_description"],
            record["description"],
            record["close_notes"],
            *record["notes"],
        ]
        assert len(record["notes"]) >= 2
        for text in texts:
            assert not self.CODE_TAG.search(text), text
            assert written in text.replace("\u200b", ""), text


class TestFreshservice:
    def test_ticket_note_and_status(
        self, desks_client: TestClient, secrets: Path, fake: FakeDesks, agent: dict[str, Any]
    ) -> None:
        desk(
            desks_client,
            secrets,
            "fs",
            "freshservice",
            FRESH,
            tickets={"requester": "agentgov@example.com", "group": 42},
        )
        fid = issue(desks_client, agent["id"], severity="critical")
        run(desks_client)
        (made,) = fake.fresh.values()
        assert (made["email"], made["group_id"], made["priority"], made["status"]) == (
            "agentgov@example.com",
            42,
            4,
            2,
        )
        assert made["tags"][0] == "agentgov" and "<br>" in made["description"]
        assert fake.requests[0].headers["Authorization"] == basic("key123:X")
        assert ticket_of(desks_client, fid)["key"] == f"#{made['id']}"
        made["responder_id"] = 7
        with rt_of(desks_client).db.session() as s:
            for row in s.scalars(select(Ticket)):
                row.synced_at = None
            f = s.get(Finding, fid)
            issues.accept(
                s,
                f,
                reason="Retiring it next week",
                until=30,
                actor="admin:ada",
                by="ada@example.com",
            )
        run(desks_client)
        assert ticket_of(desks_client, fid)["assignee"] == "Dana Lee"
        assert made["status"] == 4
        assert (
            made["notes"][-1]["private"] is True
            and "risk was accepted" in made["notes"][-1]["body"]
        )


def test_manifests_and_cli(
    desks_client: TestClient, secrets: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    desk(desks_client, secrets, "itsm", "servicenow", SNOW, tickets={"group": "AI Governance"})
    exported = desks_client.get("/v1/export", headers=ADMIN).text
    assert "kind: servicenow" in exported and "group: AI Governance" in exported
    headers = {**ADMIN, "content-type": "application/yaml"}
    again = desks_client.post("/v1/apply", content=exported, headers=headers).json()["results"]
    assert {r["action"] for r in again if r["kind"] == "Destination"} == {"unchanged"}
    monkeypatch.setattr(cli, "_client", lambda: _Shared(desks_client, "test-admin"))
    out = runner.invoke(
        cli.app, ["destinations", "update", "itsm", "--team-group", "cx=CX Platform"]
    )
    assert out.exit_code == 0, out.output
    got = desks_client.get("/v1/destinations/itsm", headers=ADMIN).json()["tickets"]
    assert got == {"group": "AI Governance", "groups": {"cx": "CX Platform"}}
    out = runner.invoke(cli.app, ["tickets", "list"])
    assert out.exit_code == 0 and "no tickets" in out.output.lower(), out.output
