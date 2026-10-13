"""Who made each agent on another platform, and who owns it there, by name: looked up in
Microsoft Graph or uploaded from the directory (docs/platforms.md#who-made-each-agent)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import ANY
from urllib.parse import unquote

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from agentgov import cli, ids
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.models import Person
from agentgov.platforms.base import Found, Inventory, PlatformError
from agentgov.platforms.microsoft import lookup_users
from agentgov.registry import people, platforms
from agentgov.runtime import Runtime
from tests.conftest import ADMIN
from tests.test_cli import _Shared, runner
from tests.test_platforms import TENANT, app_token, bot

DANA = "11111111-aaaa-bbbb-cccc-000000000001"
EVE = "11111111-aaaa-bbbb-cccc-000000000002"
FRANK = "11111111-aaaa-bbbb-cccc-000000000003"
NOBODY = "11111111-aaaa-bbbb-cccc-000000000099"
USERS = (
    "objectId,userPrincipalName,displayName,mail,accountEnabled\n"
    f"{DANA},dana@contoso.com,Dana Owner,dana@contoso.com,True\n"
    f"{EVE},eve@contoso.com,Eve Maker,,False\n"
    f"{FRANK},frank@contoso.com,Frank Builder,frank@contoso.com,True\n"
)


def studio(name: str, display: str, *, owner: str = DANA, creator: str = FRANK) -> dict:
    """A Copilot Studio agent whose owner and creator the inventory names by Entra ID."""
    row = bot(name, display)
    row["properties"].update(ownerId=owner, createdBy=creator)
    return row


def import_studio(client: TestClient, *rows: dict[str, Any]) -> dict[str, Any]:
    resp = client.post("/v1/platforms/copilot-studio/import", json=list(rows), headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def upload(client: TestClient, text: str, kind: str = "text/csv") -> httpx.Response:
    return client.post(
        "/v1/platforms/entra-users/import",
        content=text.encode(),
        headers={**ADMIN, "content-type": kind},
    )


def agent(client: TestClient, name: str) -> dict[str, Any]:
    resp = client.get(f"/v1/agents/{name}", headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestWhoMadeIt:
    def test_the_inventory_names_them_by_entra_id(self, client) -> None:
        import_studio(client, studio("bot-sales", "Sales Helper"))
        found = agent(client, "sales-helper")
        assert [(m["entra_id"], m["roles"], m["looked_up"]) for m in found["makers"]] == [
            (DANA, ["owner"], False),
            (FRANK, ["creator"], False),
        ]
        assert found["suggested_owner"] is None
        [listed] = client.get("/v1/agents", headers=ADMIN).json()
        assert listed["maker"]["entra_id"] == DANA

    def test_one_person_who_made_and_owns_it(self, client) -> None:
        import_studio(client, studio("bot-sales", "Sales Helper", creator=DANA))
        [maker] = agent(client, "sales-helper")["makers"]
        assert maker["roles"] == ["owner", "creator"]

    def test_a_list_of_users_from_the_directory_names_them(self, client) -> None:
        import_studio(
            client,
            studio("bot-sales", "Sales Helper"),
            studio("bot-hr", "HR FAQ", owner=EVE, creator=DANA),
        )
        resp = upload(client, "﻿" + USERS)
        assert resp.status_code == 200, resp.text
        assert resp.json()["people"] == 3
        assert resp.json()["makers"] == {
            "named": 3, "known": 3, "unknown": 0, "left": 0, "disabled": 1
        }  # fmt: skip
        sales = agent(client, "sales-helper")
        assert [(m["name"], m["email"], m["enabled"]) for m in sales["makers"]] == [
            ("Dana Owner", "dana@contoso.com", True),
            ("Frank Builder", "frank@contoso.com", True),
        ]
        assert sales["suggested_owner"] == "dana@contoso.com"
        # Its owner's account is disabled (no mail, so the UPN): its maker is suggested.
        hr = agent(client, "hr-faq")
        assert hr["makers"][0]["email"] == "eve@contoso.com"
        assert hr["suggested_owner"] == "dana@contoso.com"
        [entry] = client.get(
            "/v1/ledger", params={"type": "people.imported"}, headers=ADMIN
        ).json()  # fmt: skip
        assert entry["details"] == {"people": 3, "skipped": 0}

    def test_lists_in_other_shapes(self, client) -> None:
        import_studio(client, studio("bot-sales", "Sales Helper"))
        powershell = (
            "#TYPE Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser\n"
            '"Id","DisplayName","Mail","UserPrincipalName"\n'
            f'"{DANA}","Dana Owner","dana@contoso.com","dana@contoso.com"\n'
            '"not-an-id","Nobody","x@contoso.com","x@contoso.com"\n'
        )
        resp = upload(client, powershell)
        assert resp.json()["people"] == 1 and resp.json()["skipped"] == 1
        graph = {"value": [{"id": FRANK, "displayName": "Frank", "mail": "frank@contoso.com"}]}
        assert upload(client, json.dumps(graph), "application/json").json()["people"] == 1
        assert [m["known"] for m in agent(client, "sales-helper")["makers"]] == [True, True]
        for bad in ("name,mail\nDana,dana@contoso.com\n", ""):
            refused = upload(client, bad)
            assert refused.status_code == 422 and "object ID" in refused.json()["detail"]
        assert upload(client, "{", "application/json").status_code == 422

    def test_a_platform_that_names_them_by_email(self, client) -> None:
        rt = client.app.state.rt
        found = Found(
            external_id="ws/serving-endpoints/1",
            name="Claims helper",
            kind="Agent on Model Serving",
            part="",
            details={},
            maker="Ann@Contoso.com",
        )
        machine = Found(
            external_id="ws/serving-endpoints/2",
            name="Batch scorer",
            kind="Agent on Model Serving",
            part="",
            details={},
            maker="0a1b2c3d-1111-2222-3333-444455556666",  # a service principal
        )
        with rt.db.session() as s:
            platforms.record_inventory(
                s, "databricks", Inventory(found=[found, machine], read={""})
            )  # fmt: skip
        claims = agent(client, "claims-helper")
        assert claims["makers"] == [
            {
                "email": "ann@contoso.com",
                "roles": ["creator"],
                "source": "databricks",
                "name": None,
                "known": True,
                "looked_up": False,
                "enabled": None,
                "left": False,
                "left_at": None,
            }
        ]
        assert claims["suggested_owner"] == "ann@contoso.com"
        assert agent(client, "batch-scorer")["makers"] == []


# ------------------------------------------------------------- looked up in Graph


class FakeDirectory:
    """Entra ID's token endpoint, and Graph's users answered in batches."""

    def __init__(self) -> None:
        self.roles: tuple[str, ...] = ("User.Read.All",)
        self.users = {
            DANA: {"id": DANA, "displayName": "Dana Owner", "mail": "dana@contoso.com",
                   "userPrincipalName": "dana@contoso.com", "accountEnabled": True},
            FRANK: {"id": FRANK, "displayName": "Frank Builder", "mail": None,
                    "userPrincipalName": "frank@contoso.com", "accountEnabled": True},
        }  # fmt: skip
        self.batches: list[list[str]] = []
        self.by_email: list[str] = []
        self.refuse = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(
                200, json={"access_token": app_token(*self.roles), "expires_in": 3599}
            )
        assert request.url.path == "/v1.0/$batch" and request.method == "POST"
        body = json.loads(request.content)
        assert len(body["requests"]) <= 20
        self.batches.append([r["url"] for r in body["requests"]])
        answers = []
        for item in body["requests"]:
            if item["url"].startswith("/users?"):  # by email address
                where = unquote(item["url"].split("$filter=")[1].split("&")[0])
                email = where.split("'")[1]
                self.by_email.append(email)
                users = [
                    {
                        k: v
                        for k, v in u.items()
                        if k != "accountEnabled" or "accountEnabled" in item["url"]
                    }
                    for u in self.users.values()
                    if email in (u.get("mail"), u.get("userPrincipalName"))
                ]
                answers.append({"id": item["id"], "status": 200, "body": {"value": users}})
                continue
            oid = item["url"].split("/users/")[1].split("?")[0]
            if self.refuse:
                answers.append(
                    {
                        "id": item["id"],
                        "status": 403,
                        "body": {
                            "error": {
                                "code": "Authorization_RequestDenied",
                                "message": "Insufficient privileges to complete the operation.",
                            }
                        },
                    }
                )
            elif oid in self.users:
                user = dict(self.users[oid])
                if "accountEnabled" not in item["url"]:
                    user.pop("accountEnabled")
                answers.append({"id": item["id"], "status": 200, "body": user})
            else:
                answers.append(
                    {
                        "id": item["id"],
                        "status": 404,
                        "body": {
                            "error": {"code": "Request_ResourceNotFound", "message": "Not found."}
                        },
                    }
                )
        return httpx.Response(200, json={"responses": answers})  # fmt: skip


@pytest.fixture
def directory() -> FakeDirectory:
    return FakeDirectory()


@pytest.fixture
def ms(settings: Settings, directory: FakeDirectory) -> Iterator[TestClient]:
    configured = settings.with_overrides(
        m365_tenant_id=TENANT, m365_client_id="agentgov-app", m365_client_secret="m365-secret"
    )
    runtime = Runtime(
        configured, m365_http=httpx.Client(transport=httpx.MockTransport(directory.handle))
    )
    with TestClient(create_app(configured, runtime=runtime, background=False)) as client:
        yield client


class TestLookedUpInGraph:
    def test_an_import_looks_its_makers_up(self, ms, directory) -> None:
        counts = import_studio(
            ms, studio("bot-sales", "Sales Helper"), studio("bot-hr", "HR FAQ", owner=NOBODY)
        )
        assert counts["people"] == {"found": 2, "not_found": 1, "left": 0}
        assert all("accountEnabled" in url for url in directory.batches[0])
        sales = agent(ms, "sales-helper")
        assert [(m["name"], m["email"]) for m in sales["makers"]] == [
            ("Dana Owner", "dana@contoso.com"),
            ("Frank Builder", "frank@contoso.com"),
        ]
        hr = agent(ms, "hr-faq")
        # Its owner isn't a user in the directory: its maker is suggested.
        assert (hr["makers"][0]["looked_up"], hr["makers"][0]["known"]) == (True, False)
        assert hr["suggested_owner"] == "frank@contoso.com"
        state = {c["key"]: c for c in ms.get("/v1/platforms", headers=ADMIN).json()["connections"]}
        assert state["entra-users"]["status"] == "ok"
        # Looked up: the next import doesn't look them up again.
        assert "people" not in import_studio(ms, studio("bot-sales", "Sales Helper"))
        assert len(directory.batches) == 1

    def test_with_basic_read_it_doesnt_ask_whose_account_is_enabled(self, ms, directory) -> None:
        directory.roles = ("User.ReadBasic.All",)
        import_studio(ms, studio("bot-sales", "Sales Helper"))
        assert not any("accountEnabled" in url for url in directory.batches[0])
        assert {m["enabled"] for m in agent(ms, "sales-helper")["makers"]} == {None}

    def test_someone_who_leaves(self, ms, directory) -> None:
        import_studio(ms, studio("bot-sales", "Sales Helper"))
        rt = ms.app.state.rt
        del directory.users[DANA]
        assert rt.sync_people() == {"found": 0, "not_found": 0, "left": 0}  # read this week
        with rt.db.session() as s:
            s.execute(update(Person).values(checked_at=ids.utcnow() - timedelta(days=8)))
        assert rt.sync_people(actor="admin:test") == {"found": 1, "not_found": 0, "left": 1}
        dana = agent(ms, "sales-helper")["makers"][0]
        assert dana["left"] is True and dana["left_at"]
        assert agent(ms, "sales-helper")["suggested_owner"] == "frank@contoso.com"
        [entry] = ms.get("/v1/ledger", params={"type": "person.left"}, headers=ADMIN).json()
        assert entry["details"] == {"name": "Dana Owner", "email": "dana@contoso.com"}

    def test_a_refusal_says_what_it_takes(self, ms, directory) -> None:
        directory.refuse = True
        counts = import_studio(ms, studio("bot-sales", "Sales Helper"))
        assert counts["created"] == 1 and "User.Read.All" in counts["people"]["error"]
        state = {c["key"]: c for c in ms.get("/v1/platforms", headers=ADMIN).json()["connections"]}
        assert state["entra-users"]["status"] == "failing"
        refused = ms.post("/v1/platforms/entra-users/sync", headers=ADMIN)
        assert refused.status_code == 502

    def test_turned_off_nobody_is_looked_up(self, ms, directory) -> None:
        ms.put("/v1/features/entra-users", json={"mode": "off"}, headers=ADMIN)
        assert "people" not in import_studio(ms, studio("bot-sales", "Sales Helper"))
        assert directory.batches == []

    def test_twenty_to_a_batch(self) -> None:
        sent: list[dict[str, Any]] = []

        def send(url: str, body: dict[str, Any]) -> dict[str, Any]:
            sent.append(body)
            answers = [{"id": r["id"], "status": 404} for r in body["requests"]]
            answers[0] = {"id": "0", "status": 429}  # throttled: neither found nor missing
            return {"responses": answers}

        wanted = [f"11111111-aaaa-bbbb-cccc-{n:012d}" for n in range(45)]
        found, missing = lookup_users(send, "https://graph", [*wanted, "nope"], enabled=True)
        assert [len(b["requests"]) for b in sent] == [20, 20, 5]
        assert found == [] and len(missing) == 42
        with pytest.raises(PlatformError, match=r"User\.Read\.All"):
            lookup_users(
                lambda url, body: {"responses": [{"id": "0", "status": 403, "body": {}}]},
                "https://graph",
                wanted[:1],
                enabled=False,
            )


# ------------------------------------------------------------------- adopting


@pytest.fixture
def named(client: TestClient) -> TestClient:
    """Three Copilot Studio agents: two whose makers AgentGov knows, one whose it doesn't."""
    import_studio(
        client,
        studio("bot-sales", "Sales Helper"),
        studio("bot-hr", "HR FAQ", owner=EVE, creator=DANA),
        studio("bot-it", "IT Helpdesk", owner=NOBODY, creator=NOBODY),
    )
    upload(client, USERS).raise_for_status()
    return client


def adopt(client: TestClient, body: dict[str, Any], headers=ADMIN) -> httpx.Response:
    return client.post("/v1/agents/adopt", json=body, headers=headers)


class TestAdopting:
    def test_many_at_once_with_their_makers(self, named) -> None:
        names = ["sales-helper", "hr-faq", "it-helpdesk"]
        out = adopt(named, {"agents": names, "makers": True, "reason": "first review"})
        assert out.status_code == 200, out.text
        assert [(a["agent"], a["owner"], a["sponsors"]) for a in out.json()["adopted"]] == [
            ("sales-helper", "dana@contoso.com", ["dana@contoso.com"]),
            ("hr-faq", "dana@contoso.com", ["dana@contoso.com"]),
        ]
        assert out.json()["left"] == [
            {"agent": "it-helpdesk", "why": "AgentGov doesn't know who made it: give it an owner"}
        ]
        sales = agent(named, "sales-helper")
        assert (sales["status"], sales["owner"]) == ("pending", "dana@contoso.com")
        # One left to review; then a team for those whose makers aren't known.
        named.post(
            "/v1/teams", json={"name": "ai-gov", "emails": ["gov@contoso.com"]}, headers=ADMIN
        ).raise_for_status()
        again = adopt(named, {"agents": names, "makers": True, "owner": "ai-gov"}).json()
        assert [a["owner"] for a in again["adopted"]] == ["ai-gov"]
        assert [x["why"] for x in again["left"]] == [
            "it isn't waiting to be adopted: it is pending"
        ] * 2
        entries = named.get("/v1/ledger", params={"type": "agent.adopt"}, headers=ADMIN).json()
        assert len(entries) == 3

    def test_their_makers_first_then_the_owner_given(self, named) -> None:
        out = adopt(
            named,
            {"agents": ["sales-helper", "it-helpdesk"], "makers": True,
             "owner": "carol@contoso.com", "sponsors": ["carol@contoso.com"]},
        ).json()  # fmt: skip
        assert [(a["owner"], a["sponsors"]) for a in out["adopted"]] == [
            ("dana@contoso.com", ["dana@contoso.com"]),
            ("carol@contoso.com", ["carol@contoso.com"]),
        ]

    def test_one_owner_for_all(self, named) -> None:
        out = adopt(
            named,
            {"agents": ["sales-helper", "it-helpdesk"], "owner": "carol@contoso.com",
             "sponsors": ["carol@contoso.com"]},
        ).json()  # fmt: skip
        assert {a["owner"] for a in out["adopted"]} == {"carol@contoso.com"}
        assert out["left"] == []

    def test_it_says_what_it_takes(self, named) -> None:
        from tests.test_api import key

        for body, says in (
            ({"agents": []}, "one at least"),
            ({"agents": "sales-helper", "makers": True}, "a list"),
            ({"agents": ["sales-helper"]}, "an owner, or their makers"),
            ({"agents": ["sales-helper"], "owner": 3}, "a team or a person"),
            ({"agents": ["sales-helper"], "makers": True, "sponsors": "x"}, "email addresses"),
        ):
            resp = adopt(named, body)
            assert resp.status_code == 422 and says in resp.text, (body, resp.text)
        out = adopt(named, {"agents": ["nope"], "makers": True}).json()
        assert out["left"] == [{"agent": "nope", "why": "there is no such agent"}]
        auditor = key(named, "auditor")
        assert (
            adopt(named, {"agents": ["sales-helper"], "makers": True}, auditor).status_code == 403
        )

    def test_the_cli(self, named, monkeypatch, tmp_path) -> None:
        bearer = ADMIN["Authorization"].removeprefix("Bearer ")
        monkeypatch.setattr(cli, "_client", lambda: _Shared(named, bearer))
        users = tmp_path / "users.csv"
        users.write_text(USERS)
        out = runner.invoke(cli.app, ["platforms", "import-users", str(users)])
        assert out.exit_code == 0, out.output
        assert "users.csv: 3 kept" in out.output and "3 of the 4 people" in out.output
        out = runner.invoke(
            cli.app, ["agents", "adopt", "--platform", "copilot-studio", "--makers"]
        )  # fmt: skip
        assert out.exit_code == 0, out.output
        assert "adopted sales-helper: owner dana@contoso.com" in out.output
        assert "left it-helpdesk: AgentGov doesn't know who made it" in out.output
        refused = runner.invoke(cli.app, ["agents", "adopt", "it-helpdesk"])
        assert refused.exit_code != 0 and "--owner" in refused.output


def test_microsoft_places_look_up_people(client) -> None:
    client.put("/v1/start", json={"places": ["aws"]}, headers=ADMIN).raise_for_status()
    modes = {
        f["key"]: f["mode"] for f in client.get("/v1/features", headers=ADMIN).json()["features"]
    }
    assert modes["entra-users"] == "off"
    client.put("/v1/start", json={"places": ["copilot-studio"]}, headers=ADMIN).raise_for_status()
    modes = {
        f["key"]: f["mode"] for f in client.get("/v1/features", headers=ADMIN).json()["features"]
    }
    assert modes["entra-users"] == "on"


def test_wanted_first_those_never_looked_up(client) -> None:
    import_studio(client, studio("bot-sales", "Sales Helper"))
    rt = client.app.state.rt
    with rt.db.session() as s:
        assert sorted(people.wanted(s)) == [DANA, FRANK]
        people.record_lookup(s, [{"id": DANA, "displayName": "Dana"}], [])
    with rt.db.session() as s:
        assert people.wanted(s) == [FRANK]
        assert people.wanted(s, ids.utcnow() + timedelta(days=8)) == [FRANK, DANA]


# ------------------------------------------------------------- people who leave


def owned(client: TestClient, owner: str, sponsors: list[str]) -> dict[str, Any]:
    """support-bot, active, owned and sponsored by people AgentGov names by email."""
    from tests.conftest import seed

    created = seed(client, sponsors=sponsors)
    resp = client.patch(f"/v1/agents/{created['id']}", json={"owner": owner}, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def open_of(client: TestClient, type_: str) -> list[dict[str, Any]]:
    return client.get("/v1/findings", params={"type": type_}, headers=ADMIN).json()


class TestPeopleWhoLeave:
    def test_owners_and_sponsors_are_looked_up_by_email(self, ms, directory) -> None:
        owned(ms, "dana@contoso.com", ["frank@contoso.com", "zoe@elsewhere.example"])
        rt = ms.app.state.rt
        counts = rt.sync_people(actor="admin:test")
        assert counts == {"found": 2, "not_found": 1, "left": 0}
        assert sorted(directory.by_email) == [
            "dana@contoso.com", "frank@contoso.com", "zoe@elsewhere.example"
        ]  # fmt: skip
        # Found, they are read again by ID; not found, they are asked again a week on.
        directory.by_email.clear()
        assert rt.sync_people(actor="admin:test")["found"] == 0
        assert directory.by_email == []

    def test_an_owner_who_leaves_is_flagged_and_passed_over(self, ms, directory) -> None:
        agent_ = owned(ms, "dana@contoso.com", ["frank@contoso.com"])
        rt = ms.app.state.rt
        rt.sync_people(actor="admin:test")
        del directory.users[DANA]
        with rt.db.session() as s:
            s.execute(update(Person).values(checked_at=ids.utcnow() - timedelta(days=8)))
        assert rt.sync_people(actor="admin:test")["left"] == 1
        ms.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        [flagged] = open_of(ms, "agent.owner_left")
        assert flagged["severity"] == "medium"
        assert flagged["description"].startswith("dana@contoso.com has left")
        assert agent(ms, agent_["name"])["left"] == [
            {"name": "dana@contoso.com", "role": "owner", "how": "left", "at": ANY}
        ]
        # Its issues go to its sponsors: the owner who left is passed over.
        rt.run_issues()
        assert finding_level(ms, flagged["id"]) == ("sponsors", ["frank@contoso.com"])
        # A new owner: the next scan resolves it.
        ms.patch(f"/v1/agents/{agent_['id']}", json={"owner": "frank@contoso.com"}, headers=ADMIN)
        ms.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        assert open_of(ms, "agent.owner_left") == []

    def test_a_disabled_account_counts_as_gone(self, ms, directory) -> None:
        directory.users[FRANK]["accountEnabled"] = False
        owned(ms, "dana@contoso.com", ["frank@contoso.com", "dana@contoso.com"])
        ms.app.state.rt.sync_people(actor="admin:test")
        ms.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        [flagged] = open_of(ms, "agent.sponsor_left")
        # One of two sponsors: low.
        assert flagged["severity"] == "low"
        assert flagged["description"] == "frank@contoso.com's account is disabled."
        assert open_of(ms, "agent.owner_left") == []

    def test_a_list_of_users_says_so_without_graph(self, client) -> None:
        owned(client, "dana@contoso.com", ["eve@contoso.com"])
        # Eve's account is disabled in the list: she is the only sponsor.
        upload(client, USERS).raise_for_status()
        client.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        [flagged] = open_of(client, "agent.sponsor_left")
        assert flagged["severity"] == "medium" and flagged["title"].startswith("Every sponsor")


def finding_level(client: TestClient, fid: str) -> tuple[str, list[str]]:
    f = client.get(f"/v1/findings/{fid}", headers=ADMIN).json()
    return f["level"], f["assignees"]
