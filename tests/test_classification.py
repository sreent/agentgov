"""Each agent's classification under the EU AI Act, and the classification register
(docs/evidence.md#a-classification-register)."""

from __future__ import annotations

import csv
import io
import zipfile
from typing import Any

import httpx
from fastapi.testclient import TestClient

from tests.conftest import ADMIN, seed
from tests.test_api import key
from tests.test_people import import_studio, studio

MINIMAL = {"category": "minimal", "role": "deployer", "purpose": "Answers staff questions"}


def classify(
    client: TestClient, ref: str, body: dict[str, Any], headers: dict[str, str] = ADMIN
) -> httpx.Response:
    return client.put(f"/v1/agents/{ref}/classification", json=body, headers=headers)


def classified(client: TestClient) -> list[dict[str, Any]]:
    entries = client.get("/v1/ledger", params={"type": "agent.classified"}, headers=ADMIN)
    return [e["details"] for e in entries.json()]


def control(client: TestClient, cid: str = "Art. 5, 6, 50") -> dict[str, Any]:
    report = client.get("/v1/evidence/report", params={"framework": "eu-ai-act"}, headers=ADMIN)
    return next(c for c in report.json()["controls"] if c["id"] == cid)


class TestClassifying:
    def test_who_when_and_what_it_was(self, client) -> None:
        seed(client)
        resp = classify(client, "support-bot", MINIMAL)
        assert resp.status_code == 200, resp.text
        c = resp.json()["classification"]
        assert (c["category"], c["role"], c["purpose"], c["by"]) == (
            "minimal",
            "deployer",
            "Answers staff questions",
            "admin:bootstrap",
        )
        assert c["at"]
        # The same again changes nothing.
        classify(client, "support-bot", MINIMAL).raise_for_status()
        assert len(classified(client)) == 1
        high = {"category": "high-risk", "role": "deployer", "basis": "Annex III 5(b): credit"}
        classify(client, "support-bot", high).raise_for_status()
        latest = classified(client)[0]
        assert (latest["from"]["category"], latest["to"]["category"]) == ("minimal", "high-risk")
        cleared = client.delete("/v1/agents/support-bot/classification", headers=ADMIN)
        assert cleared.json()["classification"] is None
        assert classified(client)[0]["to"] is None

    def test_it_says_what_it_takes(self, client) -> None:
        seed(client)
        for body, says in (
            ({}, "category is one of"),
            ({"category": "high-risk", "role": "deployer"}, "say why it is high-risk"),
            ({"category": "minimal", "role": "user"}, "role is one of"),
            ({**MINIMAL, "risk": "low"}, "unknown field"),
            ({**MINIMAL, "purpose": "x" * 2001}, "2000 characters"),
        ):
            resp = classify(client, "support-bot", body)
            assert resp.status_code == 422 and says in resp.json()["detail"], (body, resp.text)

    def test_who_may(self, client) -> None:
        seed(client)
        import_studio(client, studio("bot-sales", "Sales Helper"))
        approver = key(client, "approver", "dana")
        assert classify(client, "support-bot", MINIMAL, approver).status_code == 200
        for role in ("auditor", "secops"):
            refused = classify(client, "support-bot", MINIMAL, key(client, role))
            assert refused.status_code == 403, role
        # Approvers classify many at once, and do nothing else to them.
        many = {"action": "classify", "agents": ["support-bot", "sales-helper"], "fields": MINIMAL}
        out = client.post("/v1/agents/bulk", json=many, headers=approver)
        assert out.status_code == 200 and len(out.json()["done"]) == 2, out.text
        block = {"action": "block", "agents": ["support-bot"]}
        assert client.post("/v1/agents/bulk", json=block, headers=approver).status_code == 403
        empty = client.post(
            "/v1/agents/bulk", json={"action": "classify", "agents": ["support-bot"]}, headers=ADMIN
        )
        assert empty.status_code == 422 and "how to classify" in empty.json()["detail"]


class TestTheRegister:
    def test_in_the_report_and_the_pack(self, client) -> None:
        seed(client)
        import_studio(client, studio("bot-sales", "Sales Helper"))
        rows = client.get("/v1/evidence/register", headers=ADMIN).json()
        assert {r["agent"]: r["category"] for r in rows} == {
            "support-bot": None,
            "sales-helper": None,
        }
        assert control(client)["status"] == "not_set_up"
        classify(client, "support-bot", MINIMAL).raise_for_status()
        art6 = control(client)
        assert art6["status"] == "partly"
        assert art6["gaps"] == ["1 agent(s) not classified, 1 of them found and not reviewed yet."]
        classify(client, "sales-helper", MINIMAL).raise_for_status()
        assert control(client)["status"] == "in_place"
        nist = client.get(
            "/v1/evidence/report", params={"framework": "nist-ai-rmf"}, headers=ADMIN
        ).json()
        assert any(c["id"] == "MAP 1.1" and c["status"] == "in_place" for c in nist["controls"])
        # Active, and a prohibited practice: someone must look.
        banned = {"category": "prohibited", "role": "deployer", "basis": "Social scoring"}
        classify(client, "support-bot", banned).raise_for_status()
        art6 = control(client)
        assert art6["status"] == "attention" and "support-bot" in art6["gaps"][-1]
        pack = zipfile.ZipFile(io.BytesIO(client.get("/v1/evidence/pack", headers=ADMIN).content))
        sheet = list(csv.DictReader(io.StringIO(pack.read("register.csv").decode())))
        assert {r["agent"]: r["category"] for r in sheet} == {
            "support-bot": "prohibited",
            "sales-helper": "minimal",
        }
        assert "register.json" in pack.namelist()

    def test_manifests_carry_it(self, client) -> None:
        seed(client)
        classify(client, "support-bot", MINIMAL).raise_for_status()
        exported = client.get("/v1/export", headers=ADMIN).text
        assert "classification:" in exported and "category: minimal" in exported
        headers = {**ADMIN, "content-type": "application/yaml"}
        again = client.post("/v1/apply", content=exported, headers=headers).json()["results"]
        assert {r["action"] for r in again if r["kind"] == "Agent"} == {"unchanged"}
        changed = exported.replace("category: minimal", "category: transparency")
        out = client.post("/v1/apply", content=changed, headers=headers).json()["results"]
        assert {r["action"] for r in out if r["kind"] == "Agent"} == {"configured"}
        agent = client.get("/v1/agents/support-bot", headers=ADMIN).json()
        assert agent["classification"]["category"] == "transparency"


def test_the_cli(client, monkeypatch) -> None:
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    seed(client)
    import_studio(client, studio("bot-sales", "Sales Helper"))
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
    out = runner.invoke(
        cli.app,
        ["agents", "classify", "support-bot", "--category", "minimal", "--role", "deployer"],
    )
    assert out.exit_code == 0 and "classified minimal" in out.output, out.output
    out = runner.invoke(
        cli.app,
        [
            "agents", "classify", "support-bot", "sales-helper",
            "--category", "transparency", "--role", "deployer", "--purpose", "Answers questions",
        ],
    )  # fmt: skip
    assert out.exit_code == 0 and "agent/sales-helper: classified" in out.output, out.output
    table = runner.invoke(cli.app, ["evidence", "register"]).output
    assert "transparency" in table and "Answers questions" in table
    out = runner.invoke(cli.app, ["agents", "classify", "sales-helper", "--clear"])
    assert "not classified" in out.output
    sheet = runner.invoke(cli.app, ["evidence", "register", "--csv"]).stdout
    rows = {r["agent"]: r["category"] for r in csv.DictReader(io.StringIO(sheet))}
    assert rows == {"support-bot": "transparency", "sales-helper": ""}
