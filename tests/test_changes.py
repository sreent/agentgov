"""Each edit's ledger entry says what it changed, from what to what
(agentgov.registry.versions.changes)."""

from __future__ import annotations

from typing import Any

from starlette.testclient import TestClient

from tests.conftest import ADMIN, seed


def last(client: TestClient, type_: str) -> dict[str, Any]:
    entries = client.get("/v1/ledger", params={"type": type_}, headers=ADMIN).json()
    return entries[0]["details"]  # type: ignore[no-any-return]


def test_an_agents_edit(client: TestClient) -> None:
    created = seed(client, sponsors=["alice@example.com"])
    client.patch(
        f"/v1/agents/{created['id']}",
        json={"owner": "ops", "sponsors": ["alice@example.com", "bob@example.com"]},
        headers=ADMIN,
    ).raise_for_status()
    details = last(client, "agent.updated")
    assert details["changes"]["owner"] == {"from": "cx", "to": "ops"}
    assert details["changes"]["sponsors"] == {
        "from": ["alice@example.com"],
        "to": ["alice@example.com", "bob@example.com"],
    }
    # Only what the edit changed: not its version, nor when.
    assert set(details["changes"]) == {"owner", "sponsors"}


def test_a_blueprint_and_a_team(client: TestClient) -> None:
    seed(client)
    client.patch(
        "/v1/blueprints/support", json={"risk_tier": "high"}, headers=ADMIN
    ).raise_for_status()
    assert last(client, "blueprint.updated")["changes"]["risk_tier"]["to"] == "high"
    client.post("/v1/teams", json={"name": "cx", "emails": ["cx@example.com"]}, headers=ADMIN)
    client.patch("/v1/teams/cx", json={"emails": ["cx-team@example.com"]}, headers=ADMIN)
    assert last(client, "team.updated")["changes"]["emails"] == {
        "from": ["cx@example.com"],
        "to": ["cx-team@example.com"],
    }


def test_long_text_by_its_length_and_hash(client: TestClient) -> None:
    created = seed(client)
    long = "x" * 1500
    client.patch(f"/v1/agents/{created['id']}", json={"description": long}, headers=ADMIN)
    change = last(client, "agent.updated")["changes"]["description"]
    assert change["from"] == "" and change["to"]["length"] == 1500
    assert len(change["to"]["sha256"]) == 64


def test_a_policy_keeps_each_version_in_force(client: TestClient) -> None:
    rego = 'package agentgov.custom.extra\n\ndeny contains msg if { false; msg := "no" }\n'
    client.post(
        "/v1/policies", json={"name": "extra", "rego": rego}, headers=ADMIN
    ).raise_for_status()
    newer = rego.replace('"no"', '"never"')
    client.put("/v1/policies/extra", json={"rego": newer}, headers=ADMIN).raise_for_status()
    details = last(client, "policy.updated")
    assert details["rego"] == newer
    assert details["changes"]["rego"] == {"from": rego, "to": newer}
    client.put(
        "/v1/policies/extra", json={"rego": newer, "enabled": False}, headers=ADMIN
    ).raise_for_status()
    details = last(client, "policy.updated")
    assert "rego" not in details and details["changes"] == {"enabled": {"from": True, "to": False}}
