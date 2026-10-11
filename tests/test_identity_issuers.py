"""Identity issuers and agents' workload identities: agents that authenticate with an
identity they already have instead of a client secret (agentgov.registry.identity_issuers).
Keycloak's side is in tests/test_keycloak.py."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import cli
from agentgov.config import Settings
from agentgov.models import Agent, Finding, LedgerEntry
from agentgov.opa import bundle
from agentgov.registry import agents, blueprints, identity_issuers, manifests, posture
from agentgov.registry.errors import Conflict, InvalidTransition, NotFound, ValidationError
from tests.conftest import ADMIN
from tests.test_api import key
from tests.test_cli import _Shared, ok, runner

CLUSTER = {"name": "cluster", "kind": "kubernetes", "issuer": "https://k8s.example.com"}
SPIRE = {
    "name": "spire",
    "kind": "spiffe",
    "issuer": "spiffe://example.org",
    "keys_url": "https://spire.example.org/bundle",
}
ENTRA = {
    "name": "entra",
    "kind": "oidc",
    "issuer": "https://login.microsoftonline.com/tid/v2.0",
    "audience": "api://agentgov",
}
SA = "system:serviceaccount:agents:bot"


@pytest.fixture
def issuers(rt) -> None:
    with rt.db.session() as s:
        for spec in (CLUSTER, SPIRE, ENTRA):
            identity_issuers.create(s, spec, actor="admin:a")


def _register(
    s: Session,
    settings: Settings,
    name: str,
    identity: dict[str, str] | None = None,
    *,
    approve: bool = True,
    **data: Any,
) -> Agent:
    body = {"name": name, "sponsors": ["a"], **data}
    if identity is not None:
        body["workload_identity"] = identity
    return agents.register(s, settings, body, actor="a", approve=approve)


class TestIssuers:
    def test_validation(self, rt) -> None:
        cases = [
            ({"name": "x"}, "kind .* and issuer are required"),
            ({"name": "x", "kind": "saml", "issuer": "https://a"}, "kind must be one of"),
            ({"name": "x", "kind": "kubernetes", "issuer": "k8s"}, "issuer must be an http"),
            ({"name": "x", "kind": "oidc", "issuer": ""}, "issuer is required"),
            ({"name": "x", "kind": "spiffe", "issuer": "https://a"}, "its trust domain"),
            ({"name": "x", "kind": "spiffe", "issuer": "spiffe://Example.org"}, "trust domain"),
            ({"name": "x", "kind": "spiffe", "issuer": "spiffe://a.org/x"}, "trust domain"),
            ({"name": "x", "kind": "spiffe", "issuer": "spiffe://a.org"}, "needs keys_url"),
            (
                {"name": "x", "kind": "kubernetes", "issuer": "https://a", "keys_url": "ftp://a"},
                "keys_url must be an http",
            ),
            (
                {"name": "x", "kind": "kubernetes", "issuer": "https://a", "audience": "x"},
                "OpenID Connect issuers only",
            ),
            (
                {"name": "x", "kind": "kubernetes", "issuer": "https://a", "allow_reuse": True},
                "OpenID Connect issuers only",
            ),
            ({"name": "Bad Name", "kind": "oidc", "issuer": "https://a"}, "lowercase"),
        ]
        for data, message in cases:
            with pytest.raises(ValidationError, match=message), rt.db.session() as s:
                identity_issuers.create(s, data, actor="a")

    def test_each_kind_is_presented_its_own_way(self, rt, issuers) -> None:
        with rt.db.session() as s:
            shown = {i.name: identity_issuers.to_dict(i) for i in identity_issuers.list_all(s)}
        assert shown["cluster"]["keycloak_alias"] == "agentgov-cluster"
        assert shown["cluster"]["assertion_type"] == identity_issuers.JWT_BEARER
        assert shown["entra"]["assertion_type"] == identity_issuers.JWT_BEARER
        # SPIFFE's JWT-SVIDs have their own client assertion type.
        assert shown["spire"]["assertion_type"] == identity_issuers.JWT_SPIFFE
        assert shown["entra"]["audience"] == "api://agentgov"
        assert shown["cluster"]["sync"] == {"synced_at": None, "error": None}

    def test_names_and_issuers_are_unique_and_kinds_fixed(self, rt, issuers) -> None:
        with pytest.raises(Conflict, match="already exists"), rt.db.session() as s:
            identity_issuers.create(s, {**CLUSTER, "issuer": "https://b"}, actor="a")
        # One issuer, one identity provider in Keycloak.
        with pytest.raises(Conflict, match="cluster' already has issuer"), rt.db.session() as s:
            identity_issuers.create(s, {**CLUSTER, "name": "again"}, actor="a")
        with pytest.raises(Conflict, match="already has issuer"), rt.db.session() as s:
            entra = identity_issuers.get(s, "entra")
            identity_issuers.update(s, entra, {"issuer": CLUSTER["issuer"]}, actor="a")
        with pytest.raises(ValidationError, match="kind can't change"), rt.db.session() as s:
            entra = identity_issuers.get(s, "entra")
            identity_issuers.update(s, entra, {"kind": "kubernetes"}, actor="a")
        with rt.db.session() as s:
            entra = identity_issuers.get(s, "entra")
            assert identity_issuers.update(s, entra, {"kind": "oidc"}, actor="a") == []
            changed = identity_issuers.update(
                s,
                entra,
                {"keys_url": "https://login.example.com/keys/", "allow_reuse": True},
                actor="a",
            )
            assert changed == ["keys_url", "allow_reuse"]
            assert entra.keys_url == "https://login.example.com/keys"
            assert identity_issuers.update(s, entra, {"audience": ""}, actor="a") == ["audience"]
            assert entra.audience is None
        with pytest.raises(NotFound), rt.db.session() as s:
            identity_issuers.get(s, "nowhere")

    def test_blocking_and_deleting_are_recorded(self, rt, settings, issuers) -> None:
        with rt.db.session() as s:
            cluster = identity_issuers.get(s, "cluster")
            _register(s, settings, "bot", {"issuer": "cluster", "subject": SA})
            identity_issuers.set_status(s, cluster, "block", actor="admin:a")
            assert cluster.status == "blocked"
            with pytest.raises(InvalidTransition):
                identity_issuers.set_status(s, cluster, "block", actor="admin:a")
            identity_issuers.set_status(s, cluster, "unblock", actor="admin:a")
            with pytest.raises(InvalidTransition):
                identity_issuers.set_status(s, cluster, "unblock", actor="admin:a")
            # Not while an agent authenticates with it.
            with pytest.raises(Conflict, match="workload identity of 1 agent"):
                identity_issuers.delete(s, cluster, actor="admin:a")
            agents.update(s, agents.get(s, "bot"), {"workload_identity": None}, actor="a")
            identity_issuers.delete(s, cluster, actor="admin:a")
        with rt.db.session() as s:
            entries = s.scalars(
                select(LedgerEntry).where(LedgerEntry.resource == "identity-issuer/cluster")
            ).all()
            assert [e.type for e in entries] == [
                "identity_issuer.registered",
                "identity_issuer.block",
                "identity_issuer.unblock",
                "identity_issuer.deleted",
            ]
            assert entries[1].severity == "warning" and entries[1].details["agents"] == 1


class TestAgents:
    def test_an_agent_names_its_subject_at_an_issuer(self, rt, settings, issuers) -> None:
        with rt.db.session() as s:
            bot = _register(s, settings, "bot", {"issuer": "cluster", "subject": SA})
            shown = agents.to_dict(bot)
            assert shown["workload_identity"] == {"issuer": "cluster", "subject": SA}
            assert shown["identity"]["method"] == "workload-identity"
            plain = _register(s, settings, "plain")
            assert agents.to_dict(plain)["workload_identity"] is None
            assert agents.to_dict(plain)["identity"]["method"] == "client-secret"
            # SPIFFE IDs are in the issuer's trust domain.
            spiffe = {"issuer": "spire", "subject": "spiffe://example.org/ns/agents/sa/bot"}
            agents.update(s, plain, {"workload_identity": spiffe}, actor="a")
            assert agents.workload_identity(plain) == spiffe

    @pytest.mark.parametrize(
        ("identity", "error", "message"),
        [
            ({"issuer": "nowhere", "subject": SA}, NotFound, "nowhere"),
            ("cluster:" + SA, ValidationError, "workload_identity is"),
            ({"issuer": "cluster", "subject": SA, "x": 1}, ValidationError, "workload_identity is"),
            ({"issuer": "cluster", "subject": " "}, ValidationError, "subject is the agent's"),
            ({"issuer": "cluster", "subject": "x" * 513}, ValidationError, "subject is"),
            (
                {"issuer": "spire", "subject": "spiffe://other.org/bot"},
                ValidationError,
                "looks like spiffe://example.org/<path>",
            ),
        ],
    )
    def test_invalid_identities(self, rt, settings, issuers, identity, error, message) -> None:
        with pytest.raises(error, match=message), rt.db.session() as s:
            _register(s, settings, "bot", identity)

    def test_one_agent_per_identity(self, rt, settings, issuers) -> None:
        with rt.db.session() as s:
            _register(s, settings, "bot", {"issuer": "cluster", "subject": SA})
        with pytest.raises(Conflict, match="'bot' already has this"), rt.db.session() as s:
            _register(s, settings, "twin", {"issuer": "cluster", "subject": SA})
        with rt.db.session() as s:
            # The same subject at another issuer is another identity.
            _register(s, settings, "twin", {"issuer": "entra", "subject": SA})
            same = {"workload_identity": {"issuer": "cluster", "subject": SA}}
            assert agents.update(s, agents.get(s, "bot"), same, actor="a") == []

    def test_blueprints_can_require_one(self, rt, settings, issuers) -> None:
        with rt.db.session() as s:
            secretless = {"name": "secretless", "require_workload_identity": True}
            blueprints.create(s, secretless, actor="a")
            blueprints.create(s, {"name": "open"}, actor="a")
        with pytest.raises(Conflict, match="requires a workload identity"), rt.db.session() as s:
            _register(s, settings, "bot", blueprint="secretless")
        with rt.db.session() as s:
            identity = {"issuer": "cluster", "subject": SA}
            _register(s, settings, "bot", identity, blueprint="secretless")
            _register(s, settings, "plain", blueprint="open")
            pending = _register(s, settings, "later", blueprint="secretless", approve=False)
            assert pending.status == "pending"  # it can wait for one
        with pytest.raises(Conflict, match="no client secret"), rt.db.session() as s:
            agents.update(s, agents.get(s, "bot"), {"workload_identity": None}, actor="a")
        with pytest.raises(Conflict, match="no client secret"), rt.db.session() as s:
            agents.update(s, agents.get(s, "plain"), {"blueprint": "secretless"}, actor="a")
        with rt.db.session() as s:
            assert blueprints.to_dict(blueprints.get(s, "secretless"))["require_workload_identity"]
            assert not blueprints.to_dict(blueprints.get(s, "open"))["require_workload_identity"]

    def test_posture_flags_secrets_no_longer_allowed(self, rt, settings, issuers) -> None:
        with rt.db.session() as s:
            bp = blueprints.create(s, {"name": "bp"}, actor="a")
            _register(s, settings, "plain", blueprint="bp")
            blueprints.update(s, bp, {"require_workload_identity": True}, actor="a")
            posture.scan(s, settings)
        with rt.db.session() as s:
            finding = s.scalar(select(Finding).where(Finding.type == "agent.no_workload_identity"))
            assert finding is not None and finding.status == "open"
            assert "requires a workload identity" in finding.description
            identity = {"issuer": "cluster", "subject": SA}
            agents.update(s, agents.get(s, "plain"), {"workload_identity": identity}, actor="a")
            posture.scan(s, settings)
        with rt.db.session() as s:
            finding = s.scalar(select(Finding).where(Finding.type == "agent.no_workload_identity"))
            assert finding is not None and finding.status == "resolved"

    def test_posture_flags_issuers_out_of_sync(self, rt, settings, issuers) -> None:
        with rt.db.session() as s:
            identity_issuers.get(s, "cluster").sync_error = "Keycloak refused it"
            spire = identity_issuers.get(s, "spire")
            spire.sync_error = "Keycloak refused it"
            identity_issuers.set_status(s, spire, "block", actor="a")
            posture.scan(s, settings)
        with rt.db.session() as s:
            found = {
                f.subject: f
                for f in s.scalars(
                    select(Finding).where(Finding.type == "identity_issuer.sync_error")
                )
            }
            cluster, spire = identity_issuers.get(s, "cluster"), identity_issuers.get(s, "spire")
            assert found[cluster.id].severity == "medium"
            # A block that hasn't reached Keycloak leaves its agents signing in.
            assert found[spire.id].severity == "high"
            assert found[spire.id].description == "Keycloak refused it"
            cluster.sync_error = spire.sync_error = None
            posture.scan(s, settings)
        with rt.db.session() as s:
            statuses = s.scalars(
                select(Finding.status).where(Finding.type == "identity_issuer.sync_error")
            ).all()
            assert set(statuses) == {"resolved"}

    def test_opa_knows_how_each_agent_authenticates(self, rt, settings, issuers) -> None:
        with rt.db.session() as s:
            bot = _register(s, settings, "bot", {"issuer": "cluster", "subject": SA})
            plain = _register(s, settings, "plain")
            snapshot = bundle.registry_snapshot(s)
            assert snapshot["agents"][bot.id]["workload_identity"] == {
                "issuer": "cluster",
                "subject": SA,
            }
            assert snapshot["agents"][plain.id]["workload_identity"] is None


class TestApi:
    def test_api_and_roles(self, client) -> None:
        auditor = key(client, "auditor")
        assert client.post("/v1/identity-issuers", json=CLUSTER, headers=auditor).status_code == 403
        created = client.post("/v1/identity-issuers", json=CLUSTER, headers=ADMIN)
        assert created.status_code == 201
        assert (created.json()["status"], created.json()["agents"]) == ("approved", 0)
        again = client.post("/v1/identity-issuers", json=CLUSTER, headers=ADMIN)
        assert again.status_code == 409
        bad = client.post("/v1/identity-issuers", json={**SPIRE, "keys_url": None}, headers=ADMIN)
        assert bad.status_code == 422 and "bundle endpoint" in bad.json()["detail"]
        bot = {
            "name": "bot",
            "sponsors": ["a"],
            "workload_identity": {"issuer": "cluster", "subject": SA},
        }
        client.post("/v1/agents", json=bot, headers=ADMIN).raise_for_status()
        [listed] = client.get("/v1/identity-issuers", headers=auditor).json()
        assert (listed["name"], listed["agents"]) == ("cluster", 1)
        assert client.get("/v1/identity-issuers/cluster", headers=auditor).json()["agents"] == 1
        patched = client.patch(
            "/v1/identity-issuers/cluster", json={"description": "prod"}, headers=ADMIN
        )
        assert patched.json()["description"] == "prod"
        blocked = client.post("/v1/identity-issuers/cluster/block", headers=ADMIN)
        assert blocked.json()["status"] == "blocked"
        assert client.post("/v1/identity-issuers/cluster/block", headers=ADMIN).status_code == 409
        assert client.post("/v1/identity-issuers/cluster/explode", headers=ADMIN).status_code == 404
        assert client.delete("/v1/identity-issuers/cluster", headers=ADMIN).status_code == 409
        agent = client.get("/v1/agents/bot", headers=ADMIN).json()
        assert agent["workload_identity"] == {"issuer": "cluster", "subject": SA}
        client.patch(
            "/v1/agents/bot", json={"workload_identity": None}, headers=ADMIN
        ).raise_for_status()
        assert client.delete("/v1/identity-issuers/cluster", headers=ADMIN).status_code == 204
        assert client.get("/v1/identity-issuers/cluster", headers=ADMIN).status_code == 404

    def test_the_feature_switch(self, client) -> None:
        listed = client.get("/v1/features", headers=ADMIN).json()
        features = {f["key"]: f for f in listed["features"]}
        assert listed["groups"]["identity"] == "Identity"
        assert features["workload-identity"]["mode"] == "on"
        assert features["workload-identity"]["group"] == "identity"


class TestManifestsAndCli:
    def test_apply_and_export(self, rt, settings) -> None:
        docs = [
            {
                "apiVersion": manifests.API_VERSION,
                "kind": "IdentityIssuer",
                "metadata": {"name": "entra"},
                "spec": {
                    "kind": "oidc",
                    "issuer": ENTRA["issuer"],
                    "audience": "api://agentgov",
                    "description": "Microsoft Entra Agent ID",
                },
            },
            {
                "apiVersion": manifests.API_VERSION,
                "kind": "Agent",
                "metadata": {"name": "bot"},
                "spec": {
                    "sponsors": ["a"],
                    "workload_identity": {"issuer": "entra", "subject": "f0e1d2c3"},
                },
            },
        ]
        # Issuers come before the agents that name them, in whatever order they're given.
        with rt.db.session() as s:
            results = manifests.apply(s, settings, list(reversed(docs)), actor="ci")
            assert [(r["kind"], r["action"]) for r in results] == [
                ("IdentityIssuer", "created"),
                ("Agent", "created"),
            ]
        with rt.db.session() as s:
            again = manifests.apply(s, settings, docs, actor="ci")
            assert {r["action"] for r in again} == {"unchanged"}
            blocked = {**docs[0], "spec": {**docs[0]["spec"], "status": "blocked"}}
            assert manifests.apply(s, settings, [blocked], actor="ci")[0]["action"] == "configured"
            assert identity_issuers.get(s, "entra").status == "blocked"
        with rt.db.session() as s:
            exported = {d["kind"]: d for d in manifests.export(s)}
        assert exported["IdentityIssuer"]["spec"] == {**docs[0]["spec"], "status": "blocked"}
        assert exported["Agent"]["spec"]["workload_identity"] == {
            "issuer": "entra",
            "subject": "f0e1d2c3",
        }
        with pytest.raises(ValidationError, match="approved or blocked"), rt.db.session() as s:
            bad = {**docs[0], "spec": {**docs[0]["spec"], "status": "pending"}}
            manifests.apply(s, settings, [bad], actor="ci")

    def test_cli(self, client, monkeypatch) -> None:
        def agentgov(*args: str):  # type: ignore[no-untyped-def]
            monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
            return runner.invoke(cli.app, list(args))

        out = ok(agentgov("issuers", "create", "cluster", "--kind", "kubernetes",
                          "--issuer", "https://k8s.example.com",
                          "--keys-url", "https://k8s.example.com/"))  # fmt: skip
        assert "cluster" in out and "approved" in out
        ok(agentgov("issuers", "create", "entra", "--kind", "oidc", "--issuer", ENTRA["issuer"],
                    "--audience", "api://agentgov", "--allow-reuse"))  # fmt: skip
        listed = ok(agentgov("issuers", "list"))
        assert "cluster" in listed and "waiting" in listed  # not in Keycloak yet
        entra = json.loads(ok(agentgov("issuers", "get", "entra")))
        assert (entra["audience"], entra["allow_reuse"]) == ("api://agentgov", True)
        ok(agentgov("issuers", "update", "entra", "--audience", "", "--no-reuse"))
        entra = json.loads(ok(agentgov("issuers", "get", "entra")))
        assert (entra["audience"], entra["allow_reuse"]) == (None, False)
        assert agentgov("issuers", "update", "entra").exit_code != 0  # nothing to change

        ok(agentgov("blueprints", "create", "secretless", "--require-workload-identity"))
        assert client.get("/v1/blueprints/secretless", headers=ADMIN).json()[
            "require_workload_identity"
        ]
        ok(agentgov("agents", "create", "bot", "--blueprint", "secretless", "--sponsor", "a",
                    "--workload-identity", f"cluster:{SA}", "--approve"))  # fmt: skip
        bot = client.get("/v1/agents/bot", headers=ADMIN).json()
        # Split at the first colon: subjects have colons of their own.
        assert bot["workload_identity"] == {"issuer": "cluster", "subject": SA}
        assert bot["status"] == "active"
        assert agentgov("agents", "update", "bot", "--workload-identity", "cluster").exit_code == 2
        assert (
            "requires a workload identity"
            in agentgov("agents", "update", "bot", "--no-workload-identity").output
        )
        ok(agentgov("blueprints", "update", "secretless", "--allow-secrets"))
        ok(agentgov("agents", "update", "bot", "--no-workload-identity"))
        assert client.get("/v1/agents/bot", headers=ADMIN).json()["workload_identity"] is None

        assert "blocked" in ok(agentgov("issuers", "block", "cluster"))
        assert "approved" in ok(agentgov("issuers", "unblock", "cluster"))
        ok(agentgov("issuers", "delete", "cluster", "--yes"))
        assert "cluster" not in ok(agentgov("issuers", "list"))
