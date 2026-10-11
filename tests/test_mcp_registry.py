"""The enterprise MCP registry for developers' MCP clients, and the MCP servers developers
set up on their machines (agentgov.registry.mcp_registry, mcp_sightings)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import pytest
from sqlalchemy import select

from agentgov import cli
from agentgov.config import Settings
from agentgov.gateway import render
from agentgov.models import Finding, ToolServer
from agentgov.opa.bundle import registry_snapshot
from agentgov.registry import manifests, mcp_registry, toolservers
from agentgov.registry.errors import Conflict, ValidationError
from tests.conftest import ADMIN
from tests.test_api import key
from tests.test_cli import _Shared, ok, runner

PLAYWRIGHT = {"registry_type": "npm", "identifier": "@playwright/mcp", "version": "0.0.41"}


def register(client, name: str, **spec: Any) -> dict[str, Any]:
    resp = client.post("/v1/toolservers", json={"name": name, **spec}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()


def registry_on(client) -> None:
    resp = client.put("/v1/features/mcp-registry", json={"mode": "on"}, headers=ADMIN)
    assert resp.status_code == 200, resp.text


@pytest.fixture
def listed(client) -> None:
    """A gateway server listed for developers, one only for developers, and one not listed."""
    register(client, "crm", url="http://crm:9000/mcp", developers=True, description="Customers")
    register(client, "playwright", gateway=False, developers=True, packages=[PLAYWRIGHT])
    register(client, "github", url="https://api.githubcopilot.com/mcp/", gateway=False,
             developers=True)  # fmt: skip
    register(client, "hr", url="http://hr:9000/mcp")


class TestToolServers:
    def test_how_a_server_is_used_is_checked(self, rt) -> None:
        with rt.db.session() as s:
            with pytest.raises(ValidationError, match=r"gateway, listed for developers, or both"):
                toolservers.create(
                    s, {"name": "x", "url": "http://x/mcp", "gateway": False}, actor="a",
                    approve=True,
                )  # fmt: skip
            with pytest.raises(ValidationError, match="url or the packages"):
                toolservers.create(
                    s, {"name": "x", "gateway": False, "developers": True}, actor="a",
                    approve=True,
                )  # fmt: skip
            with pytest.raises(ValidationError, match="url is required"):
                toolservers.create(s, {"name": "x"}, actor="a", approve=True)
            with pytest.raises(ValidationError, match="packages are for servers listed"):
                toolservers.create(
                    s, {"name": "x", "url": "http://x/mcp", "packages": [PLAYWRIGHT]},
                    actor="a", approve=True,
                )  # fmt: skip
            with pytest.raises(ValidationError, match="not latest"):
                toolservers.create(
                    s,
                    {"name": "x", "gateway": False, "developers": True,
                     "packages": [{**PLAYWRIGHT, "version": "latest"}]},
                    actor="a", approve=True,
                )  # fmt: skip
            with pytest.raises(ValidationError, match="namespace/name"):
                toolservers.create(
                    s, {"name": "x", "url": "http://x/mcp", "registry_name": "no-slash"},
                    actor="a", approve=True,
                )  # fmt: skip

    def test_registry_names_are_unique(self, rt) -> None:
        with rt.db.session() as s:
            spec = {"url": "http://x/mcp", "developers": True, "registry_name": "com.acme/crm"}
            toolservers.create(s, {"name": "a", **spec}, actor="a", approve=True)
            with pytest.raises(Conflict, match=r"com\.acme/crm"):
                toolservers.create(s, {"name": "b", **spec}, actor="a", approve=True)

    def test_what_developers_see_bumps_the_revision(self, rt) -> None:
        with rt.db.session() as s:
            ts = toolservers.create(
                s, {"name": "crm", "url": "http://crm/mcp", "developers": True}, actor="a",
                approve=True,
            )  # fmt: skip
            assert ts.revision == 0
            toolservers.update(s, ts, {"owner": "crm-team"}, actor="a")
            assert ts.revision == 0
            toolservers.update(s, ts, {"description": "Customer records"}, actor="a")
            assert ts.revision == 1
            assert mcp_registry.version(ts) == "1.0.1"

    def test_servers_only_for_developers_stay_off_the_gateway(self, rt, settings) -> None:
        with rt.db.session() as s:
            toolservers.create(s, {"name": "crm", "url": "http://crm/mcp"}, actor="a", approve=True)
            toolservers.create(
                s, {"name": "github", "url": "https://api.githubcopilot.com/mcp/",
                    "gateway": False, "developers": True},
                actor="a", approve=True,
            )  # fmt: skip
            servers = list(s.scalars(select(ToolServer)))
            names = {
                r["name"] for r in render(servers, settings)["binds"][0]["listeners"][0]["routes"]
            }
            assert names == {"mcp-crm", "agentgov-health"}
            assert set(registry_snapshot(s)["toolservers"]) == {"crm"}

    def test_manifests(self, rt, settings) -> None:
        doc = {
            "apiVersion": manifests.API_VERSION,
            "kind": "ToolServer",
            "metadata": {"name": "playwright"},
            "spec": {"gateway": False, "developers": True, "packages": [PLAYWRIGHT]},
        }
        with rt.db.session() as s:
            assert manifests.apply(s, settings, [doc], actor="ci")[0]["action"] == "created"
        with rt.db.session() as s:
            assert manifests.apply(s, settings, [doc], actor="ci")[0]["action"] == "unchanged"
            [exported] = [d for d in manifests.export(s) if d["kind"] == "ToolServer"]
        assert exported["spec"]["packages"] == [PLAYWRIGHT]
        assert exported["spec"]["gateway"] is False and "url" not in exported["spec"]


class TestRegistry:
    def test_off_until_turned_on(self, client, listed) -> None:
        resp = client.get("/registry/v0.1/servers")
        assert resp.status_code == 404
        assert "mcp-registry" in resp.json()["error"]

    def test_the_servers_listed_for_developers(self, client, listed) -> None:
        registry_on(client)
        resp = client.get("/registry/v0.1/servers")  # no credentials, as clients read it
        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == "*"
        page = resp.json()
        servers = {s["server"]["name"]: s for s in page["servers"]}
        assert list(servers) == [
            "local.agentgov/crm", "local.agentgov/github", "local.agentgov/playwright",
        ]  # fmt: skip
        assert page["metadata"] == {"count": 3}
        crm = servers["local.agentgov/crm"]["server"]
        assert crm["remotes"] == [
            {"type": "streamable-http", "url": "http://localhost:8080/mcp/crm"}
        ]
        assert (crm["description"], crm["version"]) == ("Customers", "1.0.0")
        github = servers["local.agentgov/github"]["server"]
        assert github["remotes"][0]["url"] == "https://api.githubcopilot.com/mcp/"
        playwright = servers["local.agentgov/playwright"]["server"]
        assert "remotes" not in playwright
        assert playwright["packages"] == [
            {"registryType": "npm", "identifier": "@playwright/mcp", "version": "0.0.41",
             "transport": {"type": "stdio"}},
        ]  # fmt: skip
        official = servers["local.agentgov/crm"]["_meta"][mcp_registry.OFFICIAL]
        assert official["status"] == "active" and official["isLatest"] is True

    def test_pages_search_and_versions(self, client, listed) -> None:
        registry_on(client)
        first = client.get("/registry/v0.1/servers", params={"limit": 2}).json()
        assert first["metadata"]["count"] == 2 and first["metadata"]["nextCursor"]
        rest = client.get(
            "/registry/v0.1/servers", params={"cursor": first["metadata"]["nextCursor"]}
        ).json()
        assert [s["server"]["name"] for s in rest["servers"]] == ["local.agentgov/playwright"]
        assert "nextCursor" not in rest["metadata"]
        found = client.get("/registry/v0.1/servers", params={"search": "PLAY"}).json()
        assert [s["server"]["name"] for s in found["servers"]] == ["local.agentgov/playwright"]
        name = quote("local.agentgov/crm", safe="")
        latest = client.get(f"/registry/v0.1/servers/{name}/versions/latest")
        assert latest.status_code == 200 and latest.json()["server"]["version"] == "1.0.0"
        assert client.get(f"/registry/v0.1/servers/{name}/versions/1.0.0").status_code == 200
        assert client.get(f"/registry/v0.1/servers/{name}/versions/9.9.9").status_code == 404
        versions = client.get(f"/registry/v0.1/servers/{name}/versions").json()
        assert versions["metadata"]["count"] == 1
        missing = quote("local.agentgov/nothing", safe="")
        assert client.get(f"/registry/v0.1/servers/{missing}/versions").status_code == 404
        bad = client.get("/registry/v0.1/servers", params={"updated_since": "yesterday"})
        assert bad.status_code == 400

    def test_blocked_servers_are_deleted_there(self, client, listed) -> None:
        registry_on(client)
        client.post("/v1/toolservers/crm/block", json={}, headers=ADMIN).raise_for_status()
        names = [
            s["server"]["name"] for s in client.get("/registry/v0.1/servers").json()["servers"]
        ]
        assert "local.agentgov/crm" not in names
        everything = client.get("/registry/v0.1/servers", params={"include_deleted": "true"})
        [crm] = [s for s in everything.json()["servers"] if s["server"]["title"] == "crm"]
        assert crm["_meta"][mcp_registry.OFFICIAL]["status"] == "deleted"

    def test_the_admin_view_and_managed_settings(self, client, listed) -> None:
        view = client.get("/v1/mcp/registry", headers=ADMIN).json()
        assert view["enabled"] is False and view["url"] == "http://localhost:8000/registry"
        assert len(view["servers"]) == 3
        allowlist = client.get("/v1/mcp/managed-settings", headers=ADMIN).json()
        assert allowlist == {
            "allowedMcpServers": [
                {"serverUrl": "http://localhost:8080/mcp/crm"},
                {"serverUrl": "https://api.githubcopilot.com/mcp/"},
                {"serverCommand": ["npx", "@playwright/mcp@0.0.41"]},
            ]
        }

    def test_namespace(self) -> None:
        assert mcp_registry.namespace(Settings(public_url="https://agentgov.contoso.com")) == (
            "com.contoso.agentgov"
        )
        assert mcp_registry.namespace(Settings(mcp_registry_namespace="com.acme")) == "com.acme"


def scanned(*servers: dict[str, Any]) -> dict[str, Any]:
    return {"machine": "laptop-1", "user": "alice", "servers": list(servers)}


GATEWAY_CRM = {
    "name": "crm", "client": "vscode", "scope": "user", "transport": "http",
    "url": "http://localhost:8080/mcp/crm", "identity": "url:http://localhost:8080/mcp/crm",
}  # fmt: skip
DIRECT_CRM = {
    "name": "crm-direct", "client": "vscode", "scope": "project", "transport": "http",
    "url": "http://crm:9000/mcp", "identity": "url:http://crm:9000/mcp",
}  # fmt: skip
PLAYWRIGHT_SEEN = {
    "name": "playwright", "client": "cursor", "scope": "user", "transport": "stdio",
    "command": ["npx", "-y", "@playwright/mcp@0.0.41"], "identity": "npm:@playwright/mcp",
}  # fmt: skip
SHADOW = {
    "name": "notes", "client": "claude-desktop", "scope": "user", "transport": "stdio",
    "command": ["python3", "notes.py"], "env": ["NOTES_TOKEN"],
    "identity": "command:python3 notes.py",
}  # fmt: skip


class TestSightings:
    def test_reports_are_compared_with_the_approved_servers(self, client, listed) -> None:
        reporter = key(client, "registrar")
        body = scanned(GATEWAY_CRM, DIRECT_CRM, PLAYWRIGHT_SEEN, SHADOW)
        resp = client.post("/v1/mcp/sightings", json=body, headers=reporter)
        assert resp.status_code == 200, resp.text
        assert resp.json() == {
            "servers": 4, "approved": 2, "bypass": 1, "blocked": 0, "unapproved": 1,
        }  # fmt: skip
        view = {g["identity"]: g for g in client.get("/v1/mcp/sightings", headers=ADMIN).json()}
        direct = view["url:http://crm:9000/mcp"]
        assert (direct["status"], direct["server"]) == ("bypass", "crm")
        assert view["npm:@playwright/mcp"]["status"] == "approved"
        assert view["command:python3 notes.py"]["status"] == "unapproved"
        assert view["command:python3 notes.py"]["machines"] == 1
        # Registrars report; they can't read the registry back.
        assert client.get("/v1/mcp/sightings", headers=reporter).status_code == 403
        open_findings = {
            f["type"]: f
            for f in client.get("/v1/findings", headers=ADMIN).json()
            if f["type"].startswith("mcp.")
        }
        assert set(open_findings) == {"mcp.gateway_bypass", "mcp.unapproved_server"}
        assert "notes" in open_findings["mcp.unapproved_server"]["title"]

    def test_a_report_replaces_the_last_one(self, client, listed) -> None:
        client.post("/v1/mcp/sightings", json=scanned(SHADOW), headers=ADMIN).raise_for_status()
        client.post(
            "/v1/mcp/sightings", json=scanned(GATEWAY_CRM), headers=ADMIN
        ).raise_for_status()
        view = client.get("/v1/mcp/sightings", headers=ADMIN).json()
        assert [g["identity"] for g in view] == [GATEWAY_CRM["identity"]]
        mcp_findings = [
            f for f in client.get("/v1/findings", headers=ADMIN).json()
            if f["type"].startswith("mcp.") and f["status"] == "open"
        ]  # fmt: skip
        assert mcp_findings == []

    def test_another_machine_leaves_the_findings_alone(self, client, listed) -> None:
        def open_types() -> set[str]:
            return {
                f["type"] for f in client.get("/v1/findings", headers=ADMIN).json()
                if f["type"].startswith("mcp.") and f["status"] == "open"
            }  # fmt: skip

        client.post("/v1/mcp/sightings", json=scanned(SHADOW), headers=ADMIN).raise_for_status()
        other = {**scanned(GATEWAY_CRM), "machine": "laptop-2"}
        client.post("/v1/mcp/sightings", json=other, headers=ADMIN).raise_for_status()
        assert open_types() == {"mcp.unapproved_server"}
        client.post("/v1/mcp/sightings", json=scanned(), headers=ADMIN).raise_for_status()
        assert open_types() == set()

    def test_approving_a_server_resolves_its_finding(self, client, listed) -> None:
        client.post("/v1/mcp/sightings", json=scanned(SHADOW), headers=ADMIN).raise_for_status()
        rt = client.app.state.rt
        with rt.db.session() as s:
            finding = s.scalar(select(Finding).where(Finding.type == "mcp.unapproved_server"))
            assert finding.status == "open"
        package = {"registry_type": "pypi", "identifier": "notes-mcp",
                   "command": ["python3", "notes.py"]}  # fmt: skip
        register(client, "notes", gateway=False, developers=True, packages=[package])
        assert rt.refresh_developer_mcp() == 1  # the runtime does this when servers change
        with rt.db.session() as s:
            finding = s.scalar(select(Finding).where(Finding.type == "mcp.unapproved_server"))
            assert finding.status == "resolved"
        view = client.get("/v1/mcp/sightings", headers=ADMIN).json()
        assert (view[0]["status"], view[0]["server"]) == ("approved", "notes")

    def test_bad_reports_and_the_switch(self, client, listed) -> None:
        bad = client.post("/v1/mcp/sightings", json={"machine": "", "servers": []}, headers=ADMIN)
        assert bad.status_code == 422
        client.put("/v1/features/mcp-discovery", json={"mode": "off"}, headers=ADMIN)
        off = client.post("/v1/mcp/sightings", json=scanned(SHADOW), headers=ADMIN)
        assert off.status_code == 409


def test_cli(client, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))

    def agentgov(*args: str):
        return runner.invoke(cli.app, list(args))

    out = ok(agentgov("toolservers", "create", "playwright", "--no-gateway", "--developers",
                      "--package", "npm:@playwright/mcp@0.0.41"))  # fmt: skip
    assert out.strip() == "toolserver/playwright: approved, listed for developers"
    ts = client.get("/v1/toolservers/playwright", headers=ADMIN).json()
    assert ts["packages"] == [PLAYWRIGHT] and ts["gateway_url"] is None
    ok(agentgov("toolservers", "create", "crm", "--url", "http://crm:9000/mcp", "--developers"))
    listing = ok(agentgov("mcp", "registry"))
    assert "local.agentgov/playwright" in listing and "npm:@playwright/mcp@0.0.41" in listing
    assert "(off (agentgov features set mcp-registry on))" in listing
    allowlist = tmp_path / "managed-settings.json"
    ok(agentgov("mcp", "managed-settings", "--output", str(allowlist)))
    assert {"serverUrl": "http://localhost:8080/mcp/crm"} in json.loads(allowlist.read_text())[
        "allowedMcpServers"
    ]
    bad = agentgov("toolservers", "update", "crm", "--package", "npm")
    assert bad.exit_code == 2

    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "crm": {"url": "http://localhost:8080/mcp/crm"},
        "notes": {"command": "python3", "args": ["notes.py"], "env": {"NOTES_TOKEN": "s3cret"}},
    }}))  # fmt: skip
    out = ok(agentgov("mcp", "scan", "--home", str(home), "--dir", str(tmp_path), "--report"))
    assert "reported 2 servers: 1 approved, 1 not approved" in out
    sightings = ok(agentgov("mcp", "sightings"))
    assert "unapproved" in sightings and "command:python3 notes.py" in sightings
    assert "s3cret" not in json.dumps(client.get("/v1/mcp/sightings", headers=ADMIN).json())
