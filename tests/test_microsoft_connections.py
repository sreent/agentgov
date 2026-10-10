"""AgentGov's optional connections to Microsoft: each runs when the app may use it."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from agentgov import cli, ids
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.models import AgentActivity, IntegrationState
from agentgov.runtime import Runtime
from tests.conftest import ADMIN
from tests.test_cli import _Shared, runner
from tests.test_platforms import TENANT, app_token, bot

GRAPH = "https://graph.microsoft.com/v1.0"
ALL = (
    "CopilotPackages.Read.All",
    "AgentIdentity.Read.All",
    "AuditLogsQuery.Read.All",
    "SecurityAlert.Read.All",
)
STUDIO_BLUEPRINT = "25664c89-cea5-4ab6-b924-a54fd8a19ae0"
SALES_ENTRA_ID = "aaaaaaaa-1111-2222-3333-444444444444"


def identity(id_: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": id_,
        "displayName": name,
        "accountEnabled": True,
        "agentIdentityBlueprintId": STUDIO_BLUEPRINT,
        "createdByAppId": "bbbbbbbb-0000-0000-0000-000000000000",
        "createdDateTime": "2026-06-01T10:00:00Z",
        "disabledByMicrosoftStatus": None,
        "servicePrincipalType": "ServiceIdentity",
        "tags": [],
        **extra,
    }


def interaction(agent_id: str, user: str, *, jailbreak: bool = False, xpia: bool = False) -> dict:
    return {
        "id": f"rec-{user}-{agent_id}",
        "createdDateTime": "2026-10-09T14:00:00Z",
        "auditLogRecordType": "CopilotInteraction",
        "operation": "CopilotInteraction",
        "userPrincipalName": user,
        "auditData": {
            "CopilotEventData": {
                "AppHost": "Teams",
                "AgentId": f"CopilotStudio.Declarative.{agent_id}",
                "AgentName": "Sales Helper",
                "Messages": [{"Id": "1", "isPrompt": True, "JailbreakDetected": jailbreak}],
                "AccessedResources": [{"Name": "quote.docx", "XPIADetected": xpia}],
            }
        },
    }


def maker_event(operation: str, bot_id: str, user: str) -> dict[str, Any]:
    return {
        "id": f"rec-{operation}",
        "createdDateTime": "2026-10-09T09:30:00Z",
        "operation": operation,
        "userPrincipalName": user,
        "auditData": {"BotId": bot_id, "BotSchemaName": "cr123_salesHelper"},
    }


def alert(id_: str, agent_id: str | None, **extra: Any) -> dict[str, Any]:
    evidence = [{"@odata.type": "#microsoft.graph.security.userEvidence"}]
    if agent_id:
        evidence.append(
            {
                "@odata.type": "#microsoft.graph.security.aiAgentEvidence",
                "agentId": agent_id,
                "agentName": "Sales Helper",
                "hostingPlatformType": "copilotStudio",
            }
        )
    return {
        "id": id_,
        "title": "Jailbreak attempt on an AI agent",
        "severity": "high",
        "status": "new",
        "serviceSource": "microsoftSecurityForAI",
        "detectionSource": "microsoftDefenderForAIServices",
        "description": "A user tried to make the agent ignore its instructions.",
        "recommendedActions": "Review the conversation and the user's other activity.",
        "alertWebUrl": f"https://security.microsoft.com/alerts/{id_}",
        "lastUpdateDateTime": "2026-10-09T15:00:00Z",
        "evidence": evidence,
        **extra,
    }


class FakeGraph:
    """Entra ID's token endpoint and the Graph APIs the connections read."""

    def __init__(self) -> None:
        self.roles: tuple[str, ...] = ALL
        self.identities = [
            identity(SALES_ENTRA_ID, "Sales Helper"),
            identity("cccccccc-1111-2222-3333-444444444444", "Foundry Researcher",
                     agentIdentityBlueprintId="dddddddd-0000-0000-0000-000000000000"),
        ]  # fmt: skip
        self.queries: dict[str, dict[str, Any]] = {}
        self.query_status = "running"
        self.usage_records = [
            interaction("bot-sales", "alice@contoso.com"),
            interaction("bot-sales", "bob@contoso.com", jailbreak=True),
            interaction("bot-unknown", "carol@contoso.com"),
        ]
        self.maker_records = [
            maker_event("BotUpdateOperation-BotPublish", "bot-sales", "dana@contoso.com"),
            maker_event("BotUpdateOperation-BotShare", "bot-sales", "dana@contoso.com"),
            maker_event("BotComponentUpdate", "bot-sales", "dana@contoso.com"),  # not recorded
        ]
        self.alerts = [
            alert("a-1", "bot-sales"),
            alert("a-2", None, serviceSource="microsoftDefenderForEndpoint",
                  detectionSource="antivirus"),  # not about agents
        ]  # fmt: skip
        self.alert_filters: list[str] = []
        self.fail: set[str] = set()

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(
                200, json={"access_token": app_token(*self.roles), "expires_in": 3599}
            )
        path = request.url.path.removeprefix("/v1.0")
        for prefix in self.fail:
            if path.startswith(prefix):
                return httpx.Response(
                    403, json={"error": {"code": "Forbidden", "message": "Access denied."}}
                )
        if path == "/copilot/admin/catalog/packages":
            return httpx.Response(200, json={"value": []})
        if path == "/servicePrincipals/microsoft.graph.agentIdentity":
            assert request.url.params["$top"] == "100"
            if request.url.params.get("$skiptoken") == "2":
                return httpx.Response(200, json={"value": self.identities[1:]})
            return httpx.Response(
                200,
                json={
                    "value": self.identities[:1],
                    "@odata.nextLink": f"{GRAPH}{path}?$top=100&$skiptoken=2",
                },
            )
        if path == "/security/auditLog/queries" and request.method == "POST":
            body = json.loads(request.content)
            query_id = f"q-{len(self.queries) + 1}"
            self.queries[query_id] = body
            return httpx.Response(201, json={**body, "id": query_id, "status": "notStarted"})
        if path.startswith("/security/auditLog/queries/"):
            query_id = path.split("/")[4]
            body = self.queries[query_id]
            if path.endswith("/records"):
                usage = body["operationFilters"] == ["CopilotInteraction"]
                return httpx.Response(
                    200, json={"value": self.usage_records if usage else self.maker_records}
                )
            return httpx.Response(200, json={**body, "id": query_id, "status": self.query_status})
        if path == "/security/alerts_v2":
            assert request.headers["prefer"] == "include-unknown-enum-members"
            self.alert_filters.append(request.url.params["$filter"])
            return httpx.Response(200, json={"value": self.alerts})
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": path}})


@pytest.fixture
def graph() -> FakeGraph:
    return FakeGraph()


@pytest.fixture
def app_settings(settings: Settings) -> Settings:
    return settings.with_overrides(
        m365_tenant_id=TENANT, m365_client_id="agentgov-app", m365_client_secret="m365-secret"
    )


@pytest.fixture
def ms(app_settings: Settings, graph: FakeGraph) -> Iterator[TestClient]:
    runtime = Runtime(
        app_settings, m365_http=httpx.Client(transport=httpx.MockTransport(graph.handle))
    )
    with TestClient(create_app(app_settings, runtime=runtime, background=False)) as client:
        client.post(
            "/v1/platforms/copilot-studio/import",
            json=[bot("bot-sales", "Sales Helper", entra_id=SALES_ENTRA_ID)],
            headers=ADMIN,
        ).raise_for_status()
        yield client


def connections(client: TestClient) -> dict[str, dict[str, Any]]:
    view = client.get("/v1/platforms", headers=ADMIN).json()
    return {c["key"]: c for c in view["connections"]}


def sync(client: TestClient, source: str) -> httpx.Response:
    return client.post(f"/v1/platforms/{source}/sync", headers=ADMIN)


class TestWhatAgentGovHas:
    def test_without_an_app_registration_everything_still_works(self, client) -> None:
        state = connections(client)
        assert {k: c["status"] for k, c in state.items() if c["via"] == "app"} == {
            "microsoft-365": "off",
            "entra-agent-id": "off",
            "purview-audit": "off",
            "defender": "off",
        }
        assert state["threat-detection"]["status"] == "off"
        assert state["copilot-studio"]["status"] == "import"
        assert sync(client, "defender").status_code == 409

    def test_each_connection_runs_only_with_its_permission(self, ms, graph) -> None:
        graph.roles = ("CopilotPackages.Read.All", "AgentIdentity.Read.All")
        results = ms.post("/v1/platforms/sync", headers=ADMIN).json()
        assert results["purview-audit"] == {"lacks_permission": "AuditLogsQuery.Read.All"}
        assert results["defender"] == {"lacks_permission": "SecurityAlert.Read.All"}
        assert "error" not in results["entra-agent-id"]
        state = connections(ms)
        assert state["entra-agent-id"]["status"] == "ok"
        assert state["purview-audit"]["status"] == "missing_permission"
        refused = sync(ms, "defender")
        assert refused.status_code == 409 and "SecurityAlert.Read.All" in refused.json()["detail"]

    def test_a_permission_granted_later_is_picked_up(self, ms, graph) -> None:
        graph.roles = ("CopilotPackages.Read.All",)
        assert sync(ms, "entra-agent-id").status_code == 409
        graph.roles = ALL  # an admin grants it; the app's cached token doesn't have it yet
        assert sync(ms, "entra-agent-id").status_code == 200

    def test_one_failing_connection_does_not_stop_the_others(self, ms, graph) -> None:
        graph.fail = {"/security/alerts_v2"}
        results = ms.post("/v1/platforms/sync", headers=ADMIN).json()
        assert "Access denied" in results["defender"]["error"]
        assert "SecurityAlert.Read.All" in results["defender"]["error"]
        assert results["entra-agent-id"]["created"] == 1
        assert connections(ms)["defender"]["status"] == "failing"

    def test_unknown_sources(self, ms) -> None:
        assert sync(ms, "sharepoint").status_code == 404


class TestEntraAgentId:
    def test_identities_are_linked_to_their_agents(self, ms) -> None:
        counts = sync(ms, "entra-agent-id").json()
        assert counts == {"created": 1, "updated": 1, "skipped": 0, "linked": 1}
        sales = ms.get("/v1/agents/sales-helper", headers=ADMIN).json()
        views = {v["source"]: v for v in sales["platforms"]}
        assert set(views) == {"copilot-studio", "entra-agent-id"}
        assert views["entra-agent-id"]["enabled"] is True
        assert views["entra-agent-id"]["blueprint"] == "Copilot Studio"
        # An identity that no other source reports is an agent of its own.
        found = ms.get(
            "/v1/agents", params={"source": "platform:entra-agent-id"}, headers=ADMIN
        ).json()
        assert [a["name"] for a in found] == ["foundry-researcher"]
        assert found[0]["status"] == "discovered"

    def test_microsoft_disabling_an_identity_is_a_finding(self, ms, graph) -> None:
        graph.identities[0]["disabledByMicrosoftStatus"] = (
            "DisabledDueToViolationOfServicesAgreement"
        )
        graph.identities[0]["accountEnabled"] = False
        sync(ms, "entra-agent-id").raise_for_status()
        open_ = ms.get("/v1/findings", params={"status": "open"}, headers=ADMIN).json()
        assert [f["type"] for f in open_ if f["type"].startswith("entra.")] == [
            "entra.disabled_by_microsoft"
        ]
        risk = ms.get("/v1/agents/sales-helper/risk", headers=ADMIN).json()
        assert any("disabled by Microsoft" in f["factor"] for f in risk["factors"])
        graph.identities[0]["disabledByMicrosoftStatus"] = "NotDisabled"
        sync(ms, "entra-agent-id").raise_for_status()
        open_ = ms.get("/v1/findings", params={"status": "open"}, headers=ADMIN).json()
        assert not [f for f in open_ if f["type"].startswith("entra.")]

    def test_deleted_identities_are_kept_and_marked(self, ms, graph) -> None:
        sync(ms, "entra-agent-id").raise_for_status()
        graph.identities = graph.identities[:1]
        sync(ms, "entra-agent-id").raise_for_status()
        agent = ms.get("/v1/agents/foundry-researcher", headers=ADMIN).json()
        assert agent["platforms"][0]["in_directory"] is False


class TestPurviewAudit:
    def test_searches_run_across_syncs(self, ms, graph, monkeypatch) -> None:
        first = sync(ms, "purview-audit").json()
        assert first == {"interactions": 0, "maker_events": 0, "searching": 2}
        [usage, makers] = graph.queries.values()
        assert usage["operationFilters"] == ["CopilotInteraction"]
        assert "BotUpdateOperation-BotPublish" in makers["operationFilters"]
        assert usage["filterEndDateTime"] > usage["filterStartDateTime"]

        assert sync(ms, "purview-audit").json()["searching"] == 2  # still running
        graph.query_status = "succeeded"
        done = sync(ms, "purview-audit").json()
        assert done == {"interactions": 2, "maker_events": 2, "searching": 0}
        # An hour later, the next searches start where these ended.
        later = ids.utcnow() + timedelta(hours=1)
        monkeypatch.setattr(ids, "utcnow", lambda: later)
        assert sync(ms, "purview-audit").json()["searching"] == 2
        assert graph.queries["q-3"]["filterStartDateTime"] == usage["filterEndDateTime"]

    def test_use_shows_on_the_agent(self, ms, graph) -> None:
        graph.query_status = "succeeded"
        sync(ms, "purview-audit")
        sync(ms, "purview-audit")
        sales = ms.get("/v1/agents/sales-helper", headers=ADMIN).json()
        assert sales["last_seen_at"].startswith("2026-10-09T14:00")
        usage = sales["platforms"][0]["usage"]
        assert usage["recent_users"] == ["bob@contoso.com", "alice@contoso.com"]
        assert usage["hosts"] == {"Teams": 2}
        with ms.app.state.rt.db.session() as s:
            calls = s.scalar(
                select(func.sum(AgentActivity.model_calls)).where(
                    AgentActivity.agent_id == sales["id"]
                )
            )
        assert calls == 2  # each interaction counts as a model call on the agent
        open_ = ms.get("/v1/findings", params={"status": "open"}, headers=ADMIN).json()
        assert "agent.jailbreak_attempts" in {f["type"] for f in open_}

    def test_makers_changes_go_into_the_ledger(self, ms, graph) -> None:
        graph.query_status = "succeeded"
        sync(ms, "purview-audit")
        sync(ms, "purview-audit")
        entries = ms.get("/v1/ledger", params={"type": "platform.agent_*"}, headers=ADMIN).json()
        types = sorted(e["type"] for e in entries)
        assert types == ["platform.agent_published", "platform.agent_shared"]
        assert {e["actor"] for e in entries} == {"maker:dana@contoso.com"}
        assert entries[0]["agent_name"] == "sales-helper"

    def test_a_failed_search_is_tried_again(self, ms, graph) -> None:
        sync(ms, "purview-audit")
        graph.query_status = "failed"
        sync(ms, "purview-audit")
        # The same windows are searched again.
        starts = [q["filterStartDateTime"] for q in graph.queries.values()]
        assert starts[2:] == starts[:2]

    def test_a_search_that_never_finishes_is_given_up(self, ms, graph) -> None:
        sync(ms, "purview-audit")
        rt = ms.app.state.rt
        with rt.db.session() as s:
            state = s.get(IntegrationState, "purview-audit")
            stale = dict(state.data)
            for kind in ("usage", "makers"):
                stale[kind] = {**stale[kind], "started": "2026-01-01T00:00:00+00:00"}
            s.execute(
                update(IntegrationState)
                .where(IntegrationState.key == "purview-audit")
                .values(data=stale, updated_at=ids.utcnow())
            )
        sync(ms, "purview-audit")
        assert len(graph.queries) == 4


class TestDefender:
    def test_alerts_about_agents_become_findings(self, ms, graph) -> None:
        counts = sync(ms, "defender").json()
        assert counts == {"alerts": 1, "matched": 1, "resolved": 0}
        assert graph.alert_filters[0].startswith("lastUpdateDateTime ge ")
        open_ = ms.get("/v1/findings", params={"status": "open"}, headers=ADMIN).json()
        [finding] = [f for f in open_ if f["type"] == "defender.alert"]
        assert finding["severity"] == "high" and finding["category"] == "threat"
        assert finding["agent_id"] is not None
        assert finding["details"]["alert_url"] == "https://security.microsoft.com/alerts/a-1"
        risk = ms.get("/v1/agents/sales-helper/risk", headers=ADMIN).json()
        assert any(f["factor"] == "Open Microsoft Defender alerts" for f in risk["factors"])

    def test_resolved_in_defender_resolves_the_finding(self, ms, graph) -> None:
        sync(ms, "defender").raise_for_status()
        graph.alerts = [alert("a-1", "bot-sales", status="resolved",
                              lastUpdateDateTime="2026-10-10T08:00:00Z")]  # fmt: skip
        assert sync(ms, "defender").json()["resolved"] == 1
        open_ = ms.get("/v1/findings", params={"status": "open"}, headers=ADMIN).json()
        assert not [f for f in open_ if f["type"] == "defender.alert"]
        # The next read starts from the newest alert seen.
        assert graph.alert_filters[-1] == "lastUpdateDateTime ge 2026-10-09T15:00:00Z"


class TestCli:
    def test_status_and_sync(self, ms, graph, monkeypatch) -> None:
        graph.roles = ("CopilotPackages.Read.All", "AgentIdentity.Read.All")
        monkeypatch.setattr(cli, "_client", lambda: _Shared(ms, "test-admin"))
        out = runner.invoke(cli.app, ["platforms", "sync", "entra-agent-id"])
        assert out.exit_code == 0, out.output
        assert out.output.strip() == (
            "platform/entra-agent-id: synced (1 new, 1 updated, 1 linked to agents)"
        )
        status = runner.invoke(cli.app, ["platforms", "status"]).output
        assert "grant AuditLogsQuery.Read.All" in status
        assert "entra-agent-id      ok" in status
