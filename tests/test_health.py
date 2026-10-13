"""Whether each feature can do what its mode says (agentgov.health): the governance
processors' reports, the control plane's own checks, and the Features page's status."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from agentgov import cli
from agentgov.api.app import create_app
from agentgov.config import Settings
from tests.conftest import ADMIN, SERVICE
from tests.test_api import key
from tests.test_cli import _Shared, ok, runner


def processor(
    *,
    opa: bool = True,
    presidio: dict[str, Any] | None = None,
    guardian: dict[str, Any] | None = None,
    authzen: dict[str, Any] | None = None,
    failure_mode: str = "closed",
    instance: str = "processor-0",
) -> dict[str, Any]:
    """A processor's report: what it can reach."""
    up = {"configured": True, "ok": True, "detail": ""}
    return {
        "component": "processor",
        "instance": instance,
        "version": "0.1.0",
        "interval": 60,
        "checks": {
            "opa": up if opa else {"configured": True, "ok": False, "detail": "refused"},
            "presidio": presidio or up,
            "guardian": guardian or {"configured": False, "ok": False},
            "authzen": authzen or {"configured": False, "ok": False},
        },
        "settings": {"presidio_failure_mode": failure_mode},
    }


def report(client: TestClient, body: dict[str, Any]) -> None:
    resp = client.post("/v1/internal/components", json=body, headers=SERVICE)
    assert resp.status_code == 200, resp.text


def feature(client: TestClient, key: str) -> dict[str, Any]:
    resp = client.get(f"/v1/features/{key}", headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def set_mode(client: TestClient, key: str, mode: str) -> None:
    resp = client.put(f"/v1/features/{key}", json={"mode": mode}, headers=ADMIN)
    assert resp.status_code == 200, resp.text


def test_a_processor_says_what_it_can_reach(client) -> None:
    auditor = key(client, "auditor")
    resp = client.post("/v1/internal/components", json=processor(), headers=auditor)
    assert resp.status_code == 403
    report(client, processor())
    view = client.get("/v1/components", headers=ADMIN).json()
    [proc] = view["processors"]
    assert proc["instance"] == "processor-0" and proc["fresh"] is True
    assert proc["checks"]["opa"]["ok"] is True
    assert proc["checks"]["guardian"]["configured"] is False
    # The control plane's own: neither OPA nor Keycloak is set up here.
    assert view["control_plane"]["opa"]["configured"] is False


def test_reports_that_arent_a_processors_are_refused(client) -> None:
    for body in (
        {**processor(), "component": "gateway"},
        {**processor(), "instance": "x" * 201},
        ["not", "an", "object"],
    ):
        resp = client.post("/v1/internal/components", json=body, headers=SERVICE)
        assert resp.status_code == 422, resp.text


def test_with_no_processor_the_controls_check_nothing(client) -> None:
    least = feature(client, "least-privilege")
    assert least["mode"] == "enforce" and least["status"] == "inactive"
    assert "No governance processor has reported" in least["problems"][0]
    # Features that don't need the gateway are as their mode says.
    assert feature(client, "posture-checks")["status"] == "active"
    set_mode(client, "discovery", "off")
    assert feature(client, "discovery")["status"] == "off"


def test_a_processor_that_cant_reach_opa_refuses_every_call(client) -> None:
    report(client, processor(opa=False))
    for name in ("least-privilege", "mcp-gateway", "jailbreak-detection"):
        found = feature(client, name)
        assert found["status"] == "failing", name
        assert "every call through the gateway is refused" in found["problems"][0]


def test_in_touch_processors_and_ones_that_went_quiet(client) -> None:
    from agentgov.models import ComponentReport

    report(client, processor())
    assert feature(client, "least-privilege")["status"] == "active"
    rt = client.app.state.rt
    with rt.db.session() as s:
        row = s.get(ComponentReport, ("processor", "processor-0"))
        row.reported_at -= timedelta(minutes=10)
    found = feature(client, "least-privilege")
    assert found["status"] == "inactive"
    assert "since" in found["problems"][0]
    assert client.get("/v1/components", headers=ADMIN).json()["processors"][0]["fresh"] is False


def test_data_protection_without_presidio(client) -> None:
    report(client, processor(presidio={"configured": False, "ok": False}))
    found = feature(client, "data-protection")
    assert found["status"] == "limited"
    assert "Personal data isn't looked for" in found["problems"][0]
    masking = feature(client, "a2a-masking")
    assert masking["status"] == "inactive"
    assert "Nothing finds the personal data to mask" in masking["problems"][0]


def test_presidio_down_refuses_calls_while_enforced_and_closed(client) -> None:
    down = {"configured": True, "ok": False, "detail": "unreachable: connection refused"}
    report(client, processor(presidio=down))
    found = feature(client, "data-protection")
    assert found["status"] == "failing"
    assert "refused until it is" in found["problems"][0]
    assert "connection refused" in found["problems"][0]
    # Refusing calls is data protection's doing; masking only has nothing to mask.
    assert feature(client, "a2a-masking")["status"] == "inactive"

    report(client, processor(presidio=down, failure_mode="open"))
    assert feature(client, "data-protection")["status"] == "limited"
    report(client, processor(presidio=down))
    set_mode(client, "data-protection", "monitor")
    assert feature(client, "data-protection")["status"] == "limited"
    set_mode(client, "data-protection", "off")
    masking = feature(client, "a2a-masking")
    assert masking["status"] == "inactive" and "Data protection is off" in masking["problems"][0]


def test_token_budgets_need_the_gateways_access_logs(settings: Settings) -> None:
    for endpoint, status in ((None, "inactive"), ("http://otel-collector:4317", "active")):
        app = create_app(settings.with_overrides(gateway_otlp_endpoint=endpoint), background=False)
        with TestClient(app) as client:
            report(client, processor())
            found = feature(client, "token-budgets")
            assert found["status"] == status
            if endpoint is None:
                assert "budgets never run out" in found["problems"][0]


def test_the_traffic_classifier_and_your_decision_point(settings: Settings) -> None:
    configured = settings.with_overrides(
        guardian_url="http://guardian:8000/v1", authzen_url="https://pdp.example.com"
    )
    with TestClient(create_app(configured, background=False)) as client:
        # Set up where the control plane runs, but not where the processor does.
        report(client, processor())
        classifier = feature(client, "traffic-classifier")
        assert classifier["status"] == "inactive"
        assert "no Granite Guardian" in classifier["problems"][0]
        set_mode(client, "external-decision-point", "enforce")
        decision = feature(client, "external-decision-point")
        assert decision["status"] == "inactive"
        assert "no AGENTGOV_AUTHZEN_URL" in decision["problems"][0]

        down = {"configured": True, "ok": False, "detail": "unreachable"}
        report(client, processor(guardian=down, authzen=down))
        assert feature(client, "traffic-classifier")["status"] == "limited"
        assert feature(client, "external-decision-point")["status"] == "failing"
        set_mode(client, "external-decision-point", "monitor")
        assert feature(client, "external-decision-point")["status"] == "limited"


def test_the_control_planes_own_checks(settings: Settings, monkeypatch) -> None:
    from agentgov import health

    seen: list[str] = []

    def get(url: str, **kwargs: Any) -> httpx.Response:
        seen.append(url)
        return httpx.Response(500, text="bundle not activated", request=httpx.Request("GET", url))

    monkeypatch.setattr(health.httpx, "get", get)
    with TestClient(
        create_app(settings.with_overrides(opa_url="http://opa:8181"), background=False)
    ) as client:
        set_mode(client, "authzen-decision-point", "on")
        found = feature(client, "authzen-decision-point")
        assert found["status"] == "failing"
        assert "OPA isn't reachable from the control plane" in found["problems"][0]
        opa = client.get("/v1/components", headers=ADMIN).json()["control_plane"]["opa"]
        assert opa["ok"] is False and "500" in opa["detail"]
    # Its policies loaded, not only OPA up; and run once for both requests.
    assert seen == ["http://opa:8181/health?bundles=true"]


def test_platforms_and_connections_that_arent_set_up(client) -> None:
    aws = feature(client, "aws")
    assert aws["status"] == "inactive" and aws["problems"][0].startswith("Not configured")
    m365 = feature(client, "microsoft-365")
    assert m365["status"] == "inactive" and m365["problems"][0].startswith("Not set up")
    set_mode(client, "security-operations", "inform")
    secops = feature(client, "security-operations")
    assert secops["status"] == "inactive" and "no destinations" in secops["problems"][0]


def test_the_processor_reports_its_checks() -> None:
    from agentgov.processor.health import ComponentReporter

    def components(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/health" and request.url.params["bundles"] == "true"
        return httpx.Response(200, json={})

    def services(request: httpx.Request) -> httpx.Response:
        if request.url.host == "presidio":
            return httpx.Response(200, text="Presidio Analyzer service is up")
        assert request.url.path == "/v1/models"
        assert request.headers["authorization"] == "Bearer guardian-key"
        return httpx.Response(503, text="loading")

    class ControlPlane:
        sent: list[dict[str, Any]] = []

        async def report_component(self, payload: dict[str, Any]) -> dict[str, Any]:
            self.sent.append(payload)
            return {}

    settings = Settings(
        opa_url="http://opa:8181",
        presidio_url="http://presidio:3000",
        guardian_url="http://guardian:8000/v1",
        guardian_api_key="guardian-key",
    )

    async def go() -> dict[str, Any]:
        reporter = ComponentReporter(
            settings,
            ControlPlane(),  # type: ignore[arg-type]
            components=httpx.AsyncClient(transport=httpx.MockTransport(components)),
            services=httpx.AsyncClient(transport=httpx.MockTransport(services)),
            instance="proc-a",
        )
        try:
            return await reporter.report()
        finally:
            await reporter.stop()

    payload = asyncio.run(go())
    checks = payload["checks"]
    assert payload["instance"] == "proc-a" and payload["interval"] == 60
    assert checks["opa"] == {"configured": True, "ok": True, "detail": ""}
    assert checks["presidio"]["ok"] is True
    assert checks["guardian"]["ok"] is False and "503" in checks["guardian"]["detail"]
    assert checks["authzen"] == {"configured": False, "ok": False, "detail": ""}
    assert payload["settings"] == {"presidio_failure_mode": "closed"}


def test_a_processor_without_opas_address_says_where_it_asks() -> None:
    from agentgov.processor.health import checks

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    async def go() -> dict[str, Any]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(refused)) as http:
            return await checks(Settings(), components=http, services=http)

    found = asyncio.run(go())
    assert found["opa"]["configured"] is False and found["opa"]["ok"] is False
    assert "http://localhost:8181" in found["opa"]["detail"]


@pytest.mark.parametrize("seconds", [-1])
def test_the_report_interval_is_checked(seconds: int) -> None:
    with pytest.raises(ValueError, match="AGENTGOV_COMPONENT_REPORT_SECONDS"):
        Settings(component_report_seconds=seconds).validate()


def test_the_cli_says_what_stops_a_feature(client, monkeypatch) -> None:
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
    out = ok(runner.invoke(cli.app, ["features", "list"]))
    assert "inactive" in out and "No governance processor has reported" in out
    out = ok(runner.invoke(cli.app, ["components"]))
    assert "none has reported" in out
    report(client, processor(presidio={"configured": False, "ok": False}))
    out = ok(runner.invoke(cli.app, ["components"]))
    assert "processor-0" in out and "not set up" in out and "reachable" in out
