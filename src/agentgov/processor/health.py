"""What this processor can reach, told to the control plane every
AGENTGOV_COMPONENT_REPORT_SECONDS (agentgov.health): OPA, Presidio, Granite Guardian and
your decision point, as this processor is set up, which may not be as the control plane
is. The Features page says from it whether each control can do what its mode says."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from typing import Any

import httpx

from agentgov import __version__
from agentgov.config import Settings
from agentgov.processor.control_plane import ControlPlaneClient, ControlPlaneError

log = logging.getLogger(__name__)
TIMEOUT = 3.0


def _check(configured: bool, ok: bool = False, detail: str = "") -> dict[str, Any]:
    return {"configured": configured, "ok": ok, "detail": detail[:300]}


async def _probe(
    http: httpx.AsyncClient,
    url: str,
    *,
    any_answer: bool,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """GET ``url``: up when it answers 200 (or, with ``any_answer``, anything below 500)."""
    try:
        resp = await http.get(url, headers=headers or {}, timeout=TIMEOUT)
    except httpx.HTTPError as exc:
        return _check(True, False, f"unreachable: {exc}")
    if resp.status_code == 200 or (any_answer and resp.status_code < 500):
        return _check(True, True)
    return _check(True, False, f"answered {resp.status_code}: {resp.text[:120]}")


def _bearer(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


async def checks(
    settings: Settings, *, components: httpx.AsyncClient, services: httpx.AsyncClient
) -> dict[str, dict[str, Any]]:
    """Each dependency: whether it is set up here and answers. ``components`` calls
    AgentGov's own (OPA, over mutual TLS when the components have certificates);
    ``services`` the others."""
    opa_url = settings.opa_url or "http://localhost:8181"
    # With its policies loaded: before that OPA answers, but every decision is undefined.
    opa = await _probe(components, f"{opa_url.rstrip('/')}/health?bundles=true", any_answer=False)
    if not settings.opa_url:
        opa = _check(False, opa["ok"], f"AGENTGOV_OPA_URL isn't set, so it asks {opa_url}")
    out = {"opa": opa}
    out["presidio"] = (
        await _probe(services, f"{settings.presidio_url.rstrip('/')}/health", any_answer=False)
        if settings.presidio_url
        else _check(False)
    )
    out["guardian"] = (
        await _probe(
            services,
            f"{settings.guardian_url.rstrip('/')}/models",  # an OpenAI-compatible API's
            any_answer=True,
            headers=_bearer(settings.guardian_api_key),
        )
        if settings.guardian_url
        else _check(False)
    )
    out["authzen"] = (
        await _probe(
            services,
            f"{settings.authzen_url.rstrip('/')}/.well-known/authzen-configuration",
            any_answer=True,
            headers=_bearer(settings.authzen_token),
        )
        if settings.authzen_url
        else _check(False)
    )
    return out


class ComponentReporter:
    """Reports this processor's checks to the control plane now and at every interval."""

    def __init__(
        self,
        settings: Settings,
        control_plane: ControlPlaneClient,
        *,
        components: httpx.AsyncClient,
        services: httpx.AsyncClient | None = None,
        instance: str | None = None,
    ) -> None:
        self.settings = settings
        self.control_plane = control_plane
        self.components = components
        self.services = services or httpx.AsyncClient(timeout=TIMEOUT)
        self.instance = instance or socket.gethostname()
        self._task: asyncio.Task[None] | None = None

    async def report(self) -> dict[str, Any]:
        payload = {
            "component": "processor",
            "instance": self.instance,
            "version": __version__,
            "interval": self.settings.component_report_seconds,
            "checks": await checks(
                self.settings, components=self.components, services=self.services
            ),
            "settings": {"presidio_failure_mode": self.settings.presidio_failure_mode},
        }
        await self.control_plane.report_component(payload)
        return payload

    async def _run(self) -> None:
        while True:
            try:
                await self.report()
            except ControlPlaneError as exc:
                log.warning("could not report to the control plane: %s", exc)
            except Exception:
                log.exception("component report failed")
            await asyncio.sleep(self.settings.component_report_seconds)

    def start(self) -> None:
        if self.settings.component_report_seconds > 0:
            self._task = asyncio.create_task(self._run(), name="component-reporter")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        await self.services.aclose()
