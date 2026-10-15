"""Features: which parts of AgentGov are used, and how strictly (docs/features.md)."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from ninja import Body

from agentgov import health
from agentgov.api.auth import READ_ROLES
from agentgov.registry import features
from agentgov.registry.errors import ValidationError
from agentgov.web.api import Router
from agentgov.web.auth import require, runtime

router = Router(tags=["features"])
read = require(*READ_ROLES)
admin = require("admin")


def _described(s: Any, rt: Any, key: str | None = None) -> list[dict[str, Any]]:
    """Features as features.describe gives them, with whether each can do what its mode
    says (agentgov.health): its status, and the problems that make it so."""
    items = features.describe(s, rt.settings, key)
    situation = health.situation(s, rt.settings, rt)
    for item in items:
        # As strict as it is for any agent: off, but enforced for some, it isn't off.
        mode = situation.modes.get(item["key"], item["mode"])
        item.update(health.assess(features.BY_KEY[item["key"]], mode, situation))
    return items


@router.get("/v1/features", auth=read)
def list_features(request: HttpRequest) -> dict[str, Any]:
    """Every feature, its mode, what that mode does, who chose it and whether it can do
    what its mode says."""
    rt = runtime(request)
    with rt.db.session() as s:
        return {"groups": features.GROUPS, "features": _described(s, rt)}


@router.get("/v1/features/{key}", auth=read)
def get_feature(request: HttpRequest, key: str) -> dict[str, Any]:
    rt = runtime(request)
    with rt.db.session() as s:
        return _described(s, rt, key)[0]


@router.get("/v1/components", auth=read)
def list_components(request: HttpRequest) -> dict[str, Any]:
    """What the control plane reaches itself, and what each governance processor said it
    reaches, with whether it is in touch; and the hosts credentials may go to
    (AGENTGOV_CREDENTIAL_HOSTS; none listed, any host)."""
    rt = runtime(request)
    with rt.db.session() as s:
        return {
            "control_plane": rt.health.get(),
            "processors": health.reports(s),
            "credential_hosts": rt.settings.credential_host_list(),
            # What vouches for the evidence ledger outside its database.
            "ledger": health.ledger_checks(rt.settings),
        }


@router.get("/v1/feature-presets", auth=read)
def list_presets(request: HttpRequest) -> dict[str, Any]:
    """Starting points that set many modes at once, with what each would change now and
    what it would leave (docs/features.md#starting-points)."""
    rt = runtime(request)
    with rt.db.session() as s:
        return {
            "presets": [features.preview_preset(s, rt.settings, name) for name in features.PRESETS],
            "applied": features.deployment_preset(s),
        }


@router.post("/v1/feature-presets/{name}", auth=admin)
def apply_preset(request: HttpRequest, name: str) -> dict[str, Any]:
    """Apply a starting point: each mode it changes is a feature.changed entry in the
    ledger that names it. Features the deployment pins keep their pins."""
    rt = runtime(request)
    with rt.db.session() as s:
        plan = features.apply_preset(s, rt.settings, name, actor=request.auth.actor)
        return {**plan, "features": _described(s, rt)}


@router.put("/v1/features/{key}", auth=admin)
def set_feature(request: HttpRequest, key: str, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Choose a feature's mode, ``{"mode": "monitor"}``, and for a control its exceptions,
    ``{"scopes": [{"mode": "enforce", "scope": {"teams": ["payments"]}}]}``: its mode for
    the agents in a scope, the first that matches (docs/features.md#exceptions). Features
    the deployment pins (AGENTGOV_FEATURES) can only be changed there."""
    if "mode" not in body and "scopes" not in body:
        raise ValidationError("give the feature's mode, its exceptions (scopes), or both")
    rt = runtime(request)
    actor = request.auth.actor
    with rt.db.session() as s:
        if "mode" in body:
            features.set_mode(s, rt.settings, key, body.get("mode"), actor=actor)
        if "scopes" in body:
            features.set_scopes(s, rt.settings, key, body.get("scopes"), actor=actor)
        return _described(s, rt, key)[0]
