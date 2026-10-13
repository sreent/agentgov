"""Features: which parts of AgentGov are used, and how strictly (docs/features.md)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request

from agentgov import health
from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.registry import features

router = APIRouter(prefix="/v1", tags=["features"])
read = require(*READ_ROLES)
admin = require("admin")


def _described(s: Any, rt: Any, key: str | None = None) -> list[dict[str, Any]]:
    """Features as features.describe gives them, with whether each can do what its mode
    says (agentgov.health): its status, and the problems that make it so."""
    items = features.describe(s, rt.settings, key)
    situation = health.situation(s, rt.settings, rt)
    for item in items:
        item.update(health.assess(features.BY_KEY[item["key"]], item["mode"], situation))
    return items


@router.get("/features")
def list_features(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Every feature, its mode, what that mode does, who chose it and whether it can do
    what its mode says."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        return {"groups": features.GROUPS, "features": _described(s, rt)}


@router.get("/features/{key}")
def get_feature(request: Request, key: str, _: Principal = Depends(read)) -> dict[str, Any]:
    rt = request.app.state.rt
    with rt.db.session() as s:
        return _described(s, rt, key)[0]


@router.get("/components")
def list_components(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """What the control plane reaches itself, and what each governance processor said it
    reaches, with whether it is in touch."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        return {"control_plane": rt.health.get(), "processors": health.reports(s)}


@router.put("/features/{key}")
def set_feature(
    request: Request,
    key: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    """Choose a feature's mode: ``{"mode": "monitor"}``. Features the deployment pins
    (AGENTGOV_FEATURES) can only be changed there."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        features.set_mode(s, rt.settings, key, body.get("mode"), actor=principal.actor)
        return _described(s, rt, key)[0]
