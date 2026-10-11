"""Features: which parts of AgentGov are used, and how strictly (docs/features.md)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.registry import features

router = APIRouter(prefix="/v1", tags=["features"])
read = require(*READ_ROLES)
admin = require("admin")


@router.get("/features")
def list_features(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Every feature, its mode, what that mode does and who chose it."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        return {"groups": features.GROUPS, "features": features.describe(s, rt.settings)}


@router.get("/features/{key}")
def get_feature(request: Request, key: str, _: Principal = Depends(read)) -> dict[str, Any]:
    rt = request.app.state.rt
    with rt.db.session() as s:
        return features.describe(s, rt.settings, key)[0]


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
        return features.describe(s, rt.settings, key)[0]
