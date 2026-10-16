"""Blueprints: IT-approved templates that define what a class of agents may do."""

from __future__ import annotations

from typing import Any

from agentgov import db, ids, ledger
from agentgov.db import mark_changed
from agentgov.db.models import Agent, Blueprint
from agentgov.registry import scopes, teams, validation
from agentgov.registry.errors import Conflict, NotFound, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

FIELDS = (
    "description",
    "risk_tier",
    "permissions",
    "model_access",
    "agent_access",
    "daily_token_budget",
    "acts_for",
    "people_groups",
    "approvals_by",
    "require_workload_identity",
    "require_sponsor",
    "attestation_days",
    "labels",
    "team",
)


def get(tx: db.Where, ref: str) -> Blueprint:
    bp = Blueprint.objects.filter(pk=ref).first() or Blueprint.objects.filter(name=ref).first()
    if bp is None:
        raise NotFound(f"blueprint {ref!r} not found")
    return bp


def list_all(tx: db.Where) -> list[Blueprint]:
    return list(Blueprint.objects.order_by("name"))


def _apply(tx: db.Where, bp: Blueprint, data: dict[str, Any]) -> list[str]:
    changed = []
    for key in FIELDS:
        if key not in data:
            continue
        value = data[key]
        if key == "risk_tier":
            value = validation.risk_tier(value)
        elif key == "permissions":
            value = validation.permissions(value)
        elif key == "model_access":
            value = validation.model_access(value)
        elif key == "agent_access":
            value = validation.agent_access(value)
        elif key == "daily_token_budget":
            value = validation.token_budget(value)
        elif key == "acts_for":
            value = validation.acts_for(value)
        elif key == "people_groups":
            value = validation.people_groups(value)
        elif key == "approvals_by":
            value = validation.approvals_by(value)
        elif key == "labels":
            value = validation.labels(value)
        elif key == "team":
            value = teams.reference(tx, value)
        elif key in ("require_sponsor", "require_workload_identity"):
            value = bool(value)
        elif key == "attestation_days":
            if value is not None and (not isinstance(value, int) or value <= 0):
                raise ValidationError("attestation_days must be a positive integer or null")
        elif key == "description":
            value = str(value or "")
        if getattr(bp, key) != value:
            setattr(bp, key, value)
            changed.append(key)
    return changed


def create(tx: db.Where, data: dict[str, Any], *, actor: str) -> Blueprint:
    name = validation.slug(data.get("name"), "name")
    if Blueprint.objects.filter(name=name).exists():
        raise Conflict(f"blueprint {name!r} already exists")
    bp = Blueprint(
        id=ids.new_id(ids.BLUEPRINT),
        name=name,
        permissions=[],
        model_access=[],
        agent_access=[],
        labels={},
        acts_for="either",
        people_groups=[],
        approvals_by="approvers",
        require_workload_identity=False,
    )
    _apply(tx, bp, data)
    bp.save(force_insert=True)
    ledger.append(
        tx,
        type="blueprint.created",
        actor=actor,
        resource=f"blueprint/{name}",
        details={"permissions": bp.permissions, "risk_tier": bp.risk_tier},
    )
    mark_changed(tx, "blueprints")
    return bp


def update(
    tx: db.Where,
    bp: Blueprint,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(tx, bp, version, f"blueprint {bp.name}")
    changed = _apply(tx, bp, data)
    if changed:
        edited(bp)
        bp.save()
        ledger.append(
            tx,
            type="blueprint.updated",
            actor=actor,
            resource=f"blueprint/{bp.name}",
            details={**{k: getattr(bp, k) for k in changed}, "changes": changes(bp)},
        )
        mark_changed(tx, "blueprints")
    return changed


def delete(tx: db.Where, bp: Blueprint, *, actor: str) -> None:
    in_use = Agent.objects.filter(blueprint_id=bp.id).count()
    if in_use:
        raise Conflict(f"blueprint {bp.name!r} is used by {in_use} agent(s)")
    named_by = scopes.naming(tx, "blueprints", bp.name)
    if named_by:
        raise Conflict(f"{', '.join(named_by)} name blueprint {bp.name!r}: change them first")
    ledger.append(tx, type="blueprint.deleted", actor=actor, resource=f"blueprint/{bp.name}")
    Blueprint.objects.filter(pk=bp.id).delete()
    mark_changed(tx, "blueprints")


def to_dict(bp: Blueprint) -> dict[str, Any]:
    return {
        "id": bp.id,
        "name": bp.name,
        "version": bp.version,
        "description": bp.description,
        "risk_tier": bp.risk_tier,
        "permissions": bp.permissions or [],
        "model_access": bp.model_access or [],
        "agent_access": bp.agent_access or [],
        "daily_token_budget": bp.daily_token_budget,
        "acts_for": bp.acts_for,
        "people_groups": bp.people_groups or [],
        "approvals_by": bp.approvals_by,
        "require_workload_identity": bp.require_workload_identity,
        "require_sponsor": bp.require_sponsor,
        "attestation_days": bp.attestation_days,
        "labels": bp.labels or {},
        "team": bp.team,
        "created_at": ids.isoformat(bp.created_at),
        "updated_at": ids.isoformat(bp.updated_at),
    }
