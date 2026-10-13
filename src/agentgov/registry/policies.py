"""Organisation policies: Rego modules distributed to OPA with the library."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.db import mark_changed
from agentgov.models import Policy
from agentgov.opa import bundle as opa_bundle
from agentgov.opa import rego
from agentgov.registry import validation
from agentgov.registry.errors import Conflict, NotFound, ValidationError
from agentgov.registry.versions import changes, start_edit


def get(session: Session, ref: str) -> Policy:
    policy = session.get(Policy, ref) or session.scalar(select(Policy).where(Policy.name == ref))
    if policy is None:
        raise NotFound(f"policy {ref!r} not found")
    return policy


def list_all(session: Session) -> list[Policy]:
    return list(session.scalars(select(Policy).order_by(Policy.name)))


def _validate(session: Session, name: str, source: str, enabled: bool) -> None:
    if not isinstance(source, str) or not source.strip():
        raise ValidationError("rego must be a non-empty string")
    if not enabled:
        return  # disabled modules are not shipped, so they cannot break the bundle
    others = {
        path: src
        for path, src in opa_bundle.custom_modules(session).items()
        if path != f"agentgov/custom/{name}.rego"
    }
    rego.check_custom_policy(
        name, source, others=others, registry=opa_bundle.registry_snapshot(session)
    )


def create(session: Session, data: dict[str, Any], *, actor: str) -> Policy:
    name = validation.slug(data.get("name"), "name")
    if session.scalar(select(Policy).where(Policy.name == name)):
        raise Conflict(f"policy {name!r} already exists")
    enabled = bool(data.get("enabled", True))
    source = data.get("rego")
    _validate(session, name, source, enabled)
    policy = Policy(
        id=ids.new_id(ids.POLICY),
        name=name,
        description=str(data.get("description") or ""),
        rego=source,
        enabled=enabled,
        version=1,
    )
    session.add(policy)
    session.flush()
    ledger.append(
        session,
        type="policy.created",
        actor=actor,
        resource=f"policy/{name}",
        details={"version": 1, "enabled": enabled, "package": opa_bundle.custom_package(name)},
    )
    mark_changed(session, "policies")
    return policy


def update(
    session: Session,
    policy: Policy,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> bool:
    start_edit(session, policy, version, f"policy {policy.name}")
    source = data.get("rego", policy.rego)
    enabled = bool(data.get("enabled", policy.enabled))
    description = str(data.get("description", policy.description) or "")
    if (source, enabled, description) == (policy.rego, policy.enabled, policy.description):
        return False
    _validate(session, policy.name, source, enabled)
    policy.rego, policy.enabled, policy.description = source, enabled, description
    policy.version += 1
    ledger.append(
        session,
        type="policy.updated",
        actor=actor,
        resource=f"policy/{policy.name}",
        details={
            "version": policy.version,
            "enabled": enabled,
            "changes": changes(policy),
            # The policy as it now is: the ledger holds each version that was in force.
            **({"rego": source} if "rego" in changes(policy) else {}),
        },
    )
    mark_changed(session, "policies")
    return True


def delete(session: Session, policy: Policy, *, actor: str) -> None:
    ledger.append(session, type="policy.deleted", actor=actor, resource=f"policy/{policy.name}")
    session.delete(policy)
    mark_changed(session, "policies")


def to_dict(policy: Policy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "name": policy.name,
        "description": policy.description,
        "package": opa_bundle.custom_package(policy.name),
        "rego": policy.rego,
        "enabled": policy.enabled,
        "version": policy.version,
        "created_at": ids.isoformat(policy.created_at),
        "updated_at": ids.isoformat(policy.updated_at),
    }
