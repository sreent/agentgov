"""Identity issuers: where agents' own identities come from, so they need no client secret.

An agent that runs where it already has an identity authenticates with it: a pod with
its Kubernetes service account token, a workload with its SPIFFE JWT-SVID, an agent on
Microsoft's platform with its Entra Agent ID, or any workload whose OpenID Connect
issuer (Okta, AWS, Google, GitHub Actions) gives it a token. An administrator approves
the issuer; each agent names its subject there. AgentGov makes the issuer an identity
provider in Keycloak, and the agent's client one that authenticates with that issuer's
token for that subject instead of a secret (Keycloak's federated client
authentication). The agent still gets an AgentGov token for the gateway, so every
control applies as before.

Trusted at the gateway (``gateway``), an issuer's tokens are taken there directly too, as
Keycloak's are: the agent calls with its own token, and is the agent whose workload
identity it names (docs/agent-identity.md#straight-to-the-gateway).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.db import lock, mark_changed
from agentgov.models import BLOCKED, ISSUER_KINDS, Agent, IdentityIssuer
from agentgov.registry import features, validation
from agentgov.registry.errors import Conflict, InvalidTransition, NotFound, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

APPROVED = "approved"
KUBERNETES, SPIFFE, OIDC = ISSUER_KINDS
FIELDS = (
    "kind",
    "description",
    "issuer",
    "keys_url",
    "audience",
    "allow_reuse",
    "gateway",
    "labels",
)
# Keycloak's identity provider aliases for AgentGov's issuers.
ALIAS_PREFIX = "agentgov-"
_TRUST_DOMAIN = re.compile(r"^spiffe://[a-z0-9.\-_]+$")
# How a token is presented to Keycloak (RFC 7523; SPIFFE's own type for JWT-SVIDs).
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
JWT_SPIFFE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"


def get(session: Session, ref: str) -> IdentityIssuer:
    issuer = session.get(IdentityIssuer, ref) or session.scalar(
        select(IdentityIssuer).where(IdentityIssuer.name == ref)
    )
    if issuer is None:
        raise NotFound(f"identity issuer {ref!r} not found")
    return issuer


def list_all(session: Session) -> list[IdentityIssuer]:
    return list(session.scalars(select(IdentityIssuer).order_by(IdentityIssuer.name)))


def alias(name: str) -> str:
    """The issuer's identity provider in Keycloak."""
    return ALIAS_PREFIX + name


def assertion_type(issuer: IdentityIssuer) -> str:
    return JWT_SPIFFE if issuer.kind == SPIFFE else JWT_BEARER


def _url(value: Any, field: str) -> str:
    parts = urlsplit(str(value))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValidationError(f"{field} must be an http(s) URL (got {value!r})")
    return str(value).rstrip("/") if field == "keys_url" else str(value)


def _apply(issuer: IdentityIssuer, data: dict[str, Any]) -> list[str]:
    changed = []
    for key in FIELDS:
        if key not in data:
            continue
        value = data[key]
        if key == "kind":
            value = validation.one_of(value, ISSUER_KINDS, "kind")
            if issuer.kind and value != issuer.kind:
                raise ValidationError("an issuer's kind can't change: register another issuer")
        elif key == "issuer":
            if not isinstance(value, str) or not value:
                raise ValidationError("issuer is required")
        elif key == "keys_url":
            value = _url(value, "keys_url") if value else None
        elif key == "audience":
            value = str(value) if value else None
        elif key == "allow_reuse":
            value = bool(value)
        elif key == "gateway":
            if not isinstance(value, bool):
                raise ValidationError("gateway is true (the gateway takes its tokens) or false")
        elif key == "labels":
            value = validation.labels(value)
        elif key == "description":
            value = str(value or "")
        if getattr(issuer, key) != value:
            setattr(issuer, key, value)
            changed.append(key)
    _check(issuer)
    return changed


def _check(issuer: IdentityIssuer) -> None:
    """What each kind of issuer needs, and takes."""
    if issuer.kind == SPIFFE:
        if not _TRUST_DOMAIN.match(issuer.issuer or ""):
            raise ValidationError(
                "a SPIFFE issuer is its trust domain, such as spiffe://example.org"
            )
        if not issuer.keys_url:
            raise ValidationError("a SPIFFE issuer needs keys_url: its bundle endpoint")
    else:
        _url(issuer.issuer, "issuer")
    if issuer.kind != OIDC and (issuer.audience or issuer.allow_reuse):
        raise ValidationError("audience and allow_reuse are for OpenID Connect issuers only")
    if issuer.gateway and issuer.kind == SPIFFE:
        raise ValidationError(
            "the gateway can't take a SPIFFE trust domain's JWT-SVIDs itself: its agents get "
            "AgentGov tokens through Keycloak, or register SPIRE's OIDC Discovery Provider as "
            "an OpenID Connect issuer"
        )
    if not issuer.gateway:
        # No longer trusted there: fetched again, should it be again.
        issuer.gateway_keys = issuer.keys_at = issuer.keys_error = None


def _unique(session: Session, issuer: IdentityIssuer) -> None:
    with session.no_autoflush:  # the change being checked isn't written yet
        taken = session.scalar(
            select(IdentityIssuer).where(
                IdentityIssuer.issuer == issuer.issuer, IdentityIssuer.id != issuer.id
            )
        )
    if taken is not None:
        raise Conflict(f"identity issuer {taken.name!r} already has issuer {issuer.issuer}")


def create(session: Session, data: dict[str, Any], *, actor: str) -> IdentityIssuer:
    name = validation.slug(data.get("name"), "name")
    if session.scalar(select(IdentityIssuer).where(IdentityIssuer.name == name)):
        raise Conflict(f"identity issuer {name!r} already exists")
    if "kind" not in data or "issuer" not in data:
        raise ValidationError(f"kind ({', '.join(ISSUER_KINDS)}) and issuer are required")
    issuer = IdentityIssuer(
        id=ids.new_id(ids.ISSUER),
        name=name,
        kind="",
        description="",
        issuer="",
        allow_reuse=False,
        status=APPROVED,
        labels={},
        created_by=actor,
    )
    issuer.kind = validation.one_of(data["kind"], ISSUER_KINDS, "kind")
    _apply(issuer, data)
    _unique(session, issuer)
    session.add(issuer)
    session.flush()
    ledger.append(
        session,
        type="identity_issuer.registered",
        actor=actor,
        resource=f"identity-issuer/{name}",
        details={"kind": issuer.kind, "issuer": issuer.issuer},
    )
    mark_changed(session, "issuers")
    return issuer


def update(
    session: Session,
    issuer: IdentityIssuer,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(session, issuer, version, f"identity issuer {issuer.name}")
    changed = _apply(issuer, data)
    if changed:
        edited(issuer)
        _unique(session, issuer)
        ledger.append(
            session,
            type="identity_issuer.updated",
            actor=actor,
            resource=f"identity-issuer/{issuer.name}",
            details={**{k: getattr(issuer, k) for k in changed}, "changes": changes(issuer)},
        )
        mark_changed(session, "issuers")
    return changed


def set_status(
    session: Session, issuer: IdentityIssuer, action: str, *, actor: str
) -> IdentityIssuer:
    """Block an issuer: none of its tokens authenticate an agent until it is unblocked."""
    if action not in ("block", "unblock"):
        raise ValidationError(f"unknown action {action!r}")
    lock(session, issuer)
    if action == "unblock" and issuer.status != BLOCKED:
        raise InvalidTransition("identity issuer is not blocked")
    if action == "block" and issuer.status == BLOCKED:
        raise InvalidTransition("identity issuer is already blocked")
    previous = issuer.status
    issuer.status = BLOCKED if action == "block" else APPROVED
    ledger.append(
        session,
        type=f"identity_issuer.{action}",
        actor=actor,
        resource=f"identity-issuer/{issuer.name}",
        severity="warning" if action == "block" else "info",
        details={"from": previous, "to": issuer.status, "agents": agent_count(session, issuer)},
    )
    mark_changed(session, "issuers")
    return issuer


def agent_count(session: Session, issuer: IdentityIssuer) -> int:
    return (
        session.scalar(
            select(func.count()).select_from(Agent).where(Agent.workload_issuer == issuer.name)
        )
        or 0
    )


def delete(session: Session, issuer: IdentityIssuer, *, actor: str) -> None:
    used = agent_count(session, issuer)
    if used:
        raise Conflict(
            f"identity issuer {issuer.name!r} is the workload identity of {used} agent(s)"
        )
    ledger.append(
        session,
        type="identity_issuer.deleted",
        actor=actor,
        resource=f"identity-issuer/{issuer.name}",
    )
    session.delete(issuer)
    mark_changed(session, "issuers")


def workload_identity(session: Session, agent: Agent, value: Any) -> tuple[str, str] | None:
    """Check an agent's workload identity, ``{"issuer": name, "subject": sub}`` or null."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"issuer", "subject"}:
        raise ValidationError('workload_identity is {"issuer": "<issuer>", "subject": "<subject>"}')
    issuer = get(session, str(value.get("issuer") or ""))
    subject = value.get("subject")
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise ValidationError("workload_identity.subject is the agent's subject at its issuer")
    if issuer.kind == SPIFFE and not subject.startswith(issuer.issuer + "/"):
        raise ValidationError(
            f"a SPIFFE ID in {issuer.issuer} looks like {issuer.issuer}/<path> (got {subject!r})"
        )
    taken = session.scalar(
        select(Agent).where(
            Agent.workload_issuer == issuer.name,
            Agent.workload_subject == subject,
            Agent.id != agent.id,
        )
    )
    if taken is not None:
        raise Conflict(f"agent {taken.name!r} already has this workload identity")
    return issuer.name, subject


def _taking(issuer: IdentityIssuer) -> bool:
    return bool(issuer.gateway and issuer.gateway_keys and issuer.status == APPROVED)


def at_the_gateway(session: Session) -> list[IdentityIssuer]:
    """The identity issuers whose tokens the gateway takes
    (docs/agent-identity.md#straight-to-the-gateway): trusted there and approved, with the
    keys AgentGov fetched from them; none while agents' own identities are off, as in
    Keycloak."""
    if not features.is_on(session, "workload-identity"):
        return []
    stmt = select(IdentityIssuer).where(IdentityIssuer.gateway.is_(True))
    return [i for i in session.scalars(stmt.order_by(IdentityIssuer.name)) if _taking(i)]


def gateway_state(issuer: IdentityIssuer, *, on: bool = True) -> dict[str, Any]:
    """Whether the gateway takes ``issuer``'s tokens: set to (``trusted``), and doing so now
    (``taking``: approved, with keys, while agents' own identities are ``on``), with how
    many keys, fetched when, and why the last fetch failed."""
    return {
        "trusted": bool(issuer.gateway),
        "taking": on and _taking(issuer),
        "keys": len(issuer.gateway_keys or []) if issuer.gateway else 0,
        "keys_at": ids.isoformat(issuer.keys_at),
        "error": issuer.keys_error if issuer.gateway else None,
    }


def to_dict(
    issuer: IdentityIssuer, agents: int | None = None, *, on: bool = True
) -> dict[str, Any]:
    """``issuer``, with how many ``agents`` have a workload identity there; ``on``: whether
    agents' own identities are (the workload-identity feature)."""
    return {
        "id": issuer.id,
        "name": issuer.name,
        "version": issuer.version,
        "kind": issuer.kind,
        "description": issuer.description or "",
        "issuer": issuer.issuer,
        "keys_url": issuer.keys_url,
        "audience": issuer.audience,
        "allow_reuse": issuer.allow_reuse,
        # Whether the gateway takes its tokens itself, and with the keys AgentGov fetched.
        "gateway": gateway_state(issuer, on=on),
        "status": issuer.status,
        "labels": issuer.labels or {},
        "keycloak_alias": alias(issuer.name),
        "assertion_type": assertion_type(issuer),
        "agents": agents,
        "sync": {"synced_at": ids.isoformat(issuer.synced_at), "error": issuer.sync_error},
        "created_by": issuer.created_by,
        "created_at": ids.isoformat(issuer.created_at),
        "updated_at": ids.isoformat(issuer.updated_at),
    }
