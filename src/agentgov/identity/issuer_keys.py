"""The signing keys of the identity issuers the gateway trusts
(docs/agent-identity.md#straight-to-the-gateway).

An issuer trusted at the gateway has its tokens checked there, as Keycloak's are, without
Keycloak. The control plane fetches its signing keys, keeps the public ones that name a key
ID, and puts them in the gateway's configuration: agentgateway won't load a key set with a
key it can't use (one without a key ID stops it starting), and the gateway never has to
reach the issuer itself. The keys are fetched again every so often, as issuers rotate them;
when they can't be, the last ones fetched stay, and the issuer says why.

Where they are: an OpenID Connect issuer's ``keys_url`` (its JWKS), else its discovery
document's ``jwks_uri``; a Kubernetes cluster's discovery document (``keys_url``, as Keycloak
takes it, else at the issuer), and its ``jwks_uri``. A ``keys_url`` may be either.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.db import mark_changed
from agentgov.models import IdentityIssuer

log = logging.getLogger(__name__)

# Key types agentgateway checks signatures with.
KEY_TYPES = ("RSA", "EC", "OKP")
# What a public key never carries: these are private parts.
PRIVATE = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
# The most keys of one issuer the gateway is given.
MAX_KEYS = 50


class IssuerKeysError(Exception):
    """An issuer's keys couldn't be fetched, or none of them can be used."""


def _json(http: httpx.Client, url: str) -> Any:
    try:
        resp = http.get(url, timeout=10, headers={"Accept": "application/json"})
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise IssuerKeysError(f"couldn't read {url}: {exc}") from exc


def _key_set(http: httpx.Client, url: str) -> Any:
    """The key set at ``url``: a JWKS, or a discovery document naming where it is."""
    found = _json(http, url)
    if isinstance(found, dict) and "keys" not in found and found.get("jwks_uri"):
        found = _json(http, str(found["jwks_uri"]))
    return found


def keys_location(issuer: IdentityIssuer) -> str:
    """Where to start looking for ``issuer``'s keys."""
    return issuer.keys_url or issuer.issuer.rstrip("/") + "/.well-known/openid-configuration"


def vet(found: Any, where: str) -> list[dict[str, Any]]:
    """The keys of key set ``found`` the gateway can check signatures with: public keys
    for signing that name a key ID, without anything private."""
    keys = found.get("keys") if isinstance(found, dict) else None
    if not isinstance(keys, list):
        raise IssuerKeysError(f"{where} is not a key set (JWKS) or a discovery document")
    kept = []
    for key in keys:
        if not isinstance(key, dict) or key.get("kty") not in KEY_TYPES:
            continue
        if not isinstance(key.get("kid"), str) or not key["kid"]:
            continue
        if key.get("use") not in (None, "sig"):
            continue
        kept.append({k: v for k, v in key.items() if k not in PRIVATE})
    if not kept:
        raise IssuerKeysError(
            f"{where} has no signing keys with a key ID (kid) the gateway can check tokens with"
        )
    return sorted(kept, key=lambda k: str(k["kid"]))[:MAX_KEYS]


def fetch(where: str, http: httpx.Client) -> list[dict[str, Any]]:
    """The signing keys at ``where`` (a key set, or a discovery document), as the gateway is
    given them."""
    return vet(_key_set(http, where), where)


def targets(session: Session, names: list[str] | None = None) -> list[tuple[str, str]]:
    """The issuers the gateway is set to trust (all, or those ``names``), by ID, with where
    their keys are: blocked ones too, whose keys stay current for when they are unblocked."""
    stmt = select(IdentityIssuer).where(IdentityIssuer.gateway.is_(True))
    if names is not None:
        stmt = stmt.where(IdentityIssuer.name.in_(names))
    return [(i.id, keys_location(i)) for i in session.scalars(stmt.order_by(IdentityIssuer.name))]


def fetch_all(
    wanted: list[tuple[str, str]], http: httpx.Client
) -> dict[str, list[dict[str, Any]] | IssuerKeysError]:
    """Each issuer's keys, or why they couldn't be had: fetched outside any transaction."""
    found: dict[str, list[dict[str, Any]] | IssuerKeysError] = {}
    for issuer_id, where in wanted:
        try:
            found[issuer_id] = fetch(where, http)
        except IssuerKeysError as exc:
            found[issuer_id] = exc
    return found


def store(
    session: Session,
    found: dict[str, list[dict[str, Any]] | IssuerKeysError],
    *,
    now: datetime | None = None,
) -> dict[str, list[str]]:
    """Keep the keys fetched: those that changed go into the gateway's configuration; where
    they couldn't be fetched, the last ones stay, and the issuer says why."""
    when = now or ids.utcnow()
    changed: list[str] = []
    failed: list[str] = []
    for issuer_id, keys in found.items():
        issuer = session.get(IdentityIssuer, issuer_id)
        if issuer is None or not issuer.gateway:
            continue  # gone, or no longer trusted at the gateway, meanwhile
        if isinstance(keys, IssuerKeysError):
            message = str(keys)[:500]
            if issuer.keys_error != message:
                issuer.keys_error = message
                changed.append(issuer.name)
            failed.append(issuer.name)
            log.warning("keys of identity issuer %s: %s", issuer.name, message)
            continue
        if keys != issuer.gateway_keys or issuer.keys_error:
            issuer.gateway_keys, issuer.keys_error = keys, None
            changed.append(issuer.name)
        issuer.keys_at = when
    if changed:
        # The gateway's configuration takes them (agentgov.gateway).
        mark_changed(session, "issuer-keys")
    return {"changed": changed, "failed": failed}
