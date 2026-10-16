"""Shadow-agent discovery: reconcile runtime observations against the registry.

Observations come from OpenTelemetry spans, from callers the gateway sees
without a registered identity (monitor mode), and from scanner imports (for
example the Agent Governance Toolkit's ``agent-discovery`` output). Anything
that does not match a registered agent is recorded as ``discovered``, the
equivalent of Agent 365's "unmanaged agents".
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from django.db.models import F, Q

from agentgov import db, ids, ledger
from agentgov.db import mark_changed
from agentgov.db.models import Agent, AgentActivity, IdentityIssuer
from agentgov.models import DISCOVERED
from agentgov.registry import findings, risk


def slugify(value: str) -> str:
    """A registry name for something known only by a display name."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:50].strip("-")
    return slug or "agent"


def unique_name(tx: db.Where, base: str) -> str:
    """``base``, or ``base-2``, ``base-3``... if an agent already has that name."""
    name, n = base, 1
    while Agent.objects.filter(name=name).exists():
        n += 1
        name = f"{base}-{n}"
    return name


def _workload(tx: db.Where, issuer: str | None, subject: str | None) -> tuple[str, str] | None:
    """The workload identity (issuer name, subject) a token of an issuer the gateway trusts
    names, or None."""
    if not issuer or not subject:
        return None
    found = IdentityIssuer.objects.filter(issuer=issuer, gateway=True).first()
    return (found.name, str(subject)[:512]) if found is not None else None


def find(
    tx: db.Where,
    *,
    agent_id: str | None = None,
    client_id: str | None = None,
    name: str | None = None,
) -> Agent | None:
    if agent_id:
        agent = Agent.objects.filter(pk=agent_id).first()
        if agent is not None:
            return agent
    clauses = Q()
    if client_id:
        clauses |= Q(client_id=client_id)
    if name:
        clauses |= Q(name=name) | Q(name=slugify(name))
    if not clauses:
        return None
    return Agent.objects.filter(clauses).first()


def observe(
    tx: db.Where,
    *,
    source: str,
    agent_id: str | None = None,
    client_id: str | None = None,
    name: str | None = None,
    framework: str | None = None,
    model: str | None = None,
    details: dict[str, Any] | None = None,
    seen_at: datetime | None = None,
    discover: bool = True,
    issuer: str | None = None,
    subject: str | None = None,
) -> Agent | None:
    """Match an observation to an agent, registering a discovered one if needed (and
    ``discover``: the discovery feature is on). ``issuer`` and ``subject``: a token of an
    identity issuer the gateway trusts, which names the agent by its workload identity; a
    discovered agent takes it on, so that adopting it is all it needs
    (docs/agent-identity.md#straight-to-the-gateway)."""
    workload = _workload(tx, issuer, subject)
    agent = None
    if workload is not None:
        agent = Agent.objects.filter(
            workload_issuer=workload[0], workload_subject=workload[1]
        ).first()
    if agent is None and workload is None:
        agent = find(tx, agent_id=agent_id, client_id=client_id, name=name)
    if agent is None:
        label = name or client_id or agent_id
        if not label or not discover:
            return None
        agent = Agent(
            id=ids.new_id(ids.AGENT),
            name=unique_name(tx, slugify(label)),
            description=f"Discovered via {source}; not registered.",
            status=DISCOVERED,
            source=f"discovered:{source}",
            framework=framework,
            sponsors=[],
            labels={},
            models=[],
            permissions=[],
            external_ids={
                k: v
                for k, v in {"agent_id": agent_id, "client_id": client_id, "name": name}.items()
                if v
            },
            workload_issuer=workload[0] if workload else None,
            workload_subject=workload[1] if workload else None,
            created_by=f"system:{source}",
        )
        agent.save(force_insert=True)
        ledger.append(
            tx,
            type="agent.discovered",
            actor=f"system:{source}",
            agent=agent,
            severity="warning",
            details={"observed_as": label, **(details or {})},
        )
        findings.raise_finding(
            tx,
            type="agent.unmanaged",
            severity="high",
            subject=agent.id,
            agent_id=agent.id,
            title=f"Unmanaged agent discovered: {label}",
            description=f"An agent was observed via {source} but is not registered, so it has no "
            "owner, sponsor, blueprint or governed identity.",
            remediation="Adopt it (assign an owner, sponsors and a blueprint, then approve) or "
            "block it.",
            details=details or {},
        )
        risk.add_signal(tx, agent.id, "unregistered_activity", source)
        mark_changed(tx, "agents")
    elif agent.status == DISCOVERED:
        risk.add_signal(tx, agent.id, "unregistered_activity", source)
    agent.last_seen_at = seen_at or ids.utcnow()
    if framework and not agent.framework:
        agent.framework = framework
    if model and model not in (agent.models or []):
        agent.models = [*(agent.models or []), model][-20:]
    agent.save()
    return agent


def seen(agent_id: str, when: datetime) -> None:
    """Record that the agent was seen at ``when``, unless it was seen later already."""
    Agent.objects.filter(
        Q(last_seen_at__isnull=True) | Q(last_seen_at__lt=when), pk=agent_id
    ).update(last_seen_at=when, updated_at=ids.utcnow())


def record_activity(
    tx: db.Where,
    agent_id: str,
    *,
    when: datetime | None = None,
    tool_calls: int = 0,
    denied: int = 0,
    model_calls: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> None:
    """Add to the agent's counters for the day."""
    day = (when or ids.utcnow()).strftime("%Y-%m-%d")
    counts = {
        "tool_calls": tool_calls,
        "denied": denied,
        "model_calls": model_calls,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }
    added = {name: F(name) + n for name, n in counts.items() if n}
    if added and not AgentActivity.objects.filter(agent_id=agent_id, day=day).update(**added):
        AgentActivity.objects.create(agent_id=agent_id, day=day, **counts)


def import_scan(
    tx: db.Where, items: list[dict[str, Any]], *, source: str, discover: bool = True
) -> dict[str, int]:
    """Import scanner results: ``[{"name": ..., "framework": ..., "location": ...}]``. One
    that names an agent there is matched; one that doesn't is recorded as unmanaged while
    ``discover`` (the discovery feature) is on. A scan sees what is installed, not what
    runs: it marks only unmanaged agents as seen, never registered ones."""
    created = matched = 0
    for item in items:
        name = item.get("name") or item.get("agent_name")
        if not isinstance(name, str) or not name:
            continue
        existing = find(tx, name=name)
        if existing is not None:
            matched += 1
            if existing.status != DISCOVERED:
                continue
        details = {k: v for k, v in item.items() if k in ("location", "path", "host", "evidence")}
        seen = observe(
            tx,
            source=source,
            name=name,
            framework=item.get("framework"),
            details=details,
            discover=discover,
        )
        if existing is None and seen is not None:
            created += 1
    return {"created": created, "matched": matched}
