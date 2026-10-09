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

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.db import mark_changed
from agentgov.models import DISCOVERED, Agent, AgentActivity
from agentgov.registry import findings, risk


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:50].strip("-")
    return slug or "agent"


def _unique_name(session: Session, base: str) -> str:
    name, n = base, 1
    while session.scalar(select(Agent.id).where(Agent.name == name)):
        n += 1
        name = f"{base}-{n}"
    return name


def find(
    session: Session,
    *,
    agent_id: str | None = None,
    client_id: str | None = None,
    name: str | None = None,
) -> Agent | None:
    if agent_id:
        agent = session.get(Agent, agent_id)
        if agent is not None:
            return agent
    clauses = []
    if client_id:
        clauses.append(Agent.client_id == client_id)
    if name:
        clauses.append(Agent.name == name)
        clauses.append(Agent.name == _slugify(name))
    if not clauses:
        return None
    return session.scalars(select(Agent).where(or_(*clauses))).first()


def observe(
    session: Session,
    *,
    source: str,
    agent_id: str | None = None,
    client_id: str | None = None,
    name: str | None = None,
    framework: str | None = None,
    model: str | None = None,
    details: dict[str, Any] | None = None,
    seen_at: datetime | None = None,
) -> Agent | None:
    """Match an observation to an agent, registering a discovered one if needed."""
    agent = find(session, agent_id=agent_id, client_id=client_id, name=name)
    if agent is None:
        label = name or client_id or agent_id
        if not label:
            return None
        agent = Agent(
            id=ids.new_id(ids.AGENT),
            name=_unique_name(session, _slugify(label)),
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
            created_by=f"system:{source}",
        )
        session.add(agent)
        session.flush()
        ledger.append(
            session,
            type="agent.discovered",
            actor=f"system:{source}",
            agent=agent,
            severity="warning",
            details={"observed_as": label, **(details or {})},
        )
        findings.raise_finding(
            session,
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
        risk.add_signal(session, agent.id, "unregistered_activity", source)
        mark_changed(session, "agents")
    elif agent.status == DISCOVERED:
        risk.add_signal(session, agent.id, "unregistered_activity", source)
    agent.last_seen_at = seen_at or ids.utcnow()
    if framework and not agent.framework:
        agent.framework = framework
    if model and model not in (agent.models or []):
        agent.models = [*(agent.models or []), model][-20:]
    return agent


def record_activity(
    session: Session,
    agent_id: str,
    *,
    when: datetime | None = None,
    tool_calls: int = 0,
    denied: int = 0,
    model_calls: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> None:
    day = (when or ids.utcnow()).strftime("%Y-%m-%d")
    row = session.get(AgentActivity, (agent_id, day))
    if row is None:
        row = AgentActivity(
            agent_id=agent_id,
            day=day,
            tool_calls=0,
            denied=0,
            model_calls=0,
            input_tokens=0,
            output_tokens=0,
        )
        session.add(row)
    row.tool_calls += tool_calls
    row.denied += denied
    row.model_calls += model_calls
    row.input_tokens += input_tokens
    row.output_tokens += output_tokens


def import_scan(session: Session, items: list[dict[str, Any]], *, source: str) -> dict[str, int]:
    """Import scanner results: ``[{"name": ..., "framework": ..., "location": ...}]``."""
    created = matched = 0
    for item in items:
        name = item.get("name") or item.get("agent_name")
        if not isinstance(name, str) or not name:
            continue
        existing = find(session, name=name)
        observe(
            session,
            source=source,
            name=name,
            framework=item.get("framework"),
            details={
                k: v for k, v in item.items() if k in ("location", "path", "host", "evidence")
            },
        )
        if existing is None:
            created += 1
        else:
            matched += 1
    return {"created": created, "matched": matched}
