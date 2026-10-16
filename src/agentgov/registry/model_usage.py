"""What agents spend on model calls through the gateway, and their daily token budgets.

agentgateway logs every model call it serves: the route (so the provider), the
model, the tokens in and out, and the agent's identity from its token. It sends
these access logs over OTLP, through the OpenTelemetry Collector, to the control
plane, which adds them up per agent, UTC day, provider and model (``ModelUsage``)
and prices them with the provider's prices.

An agent that reaches its daily token budget is over budget until the day ends:
OPA learns it from the bundle (``over_budget``) and, while the token-budgets
control is enforced, its further model calls are refused.

Usage also adds up per owner and per sponsor of the agents behind it
(``spend``), for the people and teams who answer for what agents cost.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from django.db.models import F, Sum

from agentgov import db, ids, ledger
from agentgov.db import mark_changed
from agentgov.db.models import Agent, IdentityIssuer, ModelUsage
from agentgov.registry import discovery, model_providers
from agentgov.telemetry import attrs_of

ROUTE_PREFIX = "llm-"  # agentgov.gateway names a provider's route llm-<provider>
REFUSED = {401, 403}  # no valid agent token; refused by policy


def today() -> str:
    """The UTC day usage is counted in, as YYYY-MM-DD."""
    return ids.utcnow().date().isoformat()


def tokens_used(tx: db.Transaction, day: str | None = None) -> dict[str, int]:
    """Tokens (input and output) each agent used on ``day`` (today by default)."""
    rows = (
        ModelUsage.objects.filter(day=day or today())
        .exclude(agent_id="")
        .values("agent_id")
        .annotate(total=Sum(F("input_tokens") + F("output_tokens")))
        .order_by()
        .values_list("agent_id", "total")
    )
    return {agent_id: int(total or 0) for agent_id, total in rows}


def over_budget(budget: int | None, used: int) -> bool:
    return budget is not None and used >= budget


def to_dict(row: ModelUsage) -> dict[str, Any]:
    return {
        "agent_id": row.agent_id or None,
        "day": row.day,
        "provider": row.provider,
        "model": row.model,
        "calls": row.calls,
        "refused": row.refused,
        "input_tokens": row.input_tokens,
        "output_tokens": row.output_tokens,
        "cost_usd": round(row.cost_usd, 6),
    }


# ------------------------------------------------------------------ metering


def iter_log_records(payload: dict[str, Any]) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """(attributes, record) for each OTLP log record."""
    for rl in payload.get("resourceLogs") or []:
        for sl in rl.get("scopeLogs") or []:
            for record in sl.get("logRecords") or []:
                yield attrs_of(record.get("attributes")), record


def _when(record: dict[str, Any]) -> datetime:
    # agentgateway leaves the record's time unset; the collector stamps when it saw it.
    for key in ("timeUnixNano", "observedTimeUnixNano"):
        try:
            nanos = int(record.get(key) or 0)
        except (TypeError, ValueError):
            nanos = 0
        if nanos:
            return datetime.fromtimestamp(nanos / 1e9, tz=UTC)
    return ids.utcnow()


def _int(value: Any) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def _metered(
    tx: db.Transaction,
    agent_id: Any,
    client_id: Any,
    issuer: Any,
    subject: Any,
) -> Agent | None:
    """The agent a model call was made by, as the gateway's access log names it."""
    if agent_id or client_id:
        return discovery.find(tx, agent_id=agent_id, client_id=client_id)
    if not (issuer and subject):
        return None
    names = IdentityIssuer.objects.filter(issuer=str(issuer)).values_list("name", flat=True)
    return Agent.objects.filter(
        workload_issuer__in=list(names), workload_subject=str(subject)
    ).first()


# A row's counts, which each model call adds to.
COUNTS = ("calls", "refused", "input_tokens", "output_tokens", "cost_usd")


def ingest_logs(tx: db.Transaction, payload: dict[str, Any]) -> dict[str, int]:
    """Meter the model calls in agentgateway's access logs (OTLP logs)."""
    stats = {"records": 0, "model_calls": 0, "unidentified": 0}
    providers = {p.name: p for p in model_providers.list_all(tx)}
    agents: dict[tuple[str | None, ...], Agent | None] = {}
    spent: dict[tuple[str, str], int] = {}  # tokens per (agent, day) in this batch
    # What this batch adds to each row (agent, day, provider, model), and to each agent's
    # activity on a day.
    added: dict[tuple[str, str, str, str], dict[str, float]] = {}
    activity: dict[tuple[str, str], dict[str, Any]] = {}
    last_seen: dict[str, datetime] = {}
    for attrs, record in iter_log_records(payload):
        stats["records"] += 1
        route = str(attrs.get("route") or "").rsplit("/", 1)[-1]
        if not route.startswith(ROUTE_PREFIX) or not attrs.get("gen_ai.operation.name"):
            continue  # not a model call through AgentGov's gateway
        stats["model_calls"] += 1
        provider = route.removeprefix(ROUTE_PREFIX)
        model = str(attrs.get("gen_ai.response.model") or attrs.get("gen_ai.request.model") or "")
        tokens_in = _int(attrs.get("gen_ai.usage.input_tokens"))
        tokens_out = _int(attrs.get("gen_ai.usage.output_tokens"))
        status = _int(attrs.get("http.response.status_code"))
        when = _when(record)
        # The agent or client AgentGov's own token names, or the workload identity (issuer,
        # subject) another issuer's names, whose token the gateway took.
        identity = (
            attrs.get("agentgov.agent_id"),
            attrs.get("agentgov.client_id"),
            attrs.get("agentgov.issuer"),
            attrs.get("agentgov.subject"),
        )
        if identity not in agents:
            agents[identity] = _metered(tx, *identity)
        agent = agents[identity]
        if agent is None:
            stats["unidentified"] += 1
        day = when.date().isoformat()
        key = (agent.id if agent else "", day, provider, model[:128])
        row = added.setdefault(key, dict.fromkeys(COUNTS, 0))
        row["calls"] += 1
        row["refused"] += 1 if status in REFUSED else 0
        row["input_tokens"] += tokens_in
        row["output_tokens"] += tokens_out
        price = model_providers.price_of(providers.get(provider), model)
        if price:
            row["cost_usd"] += (tokens_in * price["input"] + tokens_out * price["output"]) / 1e6
        if agent is not None:
            last_seen[agent.id] = max(last_seen.get(agent.id, when), when)
            seen = activity.setdefault(
                (agent.id, day),
                {"when": when, "model_calls": 0, "input_tokens": 0, "output_tokens": 0},
            )
            seen["model_calls"] += 1
            seen["input_tokens"] += tokens_in
            seen["output_tokens"] += tokens_out
            spent[(agent.id, day)] = spent.get((agent.id, day), 0) + tokens_in + tokens_out
    for (agent_id, day, provider, model), counts in added.items():
        _add(agent_id, day, provider, model, counts)
    for (agent_id, _), counts in activity.items():
        discovery.record_activity(tx, agent_id, **counts)
    for agent_id, when in last_seen.items():
        discovery.seen(agent_id, when)
    _budgets_reached(tx, spent)
    return stats


def _add(agent_id: str, day: str, provider: str, model: str, counts: dict[str, float]) -> None:
    """Add to the usage of an agent (or of unidentified callers: ``""``) on a day, with a
    provider's model."""
    key = {"agent_id": agent_id, "day": day, "provider": provider, "model": model}
    if not ModelUsage.objects.filter(**key).update(
        **{name: F(name) + n for name, n in counts.items()}
    ):
        ModelUsage.objects.create(**key, **counts)


def _budgets_reached(tx: db.Transaction, spent: dict[tuple[str, str], int]) -> None:
    """Record the agents whose usage today reached their budget in this batch, and have OPA
    refuse their further calls."""
    day = today()
    used = tokens_used(tx, day) if any(d == day for _, d in spent) else {}
    for (agent_id, spent_day), tokens in spent.items():
        agent = Agent.objects.filter(pk=agent_id).first()
        budget = model_providers.effective_budget(agent) if agent else None
        if spent_day != day or budget is None:
            continue
        after = used.get(agent_id, 0)
        if after - tokens < budget <= after:
            ledger.append(
                tx,
                type="model.budget_reached",
                actor="system:usage",
                agent=agent,
                severity="warning",
                reason=f"{after} of {budget} tokens used today",
                details={"budget": budget, "used": after, "day": day},
            )
            mark_changed(tx, "agents")


SPEND_BY = ("owner", "sponsor")


def spend(tx: db.Transaction, rows: list[ModelUsage]) -> dict[str, list[dict[str, Any]]]:
    """``rows`` added up per owner and per sponsor of their agents, the costliest first.

    An agent with several sponsors counts in full for each; an agent without an owner
    or sponsors counts under ``None``. Calls from unidentified callers aren't included.
    """
    ids_ = {r.agent_id for r in rows if r.agent_id}
    agents = Agent.objects.in_bulk(ids_) if ids_ else {}
    groups: dict[str, dict[str | None, dict[str, Any]]] = {by: {} for by in SPEND_BY}
    for row in rows:
        agent = agents.get(row.agent_id)
        if agent is None:
            continue
        names = {"owner": [agent.owner or None], "sponsor": list(agent.sponsors or []) or [None]}
        for by in SPEND_BY:
            for name in dict.fromkeys(names[by]):
                group = groups[by].setdefault(
                    name,
                    {by: name, "agents": set(), "calls": 0, "input_tokens": 0,
                     "output_tokens": 0, "cost_usd": 0.0},
                )  # fmt: skip
                group["agents"].add(agent.id)
                group["calls"] += row.calls
                group["input_tokens"] += row.input_tokens
                group["output_tokens"] += row.output_tokens
                group["cost_usd"] += row.cost_usd
    return {
        by: sorted(
            (
                {**g, "agents": len(g["agents"]), "cost_usd": round(g["cost_usd"], 6)}
                for g in groups[by].values()
            ),
            key=lambda g: (-g["cost_usd"], -(g["input_tokens"] + g["output_tokens"])),
        )
        for by in SPEND_BY
    }


def usage(
    tx: db.Transaction,
    *,
    days: int = 7,
    agent_id: str | None = None,
    provider: str | None = None,
) -> list[ModelUsage]:
    """Usage rows for the last ``days`` days (today included), newest first."""
    since = (ids.utcnow().date() - timedelta(days=max(days, 1) - 1)).isoformat()
    rows = ModelUsage.objects.filter(day__gte=since)
    if agent_id is not None:
        rows = rows.filter(agent_id=agent_id)
    if provider:
        rows = rows.filter(provider=provider)
    return list(rows.order_by("-day", "provider", "model"))
