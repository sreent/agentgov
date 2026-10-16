"""One thing done to many agents or findings at once. Each is done on its own: one that
can't be (not in a state for it, say, or not the caller's to answer) is left as it was,
and the answer says why (docs/administration.md#many-agents-at-once,
docs/issues.md#many-at-once)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentgov import db, ids
from agentgov.config import Settings
from agentgov.db.models import Agent, Finding
from agentgov.registry import agents as agents_svc
from agentgov.registry import blueprints, classification, issues, platforms, teams, validation
from agentgov.registry import findings as findings_svc
from agentgov.registry.errors import NotFound, RegistryError, ValidationError

MAX = 500
AGENT_ACTIONS = ("approve", "block", "unblock", "delete", "restore", "update", "classify")
FINDING_ACTIONS = ("acknowledge", "resolve", "reopen", "dismiss", "accept")
# What one edit may change on many agents at once: who is accountable for them, and how
# they are governed. Sponsors are replaced, or added to and taken from each one's own.
EDITS = (
    "owner",
    "team",
    "sponsors",
    "add_sponsors",
    "remove_sponsors",
    "blueprint",
    "environment",
    "risk_tier",
)


def _refs(value: Any, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(r, str) and r for r in value):
        raise ValidationError(f"{what} is a list of {what}' names or IDs")
    refs = list(dict.fromkeys(value))
    if not refs or len(refs) > MAX:
        raise ValidationError(f"name the {what}: one at least, {MAX} at most")
    return refs


def _as_asked(
    done: list[tuple[int, dict[str, Any]]], left: list[tuple[int, dict[str, Any]]]
) -> dict[str, Any]:
    """The answer, in the order they were asked for (each is done in the order of its ID)."""
    return {
        "done": [row for _, row in sorted(done, key=lambda x: x[0])],
        "left": [row for _, row in sorted(left, key=lambda x: x[0])],
    }


def edit(tx: db.Transaction, fields: Any) -> dict[str, Any]:
    """An edit to many agents, checked once for all of them."""
    if not isinstance(fields, dict) or not fields:
        raise ValidationError(f"say what to change (fields): {', '.join(EDITS)}")
    unknown = sorted(set(fields) - set(EDITS))
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}: many agents at once take {', '.join(EDITS)}"
        )
    if "sponsors" in fields and {"add_sponsors", "remove_sponsors"} & set(fields):
        raise ValidationError("replace the sponsors, or add and remove some: not both")
    change = dict(fields)
    for key in ("sponsors", "add_sponsors", "remove_sponsors"):
        if key in change:
            change[key] = validation.string_list(change[key], key)
    for key in ("owner", "environment"):
        if key not in change:
            continue
        if change[key] is not None and not isinstance(change[key], str):
            raise ValidationError(f"{key} must be a string")
        change[key] = (change[key] or "").strip() or None
    if "team" in change:
        change["team"] = teams.reference(tx, change["team"])
    if change.get("blueprint"):
        change["blueprint"] = blueprints.get(tx, change["blueprint"]).name
    if "risk_tier" in change:
        change["risk_tier"] = validation.risk_tier(change["risk_tier"])
    return change


def _for(agent: Agent, change: dict[str, Any]) -> dict[str, Any]:
    """The edit for one agent: sponsors added to and taken from its own."""
    data = {k: v for k, v in change.items() if k not in ("add_sponsors", "remove_sponsors")}
    if "add_sponsors" in change or "remove_sponsors" in change:
        gone = {s.lower() for s in change.get("remove_sponsors", [])}
        kept = [str(s) for s in agent.sponsors or [] if str(s).lower() not in gone]
        have = {s.lower() for s in kept}
        for sponsor in change.get("add_sponsors", []):
            if sponsor.lower() not in have:
                kept.append(sponsor)
                have.add(sponsor.lower())
        data["sponsors"] = kept
    return data


def agents(
    tx: db.Transaction,
    settings: Settings,
    refs: Any,
    action: str,
    *,
    actor: str,
    reason: str | None = None,
    fields: Any = None,
    reached: set[str] | None = None,
    check: Callable[[Agent], None] | None = None,
    keep: Callable[[Agent], None] | None = None,
) -> dict[str, Any]:
    """Approve, block, unblock, delete or restore many agents, ``update`` them with
    ``fields`` (see EDITS), or ``classify`` them with ``fields`` (a classification: see
    agentgov.registry.classification). ``done`` lists those it did, with their platform for
    those found on one (blocking or deleting them here doesn't stop them there); ``left``
    those it couldn't, each with why. For a caller with a role for some teams only:
    ``reached``, the agents (by ID) of those teams, the others not found; ``check``, which
    refuses what they may not do to an agent; ``keep``, which refuses a change that takes an
    agent out of them."""
    if action not in AGENT_ACTIONS:
        raise ValidationError(f"action is {', '.join(AGENT_ACTIONS)}")
    if action == "update":
        change = edit(tx, fields)
    elif action == "classify":
        # One classification for them all, checked once.
        if not fields:
            raise ValidationError(
                "say how to classify them (fields): category, role, basis, purpose"
            )
        given = classification.normalize(fields)
    elif fields:
        raise ValidationError("fields go with update and classify")
    names = _refs(refs, "agents")
    done: list[tuple[int, dict[str, Any]]] = []
    left: list[tuple[int, dict[str, Any]]] = []
    found: dict[str, tuple[int, Agent]] = {}
    for i, ref in enumerate(names):
        try:
            agent = agents_svc.get(tx, ref)
        except NotFound:
            agent = None
        if agent is None or (reached is not None and agent.id not in reached):
            left.append((i, {"agent": ref, "why": "there is no such agent"}))
            continue
        found.setdefault(agent.id, (i, agent))
    # In the same order every time: two of these at once lock their agents in that order.
    for i, agent in sorted(found.values(), key=lambda x: x[1].id):
        try:
            with tx.savepoint():
                if check is not None:
                    check(agent)
                if action == "update":
                    changed = agents_svc.update(
                        tx, agent, _for(agent, change), actor=actor, reason=reason
                    )
                    if set(changed) & agents_svc.RISKY_FIELDS:
                        agents_svc.refresh_risk(tx, settings, agent)
                elif action == "classify":
                    classification.classify(tx, agent, given, actor=actor)
                else:
                    agents_svc.transition(tx, settings, agent, action, actor=actor, reason=reason)
                    if action in ("approve", "restore"):
                        agents_svc.refresh_risk(tx, settings, agent)
                if keep is not None:
                    keep(agent)
        except RegistryError as exc:
            left.append((i, {"agent": agent.name, "why": str(exc)}))
            continue
        platform = agent.source.removeprefix("platform:") if agent.on_platform else None
        done.append(
            (i, {"agent": agent.name, "id": agent.id, "status": agent.status, "platform": platform})
        )
    if any(d["platform"] for _, d in done):
        # Those waiting to be reviewed on their platforms: blocked or deleted, they aren't.
        platforms.review_summary(tx)
    return _as_asked(done, left)


def findings(
    tx: db.Transaction,
    refs: Any,
    action: str,
    *,
    actor: str,
    by: str | None = None,
    reason: Any = None,
    until: Any = None,
    may: Callable[[Finding], bool] | None = None,
) -> dict[str, Any]:
    """Acknowledge, resolve, reopen, dismiss (``reason``; ``until``, for a while) or accept
    the risk of (``reason`` and ``until``) many findings. ``may``: whether the caller may
    act on a finding, when they don't triage them all (acknowledging those that reached
    them). ``done`` lists those it did; ``left`` those it couldn't, each with why."""
    if action not in FINDING_ACTIONS:
        raise ValidationError(f"action is {', '.join(FINDING_ACTIONS)}")
    given = until not in (None, "")
    if action in ("dismiss", "accept") and not str(reason or "").strip():
        raise ValidationError(
            "say why they are wrong (reason): to live with real ones, accept their risk"
            if action == "dismiss"
            else "say why their risk is acceptable (reason)"
        )
    if action == "accept" and not given:
        raise ValidationError("say until when (until): a date, a time or a number of days")
    if action not in ("dismiss", "accept") and (given or reason):
        raise ValidationError(f"{action} takes no reason or until")
    # One date for them all, however long it takes.
    when = issues.parse_until(until) if given else None
    names = _refs(refs, "findings")
    done: list[tuple[int, dict[str, Any]]] = []
    left: list[tuple[int, dict[str, Any]]] = []
    found: dict[str, tuple[int, Finding]] = {}
    for i, ref in enumerate(names):
        try:
            finding = findings_svc.get(tx, ref)
        except NotFound:
            left.append((i, {"finding": ref, "title": "", "why": "there is no such finding"}))
            continue
        found.setdefault(finding.id, (i, finding))
    for i, finding in sorted(found.values(), key=lambda x: x[1].id):
        if may is not None and not may(finding):
            left.append(
                (i, {"finding": finding.id, "title": finding.title, "why": "it isn't yours"})
            )
            continue
        try:
            with tx.savepoint():
                if action == "acknowledge":
                    issues.acknowledge(tx, finding, actor=actor)
                elif action == "dismiss":
                    issues.dismiss(tx, finding, reason=reason, actor=actor, until=when, by=by)
                elif action == "accept":
                    issues.accept(
                        tx,
                        finding,
                        reason=reason,
                        until=ids.isoformat(when),
                        actor=actor,
                        by=by,
                    )
                else:
                    status = "resolved" if action == "resolve" else "open"
                    finding = findings_svc.set_status(tx, finding.id, status, actor)
        except RegistryError as exc:
            left.append((i, {"finding": finding.id, "title": finding.title, "why": str(exc)}))
            continue
        done.append((i, {"finding": finding.id, "title": finding.title, "status": finding.status}))
    return _as_asked(done, left)
