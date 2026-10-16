"""Where an organisation starts (docs/administration.md#start-here).

It says where its agents are: AgentGov turns on what reads those places, turns off what
reads places it doesn't use, and starts from the inventory starting point, or from the
monitor one when agents will call through its gateway. A checklist then leads to a first
useful day: its agents found, a catch-all team named, the agents reviewed, an owner for
each. The checklist is worked out from what is in the registry, so it is never out of date.
"""

from __future__ import annotations

from typing import Any

from agentgov import db, ids, ledger
from agentgov.config import Settings
from agentgov.db.models import DELETED, DISCOVERED, Agent, FeatureSetting, IntegrationState
from agentgov.registry import features, teams
from agentgov.registry.errors import ValidationError

STATE = "start"
GATEWAY = "gateway"
# Where an organisation's agents may be: its name, the features that read it, and how
# AgentGov finds its agents.
PLACES: dict[str, tuple[str, tuple[str, ...], str]] = {
    "copilot-studio": (
        "Copilot Studio",
        (),
        "Import its inventory on the Platforms page (a Power Platform admin's export)",
    ),
    "microsoft-365": (
        "Microsoft 365 Copilot agents",
        ("microsoft-365",),
        "Connect AgentGov's app to Microsoft 365 (an Agent 365 licence)",
    ),
    "entra-agent-id": (
        "Microsoft Entra Agent ID",
        ("entra-agent-id",),
        "Connect AgentGov's app to Microsoft Entra",
    ),
    "aws": ("AWS", ("aws",), "Give AgentGov read access to your AWS accounts"),
    "google-cloud": (
        "Google Cloud",
        ("google-cloud",),
        "Give AgentGov read access to your projects",
    ),
    "salesforce": ("Salesforce", ("salesforce",), "Connect AgentGov to your Salesforce org"),
    "databricks": ("Databricks", ("databricks",), "Connect AgentGov to your workspaces"),
    "microsoft-foundry": (
        "Microsoft Foundry",
        ("microsoft-foundry",),
        "Give AgentGov read access to your Foundry projects",
    ),
    GATEWAY: (
        "Our own agents, through AgentGov's gateway",
        (),
        "Register an agent, and point it at the gateway",
    ),
}
# With Microsoft's platforms, what Microsoft knows about their agents too.
MICROSOFT = {"copilot-studio", "microsoft-365", "entra-agent-id"}
MICROSOFT_EXTRAS = ("purview-audit", "defender", "entra-users")
READERS = tuple(
    sorted({key for _, keys, _ in PLACES.values() for key in keys} | set(MICROSOFT_EXTRAS))
)


def _row() -> IntegrationState:
    """Where the organisation said it starts from (a new row if it said nothing yet)."""
    return IntegrationState.objects.filter(pk=STATE).first() or IntegrationState(key=STATE, data={})


def answer(tx: db.Transaction, settings: Settings, value: Any, *, actor: str) -> dict[str, Any]:
    """Where the organisation's agents are (``{"places": [...]}``): what reads them on,
    what reads other places off (but what the deployment pins), and the starting point."""
    if not isinstance(value, dict) or set(value) - {"places"}:
        raise ValidationError('send {"places": [...]}: ' + ", ".join(PLACES))
    places = value.get("places")
    if not isinstance(places, list) or not places:
        raise ValidationError("say where your agents are: one place at least, " + ", ".join(PLACES))
    unknown = sorted({str(p) for p in places} - set(PLACES))
    if unknown:
        raise ValidationError(f"unknown place(s) {', '.join(unknown)}: " + ", ".join(PLACES))
    chosen = [p for p in PLACES if p in places]
    gateway = GATEWAY in chosen
    preset = "monitor" if gateway else "inventory"
    features.apply_preset(tx, settings, preset, actor=actor)
    wanted = {key for p in chosen for key in PLACES[p][1]}
    if MICROSOFT & set(chosen):
        wanted |= set(MICROSOFT_EXTRAS)
    changed = []
    for key in READERS:
        row = FeatureSetting.objects.filter(pk=key).first()
        if row is not None and row.pinned:
            continue  # the deployment decides
        mode = features.ON if key in wanted else features.OFF
        if features.set_mode(tx, settings, key, mode, actor=actor):
            changed.append(f"{key}={mode}")
    row = _row()
    now = ids.utcnow()
    row.data = {**(row.data or {}), "places": chosen, "by": actor, "at": ids.isoformat(now)}
    row.updated_at = now
    row.save(force_insert=row._state.adding)
    ledger.append(
        tx,
        type="start.answered",
        actor=actor,
        details={"places": chosen, "starting_point": preset, "features": changed},
    )
    return checklist(tx)


def hide(tx: db.Transaction, hidden: bool, *, actor: str) -> dict[str, Any]:
    """Hide the checklist (or show it again)."""
    row = _row()
    row.data = {**(row.data or {}), "hidden": bool(hidden)}
    row.updated_at = ids.utcnow()
    row.save(force_insert=row._state.adding)
    return checklist(tx)


def checklist(tx: db.Transaction) -> dict[str, Any]:
    """Where the organisation is: what it said it has, and each step to a first useful day,
    done or not, worked out from the registry."""
    data = _row().data or {}
    places = [p for p in data.get("places") or [] if p in PLACES]
    agents = list(Agent.objects.exclude(status=DELETED))
    to_review = sum(1 for a in agents if a.status == DISCOVERED and a.on_platform)
    unowned = sum(1 for a in agents if not a.owner and (a.status != DISCOVERED or a.on_platform))
    team = teams.default(tx)
    steps = [
        {
            "key": "places",
            "title": "Say where your agents are",
            "done": bool(places),
            "detail": ", ".join(PLACES[p][0] for p in places)
            if places
            else "AgentGov then turns on only what reads those places.",
        },
        {
            "key": "agents",
            "title": "Find your agents",
            "done": bool(agents),
            "detail": f"{len(agents)} found" if agents else None,
            "how": [{"place": p, "name": PLACES[p][0], "how": PLACES[p][2]} for p in places],
        },
        {
            "key": "team",
            "title": "Name a catch-all team",
            "done": team is not None,
            "detail": f"Team {team.name}"
            if team is not None
            else "Issues that no agent's owner, sponsor or team takes go to it.",
        },
        {
            "key": "review",
            "title": "Review the agents found",
            "done": bool(agents) and not to_review,
            "detail": f"{to_review} left to review: adopt the ones you keep" if to_review else None,
        },
        {
            "key": "owners",
            "title": "Give every agent an owner",
            "done": bool(agents) and not unowned,
            "detail": f"{unowned} without an owner" if unowned else None,
        },
    ]
    return {
        "places": places,
        "choices": [{"place": p, "name": name} for p, (name, _, _) in PLACES.items()],
        "steps": steps,
        "done": all(s["done"] for s in steps),
        "hidden": bool(data.get("hidden")),
    }
