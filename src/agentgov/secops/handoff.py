"""How much AgentGov hands to the security team: the security-operations feature's level.

* off: nothing is sent, and the secops role reads, as auditors do;
* inform: SIEMs get OCSF events, Teams and Slack get alerts, and the events API serves them;
* triage: the secops role also resolves, dismisses and reopens issues;
* contain: it also blocks and unblocks agents, tool servers, model providers and identity
  issuers;
* decide: it also approves and denies the approval requests sent to approvers.

Each level includes the ones before it. The secops role is for the security team's tools
(an API key for a SIEM or SOAR) and analysts (a single sign-on role), for every team or for
one team's agents (secops@sales), at the same level; administrators and approvers act as
always, whatever the level. Everything the role does is in the ledger under its name, and
administrators can undo it.
"""

from __future__ import annotations

from typing import Any

from agentgov import db
from agentgov.identity import sso
from agentgov.registry import features
from agentgov.registry.errors import Forbidden

FEATURE = "security-operations"
LEVELS = OFF, INFORM, TRIAGE, CONTAIN, DECIDE = features.HANDOFF
ROLE = "secops"
# What each level lets the secops role do, beyond reading.
MAY = {
    TRIAGE: "resolve, dismiss and reopen issues",
    CONTAIN: "block and unblock agents, tool servers, model providers and identity issuers",
    DECIDE: "approve and deny approval requests sent to approvers",
}


def level(tx: db.Transaction) -> str:
    return features.mode(tx, FEATURE)


def at_least(tx: db.Transaction, needed: str) -> bool:
    return LEVELS.index(level(tx)) >= LEVELS.index(needed)


def _held(principal: Any) -> set[str]:
    """The roles the principal holds, for every team or for some: secops@sales is the secops
    role, which the hand-off applies to as it does for every team."""
    return {sso.split_role(role)[0] for role in principal.roles}


def acting_as_secops(principal: Any, *also: str) -> bool:
    """Whether the principal acts only through the secops role, for every team or for some (not
    as an administrator, nor with another role in ``also`` that may do this anyway, either of
    those for every team)."""
    return ROLE in _held(principal) and not principal.roles & ({"admin"} | set(also))


def check(tx: db.Transaction, principal: Any, needed: str, *, also: tuple[str, ...] = ()) -> None:
    """Refuse the secops role what the hand-off level doesn't give it."""
    if not acting_as_secops(principal, *also):
        return
    current = level(tx)
    if LEVELS.index(current) < LEVELS.index(needed):
        raise Forbidden(
            f"the hand-off to security operations is at {current}: the secops role may "
            f"{MAY[needed]} from {needed} on (an administrator sets it: the "
            f"{FEATURE} feature)"
        )


def check_kill_switch(tx: db.Transaction, principal: Any, action: str) -> None:
    """Block and unblock: what the secops role may do to agents, tool servers, model
    providers and identity issuers, from contain on. Nothing else of theirs, and nothing at
    all of anyone's but administrators' (``principal`` as it is where the agent is, for an
    agent: reach.here)."""
    if principal.is_admin:
        return
    if ROLE not in _held(principal):
        raise Forbidden(f"role {principal.role!r} may not do this")
    if action not in ("block", "unblock"):
        raise Forbidden(f"role {principal.role!r} may block and unblock, nothing else here")
    check(tx, principal, CONTAIN)


def reached(tx: db.Transaction) -> list[str]:
    """The levels the hand-off has reached, beyond off."""
    return list(LEVELS[1 : LEVELS.index(level(tx)) + 1])


def describe(tx: db.Transaction) -> dict[str, Any]:
    current = level(tx)
    reached = LEVELS.index(current)
    return {
        "level": current,
        "levels": list(LEVELS),
        "sending": reached >= LEVELS.index(INFORM),
        "secops_may": [
            MAY[lvl] for lvl in (TRIAGE, CONTAIN, DECIDE) if reached >= LEVELS.index(lvl)
        ],
    }
