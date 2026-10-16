"""AgentGov's connector allowlist, pushed into Power Platform's connector policies.

Power Platform's advanced connector policies block every connector a policy
doesn't list, for every app, flow and agent in the environments it applies to.
AgentGov keeps one such policy, ``AgentGov connector allowlist``, holding the
connectors approved on its Platforms page, and applies it to the environment
groups and environments an admin picks. It never applies it where another
connector policy already applies (an environment takes one), and it refuses to
push an empty allowlist, which would block every connector.
"""

from __future__ import annotations

from typing import Any

from agentgov import db, ids, ledger
from agentgov.db.models import PlatformAgent
from agentgov.platforms import connections
from agentgov.registry import platforms

POLICY_NAME = "AgentGov connector allowlist"
RULE_SET = "ConnectorManagement"
CONNECTOR_PATH = "/providers/Microsoft.PowerApps/apis/"
STATE_KEY = "connector-policies"


def _rule_set(policy: dict[str, Any] | None) -> dict[str, Any] | None:
    for rule_set in (policy or {}).get("ruleSets") or []:
        if isinstance(rule_set, dict) and rule_set.get("id") == RULE_SET:
            return rule_set
    return None


def is_connector_policy(policy: dict[str, Any] | None) -> bool:
    return _rule_set(policy) is not None


def ours(policies: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((p for p in policies if p.get("name") == POLICY_NAME), None)


def allowed_in(policy: dict[str, Any] | None) -> list[str] | None:
    """The connectors a policy allows (short IDs), or None when it has no connector rules."""
    rule_set = _rule_set(policy)
    if rule_set is None:
        return None
    entries = (rule_set.get("inputs") or {}).get("AllowedConnectorList") or []
    found = {
        platforms.connector_key(e.get("AllowedConnector"))
        for e in entries
        if isinstance(e, dict) and e.get("AllowedConnector")
    }
    return sorted(c for c in found if c)


def approved(tx: db.Where) -> list[str]:
    return sorted(c.connector_id for c in platforms.approved_connectors(tx))


def policy_body(connectors: list[str], existing: dict[str, Any] | None) -> dict[str, Any]:
    """The policy, allowing exactly ``connectors`` (all their actions and connections)."""
    # Keep the rule set's version as the service gave it.
    version = (_rule_set(existing) or {}).get("version") or "1.0"
    return {
        "name": POLICY_NAME,
        "ruleSets": [
            {
                "id": RULE_SET,
                "version": version,
                "inputs": {
                    "AllowedConnectorList": [
                        {
                            "AllowedConnector": f"{CONNECTOR_PATH}{connector}",
                            "AllowedActionsMode": "AllAllowed",
                            "AllowedConnectionTypesMode": "AllAllowed",
                        }
                        for connector in connectors
                    ]
                },
            }
        ],
    }


def studio_environments(tx: db.Where) -> dict[str, int]:
    """Environments with Copilot Studio agents, and how many agents each holds."""
    counts: dict[str, int] = {}
    for record in PlatformAgent.objects.filter(source="copilot-studio"):
        environment = (record.data or {}).get("environment_id")
        if environment:
            counts[str(environment)] = counts.get(str(environment), 0) + 1
    return counts


def preview(
    tx: db.Where,
    policies: list[dict[str, Any]],
    targets: list[dict[str, Any]],
) -> dict[str, Any]:
    """What pushing the allowlist would do, given Power Platform's current state.

    ``targets`` are environment groups and environments, each with the IDs of the
    policies applied to it (``assigned``).
    """
    allowlist = approved(tx)
    mine = ours(policies)
    mine_id = str(mine["id"]) if mine is not None else None
    names = {str(p.get("id")): p.get("name") for p in policies}
    connector_policies = {str(p.get("id")) for p in policies if is_connector_policy(p)}
    rows = []
    for target in targets:
        assigned = [str(a) for a in target.get("assigned") or []]
        rows.append(
            {
                **{k: v for k, v in target.items() if k != "assigned"},
                "applied": mine_id in assigned,
                # An environment takes one connector policy: AgentGov won't replace these.
                "other_policies": [
                    names.get(a) or a for a in assigned if a in connector_policies and a != mine_id
                ],
            }
        )
    # Agents that use connectors outside the allowlist lose them wherever it applies.
    losing = []
    for record in PlatformAgent.objects.filter(source="copilot-studio"):
        data = record.data or {}
        used = sorted({c["connector_id"] for c in data.get("connectors") or []})
        lost = [c for c in used if c not in allowlist]
        if lost:
            losing.append(
                {
                    "agent_id": record.agent_id,
                    "name": record.name,
                    "environment_id": data.get("environment_id"),
                    "connectors": lost,
                }
            )
    in_power_platform = allowed_in(mine)
    return {
        "policy_name": POLICY_NAME,
        "policy_id": mine.get("id") if mine else None,
        "allowlist": allowlist,
        # What Microsoft's copy of the policy allows now, when it differs.
        "in_power_platform": in_power_platform,
        "out_of_date": in_power_platform is not None and in_power_platform != allowlist,
        "targets": rows,
        "agents_losing_connectors": losing,
    }


def record_push(
    tx: db.Where,
    *,
    policy_id: str,
    connectors: list[str],
    targets: list[dict[str, Any]],
    actor: str,
) -> None:
    connections.save_state(
        tx,
        STATE_KEY,
        {
            "policy_id": policy_id,
            "connectors": connectors,
            "targets": targets,
            "pushed_at": ids.isoformat(ids.utcnow()),
            "pushed_by": actor,
        },
    )
    ledger.append(
        tx,
        type="connector_policy.pushed",
        actor=actor,
        severity="warning",
        resource=f"power-platform/policy/{policy_id}",
        details={"policy": POLICY_NAME, "connectors": connectors, "targets": targets},
    )
    platforms.set_sync(
        tx,
        STATE_KEY,
        ok=True,
        counts={"connectors": len(connectors), "targets": len(targets)},
    )


def pushed(tx: db.Where) -> dict[str, Any]:
    """The last push, and whether the allowlist has changed since."""
    state = connections.load_state(tx, STATE_KEY)
    if not state:
        return {}
    return {**state, "out_of_date": state.get("connectors") != approved(tx)}
