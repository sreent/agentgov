"""Microsoft's services that AgentGov can use, each of them optional.

AgentGov governs agents without any of them. Each one it can reach adds
something: an inventory, identities, usage, threat alerts or enforcement. A
connection is turned on by what it needs (AgentGov's app registration holding
an application permission, admins who sign in through Microsoft Entra ID, or a
setting) and is otherwise left out, without affecting anything else. Its state
(working, waiting for its first run, missing a permission, failing) is shown on
the Platforms page, with what it takes to turn it on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import db, ids
from agentgov.config import Settings
from agentgov.db.models import IntegrationState
from agentgov.models import ApprovedConnector, PlatformSync
from agentgov.registry import features

# Where the permissions granted to AgentGov's app registration are remembered.
APP_STATE = "microsoft-app"
ENTRA_ACCESS = "entra-access-packages"
# What managing Entra's access packages takes, besides a catalog role.
WRITE = "EntitlementManagement.ReadWrite.All"
# Besides User.Read.All, what reads users: User.ReadBasic.All doesn't say whose account is
# disabled (agentgov.platforms.microsoft.USER_ROLES).
USERS_ALSO = ("User.ReadBasic.All", "Directory.Read.All", "User.ReadWrite.All")


@dataclass(frozen=True)
class Connection:
    key: str
    name: str
    gives: str
    # "app": AgentGov's app registration reads it on a schedule; "admin": a signed-in
    # admin does it; "endpoint": Microsoft calls AgentGov.
    via: str
    permission: str | None = None
    licence: str | None = None
    # Permissions that include ``permission``: holding one of them is enough.
    also: tuple[str, ...] = ()


CONNECTIONS: tuple[Connection, ...] = (
    Connection(
        "microsoft-365",
        "Microsoft 365 agent catalog",
        "Agents in Microsoft 365 Copilot: built in your organisation, shared by users, or "
        "from partners, with declarative agents' instructions",
        via="app",
        permission="CopilotPackages.Read.All",
        licence="Microsoft Agent 365",
    ),
    Connection(
        "copilot-studio",
        "Copilot Studio inventory",
        "Copilot Studio and Agent Builder agents with their settings and connectors, read as "
        "the signed-in admin (or imported from an export)",
        via="admin",
    ),
    Connection(
        "entra-agent-id",
        "Microsoft Entra Agent ID",
        "Agents' Entra identities, linked to the agents they belong to, and whether they are "
        "enabled; agents that only Entra knows about are added as unmanaged",
        via="app",
        permission="AgentIdentity.Read.All",
    ),
    Connection(
        "entra-users",
        "Microsoft Entra users",
        "The people Copilot Studio names as its agents' owners and makers, and the owners and "
        "sponsors AgentGov names: their names, email addresses, and whether they have left",
        via="app",
        permission="User.Read.All",
        also=USERS_ALSO,
    ),
    Connection(
        "purview-audit",
        "Microsoft Purview audit log",
        "Who uses each agent and how often, jailbreak and prompt-injection attempts against "
        "them, and makers creating, publishing and sharing Copilot Studio agents",
        via="app",
        permission="AuditLogsQuery.Read.All",
    ),
    Connection(
        "defender",
        "Microsoft Defender alerts",
        "Microsoft's threat detections for agents, as findings on the agents they concern",
        via="app",
        permission="SecurityAlert.Read.All",
        licence="Microsoft Agent 365",
    ),
    Connection(
        "entra-access-packages",
        "Microsoft Entra access packages",
        "The access packages Entra ID Governance assigns agents' Entra identities, and when "
        "each expires; managed, administrators assign and remove them from AgentGov",
        via="app",
        permission="EntitlementManagement.Read.All",
        licence="Microsoft Agent 365",
        also=("EntitlementManagement.ReadWrite.All",),
    ),
    Connection(
        "connector-policies",
        "Power Platform connector policies",
        "AgentGov's connector allowlist pushed into Power Platform's advanced connector "
        "policies, which block other connectors",
        via="admin",
    ),
    Connection(
        "threat-detection",
        "Copilot Studio threat detection",
        "A decision from AgentGov's policies before each tool call a Copilot Studio agent "
        "makes: recorded, and blocked when the policies say so",
        via="endpoint",
    ),
)
BY_KEY = {c.key: c for c in CONNECTIONS}
APP_CONNECTIONS = tuple(c.key for c in CONNECTIONS if c.via == "app")


def load_state(tx: db.Where, key: str) -> dict[str, Any]:
    state = IntegrationState.objects.filter(pk=key).first()
    return dict(state.data or {}) if state is not None else {}


def save_state(tx: db.Where, key: str, data: dict[str, Any]) -> None:
    state = IntegrationState.objects.filter(pk=key).first() or IntegrationState(key=key)
    state.data, state.updated_at = data, ids.utcnow()
    state.save(force_insert=state._state.adding)


def remember_grants(session: Session, roles: frozenset[str] | None) -> None:
    """Remember which application permissions the app registration holds."""
    save_state(session, APP_STATE, {"roles": sorted(roles) if roles is not None else None})


def granted(session: Session) -> frozenset[str] | None:
    """The app's application permissions as last seen; ``None`` if unknown."""
    state = IntegrationState.objects.filter(pk=APP_STATE).first()
    roles = (state.data or {}).get("roles") if state is not None else None
    return frozenset(roles) if isinstance(roles, list) else None


def runnable(connection: Connection, roles: frozenset[str] | None) -> bool:
    """Whether to try an app connection: its permission is granted, or Entra didn't say."""
    return roles is None or bool({connection.permission, *connection.also} & roles)


def state(
    session: Session, settings: Settings, *, threat_detection: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Each connection, what it needs and how it is doing."""
    roles = granted(session)
    rows = []
    for c in CONNECTIONS:
        sync = session.get(PlatformSync, c.key)
        last = (
            {
                "at": ids.isoformat(sync.synced_at),
                "ok": sync.ok,
                "message": sync.message,
                "counts": sync.counts or {},
            }
            if sync
            else None
        )
        needs: list[str] = []
        if c.via == "app":
            if not features.is_on(session, c.key):
                status = "turned_off"  # in Features
            elif not settings.m365_enabled:
                status = "off"
                needs.append(
                    "AgentGov's app registration (AGENTGOV_M365_TENANT_ID, "
                    "AGENTGOV_M365_CLIENT_ID and AGENTGOV_M365_CLIENT_SECRET)"
                )
            elif not runnable(c, roles):
                status = "missing_permission"
            elif last is None:
                status = "waiting"
            else:
                status = "ok" if last["ok"] else "failing"
            if c.permission:
                needs.append(f"the application permission {c.permission}")
        elif c.via == "admin":
            if settings.microsoft_admin_actions and c.key == "connector-policies":
                pushed = load_state(session, c.key).get("connectors")
                current = sorted(session.scalars(select(ApprovedConnector.connector_id)))
                if pushed is None:
                    status = "available"
                else:
                    status = "ok" if pushed == current else "out_of_date"
            elif settings.microsoft_admin_actions:
                status = "ok" if last and last["ok"] else ("failing" if last else "available")
            elif c.key == "copilot-studio":
                # Without a Microsoft sign-in, the inventory can still be imported.
                status = "ok" if last and last["ok"] else ("failing" if last else "import")
            else:
                status = "off"
            needs.append("admins who sign in through Microsoft Entra ID with admin actions on")
        else:
            mode = (threat_detection or {}).get("mode", "off")
            status = mode if mode != "off" else "off"
            needs.append(
                "an HTTPS address Microsoft can reach, and a Power Platform admin to "
                "connect it to each environment"
            )
        if c.licence:
            needs.append(f"a {c.licence} licence")
        row = {
            "key": c.key,
            "name": c.name,
            "gives": c.gives,
            "via": c.via,
            "permission": c.permission,
            "licence": c.licence,
            "status": status,
            "needs": needs,
            "last_run": last,
        }
        if c.key == ENTRA_ACCESS and features.mode(session, c.key) == features.MANAGE:
            # Managing writes into Entra: with the permission, or a catalog role Entra
            # doesn't put in the app's token (so AgentGov tries, and says what Entra said).
            row["manage"] = "unknown" if roles is None or WRITE not in roles else "ok"
            needs.append(
                f"to manage: {WRITE}, or the Access package assignment manager role in the "
                "packages' catalogs"
            )
        rows.append(row)
    return rows
