"""Whether each feature can do what its mode says (docs/features.md#is-it-working).

A mode says what should happen; this says what can. A feature can be on and do nothing
(data protection with no Presidio to look for personal data), do part of it (Presidio
down, with its failure mode open), or stop more than it should (OPA down while a control
is enforced: every call through the gateway is refused, as AGENTGOV_GATEWAY_FAILURE_MODE
says).

What AgentGov knows comes from two places: the checks the control plane runs itself (OPA
and Keycloak, where it is set to use them) and the reports each governance processor
sends it (:func:`record`): what the processor can reach where it runs, with its own
settings, which may not be the control plane's.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.config import FAILURE_SETTINGS, Settings
from agentgov.models import (
    ApprovedConnector,
    ComponentReport,
    Destination,
    IdentityIssuer,
    PlatformSync,
    Team,
)
from agentgov.registry import features
from agentgov.registry.errors import ValidationError

PROCESSOR = "processor"
# What a processor checks, in the order they are shown.
CHECKS = ("opa", "presidio", "guardian", "authzen")
# A component out of touch for longer than this many of its intervals is not counted.
MISSED = 3
# Reports older than this are forgotten.
KEEP = timedelta(days=7)
# How long the control plane's own checks are reused.
CACHE_SECONDS = 30.0
TIMEOUT = 3.0

# From the most to the least worrying.
FAILING, INACTIVE, LIMITED, ACTIVE, OFF = "failing", "inactive", "limited", "active", "off"
WORST = (FAILING, INACTIVE, LIMITED)


def check(configured: bool, ok: bool = False, detail: str = "") -> dict[str, Any]:
    return {"configured": configured, "ok": ok, "detail": detail[:300]}


def probe(
    url: str, *, verify: Any = True, headers: dict[str, str] | None = None, any_answer: bool
) -> dict[str, Any]:
    """GET ``url``: up when it answers 200 (or, with ``any_answer``, anything below 500)."""
    try:
        resp = httpx.get(url, timeout=TIMEOUT, verify=verify, headers=headers or {})
    except httpx.HTTPError as exc:
        return check(True, False, f"unreachable: {exc}")
    if resp.status_code == 200 or (any_answer and resp.status_code < 500):
        return check(True, True)
    return check(True, False, f"answered {resp.status_code}: {resp.text[:120]}")


def control_plane_checks(settings: Settings, *, verify: Any = True) -> dict[str, dict[str, Any]]:
    """What the control plane reaches itself: OPA (What if, AuthZEN, Copilot Studio's
    checks) and Keycloak's keys (the tokens the gateway checks)."""
    out = {"opa": check(False), "keycloak": check(False)}
    if settings.opa_url:
        out["opa"] = probe(
            f"{settings.opa_url.rstrip('/')}/health?bundles=true", verify=verify, any_answer=False
        )
    if settings.keycloak_jwks_url:
        out["keycloak"] = probe(settings.keycloak_jwks_url, verify=verify, any_answer=False)
    return out


class Cached:
    """The control plane's checks, run at most every CACHE_SECONDS. ``verify`` gives the
    TLS context to call with, as it is then (certificates are renewed)."""

    def __init__(self, settings: Settings, *, verify: Callable[[], Any] = lambda: True) -> None:
        self.settings = settings
        self.verify = verify
        self._at = 0.0
        self._value: dict[str, dict[str, Any]] = {}

    def get(self) -> dict[str, dict[str, Any]]:
        if not self._value or time.monotonic() - self._at > CACHE_SECONDS:
            self._value = control_plane_checks(self.settings, verify=self.verify())
            self._at = time.monotonic()
        return self._value


# ------------------------------------------------------------ the processors' reports


def record(session: Session, body: Any) -> None:
    """Keep what one instance of a component said it can reach, in place of its last
    report, and forget the reports nobody sent for a week."""
    if not isinstance(body, dict):
        raise ValidationError("a report is a JSON object")
    component, instance = body.get("component"), body.get("instance")
    if component != PROCESSOR:
        raise ValidationError(f"component must be {PROCESSOR!r}")
    if not isinstance(instance, str) or not instance.strip() or len(instance) > 200:
        raise ValidationError("instance must be a name of at most 200 characters")
    raw = body.get("checks") if isinstance(body.get("checks"), dict) else {}
    checks = {
        name: check(
            bool(raw[name].get("configured")),
            bool(raw[name].get("ok")),
            str(raw[name].get("detail") or ""),
        )
        for name in CHECKS
        if isinstance(raw.get(name), dict)
    }
    interval = body.get("interval")
    now = ids.utcnow()
    row = session.get(ComponentReport, (component, instance)) or ComponentReport(
        component=component, instance=instance
    )
    row.reported_at = now
    row.version = str(body.get("version") or "")[:32]
    row.interval = interval if isinstance(interval, int) and 0 < interval <= 86400 else 60
    row.checks = checks
    settings = body.get("settings") if isinstance(body.get("settings"), dict) else {}
    row.settings = {
        name: value
        for name in FAILURE_SETTINGS
        if isinstance(value := settings.get(name), str) and value in ("modes", "open", "closed")
    }
    session.add(row)
    session.execute(delete(ComponentReport).where(ComponentReport.reported_at < now - KEEP))


def _fresh(row: ComponentReport, now: datetime) -> bool:
    return row.reported_at >= now - timedelta(seconds=max(180, MISSED * row.interval))


def reports(session: Session) -> list[dict[str, Any]]:
    """Every processor that reported in the last week, the newest first, with whether it
    is in touch (``fresh``)."""
    now = ids.utcnow()
    rows = session.scalars(
        select(ComponentReport)
        .where(ComponentReport.component == PROCESSOR)
        .order_by(ComponentReport.reported_at.desc())
    )
    return [
        {
            "component": row.component,
            "instance": row.instance,
            "reported_at": ids.isoformat(row.reported_at),
            "fresh": _fresh(row, now),
            "version": row.version,
            "interval": row.interval,
            "checks": {name: row.checks[name] for name in CHECKS if name in row.checks},
            "settings": row.settings or {},
        }
        for row in rows
    ]


# ------------------------------------------------------------- what each feature can do


@dataclass
class Situation:
    """What is known about the deployment, for :func:`assess`."""

    settings: Settings
    modes: dict[str, str]
    control_plane: dict[str, dict[str, Any]]
    processors: list[dict[str, Any]]  # every report, fresh or not
    # The Microsoft connections, by key (platforms.connections.state).
    connections: dict[str, dict[str, Any]] = field(default_factory=dict)
    # The other platforms: whether each is configured, and its last sync.
    platforms: dict[str, dict[str, Any]] = field(default_factory=dict)
    destinations: int = 0
    # Destinations that reach people: chats and service desks.
    people_channels: int = 0
    # Connectors on the allowlist (Platforms, Connectors).
    approved_connectors: int = 0
    # Whether a team takes the issues nobody else does (docs/issues.md).
    default_team: bool = True
    # The identity issuers the gateway is to take tokens from: name, how many keys AgentGov
    # has of theirs, and why the last fetch of them failed.
    gateway_issuers: list[dict[str, Any]] = field(default_factory=list)

    @property
    def fresh(self) -> list[dict[str, Any]]:
        return [p for p in self.processors if p["fresh"]]


def situation(session: Session, settings: Settings, rt: Any) -> Situation:
    """What the runtime ``rt`` knows now."""
    from agentgov.platforms import connections
    from agentgov.registry import destinations, platforms

    connected = set(getattr(rt, "platforms", {}) or {})
    rows = {
        source: {
            "configured": source in connected,
            "last_sync": session.get(PlatformSync, source),
        }
        for source in platforms.INVENTORY_SOURCES
    }
    return Situation(
        settings=settings,
        # The strictest mode any agent has: a control enforced for some agents can refuse
        # their calls (docs/features.md#exceptions).
        modes=features.strictest_modes(session),
        control_plane=rt.health.get(),
        processors=reports(session),
        connections={row["key"]: row for row in connections.state(session, settings)},
        platforms=rows,
        destinations=len(list(session.scalars(select(Destination.id)))),
        people_channels=len(
            list(
                session.scalars(
                    select(Destination.id).where(
                        Destination.kind.in_((*destinations.CHAT, *destinations.DESK))
                    )
                )
            )
        ),
        approved_connectors=len(list(session.scalars(select(ApprovedConnector.connector_id)))),
        default_team=session.scalar(select(Team.name).where(Team.is_default.is_(True))) is not None,
        gateway_issuers=[
            {"name": i.name, "keys": len(i.gateway_keys or []), "error": i.keys_error}
            for i in session.scalars(
                select(IdentityIssuer)
                .where(IdentityIssuer.gateway.is_(True))
                .order_by(IdentityIssuer.name)
            )
        ],
    )


def _with(detail: str) -> str:
    return f" ({detail})" if detail else ""


def _processors(s: Situation, name: str) -> tuple[bool, dict[str, Any] | None]:
    """Whether every processor in touch has ``name`` set up, and the first that can't
    reach it, if one can't."""
    checks = [p["checks"].get(name) or check(False) for p in s.fresh]
    configured = bool(checks) and all(c["configured"] for c in checks)
    down = next((c for c in checks if c["configured"] and not c["ok"]), None)
    return configured, down


def _setting(s: Situation, name: str, processors: list[dict[str, Any]]) -> str:
    """A failure setting as the processors say they use it (the strictest, if they
    differ), or as the control plane has it, for processors that don't say."""
    said = {(p.get("settings") or {}).get(name) for p in processors} - {None}
    for value in ("closed", "modes", "open"):
        if value in said:
            return value
    return str(getattr(s.settings, name))


def _unchecked(s: Situation, processors: list[dict[str, Any]]) -> tuple[bool, str]:
    """Whether calls the gateway can't check go through (AGENTGOV_GATEWAY_FAILURE_MODE),
    and why, for the message."""
    setting = _setting(s, "gateway_failure_mode", processors)
    if features.fails_open(setting, s.modes):
        why = "nothing at the gateway is enforced" if setting == "modes" else "it is open"
    else:
        why = "controls at the gateway are enforced" if setting == "modes" else "it is closed"
    return features.fails_open(setting, s.modes), f"AGENTGOV_GATEWAY_FAILURE_MODE={setting}: {why}"


def _gateway(s: Situation) -> list[tuple[str, str]]:
    """What stops every control at the gateway: no gateway is on, nothing in touch checks
    calls, or what checks them can't decide."""
    if all(s.modes.get(key) == features.OFF for key in features.GATEWAYS):
        return [
            (
                INACTIVE,
                "The gateways are off (tool servers, models and agent-to-agent): there are "
                "no calls through AgentGov to check.",
            )
        ]
    if not s.fresh:
        if not s.processors:
            return [
                (
                    INACTIVE,
                    "No governance processor has reported to the control plane: these "
                    "controls check only calls through AgentGov's gateway, and nothing is "
                    "known to check them.",
                )
            ]
        passes, why = _unchecked(s, s.processors)
        outcome = "go through unchecked" if passes else "are refused"
        return [
            (
                INACTIVE,
                "No governance processor has reported to the control plane since "
                f"{s.processors[0]['reported_at']}: if it is down, calls through the gateway "
                f"{outcome} until it is back ({why}).",
            )
        ]
    opa = [p["checks"].get("opa") for p in s.fresh]
    down = next((c for c in opa if c and not c["ok"]), None)
    if down is not None:
        passes, why = _unchecked(s, s.fresh)
        cause = (
            "The governance processor can't reach OPA, or OPA has no policies loaded"
            f"{_with(down.get('detail', ''))}"
        )
        if passes:
            return [
                (
                    INACTIVE,
                    f"{cause}: calls through the gateway go through unchecked, and are "
                    f"recorded as such ({why}).",
                )
            ]
        return [(FAILING, f"{cause}: every call through the gateway is refused ({why}).")]
    return []


def _presidio(s: Situation, key: str) -> list[tuple[str, str]]:
    configured, down = _processors(s, "presidio")
    if not s.fresh:
        return []
    if not configured:
        if key == "a2a-masking":
            return [
                (
                    INACTIVE,
                    "Nothing finds the personal data to mask: the governance processor has "
                    "no Presidio (AGENTGOV_PRESIDIO_URL).",
                )
            ]
        return [
            (
                LIMITED,
                "Personal data isn't looked for: the governance processor has no Presidio "
                "(AGENTGOV_PRESIDIO_URL). Credentials still are.",
            )
        ]
    if down is None:
        return []
    if key == "a2a-masking":
        # Calls aren't masked; refusing them is data protection's doing, if anything.
        return [
            (
                INACTIVE,
                "Presidio isn't reachable from the governance processor"
                f"{_with(down.get('detail', ''))}: nothing finds the personal data to mask "
                "until it is.",
            )
        ]
    closed = _setting(s, "presidio_failure_mode", s.fresh) == "closed"
    if s.modes.get("data-protection") == features.ENFORCE and closed:
        return [
            (
                FAILING,
                "Presidio isn't reachable from the governance processor"
                f"{_with(down.get('detail', ''))}: calls with text to inspect are refused until "
                "it is (AGENTGOV_PRESIDIO_FAILURE_MODE=closed).",
            )
        ]
    return [
        (
            LIMITED,
            "Presidio isn't reachable from the governance processor"
            f"{_with(down.get('detail', ''))}: personal data isn't looked for until it is.",
        )
    ]


def _specific(key: str, mode: str, s: Situation) -> list[tuple[str, str]]:
    """What stops one feature in particular."""
    out: list[tuple[str, str]] = []
    if key == "data-protection":
        out += _presidio(s, key)
    elif key == "a2a-masking":
        if s.modes.get("data-protection") == features.OFF:
            out.append(
                (INACTIVE, "Data protection is off, so nothing finds the personal data to mask.")
            )
        else:
            out += _presidio(s, key)
    elif key == "traffic-classifier" and s.fresh:
        configured, down = _processors(s, "guardian")
        if not configured:
            out.append(
                (
                    INACTIVE,
                    "The governance processor has no Granite Guardian (AGENTGOV_GUARDIAN_URL), "
                    "so nothing gives a second opinion.",
                )
            )
        elif down is not None:
            waited = mode == features.ENFORCE and features.ENFORCE in (
                s.modes.get("prompt-injection"),
                s.modes.get("jailbreak-detection"),
            )
            if waited and _setting(s, "guardian_failure_mode", s.fresh) == "closed":
                out.append(
                    (
                        FAILING,
                        "Granite Guardian isn't reachable from the governance processor"
                        f"{_with(down.get('detail', ''))}: the calls it is waited for on are "
                        "refused until it is (AGENTGOV_GUARDIAN_FAILURE_MODE=closed).",
                    )
                )
            else:
                out.append(
                    (
                        LIMITED,
                        "Granite Guardian isn't reachable from the governance processor"
                        f"{_with(down.get('detail', ''))}: the prompt-injection and jailbreak "
                        "checks decide alone.",
                    )
                )
    elif key == "external-decision-point" and s.fresh:
        configured, down = _processors(s, "authzen")
        if not configured:
            out.append(
                (
                    INACTIVE,
                    "The governance processor has no AGENTGOV_AUTHZEN_URL, so your decision "
                    "point isn't asked.",
                )
            )
        elif (
            down is not None
            and mode == features.ENFORCE
            and _setting(s, "authzen_failure_mode", s.fresh) == "closed"
        ):
            out.append(
                (
                    FAILING,
                    "Your decision point isn't reachable from the governance processor"
                    f"{_with(down.get('detail', ''))}: the calls it would be asked about are "
                    "refused until it is (AGENTGOV_AUTHZEN_FAILURE_MODE=closed).",
                )
            )
        elif down is not None:
            out.append(
                (
                    LIMITED,
                    "Your decision point isn't reachable from the governance processor"
                    f"{_with(down.get('detail', ''))}: calls go through without its answer.",
                )
            )
    elif key == "token-budgets" and not (
        s.settings.gateway_usage_endpoint or s.settings.gateway_otlp_endpoint
    ):
        out.append(
            (
                INACTIVE,
                "Usage isn't metered, so budgets never run out: the gateway sends no access "
                "logs (AGENTGOV_GATEWAY_USAGE_ENDPOINT, or AGENTGOV_GATEWAY_OTLP_ENDPOINT).",
            )
        )
    elif key == "token-budgets" and not s.settings.gateway_usage_endpoint:
        out.append(
            (
                LIMITED,
                "Usage is reported where agents send their traces: an agent, or anything "
                "else that can send there, could report usage for another and use up its "
                "budget. Give the gateway's access logs a receiver of their own "
                "(AGENTGOV_GATEWAY_USAGE_ENDPOINT).",
            )
        )
    elif key in ("authzen-decision-point", "copilot-studio-threat-detection"):
        out += _opa_down(s)
    elif key == "connector-allowlist":
        detection = s.modes.get("copilot-studio-threat-detection")
        if detection == features.OFF:
            out.append(
                (
                    INACTIVE,
                    "Copilot Studio threat detection is off, so nothing checks agents' tool "
                    "calls as they run: agents that use a connector not on the allowlist are "
                    "flagged only.",
                )
            )
        else:
            if detection == features.MONITOR:
                out.append(
                    (
                        LIMITED,
                        "Copilot Studio threat detection is in monitor mode, so calls through "
                        "connectors not on the allowlist are recorded, not refused.",
                    )
                )
            out += _opa_down(s)
        if not s.approved_connectors:
            out.append(
                (
                    INACTIVE,
                    "The allowlist has no connector yet, so no connector is checked: approve "
                    "the ones your organisation allows (Platforms, Connectors).",
                )
            )
    elif key in ("developer-sign-in", "identity-assertions", "approvals-by-person"):
        keycloak = s.control_plane.get("keycloak") or check(False)
        if keycloak["configured"] and not keycloak["ok"]:
            out.append(
                (
                    LIMITED,
                    f"Keycloak's keys aren't reachable from the control plane"
                    f"{_with(keycloak['detail'])}.",
                )
            )
    elif key == "issues":
        if not s.default_team:
            out.append(
                (
                    LIMITED,
                    "No catch-all team: issues that no agent's owner, sponsor or team takes, "
                    "and issues about AgentGov itself, reach nobody. Name one on the Teams page.",
                )
            )
        if not (s.settings.smtp_url and s.settings.smtp_from) and not s.people_channels:
            seen = (
                "only when they sign in to AgentGov"
                if s.settings.sso_enabled
                else "only in AgentGov, where people without an AgentGov role can't sign in "
                "without single sign-on"
            )
            out.append(
                (
                    LIMITED,
                    f"Issues reach the people responsible {seen}: no mail server "
                    "(AGENTGOV_SMTP_URL), chat channel or service desk (Security operations) "
                    "is set up to tell them.",
                )
            )
    elif key == "workload-identity":
        # Issuers the gateway is to take tokens from, with the keys AgentGov fetches
        # (docs/agent-identity.md#straight-to-the-gateway).
        for issuer in s.gateway_issuers:
            if not issuer["error"]:
                continue
            if issuer["keys"]:
                message = (
                    f"AgentGov can't fetch {issuer['name']}'s keys again ({issuer['error']}): "
                    "the gateway takes its tokens with the keys fetched before, and refuses "
                    "those signed with a newer key."
                )
            else:
                message = f"The gateway can't take {issuer['name']}'s tokens: {issuer['error']}."
            out.append((LIMITED, message))
        if s.gateway_issuers and s.modes.get("developer-sign-in") == features.ON:
            names = ", ".join(i["name"] for i in s.gateway_issuers)
            out.append(
                (
                    LIMITED,
                    "While developers sign in at the gateway, tool servers there take only "
                    "Keycloak's tokens: agents with tokens of the issuers the gateway trusts "
                    f"({names}) get AgentGov tokens from Keycloak for them. Models and other "
                    "agents take their own tokens.",
                )
            )
    elif key == "security-operations" and not s.destinations:
        out.append(
            (
                INACTIVE,
                "Nothing is handed over: no destinations are set up (Security operations).",
            )
        )
    elif key in s.connections:
        out += _connection(s.connections[key])
    elif key in s.platforms:
        out += _platform(key, s.platforms[key])
    return out


def _opa_down(s: Situation) -> list[tuple[str, str]]:
    opa = s.control_plane.get("opa") or check(False)
    if opa["configured"] and not opa["ok"]:
        return [
            (
                FAILING,
                f"OPA isn't reachable from the control plane{_with(opa['detail'])}: "
                "decisions that need it fail until it is.",
            )
        ]
    return []


def _connection(row: dict[str, Any]) -> list[tuple[str, str]]:
    status = row.get("status")
    if status == "off":
        return [(INACTIVE, "Not set up: it needs " + "; ".join(row.get("needs") or []) + ".")]
    if status == "missing_permission":
        return [
            (
                INACTIVE,
                f"AgentGov's app hasn't been granted {row.get('permission')}, so it isn't read.",
            )
        ]
    if status == "failing":
        message = (row.get("last_run") or {}).get("message") or "it failed"
        return [(LIMITED, f"Its last sync failed: {message}")]
    return []


def _platform(key: str, row: dict[str, Any]) -> list[tuple[str, str]]:
    if not row["configured"]:
        needs = features.BY_KEY[key].needs or "its settings"
        return [(INACTIVE, f"Not configured: it needs {needs}.")]
    sync = row.get("last_sync")
    if sync is not None and not sync.ok:
        return [(LIMITED, f"Its last sync didn't read everything: {sync.message}")]
    return []


def assess(f: features.Feature, mode: str, s: Situation) -> dict[str, Any]:
    """How a feature is doing in its current mode: ``status`` (failing, inactive, limited,
    active or off) and the ``problems`` that make it so, the worst first."""
    if mode == features.OFF:
        return {"status": OFF, "problems": []}
    found: list[tuple[str, str]] = []
    missing = features.unmet(f.key, mode, s.settings)
    if missing:
        found.append((INACTIVE, f"{missing[:1].upper()}{missing[1:]}."))
    if f.group in ("gateway", "controls"):
        found += _gateway(s)
    found += _specific(f.key, mode, s)
    found.sort(key=lambda p: WORST.index(p[0]))
    return {
        "status": found[0][0] if found else ACTIVE,
        "problems": [message for _, message in found],
    }
