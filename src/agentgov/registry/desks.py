"""Service desks: where issues become tickets (docs/tickets.md).

A service desk is a destination of its own kind: ``servicenow`` (an instance's Table API),
``jira`` (Jira Service Management, or any Jira project, through Jira's REST API) or
``freshservice`` (its API v2). Its ``tickets`` settings say where tickets go and what they
hold:

* ``group``: the group they are assigned to (a ServiceNow assignment group, by name or
  sys_id; a Freshservice group, by ID), or for Jira the project they go to, by key;
* ``groups``: another one for the issues of some of AgentGov's teams, by team;
* ``only_listed_teams``: only the issues of the teams in ``groups`` become tickets here;
* ``fields``: more fields for every ticket, as the desk names them: a category, a caller, a
  custom field its forms require;
* ``priorities``: by severity, the fields that say how urgent a ticket is (each desk has
  defaults; ``{}`` sends none);
* ``resolve``: whether AgentGov resolves a ticket when its issue ends (else a note says so),
  and ``resolve_fields``, sent when it does (ServiceNow's close code, say);
* ServiceNow: ``table`` (``incident`` by default), and for other tables the states that
  mean someone works on it (``active_states``) or it is over (``done_states``); Jira:
  ``issue_type`` (``Task`` by default), ``resolve_transition``, and ``site``, where people
  open tickets when the URL is Atlassian's API gateway; Freshservice: ``requester``, the
  email address tickets are raised for.

Its credential is the destination's secret file, as for the other destinations: HTTP
headers, one per line (``Authorization: Basic ...``, or ServiceNow's ``x-sn-apikey: ...``),
or more simply a user name and password (ServiceNow), an email address and API token
(Jira), or an API key (Freshservice).
"""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import urlsplit

from agentgov.db.models import SEVERITIES
from agentgov.registry import validation
from agentgov.registry.errors import ValidationError

SERVICENOW, JIRA, FRESHSERVICE = "servicenow", "jira", "freshservice"
DESKS = (SERVICENOW, JIRA, FRESHSERVICE)
NAMES = {SERVICENOW: "ServiceNow", JIRA: "Jira", FRESHSERVICE: "Freshservice"}

COMMON = ("group", "groups", "only_listed_teams", "fields", "priorities", "resolve")
KEYS = {
    SERVICENOW: (*COMMON, "resolve_fields", "table", "active_states", "done_states"),
    JIRA: (*COMMON, "resolve_fields", "issue_type", "resolve_transition", "site"),
    FRESHSERVICE: (*COMMON, "resolve_fields", "requester"),
}
# What AgentGov writes itself, and the setting to use instead where there is one.
RESERVED = {
    SERVICENOW: {
        "short_description": None,
        "description": None,
        "correlation_id": None,
        "correlation_display": None,
        "work_notes": None,
        "assignment_group": "group",
    },
    JIRA: {
        "summary": None,
        "description": None,
        "project": "group",
        "issuetype": "issue_type",
    },
    FRESHSERVICE: {
        "subject": None,
        "description": None,
        "status": None,
        "email": "requester",
        "group_id": "group",
    },
}
# How urgent a ticket is, by severity. ServiceNow works an incident's priority out from its
# impact and urgency (1 is the most): critical comes out 1 (critical), info 5 (planning).
PRIORITIES: dict[str, dict[str, dict[str, Any]]] = {
    SERVICENOW: {
        "critical": {"impact": "1", "urgency": "1"},
        "high": {"impact": "1", "urgency": "2"},
        "medium": {"impact": "2", "urgency": "2"},
        "low": {"impact": "2", "urgency": "3"},
        "info": {"impact": "3", "urgency": "3"},
    },
    JIRA: {
        "critical": {"priority": {"name": "Highest"}},
        "high": {"priority": {"name": "High"}},
        "medium": {"priority": {"name": "Medium"}},
        "low": {"priority": {"name": "Low"}},
        "info": {"priority": {"name": "Lowest"}},
    },
    FRESHSERVICE: {
        "critical": {"priority": 4},
        "high": {"priority": 3},
        "medium": {"priority": 2},
        "low": {"priority": 1},
        "info": {"priority": 1},
    },
}
INCIDENT = "incident"
# ServiceNow incidents: 1 new, 2 in progress, 3 on hold, 6 resolved, 7 closed, 8 canceled.
INCIDENT_ACTIVE = ("2", "3")
INCIDENT_DONE = ("6", "7", "8")
_TABLE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_HEADER = re.compile(r"^([A-Za-z0-9!#$%&'*+.^_`|~-]+):\s*(.*)$")
MAX_TEXT = 500
MAX_FIELDS = 50


def _text(value: Any, what: str, longest: int = 200) -> str:
    text = str(value if value is not None else "").strip()
    if not text:
        raise ValidationError(f"{what} is empty")
    if len(text) > longest:
        raise ValidationError(f"{what} is {longest} characters at most")
    return text


def _group(kind: str, value: Any, what: str) -> str | int:
    if kind == FRESHSERVICE:
        try:
            number = int(str(value).strip())
        except ValueError:
            raise ValidationError(f"{what} is a Freshservice group's ID (a number)") from None
        if number <= 0:
            raise ValidationError(f"{what} is a Freshservice group's ID (a number)")
        return number
    text = _text(value, what)
    if kind == JIRA and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", text):
        raise ValidationError(f"{what} is a Jira project's key, such as OPS")
    return text


def _fields(kind: str, value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(
            f"{what} is an object: field names and values, as the desk names them"
        )
    if len(value) > MAX_FIELDS:
        raise ValidationError(f"{what} has {MAX_FIELDS} fields at most")
    for name in value:
        if not isinstance(name, str) or not name.strip():
            raise ValidationError(f"{what}: field names are text")
        if name in RESERVED[kind]:
            instead = RESERVED[kind][name]
            raise ValidationError(
                f"{what} can't set {name}: "
                + (f"use {instead} instead" if instead else "AgentGov writes it")
            )
    return dict(value)


def _states(value: Any, what: str) -> list[str]:
    states = [str(s).strip() for s in validation.string_list(value, what) if str(s).strip()]
    if not states:
        raise ValidationError(f"{what} lists the states' values, such as 6 for resolved")
    return states


def normalize(kind: str, value: Any, url: str | None) -> dict[str, Any]:
    """A desk's ticket settings, checked; what they leave out takes its default."""
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValidationError("tickets is an object: group, groups, fields and the like")
    allowed = KEYS[kind]
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise ValidationError(
            f"tickets has no {', '.join(unknown)} for {NAMES[kind]}: it takes {', '.join(allowed)}"
        )
    out: dict[str, Any] = {}
    for key, given in value.items():
        if given is None:
            continue
        if key == "group":
            out[key] = _group(kind, given, "tickets.group")
        elif key == "groups":
            if not isinstance(given, dict):
                raise ValidationError("tickets.groups is an object: a group by team")
            out[key] = {
                validation.slug(team, "a team in tickets.groups"): _group(
                    kind, group, f"tickets.groups.{team}"
                )
                for team, group in given.items()
            }
        elif key in ("only_listed_teams", "resolve"):
            if not isinstance(given, bool):
                raise ValidationError(f"tickets.{key} is true or false")
            out[key] = given
        elif key == "fields":
            out[key] = _fields(kind, given, "tickets.fields")
        elif key == "resolve_fields":
            out[key] = _fields(kind, given, "tickets.resolve_fields")
        elif key == "priorities":
            if not isinstance(given, dict):
                raise ValidationError("tickets.priorities is an object: fields by severity")
            bad = sorted(set(given) - set(SEVERITIES))
            if bad:
                raise ValidationError(
                    f"tickets.priorities is by severity ({', '.join(SEVERITIES)}), "
                    f"not {', '.join(bad)}"
                )
            out[key] = {
                sev: _fields(kind, fields, f"tickets.priorities.{sev}")
                for sev, fields in given.items()
            }
        elif key == "table":
            table = _text(given, "tickets.table", 80)
            if not _TABLE.match(table):
                raise ValidationError("tickets.table is a table's name, such as incident")
            out[key] = table
        elif key in ("active_states", "done_states"):
            out[key] = _states(given, f"tickets.{key}")
        elif key in ("issue_type", "resolve_transition"):
            out[key] = _text(given, f"tickets.{key}", 100)
        elif key == "requester":
            requester = _text(given, "tickets.requester", 320)
            if "@" not in requester:
                raise ValidationError("tickets.requester is an email address")
            out[key] = requester
        elif key == "site":
            site = _text(given, "tickets.site", 300).rstrip("/")
            if urlsplit(site).scheme != "https" or not urlsplit(site).hostname:
                raise ValidationError("tickets.site is where people open tickets: an https URL")
            out[key] = site
    _complete(kind, out, url)
    return out


def _complete(kind: str, out: dict[str, Any], url: str | None) -> None:
    """What each desk needs to open a ticket at all."""
    listed = out.get("groups") or {}
    if out.get("only_listed_teams") and not listed:
        raise ValidationError(
            "tickets.only_listed_teams needs tickets.groups: the teams whose issues go here"
        )
    if kind == JIRA and "group" not in out and not out.get("only_listed_teams"):
        raise ValidationError(
            "a Jira desk needs tickets.group: the key of the project tickets go to"
        )
    if (
        kind == FRESHSERVICE
        and "requester" not in out
        and "requester_id" not in out.get("fields", {})
    ):
        raise ValidationError(
            "a Freshservice desk needs tickets.requester: the email address tickets are "
            "raised for (AgentGov's mailbox, say)"
        )
    if (
        kind == JIRA
        and url
        and urlsplit(url).hostname == "api.atlassian.com"
        and not out.get("site")
    ):
        raise ValidationError(
            "with Atlassian's API gateway as its URL, a Jira desk needs tickets.site: where "
            "people open its tickets (https://your-site.atlassian.net)"
        )


def check_url(kind: str, url: str | None) -> None:
    if not url:
        raise ValidationError(
            f"a {NAMES[kind]} desk needs url: "
            + {
                SERVICENOW: "the instance, https://your-instance.service-now.com",
                JIRA: "the site, https://your-site.atlassian.net",
                FRESHSERVICE: "the helpdesk, https://your-domain.freshservice.com",
            }[kind]
        )
    if urlsplit(url).scheme != "https":
        raise ValidationError(f"a {NAMES[kind]} desk's url is an https URL")


# ------------------------------------------------------------------ in use


def table(settings: dict[str, Any]) -> str:
    return str(settings.get("table") or INCIDENT)


def priorities(kind: str, settings: dict[str, Any], severity: str) -> dict[str, Any]:
    chosen = settings.get("priorities")
    by_severity = PRIORITIES[kind] if chosen is None else chosen
    return dict(by_severity.get(severity) or {})


def resolve_fields(kind: str, settings: dict[str, Any]) -> dict[str, Any]:
    if "resolve_fields" in settings:
        return dict(settings["resolve_fields"])
    if kind == SERVICENOW:
        if table(settings) == INCIDENT:
            return {"state": "6", "close_code": "Solution provided"}
        return {"state": "3"}  # closed complete, on most task tables
    if kind == FRESHSERVICE:
        return {"status": 4}
    return {}


def resolves(settings: dict[str, Any]) -> bool:
    return bool(settings.get("resolve", True))


def takes(settings: dict[str, Any], team: str | None) -> bool:
    """Whether issues of this team (None: no team) become tickets here."""
    return not settings.get("only_listed_teams") or team in (settings.get("groups") or {})


def group_for(settings: dict[str, Any], team: str | None) -> str | int | None:
    """Where a team's tickets go: its own group, or else the desk's."""
    groups = settings.get("groups") or {}
    if team and team in groups:
        return groups[team]  # type: ignore[no-any-return]
    return settings.get("group")


# ------------------------------------------------------------------ credentials


def headers(kind: str, text: str) -> dict[str, str]:
    """The HTTP headers a desk's secret file gives: headers, one per line; or a user name and
    password (ServiceNow), an email address and API token (Jira), an API key (Freshservice)."""
    lines = [
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
    ]
    found: dict[str, str] = {}
    for line in lines:
        header = _HEADER.match(line)
        name = header[1].lower() if header else ""
        if header and (name == "authorization" or name.startswith("x-")):
            found[header[1]] = header[2]
    if found:
        return found
    if len(lines) != 1:
        raise ValueError(
            "it holds HTTP headers (Authorization: ...), one per line, or one line: "
            + {
                SERVICENOW: "user:password",
                JIRA: "email:api-token",
                FRESHSERVICE: "the API key",
            }[kind]
        )
    secret = lines[0]
    if kind == FRESHSERVICE:
        pair = secret if ":" in secret else f"{secret}:X"  # the key, and any password
    elif ":" not in secret:
        raise ValueError(
            "its one line is "
            + ("user:password" if kind == SERVICENOW else "email:api-token")
            + ", or it holds HTTP headers"
        )
    else:
        pair = secret
    return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}
