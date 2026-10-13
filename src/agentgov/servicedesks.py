"""The service desks' APIs (docs/tickets.md): opening a ticket, finding it again, reading
how it stands, adding a note, changing its priority, and resolving it.

* ServiceNow: the Table API (``/api/now/table/<table>``). The ticket's correlation ID is
  AgentGov's marker; notes are work notes, which the people who work tickets see and the
  caller doesn't.
* Jira, Cloud or Data Center: REST API 2 (``/rest/api/2/issue``), which takes plain text
  everywhere. The marker is a label; comments are internal on Jira Service Management
  projects; resolving takes the transition to a done status (``resolve_transition`` names
  one, where there are several).
* Freshservice: API v2 (``/api/v2/tickets``). The marker is a tag; notes are private.

Errors say what went wrong, never the credential. Some hold up the whole desk for a while:
it can't be reached, it refused AgentGov's credential, or it asked AgentGov to slow down
(its ``Retry-After`` is honoured). The others are about one ticket: a field its form
requires, say, which the desk's own message names.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote

import httpx

from agentgov import __version__
from agentgov.registry import desks
from agentgov.registry.tickets import ACTIVE, DONE, NEW, NewTicket, Seen

# Freshservice's ticket statuses.
FRESHSERVICE_STATUSES = {2: "Open", 3: "Pending", 4: "Resolved", 5: "Closed"}


class DeskError(Exception):
    """A desk couldn't do something, or refused it (never holds the credential)."""

    def __init__(
        self,
        message: str,
        *,
        whole_desk: bool = False,
        retry_after: float | None = None,
        missing: bool = False,
    ) -> None:
        super().__init__(message)
        # The desk can't be used for now: unreachable, AgentGov's credential refused, or
        # asked to slow down (for retry_after seconds).
        self.whole_desk = whole_desk
        self.retry_after = retry_after
        # No such ticket there: deleted, or out of AgentGov's reach.
        self.missing = missing


@dataclass
class Remote:
    """A ticket in its desk: its ID there, its number, and where people open it."""

    remote_id: str
    key: str
    url: str | None


def _retry_after(response: httpx.Response) -> float:
    value = response.headers.get("Retry-After", "")
    try:
        return max(float(value), 1.0)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return 60.0
    return max((when - datetime.now(UTC)).total_seconds(), 1.0)


def _detail(response: httpx.Response) -> str:
    """What the desk said was wrong, from its error's usual shape."""
    try:
        body = response.json()
    except ValueError:
        return " ".join(response.text.split())[:300]
    parts: list[str] = []
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):  # ServiceNow
            parts += [str(error.get(k)) for k in ("message", "detail") if error.get(k)]
        parts += [str(m) for m in body.get("errorMessages") or []]  # Jira
        errors = body.get("errors")
        if isinstance(errors, dict):  # Jira, by field
            parts += [f"{k}: {v}" for k, v in errors.items()]
        elif isinstance(errors, list):  # Freshservice, by field
            parts += [
                f"{e.get('field')}: {e.get('message')}" if isinstance(e, dict) else str(e)
                for e in errors
            ]
        if not parts and body.get("description"):
            parts.append(str(body["description"]))
        if not parts and body.get("message"):
            parts.append(str(body["message"]))
    return ("; ".join(parts) or json.dumps(body))[:500]


def _html(text: str) -> str:
    return html.escape(text).replace("\n", "<br>")


class Desk:
    """One desk, as AgentGov signs in to it."""

    kind = ""

    def __init__(
        self, http: httpx.Client, url: str, headers: dict[str, str], settings: dict[str, Any]
    ) -> None:
        self.http = http
        self.url = url.rstrip("/")
        self.headers = headers
        self.settings = settings

    def _redact(self, text: str) -> str:
        for secret in self.headers.values():
            if secret:
                text = text.replace(secret, "<secret>")
        return text

    def call(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        body: Any = None,
    ) -> Any:
        try:
            response = self.http.request(
                method,
                self.url + path,
                params=params,
                json=body,
                headers={
                    "Accept": "application/json",
                    "User-Agent": f"AgentGov/{__version__}",
                    **self.headers,
                },
            )
        except httpx.HTTPError as exc:
            raise DeskError(
                self._redact(f"couldn't reach it: {type(exc).__name__}: {exc}"), whole_desk=True
            ) from None
        status = response.status_code
        if status == 429:
            raise DeskError(
                "it asked AgentGov to slow down (HTTP 429)",
                whole_desk=True,
                retry_after=_retry_after(response),
            )
        if status == 401:
            raise DeskError(
                "HTTP 401: it refused AgentGov's credential (the destination's secret file)",
                whole_desk=True,
            )
        if status >= 500:
            raise DeskError(
                self._redact(f"HTTP {status}: {_detail(response)}"),
                whole_desk=True,
                retry_after=_retry_after(response) if "Retry-After" in response.headers else None,
            )
        if status == 404:
            raise DeskError(self._redact(f"HTTP 404: {_detail(response)}"), missing=True)
        if status >= 400:
            raise DeskError(self._redact(f"HTTP {status}: {_detail(response)}"))
        if status == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            # A sign-in page, say, where single sign-on stands in front of the API.
            raise DeskError(
                f"HTTP {status}, but not JSON: is url its API's address?", whole_desk=True
            ) from None

    # What each desk does.
    def create(self, ticket: NewTicket) -> Remote:
        raise NotImplementedError

    def find(self, marker: str) -> Remote | None:
        raise NotImplementedError

    def read(self, remote: Remote) -> Seen:
        raise NotImplementedError

    def note(self, remote: Remote, text: str) -> None:
        raise NotImplementedError

    def set_priority(self, remote: Remote, fields: dict[str, Any]) -> None:
        raise NotImplementedError

    def resolve(self, remote: Remote, text: str) -> None:
        raise NotImplementedError

    def test(self) -> str:
        raise NotImplementedError


class ServiceNow(Desk):
    kind = desks.SERVICENOW

    @property
    def table(self) -> str:
        return desks.table(self.settings)

    def _path(self, sys_id: str | None = None) -> str:
        return f"/api/now/table/{self.table}" + (f"/{quote(sys_id, safe='')}" if sys_id else "")

    def _link(self, sys_id: str) -> str:
        return f"{self.url}/nav_to.do?uri={quote(f'{self.table}.do?sys_id={sys_id}', safe='')}"

    def _remote(self, record: dict[str, Any]) -> Remote:
        sys_id = record.get("sys_id")
        if isinstance(sys_id, dict):
            sys_id = sys_id.get("value")
        number = record.get("number")
        if isinstance(number, dict):
            number = number.get("value")
        if not sys_id:
            raise DeskError("it answered without the ticket's sys_id")
        return Remote(str(sys_id), str(number or sys_id), self._link(str(sys_id)))

    def create(self, ticket: NewTicket) -> Remote:
        body = {
            **ticket.fields,
            **ticket.priority,
            "short_description": ticket.summary[:160],
            "description": ticket.description,
            "correlation_id": ticket.marker,
            "correlation_display": "AgentGov",
        }
        if ticket.group is not None:
            body["assignment_group"] = ticket.group
        out = self.call(
            "POST",
            self._path(),
            # Reference fields (a group, a caller) by name as well as by sys_id.
            params={"sysparm_input_display_value": "true", "sysparm_fields": "sys_id,number"},
            body=body,
        )
        return self._remote((out or {}).get("result") or {})

    def find(self, marker: str) -> Remote | None:
        out = self.call(
            "GET",
            self._path(),
            params={
                "sysparm_query": f"correlation_id={marker}",
                "sysparm_fields": "sys_id,number",
                "sysparm_limit": "1",
            },
        )
        rows = (out or {}).get("result") or []
        return self._remote(rows[0]) if rows else None

    def read(self, remote: Remote) -> Seen:
        out = self.call(
            "GET",
            self._path(remote.remote_id),
            params={
                "sysparm_fields": "number,state,active,assigned_to,close_code",
                "sysparm_display_value": "all",
                "sysparm_exclude_reference_link": "true",
            },
        )
        record = (out or {}).get("result") or {}

        def value(name: str) -> tuple[str, str]:
            got = record.get(name)
            if isinstance(got, dict):
                return str(got.get("value") or ""), str(got.get("display_value") or "")
            return str(got or ""), str(got or "")

        state, state_name = value("state")
        active, _ = value("active")
        _, assignee = value("assigned_to")
        _, close_code = value("close_code")
        incident = self.table == desks.INCIDENT
        done = self.settings.get("done_states") or (desks.INCIDENT_DONE if incident else ())
        working = self.settings.get("active_states") or (desks.INCIDENT_ACTIVE if incident else ())
        if state in done or active.lower() == "false":
            phase = DONE
        elif state in working or assignee:
            phase = ACTIVE
        else:
            phase = NEW
        return Seen(state_name or state or "?", phase, assignee or None, close_code or None)

    def note(self, remote: Remote, text: str) -> None:
        self.call("PATCH", self._path(remote.remote_id), body={"work_notes": text})

    def set_priority(self, remote: Remote, fields: dict[str, Any]) -> None:
        self.call("PATCH", self._path(remote.remote_id), body=fields)

    def resolve(self, remote: Remote, text: str) -> None:
        body = {**desks.resolve_fields(self.kind, self.settings), "work_notes": text}
        if self.table == desks.INCIDENT:
            body.setdefault("close_notes", text)
        self.call(
            "PATCH",
            self._path(remote.remote_id),
            params={"sysparm_input_display_value": "true"},
            body=body,
        )

    def test(self) -> str:
        self.call("GET", self._path(), params={"sysparm_limit": "1", "sysparm_fields": "sys_id"})
        return f"AgentGov signs in, and can read the {self.table} table"


class Jira(Desk):
    kind = desks.JIRA

    @property
    def site(self) -> str:
        return str(self.settings.get("site") or self.url).rstrip("/")

    def _remote(self, issue: dict[str, Any]) -> Remote:
        key, issue_id = issue.get("key"), issue.get("id")
        if not key and issue_id:
            key = (
                self.call("GET", f"/rest/api/2/issue/{issue_id}", params={"fields": "key"}) or {}
            ).get("key")
        if not key:
            raise DeskError("it answered without the issue's key")
        return Remote(str(issue_id or key), str(key), f"{self.site}/browse/{key}")

    def create(self, ticket: NewTicket) -> Remote:
        if ticket.group is None:
            raise DeskError("no project to put it in: set tickets.group, or the team's in groups")
        extra = dict(ticket.fields)
        labels = [str(x) for x in extra.pop("labels", None) or []]
        fields = {
            **extra,
            **ticket.priority,
            "project": {"key": str(ticket.group)},
            "issuetype": {"name": self.settings.get("issue_type") or "Task"},
            "summary": ticket.summary[:250],
            "description": ticket.description,
            "labels": [*labels, "agentgov", ticket.marker],
        }
        try:
            out = self.call("POST", "/rest/api/2/issue", body={"fields": fields})
        except DeskError as exc:
            # A project whose screens have no priority refuses one: it goes without.
            if exc.whole_desk or "priority" not in ticket.priority or "priority" not in str(exc):
                raise
            fields.pop("priority")
            out = self.call("POST", "/rest/api/2/issue", body={"fields": fields})
        return self._remote(out or {})

    def find(self, marker: str) -> Remote | None:
        params = {"jql": f'labels = "{marker}"', "fields": "key", "maxResults": "1"}
        try:
            out = self.call("GET", "/rest/api/2/search/jql", params=params)
        except DeskError as exc:
            if not exc.missing:
                raise
            out = self.call("GET", "/rest/api/2/search", params=params)  # Jira Data Center
        found = (out or {}).get("issues") or []
        return self._remote(found[0]) if found else None

    def read(self, remote: Remote) -> Seen:
        out = self.call(
            "GET",
            f"/rest/api/2/issue/{quote(remote.key, safe='')}",
            params={"fields": "status,assignee,resolution"},
        )
        fields = (out or {}).get("fields") or {}
        status = fields.get("status") or {}
        category = str((status.get("statusCategory") or {}).get("key") or "").lower()
        assignee = (fields.get("assignee") or {}).get("displayName") or None
        resolution = (fields.get("resolution") or {}).get("name") or None
        if category == "done":
            phase = DONE
        elif category == "indeterminate" or assignee:
            phase = ACTIVE
        else:
            phase = NEW
        return Seen(str(status.get("name") or "?"), phase, assignee, resolution)

    def note(self, remote: Remote, text: str) -> None:
        self.call(
            "POST",
            f"/rest/api/2/issue/{quote(remote.key, safe='')}/comment",
            # Internal on a Jira Service Management project: the customer doesn't see it.
            body={
                "body": text,
                "properties": [{"key": "sd.public.comment", "value": {"internal": True}}],
            },
        )

    def set_priority(self, remote: Remote, fields: dict[str, Any]) -> None:
        self.call("PUT", f"/rest/api/2/issue/{quote(remote.key, safe='')}", body={"fields": fields})

    def resolve(self, remote: Remote, text: str) -> None:
        if self.read(remote).phase != DONE:
            path = f"/rest/api/2/issue/{quote(remote.key, safe='')}/transitions"
            options = (self.call("GET", path) or {}).get("transitions") or []
            wanted = str(self.settings.get("resolve_transition") or "").lower()

            def done(option: dict[str, Any]) -> bool:
                to = option.get("to") or {}
                return (to.get("statusCategory") or {}).get("key") == "done"

            chosen = next(
                (o for o in options if wanted and str(o.get("name", "")).lower() == wanted), None
            ) or next((o for o in options if done(o)), None)
            if chosen is None:
                names = ", ".join(str(o.get("name")) for o in options) or "none"
                raise DeskError(
                    "no transition from its status to a done one (it has: "
                    f"{names}): name one in tickets.resolve_transition, or resolve it by hand"
                )
            body: dict[str, Any] = {"transition": {"id": chosen.get("id")}}
            resolve_fields = desks.resolve_fields(self.kind, self.settings)
            if resolve_fields:
                body["fields"] = resolve_fields
            self.call("POST", path, body=body)
        self.note(remote, text)

    def test(self) -> str:
        me = self.call("GET", "/rest/api/2/myself") or {}
        who = me.get("displayName") or me.get("emailAddress") or "its account"
        project = self.settings.get("group")
        if project:
            self.call("GET", f"/rest/api/2/project/{quote(str(project), safe='')}")
            return f"AgentGov signs in as {who}, and can see project {project}"
        return f"AgentGov signs in as {who}"


class Freshservice(Desk):
    kind = desks.FRESHSERVICE

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._agents: dict[Any, str] = {}

    def _remote(self, ticket: dict[str, Any]) -> Remote:
        number = ticket.get("id")
        if not number:
            raise DeskError("it answered without the ticket's ID")
        return Remote(str(number), f"#{number}", f"{self.url}/a/tickets/{number}")

    def create(self, ticket: NewTicket) -> Remote:
        extra = dict(ticket.fields)
        tags = [str(x) for x in extra.pop("tags", None) or []]
        body = {
            **extra,
            **ticket.priority,
            "subject": ticket.summary[:255],
            "description": _html(ticket.description),
            "status": 2,
            "tags": [*tags, "agentgov", ticket.marker],
        }
        if "requester_id" not in body:
            body["email"] = self.settings.get("requester")
        if ticket.group is not None:
            body["group_id"] = int(ticket.group)
        out = self.call("POST", "/api/v2/tickets", body=body)
        return self._remote((out or {}).get("ticket") or {})

    def find(self, marker: str) -> Remote | None:
        out = self.call("GET", "/api/v2/tickets/filter", params={"query": f"\"tag:'{marker}'\""})
        found = (out or {}).get("tickets") or []
        return self._remote(found[0]) if found else None

    def _agent(self, agent_id: Any) -> str:
        if agent_id not in self._agents:
            try:
                agent = (self.call("GET", f"/api/v2/agents/{agent_id}") or {}).get("agent") or {}
            except DeskError as exc:
                if exc.whole_desk:
                    raise
                agent = {}
            name = " ".join(filter(None, [agent.get("first_name"), agent.get("last_name")]))
            self._agents[agent_id] = name or agent.get("email") or f"agent {agent_id}"
        return self._agents[agent_id]

    def read(self, remote: Remote) -> Seen:
        ticket = (self.call("GET", f"/api/v2/tickets/{remote.remote_id}") or {}).get("ticket") or {}
        try:
            status = int(ticket.get("status") or 2)
        except (TypeError, ValueError):
            status = 2
        responder = ticket.get("responder_id")
        if status in (4, 5):
            phase = DONE
        elif status == 3 or responder:
            phase = ACTIVE
        else:
            phase = NEW
        assignee = self._agent(responder) if responder else None
        return Seen(FRESHSERVICE_STATUSES.get(status, str(status)), phase, assignee, None)

    def note(self, remote: Remote, text: str) -> None:
        self.call(
            "POST",
            f"/api/v2/tickets/{remote.remote_id}/notes",
            body={"body": _html(text), "private": True},
        )

    def set_priority(self, remote: Remote, fields: dict[str, Any]) -> None:
        self.call("PUT", f"/api/v2/tickets/{remote.remote_id}", body=fields)

    def resolve(self, remote: Remote, text: str) -> None:
        self.call(
            "PUT",
            f"/api/v2/tickets/{remote.remote_id}",
            body=desks.resolve_fields(self.kind, self.settings),
        )
        self.note(remote, text)

    def test(self) -> str:
        self.call("GET", "/api/v2/tickets", params={"per_page": "1"})
        return "AgentGov signs in, and can read its tickets"


CLIENTS: dict[str, type[Desk]] = {
    desks.SERVICENOW: ServiceNow,
    desks.JIRA: Jira,
    desks.FRESHSERVICE: Freshservice,
}


def client(
    kind: str, http: httpx.Client, url: str, headers: dict[str, str], settings: dict[str, Any]
) -> Desk:
    return CLIENTS[kind](http, url, headers, settings)
