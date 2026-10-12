"""Agents on Databricks: agents on Model Serving, Agent Bricks agents and Genie agents, in
each configured workspace.

Read-only, as a service principal (OAuth machine-to-machine) or with a token:

* **Model Serving agents**: serving endpoints whose task is an agent's (``agent/v1/chat``,
  ``agent/v2/chat``, ``agent/v1/responses``), with who may query them, what they serve,
  whether their requests and answers are kept (inference tables) and the names of their
  environment variables.
* **Agent Bricks agents**: Databricks Apps named ``agent-bricks-…``, where the Agent Bricks
  CLI deploys agents, with who may use them, the resources their service principal holds and
  the scopes they act for their users with.
* **Genie agents** (Genie spaces), with who may run them, the tables they answer from and
  their instructions.

A part is a workspace's kind of agent (``dbc-1234.cloud.databricks.com/serving``).
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from agentgov.config import Settings
from agentgov.platforms.base import Found, Inventory, PlatformError, Risk

SERVING, APPS, GENIE = "serving", "apps", "genie"
KINDS = (SERVING, APPS, GENIE)
AGENT_TASKS = {"agent/v1/chat", "agent/v2/chat", "agent/v1/responses"}
AGENT_APP = "agent-bricks-"
# The groups that hold everyone: a workspace's users, and the account's.
EVERYONE = {"users", "account users"}
SECRET_NAME = re.compile(r"(secret|passw(or)?d|token|api[_-]?key|private[_-]?key|credential)", re.I)
SECRET_REFERENCE = re.compile(r"^\{\{\s*secrets/[^/\s]+/[^}\s]+\s*\}\}$")
# Credentials that make an agent call Databricks as one fixed identity.
FIXED = ("DATABRICKS_TOKEN", "DATABRICKS_CLIENT_SECRET")
# What an app's service principal may hold that lets it change, not just use, things.
BROAD = {"CAN_MANAGE", "IS_OWNER", "WRITE", "MANAGE", "MODIFY", "WRITE_VOLUME"}
MAX_PAGES = 50
RETRIES = (0.5, 1.0, 2.0)
EARLY = 300  # renew tokens this many seconds before they expire


class DatabricksConnector:
    """Reads the agents in each workspace of ``AGENTGOV_DATABRICKS_HOSTS``."""

    def __init__(
        self,
        settings: Settings,
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.http = http or httpx.Client(timeout=30)
        self.hosts = settings.databricks_host_list()
        self.kinds = settings.databricks_kind_list()
        self.client_id = settings.databricks_client_id
        self.client_secret = settings.databricks_client_secret
        self.token = settings.databricks_token
        self._sleep = sleep
        self._lock = threading.Lock()
        self._tokens: dict[str, tuple[str, float]] = {}

    def inventory(self) -> Inventory:
        inventory = Inventory()
        readers = {SERVING: self._serving, APPS: self._apps, GENIE: self._genie}
        for url in self.hosts:
            host = urlsplit(url).hostname or url
            for kind in self.kinds:
                part = f"{host}/{kind}"
                try:
                    found = readers[kind](url, host)
                except PlatformError as exc:
                    inventory.failed[part] = str(exc)
                    continue
                for item in found:
                    item.part = part
                inventory.found += found
                inventory.read.add(part)
        if inventory.failed and not inventory.read:
            raise PlatformError(
                "; ".join(f"{part}: {error}" for part, error in sorted(inventory.failed.items()))
            )
        return inventory

    # -- tokens -------------------------------------------------------------------

    def _bearer(self, url: str, *, renew: bool = False) -> str:
        if self.token:
            return self.token
        with self._lock:
            cached = self._tokens.get(url)
            if cached and not renew and time.monotonic() < cached[1] - EARLY:
                return cached[0]
            try:
                resp = self.http.post(
                    f"{url}/oidc/v1/token",
                    data={"grant_type": "client_credentials", "scope": "all-apis"},
                    auth=(str(self.client_id), str(self.client_secret)),
                )
            except httpx.HTTPError as exc:
                raise PlatformError(f"{url} is unreachable: {exc}") from exc
            try:
                body = resp.json()
            except ValueError:
                body = {}
            if (
                resp.status_code != 200
                or not isinstance(body, dict)
                or not body.get("access_token")
            ):
                detail = body.get("error_description") if isinstance(body, dict) else None
                raise PlatformError(
                    f"Databricks refused AgentGov's service principal ({resp.status_code}): "
                    f"{detail or resp.text[:200]}",
                    status=resp.status_code,
                )
            token = str(body["access_token"])
            self._tokens[url] = (token, time.monotonic() + float(body.get("expires_in") or 3600))
            return token

    # -- calls --------------------------------------------------------------------

    def _get(self, url: str, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        renewed = False
        attempt = 0
        while True:
            headers = {"Authorization": f"Bearer {self._bearer(url, renew=renewed)}"}
            try:
                resp = self.http.get(url + path, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise PlatformError(f"{url} is unreachable: {exc}") from exc
            if resp.status_code == 200:
                try:
                    body = resp.json()
                except ValueError as exc:
                    raise PlatformError(f"{url}{path} answered with no JSON") from exc
                return body if isinstance(body, dict) else {}
            if resp.status_code == 401 and not renewed and not self.token:
                renewed = True
                continue
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < len(RETRIES):
                self._sleep(RETRIES[attempt])
                attempt += 1
                continue
            raise PlatformError(_error(resp), status=resp.status_code)

    def _pages(
        self, url: str, path: str, key: str, params: dict[str, Any] | None = None
    ) -> Iterator[dict[str, Any]]:
        token = None
        for _ in range(MAX_PAGES):
            page = self._get(
                url, path, {**(params or {}), **({"page_token": token} if token else {})}
            )
            for item in page.get(key) or []:
                if isinstance(item, dict):
                    yield item
            token = page.get("next_page_token")
            if not token:
                return

    def _acl(self, url: str, path: str) -> list[dict[str, Any]] | None:
        """An object's permissions, or None when AgentGov may not read them."""
        try:
            return list(self._get(url, path).get("access_control_list") or [])
        except PlatformError as exc:
            if exc.status in (403, 404):
                return None
            raise

    # -- the agents ---------------------------------------------------------------

    def _serving(self, url: str, host: str) -> list[Found]:
        found = []
        for summary in self._get(url, "/api/2.0/serving-endpoints").get("endpoints") or []:
            if not isinstance(summary, dict) or summary.get("task") not in AGENT_TASKS:
                continue
            name = str(summary["name"])
            try:
                endpoint = self._get(url, f"/api/2.0/serving-endpoints/{quote(name, safe='')}")
            except PlatformError as exc:
                if exc.status == 404:  # deleted since it was listed
                    continue
                raise
            acl = self._acl(url, f"/api/2.0/permissions/serving-endpoints/{endpoint.get('id')}")
            found.append(serving_agent(endpoint, acl, host))
        return found

    def _apps(self, url: str, host: str) -> list[Found]:
        found = []
        for app in self._pages(url, "/api/2.0/apps", "apps"):
            name = str(app.get("name") or "")
            if not name.startswith(AGENT_APP):
                continue
            acl = self._acl(url, f"/api/2.0/permissions/apps/{quote(name, safe='')}")
            found.append(app_agent(app, acl, host))
        return found

    def _genie(self, url: str, host: str) -> list[Found]:
        found = []
        for space in self._pages(url, "/api/2.0/genie/spaces", "spaces", {"page_size": 100}):
            space_id = str(space.get("space_id") or "")
            if not space_id:
                continue
            acl = self._acl(url, f"/api/2.0/permissions/genie/{quote(space_id, safe='')}")
            found.append(genie_agent(space, acl, host))
        return found


def _error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        body = None
    detail = ""
    if isinstance(body, dict):
        detail = ": ".join(filter(None, [body.get("error_code"), body.get("message")]))
    return (
        f"{urlsplit(str(resp.request.url)).hostname} refused ({resp.status_code}): "
        f"{detail or resp.text[:200]}"
    )


# --------------------------------------------------------------- what each one reports


def _fact(label: str, value: Any, **extra: Any) -> dict[str, Any] | None:
    if value in (None, "", [], {}):
        return None
    return {"label": label, "value": str(value), **extra}


def _facts(*facts: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [f for f in facts if f]


def _who(acl: list[dict[str, Any]] | None, levels: set[str]) -> tuple[list[str], list[str]]:
    """Who an object's permissions let in at ``levels``: (everyone groups, named principals)."""
    everyone, named = set(), set()
    for entry in acl or []:
        granted = {str(p.get("permission_level")) for p in entry.get("all_permissions") or []}
        if not granted & levels:
            continue
        group = entry.get("group_name")
        if isinstance(group, str) and group.lower() in EVERYONE:
            everyone.add(group)
        else:
            who = group or entry.get("user_name") or entry.get("service_principal_name")
            if who:
                named.add(str(who))
    return sorted(everyone), sorted(named)


def _shared(name: str, everyone: list[str], what: str) -> Risk:
    return Risk(
        "platform.shared_with_everyone",
        "medium",
        f"{name} may be used by everyone in the workspace",
        f"Its permissions let {', '.join(everyone)} {what}.",
        "Give it to the groups that need it, or confirm everyone should have it and dismiss "
        "this finding.",
        {"groups": everyone},
    )


def _plain(name: str, variables: list[str], how: str) -> Risk:
    return Risk(
        "platform.plain_secret",
        "high",
        f"{name} keeps secrets in its environment variables",
        "Their values are in its configuration, readable by anyone who may manage it: "
        + ", ".join(variables)
        + ".",
        how,
        {"variables": variables},
    )


def _who_fact(
    acl: list[dict[str, Any]] | None, everyone: list[str], named: list[str]
) -> dict[str, Any] | None:
    if acl is None:
        return _fact("Who may use it", "AgentGov may not read its permissions")
    if everyone:
        return _fact("Who may use it", "Everyone in the workspace", tone="warning")
    return _fact("Who may use it", ", ".join(named) or "Only its managers")


def serving_agent(endpoint: dict[str, Any], acl: list[dict[str, Any]] | None, host: str) -> Found:
    """An agent on Model Serving, with its endpoint's permissions (None when unread)."""
    name = str(endpoint["name"])
    config = endpoint.get("config") or {}
    served = [e for e in config.get("served_entities") or [] if isinstance(e, dict)]
    env: dict[str, str] = {}
    for entity in served:
        env.update({str(k): str(v) for k, v in (entity.get("environment_vars") or {}).items()})
    plain = sorted(
        n for n, v in env.items() if SECRET_NAME.search(n) and not SECRET_REFERENCE.match(v)
    )
    from_secrets = sorted(n for n, v in env.items() if SECRET_REFERENCE.match(v))
    everyone, named = _who(acl, {"CAN_QUERY", "CAN_MANAGE"})
    risks = []
    if everyone:
        risks.append(_shared(name, everyone, "query it"))
    if plain:
        risks.append(
            _plain(
                name,
                plain,
                "Keep them in a secret scope and refer to them as {{secrets/scope/key}}.",
            )
        )
    fixed = [n for n in FIXED if n in env]
    if fixed:
        risks.append(
            Risk(
                "platform.broad_identity",
                "medium",
                f"{name} calls Databricks with a fixed credential",
                f"It is given {', '.join(fixed)}, so everything it does in Databricks runs as "
                "that credential's owner, whoever asks it.",
                "Declare the resources it uses when you deploy it (automatic authentication), "
                "or have it act for the people who use it.",
                {"variables": fixed},
            )
        )
    tables = (endpoint.get("ai_gateway") or {}).get("inference_table_config") or {}
    logged = bool(tables.get("enabled"))
    facts = _facts(
        _fact("Workspace", host, code=True),
        _fact("Task", endpoint.get("task"), code=True),
        _fact("State", (endpoint.get("state") or {}).get("ready")),
        _fact(
            "Serves",
            ", ".join(
                f"{e.get('entity_name')} v{e.get('entity_version')}"
                if e.get("entity_version")
                else str(e.get("entity_name") or e.get("name"))
                for e in served
            ),
            code=True,
        ),
        _fact("Created by", endpoint.get("creator")),
        _who_fact(acl, everyone, named),
        _fact(
            "Requests and answers kept",
            "Yes, in inference tables" if logged else "No",
            **({} if logged else {"tone": "warning"}),
        ),
        _fact("Environment variables", ", ".join(sorted(env))),
        _fact("From secrets", ", ".join(from_secrets)),
    )
    return Found(
        external_id=f"{host}/serving-endpoints/{endpoint.get('id') or name}",
        name=name,
        kind="Agent on Model Serving",
        part="",
        description=endpoint.get("description"),
        details={
            "facts": facts,
            "task": endpoint.get("task"),
            "environment_variables": sorted(env),
        },
        external_ids={"databricks_endpoint": str(endpoint.get("id") or name)},
        risks=risks,
        complete=acl is not None,
    )


def app_agent(app: dict[str, Any], acl: list[dict[str, Any]] | None, host: str) -> Found:
    """An Agent Bricks agent (a Databricks App), with its permissions (None when unread)."""
    name = str(app["name"])
    display = name.removeprefix(AGENT_APP)
    everyone, named = _who(acl, {"CAN_USE", "CAN_MANAGE"})
    risks = []
    if everyone:
        risks.append(_shared(display, everyone, "use it"))
    tools, broad = [], []
    for resource in app.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        kind = next((k for k in resource if isinstance(resource[k], dict)), None)
        if kind is None:
            continue
        spec = resource[kind]
        permission = str(spec.get("permission") or "")
        target = (
            spec.get("name")
            or spec.get("securable_full_name")
            or spec.get("id")
            or ("/".join(filter(None, [spec.get("scope"), spec.get("key")])) or None)
            or resource.get("name")
        )
        if permission in BROAD:
            broad.append(f"{target} ({permission})")
        tools.append(
            {
                "name": str(resource.get("name") or target),
                "kind": kind.replace("_", " "),
                "detail": " · ".join(filter(None, [str(target or ""), permission])),
                **({"tone": "warning"} if permission in BROAD else {}),
            }
        )
    if broad:
        risks.append(
            Risk(
                "platform.broad_identity",
                "medium",
                f"{display}'s service principal may change what it uses",
                "It holds " + ", ".join(sorted(broad)) + ", and everyone who may use the agent "
                "acts with its service principal's permissions.",
                "Give its service principal only the permissions to use its resources (CAN "
                "QUERY, CAN USE, READ, SELECT, EXECUTE).",
                {"resources": sorted(broad)},
            )
        )
    deployment = app.get("active_deployment") or {}
    variables = [v for v in deployment.get("env_vars") or [] if isinstance(v, dict)]
    plain = sorted(
        str(v["name"])
        for v in variables
        if v.get("name") and v.get("value") and SECRET_NAME.search(str(v["name"]))
    )
    if plain:
        risks.append(
            _plain(
                display,
                plain,
                "Add the secrets as the app's resources and refer to them with valueFrom.",
            )
        )
    scopes = app.get("effective_user_api_scopes") or app.get("user_api_scopes") or []
    facts = _facts(
        _fact("Workspace", host, code=True),
        _fact("App", name, code=True),
        _fact("URL", app.get("url"), code=True),
        _fact("State", (app.get("app_status") or {}).get("state")),
        _fact("Runs as", app.get("service_principal_name")),
        _fact("Acts for its users with", ", ".join(scopes)),
        _who_fact(acl, everyone, named),
        _fact("Created by", app.get("creator")),
        _fact("Environment variables", ", ".join(sorted(str(v.get("name")) for v in variables))),
        _fact("Changed", app.get("update_time")),
    )
    return Found(
        external_id=f"{host}/apps/{name}",
        name=display,
        kind="Agent Bricks agent",
        part="",
        description=app.get("description"),
        details={"facts": facts, "tools": tools, "app": name},
        external_ids={"databricks_app": str(app.get("id") or name)},
        risks=risks,
        complete=acl is not None,
    )


def genie_agent(space: dict[str, Any], acl: list[dict[str, Any]] | None, host: str) -> Found:
    """A Genie agent (a Genie space), with its permissions (None when unread)."""
    space_id = str(space["space_id"])
    name = str(space.get("title") or space_id)
    everyone, named = _who(acl, {"CAN_VIEW", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"})
    risks = [_shared(name, everyone, "ask it questions")] if everyone else []
    try:
        serialized = json.loads(space.get("serialized_space") or "{}")
    except ValueError:
        serialized = {}
    if not isinstance(serialized, dict):
        serialized = {}
    tables = sorted(
        str(t.get("identifier"))
        for t in (serialized.get("data_sources") or {}).get("tables") or []
        if isinstance(t, dict) and t.get("identifier")
    )
    texts = [
        line
        for item in (serialized.get("instructions") or {}).get("text_instructions") or []
        if isinstance(item, dict)
        for line in item.get("content") or []
        if isinstance(line, str) and line.strip()
    ]
    facts = _facts(
        _fact("Workspace", host, code=True),
        _fact("Answers from", ", ".join(tables), code=True),
        _fact("SQL warehouse", space.get("warehouse_id"), code=True),
        _who_fact(acl, everyone, named),
        _fact("Changed", space.get("update_time")),
    )
    return Found(
        external_id=f"{host}/genie/{space_id}",
        name=name,
        kind="Genie agent",
        part="",
        description=space.get("description"),
        details={"facts": facts, "tables": tables},
        external_ids={"databricks_genie_space": space_id},
        risks=risks,
        instructions="\n".join(texts) or None,
        complete=acl is not None,
    )
