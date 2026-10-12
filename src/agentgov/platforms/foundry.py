"""Agents in Microsoft Foundry: prompt, hosted and workflow agents, in each project named and in
each project of the subscriptions named.

Read-only, as AgentGov's Microsoft app registration (client credentials): with tokens for
Foundry's data plane (``AGENTGOV_FOUNDRY_AUDIENCE``) it lists each project's agents with
their definitions, and with tokens for Azure Resource Manager it finds the projects of a
subscription's Foundry resources. A part is a project (``contoso/support``): one that refuses
is reported without holding up the rest.

Each agent is reported with the version its endpoint serves: its model, instructions
(checked), tools, the identity it acts with, who may call it and whether it is published to
Microsoft 365 and Teams (:func:`foundry_agent`). An agent with an Entra agent identity of its
own is linked to that identity, which AgentGov also reads from Microsoft Entra Agent ID.

Secrets never leave Foundry: of MCP servers' headers and hosted agents' environment variables
AgentGov keeps the names, and of URLs the host.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from agentgov.config import Settings
from agentgov.platforms.base import Found, Inventory, PlatformError, Risk

API_VERSION = "v1"
ARM_VERSION = "2025-06-01"
MAX_PAGES = 50
RETRIES = (0.5, 1.0, 2.0)
SECRET_NAME = re.compile(r"(secret|passw(or)?d|token|api[_-]?key|private[_-]?key|credential)", re.I)
# A value that refers to a secret rather than holding one (a Key Vault reference), or that the
# API hides.
SECRET_REFERENCE = re.compile(r"^(@Microsoft\.KeyVault\(|\*+$|<redacted>$)", re.I)
KINDS = {
    "prompt": "Foundry prompt agent",
    "hosted": "Foundry hosted agent",
    "workflow": "Foundry workflow agent",
    "voice": "Foundry voice agent",
    "external": "External agent in Foundry",
}
# An agent's tools: (what it is, its tone, how risky as a finding's severity).
TOOLS = {
    "shell": ("Shell", "serious", "high"),
    "local_shell": ("Shell on the caller's machine", "serious", "high"),
    "computer": ("Computer use", "serious", "high"),
    "computer_use_preview": ("Computer use", "serious", "high"),
    "code_interpreter": ("Code interpreter", "warning", "medium"),
    "browser_automation": ("Browser", "warning", "medium"),
    "browser_automation_preview": ("Browser", "warning", "medium"),
    "apply_patch": ("Edits files", "warning", "medium"),
    "mcp": ("MCP server", None, None),
    "openapi": ("OpenAPI", None, None),
    "a2a": ("Agent (A2A)", None, None),
    "a2a_preview": ("Agent (A2A)", None, None),
    "azure_function": ("Azure Function", None, None),
    "function": ("Function the caller runs", None, None),
    "custom": ("Function the caller runs", None, None),
    "file_search": ("File search", None, None),
    "azure_ai_search": ("Azure AI Search", None, None),
    "bing_grounding": ("Web search (Bing)", None, None),
    "bing_custom_search_preview": ("Web search (Bing custom search)", None, None),
    "web_search": ("Web search", None, None),
    "web_search_preview": ("Web search", None, None),
    "sharepoint_grounding_preview": ("SharePoint", None, None),
    "fabric_dataagent_preview": ("Microsoft Fabric data agent", None, None),
    "fabric_iq_preview": ("Fabric IQ", None, None),
    "work_iq_preview": ("Work IQ", None, None),
    "web_iq_preview": ("Web IQ", None, None),
    "memory_search_preview": ("Memory", None, None),
    "image_generation": ("Image generation", None, None),
    "github_copilot_toolset_preview": ("GitHub Copilot tools", None, None),
}
# Who may call an agent's endpoint, by its authorization schemes.
SCHEMES = {
    "Entra": "Microsoft Entra ID: people and apps with a Foundry role that lets them call it",
    "BotServiceRbac": "Microsoft 365 and Teams: people with a Foundry role that lets them call it",
    "BotServiceTenant": "Microsoft 365 and Teams: everyone in the organisation",
    "BotService": "Microsoft 365 and Teams, through Azure Bot Service",
}
PROTOCOLS = {
    "responses": "Responses",
    "activity": "Activity (Microsoft 365 and Teams)",
    "a2a": "A2A",
    "mcp": "MCP",
    "invocations": "Invocations",
    "invocations_ws": "Invocations (WebSocket)",
}
PUBLISHED = {
    "approved": "To Microsoft 365 and Teams",
    "no_approval_needed": "To Microsoft 365 and Teams",
    "pending": "Waiting for a Microsoft 365 admin's approval",
    "rejected": "Rejected by a Microsoft 365 admin",
}
OPENAPI_AUTH = {
    "anonymous": "with no authentication",
    "managed_identity": "with a managed identity",
    "project_connection": "with a project connection",
}
# Tool types whose tools have a name of their own; the rest are Foundry's.
NAMED = {"mcp", "openapi", "a2a", "a2a_preview", "azure_function", "function", "custom"}


def project_part(endpoint: str) -> str:
    """A project's part: its Foundry resource and name (``contoso/support``)."""
    parts = urlsplit(endpoint)
    return f"{(parts.hostname or '').split('.')[0]}/{parts.path.rstrip('/').rsplit('/', 1)[-1]}"


class FoundryConnector:
    """Reads the agents in the Foundry projects of ``AGENTGOV_FOUNDRY_PROJECTS`` and
    ``AGENTGOV_FOUNDRY_SUBSCRIPTIONS``."""

    def __init__(
        self,
        settings: Settings,
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.http = http or httpx.Client(timeout=30)
        self.settings = settings
        self.projects = settings.foundry_project_list()
        self.subscriptions = settings.foundry_subscription_list()
        self._sleep = sleep
        self._tokens: dict[str, tuple[str, float]] = {}

    def inventory(self) -> Inventory:
        inventory = Inventory()
        projects = dict.fromkeys(self.projects)
        for subscription in self.subscriptions:
            try:
                for endpoint in self._discover(subscription, inventory):
                    projects.setdefault(endpoint)
            except PlatformError as exc:
                inventory.failed[f"subscription {subscription}"] = str(exc)
        for endpoint in projects:
            part = project_part(endpoint)
            try:
                found = self._project(endpoint, part)
            except PlatformError as exc:
                inventory.failed[part] = str(exc)
                continue
            inventory.found += found
            inventory.read.add(part)
        if inventory.failed and not inventory.read:
            raise PlatformError(inventory.failures())
        return inventory

    # -- tokens and calls -----------------------------------------------------------

    def _token(self, audience: str, *, renew: bool = False) -> str:
        cached = self._tokens.get(audience)
        if cached and not renew and time.monotonic() < cached[1]:
            return cached[0]
        s = self.settings
        url = f"{s.entra_login_url.rstrip('/')}/{s.m365_tenant_id}/oauth2/v2.0/token"
        try:
            resp = self.http.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": s.m365_client_id,
                    "client_secret": s.m365_client_secret,
                    "scope": f"{audience.rstrip('/')}/.default",
                },
            )
        except httpx.HTTPError as exc:
            raise PlatformError(f"Microsoft Entra ID is unreachable: {exc}") from exc
        body = _body(resp)
        if resp.status_code != 200 or not body.get("access_token"):
            raise PlatformError(
                f"Microsoft Entra ID refused AgentGov's app ({resp.status_code}): "
                f"{body.get('error_description') or resp.text[:200]}",
                status=resp.status_code,
            )
        lifetime = max(int(body.get("expires_in") or 3600) - 300, 60)
        self._tokens[audience] = (str(body["access_token"]), time.monotonic() + lifetime)
        return str(body["access_token"])

    def _get(self, url: str, audience: str, params: dict[str, Any] | None) -> dict[str, Any]:
        renewed, attempt = False, 0
        while True:
            headers = {"Authorization": f"Bearer {self._token(audience, renew=renewed)}"}
            try:
                resp = self.http.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise PlatformError(f"{urlsplit(url).hostname} is unreachable: {exc}") from exc
            if resp.status_code == 200:
                body = _body(resp)
                if not body and resp.content.strip() not in (b"{}", b""):
                    raise PlatformError(f"{urlsplit(url).hostname} answered with no JSON object")
                return body
            if resp.status_code == 401 and not renewed:
                renewed = True
                continue
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < len(RETRIES):
                self._sleep(RETRIES[attempt])
                attempt += 1
                continue
            raise PlatformError(_error(resp), status=resp.status_code)

    def _arm(self, url: str) -> Iterator[dict[str, Any]]:
        """Every item of an Azure Resource Manager list, following ``nextLink``."""
        audience = self.settings.azure_management_url
        next_url: str | None = url
        params: dict[str, Any] | None = {"api-version": ARM_VERSION}
        for _ in range(MAX_PAGES):
            if not next_url:
                return
            page = self._get(next_url, audience, params)
            yield from (v for v in page.get("value") or [] if isinstance(v, dict))
            # The next link is opaque and carries the API version itself.
            next_url, params = page.get("nextLink"), None

    # -- projects and agents --------------------------------------------------------

    def _discover(self, subscription: str, inventory: Inventory) -> list[str]:
        """The endpoints of the projects of the subscription's Foundry resources. A resource
        whose projects the app may not list is reported, and the rest still read."""
        arm = self.settings.azure_management_url.rstrip("/")
        found = []
        accounts = self._arm(
            f"{arm}/subscriptions/{subscription}/providers/Microsoft.CognitiveServices/accounts"
        )
        for account in accounts:
            if account.get("kind") != "AIServices" or not account.get("id"):
                continue
            try:
                projects = list(self._arm(f"{arm}{account['id']}/projects"))
            except PlatformError as exc:
                if exc.status in (400, 404):
                    continue  # a resource without projects
                inventory.failed[f"{account.get('name')} (its projects)"] = str(exc)
                continue
            for project in projects:
                endpoints = (project.get("properties") or {}).get("endpoints") or {}
                endpoint = next(
                    (str(u).rstrip("/") for u in endpoints.values() if "/api/projects/" in str(u)),
                    None,
                )
                if endpoint:
                    found.append(endpoint)
        return found

    def _project(self, endpoint: str, part: str) -> list[Found]:
        audience = self.settings.foundry_audience
        found = []
        after = None
        for _ in range(MAX_PAGES):
            params = {
                "api-version": API_VERSION,
                "limit": 100,
                **({"after": after} if after else {}),
            }
            page = self._get(f"{endpoint}/agents", audience, params)
            agents = [a for a in page.get("data") or [] if isinstance(a, dict) and a.get("name")]
            for agent in agents:
                latest = (agent.get("versions") or {}).get("latest") or {}
                version, why = latest, None
                served = _served(agent)
                if served and served != str(latest.get("version")):
                    # The endpoint serves another version than the latest: that one is in use.
                    path = f"{endpoint}/agents/{quote(str(agent['name']), safe='')}/versions/"
                    try:
                        version = self._get(
                            path + quote(served, safe=""), audience, {"api-version": API_VERSION}
                        )
                    except PlatformError as exc:
                        if exc.status not in (403, 404):
                            raise
                        why = f"the version it serves ({served}) couldn't be read: {exc}"
                item = foundry_agent(agent, endpoint, part, version=version)
                if why:
                    item.complete = False
                    item.details["facts"].append(
                        {"label": "Not read in full", "value": why, "tone": "warning"}
                    )
                found.append(item)
            after = page.get("last_id")
            if not agents or not after or page.get("has_more") is False:
                break
        return found


def _body(resp: httpx.Response) -> dict[str, Any]:
    try:
        body = resp.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _error(resp: httpx.Response) -> str:
    body = _body(resp)
    error = body.get("error") if isinstance(body.get("error"), dict) else body
    detail = (
        ": ".join(str(part) for part in (error.get("code"), error.get("message")) if part)
        or resp.text[:200]
    )
    return f"{urlsplit(str(resp.request.url)).hostname} refused ({resp.status_code}): {detail}"


def _served(agent: dict[str, Any]) -> str | None:
    """The version the agent's endpoint sends its traffic to, when one is pinned."""
    selector = (agent.get("agent_endpoint") or {}).get("version_selector") or {}
    rules = [r for r in selector.get("version_selection_rules") or [] if isinstance(r, dict)]
    pinned = max(rules, key=lambda r: r.get("traffic_percentage") or 0, default=None)
    served = str((pinned or {}).get("agent_version") or "")
    return served if served and served.lower() != "latest" else None


# --------------------------------------------------------------- what each one reports


def _fact(label: str, value: Any, **extra: Any) -> dict[str, Any] | None:
    if value in (None, "", [], {}):
        return None
    return {"label": label, "value": str(value), **extra}


def _facts(*facts: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [f for f in facts if f]


def _when(value: Any) -> str | None:
    """A Foundry time, which is in Unix seconds, as the other platforms give theirs."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            return None
    return str(value) if value else None


def _host(url: Any) -> str | None:
    """A URL's scheme and host: its path or query may carry credentials."""
    parts = urlsplit(str(url or ""))
    return f"{parts.scheme}://{parts.hostname}" if parts.hostname else None


def _words(value: Any) -> str:
    return str(value or "").replace("_", " ").strip().capitalize()


def _tool(tool: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """One tool as AgentGov shows it, and the names of credentials its definition holds."""
    kind_key = str(tool.get("type") or "")
    kind, tone, _ = TOOLS.get(kind_key, (_words(kind_key) or "Tool", None, None))
    name, detail, secrets = None, [], []
    if kind_key == "mcp":
        name = tool.get("server_label")
        tunnel = tool.get("tunnel_id")
        detail.append(
            _host(tool.get("server_url"))
            or tool.get("connector_id")
            or (f"through the Secure MCP Tunnel {tunnel}" if tunnel else None)
        )
        headers = tool.get("headers") if isinstance(tool.get("headers"), dict) else {}
        held = sorted(str(k) for k, v in headers.items() if v)
        if tool.get("authorization"):
            held.append("an access token")
        if held:
            secrets += [f"{name or 'MCP server'}: {h}" for h in held]
            detail.append("credentials in its definition: " + ", ".join(held))
        if tool.get("project_connection_id"):
            detail.append(f"signs in with the connection {tool['project_connection_id']}")
        approval = tool.get("require_approval")
        never = (approval.get("never") or {}) if isinstance(approval, dict) else {}
        if approval == "never":
            detail.append("its tools run without asking")
            tone = tone or "warning"
        elif isinstance(never, dict) and never.get("tool_names"):
            names = ", ".join(str(n) for n in never["tool_names"])
            detail.append(f"these of its tools run without asking: {names}")
            tone = tone or "warning"
        elif isinstance(never, dict) and never.get("read_only"):
            detail.append("its read-only tools run without asking")
        if held:
            tone = "serious"
    elif kind_key == "openapi":
        spec = tool.get("openapi") or {}
        name = spec.get("name")
        auth = str((spec.get("auth") or {}).get("type") or "")
        detail.append(OPENAPI_AUTH.get(auth, _words(auth) or None))
        if auth == "anonymous":
            tone = "warning"
    elif kind_key in ("a2a", "a2a_preview"):
        name = _host(tool.get("base_url")) or tool.get("project_connection_id")
    elif kind_key == "azure_function":
        name = ((tool.get("azure_function") or {}).get("function") or {}).get("name")
    elif kind_key in ("function", "custom"):
        name = tool.get("name")
    elif kind_key == "azure_ai_search":
        indexes = (tool.get("azure_ai_search") or {}).get("indexes") or []
        detail.append(
            ", ".join(str(i.get("index_name")) for i in indexes if isinstance(i, dict)) or None
        )
    elif kind_key == "file_search":
        stores = tool.get("vector_store_ids") or []
        detail.append(f"{len(stores)} vector store{'s' if len(stores) != 1 else ''}")
    elif kind_key == "memory_search_preview":
        detail.append(tool.get("memory_store_name"))
    own = name or tool.get("name")
    entry = {
        "name": str(own or kind),
        # Tools Foundry provides have no name of their own, as in Databricks.
        "kind": kind if own or kind_key in NAMED else "built in",
        "detail": " · ".join(str(d) for d in detail if d) or None,
        **({"tone": tone} if tone else {}),
    }
    return entry, secrets


def foundry_agent(
    agent: dict[str, Any],
    endpoint: str,
    part: str,
    *,
    version: dict[str, Any] | None = None,
) -> Found:
    """A Foundry agent (from its project's list) as of ``version``, the one its endpoint
    serves (by default its latest)."""
    name = str(agent["name"])
    version = version or (agent.get("versions") or {}).get("latest") or {}
    definition = version.get("definition") or {}
    kind_key = str(definition.get("kind") or "")
    account, project = part.split("/", 1)
    identity = agent.get("instance_identity") or version.get("instance_identity") or {}
    principal = identity.get("principal_id") or None
    endpoint_config = agent.get("agent_endpoint") or {}
    schemes = [
        str(s.get("type"))
        for s in endpoint_config.get("authorization_schemes") or []
        if isinstance(s, dict) and s.get("type")
    ]
    protocols = endpoint_config.get("protocol_configuration") or {}
    activity = protocols.get("activity") or {}
    risks: list[Risk] = []

    tools, risky, secrets = [], [], []
    for tool in definition.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        entry, held = _tool(tool)
        tools.append(entry)
        secrets += held
        label, _, level = TOOLS.get(str(tool.get("type")), (None, None, None))
        if level:
            risky.append((label, level))
    if risky:
        risks.append(
            Risk(
                "platform.risky_tool",
                "high" if any(level == "high" for _, level in risky) else "medium",
                f"{name} can run code or work a computer",
                "Its tools act on what it is asked, so a prompt injection acts too: "
                + ", ".join(sorted({kind for kind, _ in risky}))
                + ".",
                "Keep these tools to agents that need them, behind a guardrail, or confirm the "
                "agent needs them and dismiss this finding.",
                {"tools": sorted({kind for kind, _ in risky})},
            )
        )
    variables = definition.get("environment_variables") or {}
    plain = sorted(
        str(n)
        for n, v in variables.items()
        if SECRET_NAME.search(str(n)) and v and not SECRET_REFERENCE.match(str(v))
    )
    if secrets or plain:
        risks.append(
            Risk(
                "platform.plain_secret",
                "high",
                f"{name} keeps secrets in its definition",
                "Its definition holds these credentials itself, rather than a project connection "
                "or Key Vault keeping them: "
                + ", ".join(secrets + [f"environment variable {v}" for v in plain])
                + ".",
                "Keep credentials in a project connection (or Key Vault) and refer to them, and "
                "rotate the ones that were in its definition.",
                {"credentials": secrets, "variables": plain},
            )
        )
    shared_identity = not principal and kind_key in ("prompt", "hosted", "workflow", "voice")
    if shared_identity:
        risks.append(
            Risk(
                "platform.broad_identity",
                "medium",
                f"{name} acts with its project's shared identity",
                "It was made before Foundry gave each agent an identity of its own, so it acts "
                "with the agent identity its project's older agents share: whatever any of them "
                "is given, all of them have.",
                "Create it again so it gets an identity of its own (Foundry can't change it in "
                "place yet), and give that identity only the roles it needs.",
            )
        )
    if "BotServiceTenant" in schemes:
        risks.append(
            Risk(
                "platform.shared_with_everyone",
                "medium",
                f"{name} may be used by everyone in the organisation",
                "It is published to Microsoft 365 and Teams for the whole organisation "
                "(BotServiceTenant), so anyone in the tenant may chat with it.",
                "Publish it to the people who need it (BotServiceRbac, which checks their Foundry "
                "role), or confirm everyone should have it and dismiss this finding.",
                {"scheme": "BotServiceTenant"},
            )
        )

    container = definition.get("container_configuration") or {}
    code = definition.get("code_configuration") or {}
    rai = (definition.get("rai_config") or {}).get("rai_policy_name")
    card = agent.get("agent_card") or {}
    skills = [
        str(s.get("name") or s.get("id"))
        for s in card.get("skills") or []
        if isinstance(s, dict) and (s.get("name") or s.get("id"))
    ]
    published = PUBLISHED.get(str(endpoint_config.get("publish_approval_status")))
    status = version.get("status")
    facts = _facts(
        _fact("Project", f"{project} ({account})"),
        _fact("State", "Disabled: its endpoint takes no calls")
        if agent.get("state") == "disabled"
        else None,
        _fact("Model", definition.get("model"), code=True),
        _fact(
            "Version",
            " · ".join(filter(None, [str(version.get("version") or ""), status])),
            **({"tone": "warning"} if status == "failed" else {}),
        ),
        _fact(
            "Identity",
            "Its project's shared agent identity" if shared_identity else principal,
            **({"tone": "warning"} if shared_identity else {"code": True}),
        ),
        _fact(
            "Who may call it",
            "; ".join(SCHEMES.get(s, s) for s in schemes),
            **({"tone": "warning"} if "BotServiceTenant" in schemes else {}),
        ),
        _fact(
            "Protocols",
            ", ".join(PROTOCOLS.get(p, p) for p in protocols if protocols[p] is not None),
        ),
        _fact("Published", published),
        _fact(
            "From the internet",
            "Microsoft 365 reaches its Activity endpoint over the internet"
            if activity.get("enable_m365_public_endpoint")
            else None,
        ),
        _fact(
            "Agent 365",
            "An autopilot agent" if agent.get("digital_worker_type") == "m365" else None,
        ),
        _fact(
            "Content filter",
            rai or ("Its model deployment's" if kind_key == "prompt" else None),
        ),
        _fact("Container", container.get("image"), code=True),
        _fact("Code", code.get("runtime")),
        _fact("Environment variables", ", ".join(sorted(str(v) for v in variables))),
        _fact(
            "Skills",
            ", ".join(
                [str(s.get("name")) for s in definition.get("skills") or [] if isinstance(s, dict)]
                + skills
            ),
        ),
        _fact(
            "Retiring",
            "Foundry retires workflow agents on 1 December 2026"
            if kind_key == "workflow"
            else None,
            tone="warning",
        ),
        _fact("OpenTelemetry agent ID", definition.get("otel_agent_id"), code=True),
        _fact("Changed", _when(version.get("created_at"))),
    )
    external_ids = {"foundry_agent": f"{part}/{name}"}
    if principal:
        external_ids["entra_agent_id"] = str(principal)
    return Found(
        external_id=f"{endpoint}/agents/{name}",
        name=name,
        kind=KINDS.get(kind_key, "Foundry agent"),
        part=part,
        description=version.get("description") or card.get("description"),
        details={
            "facts": facts,
            **({"tools": tools} if tools else {}),
            "definition_kind": kind_key or None,
            "model": definition.get("model"),
            "version": version.get("version"),
            # The index AgentGov links an agent's Entra identity by (registry.platforms).
            "entra_agent_id": principal,
            "identity_client_id": identity.get("client_id"),
            "environment_variables": sorted(str(v) for v in variables),
        },
        external_ids=external_ids,
        risks=risks,
        instructions=definition.get("instructions") or None,
    )
