"""Agents on Google Cloud: Agent Runtime (formerly Vertex AI Agent Engine) and Agent Registry.

Read-only, with an access token from ``agentgov.platforms.google_auth``, in each
configured project:

* each Agent Runtime agent (the API's ``reasoningEngines``), in each region, with the
  identity it runs as, how it reaches networks, the names of its environment variables,
  its encryption and memory, and who may use it (its IAM policy): :func:`runtime_agent`;
* Agent Registry's agents and MCP servers, in each region and ``global``: agents on Cloud
  Run and GKE, Gemini Enterprise's agents (which its own API lists only to whoever created
  them), agents registered by hand, and MCP servers, with where each runs and the identity
  it runs as: :func:`registry_agent`. Google's own agents and MCP servers are left out, and
  so are Agent Runtime's, read in full above.

A part is a project's service in a location (``contoso-agents/us-central1/agent-runtime``);
one whose API the project hasn't turned on is skipped.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlsplit

import httpx

from agentgov.config import Settings
from agentgov.platforms.base import Found, Inventory, PlatformError, Risk
from agentgov.platforms.google_auth import GoogleCredentials

AGENT_RUNTIME = "agent-runtime"
AGENT_REGISTRY = "agent-registry"
REGISTRY = "https://agentregistry.googleapis.com/v1"
# Agent Registry's attributes, by their keys' last part.
ATTRIBUTE = "agentregistry.googleapis.com/system/"
# What an agent in Agent Registry is, by what its ID (a URN) names.
HOSTS = (
    (":run:services:", "Cloud Run agent"),
    (":run:jobs:", "Cloud Run job"),
    (":container:clusters:", "GKE agent"),
    (":discoveryengine:", "Gemini Enterprise agent"),
    (":agentregistry:services:", "Agent registered in Agent Registry"),
)
MAX_PAGES = 50
RETRIES = (0.5, 1.0, 2.0)
SECRET_NAME = re.compile(r"(secret|passw(or)?d|token|api[_-]?key|private[_-]?key|credential)", re.I)
# Service accounts Google grants Editor on their project unless the organisation stops it.
DEFAULT_ACCOUNT = re.compile(r"(-compute@developer|@appspot)\.gserviceaccount\.com$")
ANYONE = {
    "allUsers": "anyone on the internet",
    "allAuthenticatedUsers": "anyone with a Google account",
}


def runtime_host(region: str) -> str:
    if region in ("us", "eu"):
        return f"https://aiplatform.{region}.rep.googleapis.com"
    return f"https://{region}-aiplatform.googleapis.com"


class GoogleConnector:
    """Reads the Agent Runtime agents in the configured projects' regions."""

    def __init__(
        self,
        settings: Settings,
        *,
        http: httpx.Client | None = None,
        env: dict[str, str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.http = http or httpx.Client(timeout=30)
        self.credentials = GoogleCredentials(self.http, env=env)
        self.projects = settings.google_cloud_project_list()
        self.regions = settings.google_cloud_region_list()
        self.kinds = settings.google_cloud_kind_list()
        self._sleep = sleep

    def inventory(self) -> Inventory:
        inventory = Inventory()
        for project in self.projects:
            reads: list[tuple[str, str, Callable[[str, str], list[Found]]]] = []
            if AGENT_RUNTIME in self.kinds:
                reads += [(region, AGENT_RUNTIME, self._runtime) for region in self.regions]
            if AGENT_REGISTRY in self.kinds:
                locations = dict.fromkeys([*self.regions, "global"])
                reads += [(location, AGENT_REGISTRY, self._registry) for location in locations]
            for location, service, read in reads:
                part = f"{project}/{location}/{service}"
                try:
                    found = read(project, location)
                except _NotEnabled:
                    continue  # the project doesn't use the service
                except PlatformError as exc:
                    inventory.failed[part] = str(exc)
                    continue
                for item in found:
                    item.part = part
                inventory.found += found
                inventory.read.add(part)
        if inventory.failed and not inventory.read:
            raise PlatformError(inventory.failures())
        return inventory

    # -- calls ---------------------------------------------------------------------

    def _call(self, method: str, url: str, *, params: dict[str, Any]) -> dict[str, Any]:
        for attempt, pause in enumerate((*RETRIES, None)):
            headers = self.credentials.headers()
            try:
                resp = self.http.request(method, url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise PlatformError(f"{urlsplit(url).hostname} is unreachable: {exc}") from exc
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError as exc:
                    raise PlatformError(f"{url} answered with no JSON") from exc
                return data if isinstance(data, dict) else {}
            if (resp.status_code == 429 or resp.status_code >= 500) and pause is not None:
                self._sleep(pause * (attempt + 1))
                continue
            if _reason(resp) == "SERVICE_DISABLED":
                raise _NotEnabled(_error(resp), status=resp.status_code)
            raise PlatformError(_error(resp), status=resp.status_code)
        raise AssertionError("unreachable")

    def _pages(self, url: str, key: str, *, page_size: int = 100) -> Iterator[dict[str, Any]]:
        token = None
        for _ in range(MAX_PAGES):
            params: dict[str, Any] = {"pageSize": page_size}
            if token:
                params["pageToken"] = token
            page = self._call("GET", url, params=params)
            for item in page.get(key) or []:
                if isinstance(item, dict):
                    yield item
            token = page.get("nextPageToken")
            if not token:
                return

    def _policy(self, url: str) -> dict[str, Any] | None:
        """An IAM policy, or None when AgentGov may not read it."""
        try:
            return self._call("POST", url, params={"options.requestedPolicyVersion": 3})
        except PlatformError as exc:
            if exc.status in (403, 404):
                return None
            raise

    # -- Agent Registry -------------------------------------------------------------

    def _registry(self, project: str, location: str) -> list[Found]:
        base = f"{REGISTRY}/projects/{project}/locations/{location}"
        runtime = AGENT_RUNTIME in self.kinds
        found = [
            registry_agent(agent, project, location)
            for agent in self._pages(f"{base}/agents", "agents")
            if _kept(agent.get("agentId"), skip_runtime=runtime)
        ]
        found += [
            registry_agent(server, project, location, mcp=True)
            for server in self._pages(f"{base}/mcpServers", "mcpServers")
            if _kept(server.get("mcpServerId"), skip_runtime=runtime)
        ]
        return found

    # -- Agent Runtime --------------------------------------------------------------

    def _runtime(self, project: str, region: str) -> list[Found]:
        base = f"{runtime_host(region)}/v1/projects/{project}/locations/{region}/reasoningEngines"
        found = []
        for engine in self._pages(base, "reasoningEngines"):
            name = str(engine.get("name") or "")
            policy = (
                self._policy(f"{runtime_host(region)}/v1/{name}:getIamPolicy") if name else None
            )
            found.append(runtime_agent(engine, policy, project, region))
        return found


class _NotEnabled(PlatformError):
    """The project hasn't turned the service's API on: there is nothing of it to read."""


def _reason(resp: httpx.Response) -> str | None:
    """The reason Google's ErrorInfo gives for an error (SERVICE_DISABLED, ...)."""
    try:
        error = resp.json().get("error")
    except (ValueError, AttributeError):
        return None
    details = error.get("details") if isinstance(error, dict) else None
    for detail in details or []:
        if isinstance(detail, dict) and detail.get("reason"):
            return str(detail["reason"])
    return None


def _error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        body = None
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        detail = ": ".join(filter(None, [error.get("status"), error.get("message")]))
    else:
        detail = resp.text[:200]
    return f"{urlsplit(str(resp.request.url)).hostname} refused ({resp.status_code}): {detail}"


# --------------------------------------------------------------- what each one reports


def _fact(label: str, value: Any, **extra: Any) -> dict[str, Any] | None:
    if value in (None, "", [], {}):
        return None
    return {"label": label, "value": str(value), **extra}


def _facts(*facts: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [f for f in facts if f]


def _anyone(policy: dict[str, Any] | None) -> tuple[list[str], list[str]]:
    """Who an IAM policy lets in beyond named principals: (everyone-members, domains)."""
    everyone, domains = set(), set()
    for binding in (policy or {}).get("bindings") or []:
        for member in binding.get("members") or []:
            if member in ANYONE:
                everyone.add(member)
            elif isinstance(member, str) and member.startswith("domain:"):
                domains.add(member.removeprefix("domain:"))
    return sorted(everyone), sorted(domains)


def runtime_agent(
    engine: dict[str, Any], policy: dict[str, Any] | None, project: str, region: str
) -> Found:
    """An Agent Runtime agent (a ``ReasoningEngine``), with its IAM ``policy`` when read."""
    name = str(engine["name"])
    display = str(engine.get("displayName") or name.rsplit("/", 1)[-1])
    spec = engine.get("spec") or {}
    deployment = spec.get("deploymentSpec") or {}
    identity_type = spec.get("identityType")
    account = spec.get("serviceAccount")
    effective = spec.get("effectiveIdentity") or account
    risks: list[Risk] = []
    if identity_type == "AGENT_IDENTITY":
        identity = "Its own agent identity"
    elif account and DEFAULT_ACCOUNT.search(account):
        identity = f"{account} (a default service account)"
        risks.append(
            Risk(
                "platform.broad_identity",
                "high",
                f"{display} runs as a default service account",
                f"It runs as {account}, which Google grants Editor on the project unless your "
                "organisation stops it, so the agent can change most of the project.",
                "Give the agent its own agent identity, or a service account of its own with only "
                "the roles it needs.",
                {"identity": account},
            )
        )
    elif account:
        identity = account
    else:
        identity = "The project's Agent Runtime service agent"
        risks.append(
            Risk(
                "platform.broad_identity",
                "medium",
                f"{display} runs as the project's shared service agent",
                "It names neither its own agent identity nor a service account, so it runs as "
                "the Agent Runtime service agent that every such agent shares, with its access "
                "to the project's storage, sessions and memories.",
                "Give the agent its own agent identity, or a service account of its own.",
            )
        )
    broad = any(r.type == "platform.broad_identity" for r in risks)
    env = {
        str(e.get("name")): e.get("value")
        for e in deployment.get("env") or []
        if isinstance(e, dict) and e.get("name")
    }
    secrets = sorted(n for n, v in env.items() if SECRET_NAME.search(n) and v)
    if "GOOGLE_APPLICATION_CREDENTIALS" in env:
        secrets.append("GOOGLE_APPLICATION_CREDENTIALS")
    if secrets:
        risks.append(
            Risk(
                "platform.plain_secret",
                "high",
                f"{display} keeps secrets in its environment variables",
                "Agent Runtime shows environment variables' values to anyone who may read the "
                "agent: " + ", ".join(secrets) + ".",
                "Move them to Secret Manager (secret environment variables); don't ship a "
                "service account key with the agent.",
                {"variables": secrets},
            )
        )
    everyone, domains = _anyone(policy)
    if everyone:
        widest = "allUsers" if "allUsers" in everyone else everyone[0]
        risks.append(
            Risk(
                "platform.no_authentication",
                "high",
                f"{display} may be used by {ANYONE[widest]}",
                "Its IAM policy grants a role to " + ", ".join(everyone) + ".",
                "Remove those members from the agent's IAM policy.",
                {"members": everyone},
            )
        )
    elif domains:
        risks.append(
            Risk(
                "platform.shared_with_everyone",
                "medium",
                f"{display} may be used by everyone in {', '.join(domains)}",
                "Its IAM policy grants a role to whole domains.",
                "Grant the role to the groups that need the agent, or confirm everyone should "
                "have it and dismiss this finding.",
                {"domains": domains},
            )
        )
    if deployment.get("pscInterfaceConfig"):
        network = "A Private Service Connect interface into your network"
    elif deployment.get("agentGatewayConfig"):
        network = "Through an agent gateway"
    else:
        network = "Google's network and the internet"
    container = (spec.get("containerSpec") or {}).get("imageUri")
    key = (engine.get("encryptionSpec") or {}).get("kmsKeyName")
    memory = (engine.get("contextSpec") or {}).get("memoryBankConfig")
    facts = _facts(
        _fact("Project", project, code=True),
        _fact("Region", region),
        _fact("Framework", spec.get("agentFramework")),
        _fact("Runs as", identity, **({"tone": "warning"} if broad else {})),
        _fact(
            "Who may use it",
            "Anyone"
            if everyone
            else (
                f"Everyone in {', '.join(domains)}"
                if domains
                else (
                    "Those its IAM policy names"
                    if policy is not None
                    else "AgentGov may not read its IAM policy"
                )
            ),
            **({"tone": "serious"} if everyone else {}),
        ),
        _fact("Network", network),
        _fact("Encryption key", key or "Google-managed", **({"code": True} if key else {})),
        _fact(
            "Memory bank",
            None
            if not memory
            else ("Kept until deleted" if not memory.get("ttlConfig") else "Expires"),
        ),
        _fact("Container", container, code=True),
        _fact(
            "Methods",
            ", ".join(
                str(m.get("name"))
                for m in spec.get("classMethods") or []
                if isinstance(m, dict) and m.get("name")
            ),
        ),
        _fact("Environment variables", ", ".join(sorted(env))),
        _fact(
            "From Secret Manager",
            ", ".join(
                sorted(
                    str(e.get("name"))
                    for e in deployment.get("secretEnv") or []
                    if isinstance(e, dict)
                )
            ),
        ),
        _fact("Changed", engine.get("updateTime")),
    )
    return Found(
        external_id=name,
        name=display,
        kind="Agent Runtime agent",
        part="",
        description=engine.get("description"),
        details={
            "facts": facts,
            "framework": spec.get("agentFramework"),
            "identity": effective,
            "identity_type": identity_type,
            "environment_variables": sorted(env),
        },
        external_ids={"google_resource": name},
        risks=risks,
        # Without its IAM policy, who may use it is unknown: leave those findings as they were.
        complete=policy is not None,
    )


def _kept(urn: object, *, skip_runtime: bool) -> bool:
    """Whether an Agent Registry entry is the organisation's to govern: not Google's own (a
    URN published by googleapis.com rather than a project), and not an Agent Runtime agent
    read in full from Agent Runtime."""
    text = str(urn or "")
    parts = text.split(":")
    if text.startswith("urn:") and len(parts) > 2 and not parts[2].startswith("projects-"):
        return False
    return not (skip_runtime and ":aiplatform:reasoningEngines:" in text)


def _attribute(entry: dict[str, Any], name: str, key: str) -> str | None:
    value = (entry.get("attributes") or {}).get(ATTRIBUTE + name)
    return str(value.get(key)) if isinstance(value, dict) and value.get(key) else None


def registry_agent(
    entry: dict[str, Any], project: str, location: str, *, mcp: bool = False
) -> Found:
    """An agent (or, with ``mcp``, an MCP server) as Agent Registry records it."""
    name = str(entry["name"])
    display = str(entry.get("displayName") or name.rsplit("/", 1)[-1])
    urn = str(entry.get("mcpServerId" if mcp else "agentId") or "")
    kind = (
        "MCP server"
        if mcp
        else next((label for marker, label in HOSTS if marker in urn), "Agent in Agent Registry")
    )
    identity = _attribute(entry, "RuntimeIdentity", "principal")
    risks = []
    if identity and DEFAULT_ACCOUNT.search(identity):
        risks.append(
            Risk(
                "platform.broad_identity",
                "high",
                f"{display} runs as a default service account",
                f"It runs as {identity}, which Google grants Editor on the project unless your "
                "organisation stops it, so whatever calls it can reach most of the project.",
                "Give it an identity of its own with only the roles it needs.",
                {"identity": identity},
            )
        )
    interfaces = [
        i
        for protocol in entry.get("protocols") or []
        if isinstance(protocol, dict)
        for i in protocol.get("interfaces") or []
        if isinstance(i, dict)
    ] + [i for i in entry.get("interfaces") or [] if isinstance(i, dict)]
    endpoints = sorted(
        {
            f"{u.scheme}://{u.hostname}"
            for u in (urlsplit(str(i.get("url") or "")) for i in interfaces)
            if u.hostname
        }
    )
    protocols = ", ".join(
        " ".join(
            filter(None, [str(p.get("type") or "").replace("_AGENT", ""), p.get("protocolVersion")])
        )
        for p in entry.get("protocols") or []
        if isinstance(p, dict) and p.get("type")
    )
    skills = [
        str(s.get("name") or s.get("id"))
        for s in entry.get("skills") or []
        if isinstance(s, dict) and (s.get("name") or s.get("id"))
    ]
    tools = [
        {"name": str(t.get("name")), "kind": "tool", "detail": t.get("description") or None}
        for t in entry.get("tools") or []
        if isinstance(t, dict) and t.get("name")
    ]
    facts = _facts(
        _fact("Project", project, code=True),
        _fact("Location", location),
        _fact("Runs on", _attribute(entry, "RuntimeReference", "uri"), code=True),
        _fact("Runs as", identity, **({"tone": "warning"} if risks else {})),
        _fact("Framework", _attribute(entry, "Framework", "framework")),
        _fact("Protocol", protocols),
        _fact("Endpoints", ", ".join(endpoints), code=True),
        _fact("Skills", ", ".join(skills)),
        _fact("Version", entry.get("version")),
        _fact("Changed", entry.get("updateTime")),
    )
    return Found(
        external_id=name,
        name=display,
        kind=kind,
        part="",
        description=entry.get("description"),
        details={"facts": facts, **({"tools": tools} if tools else {}), "urn": urn or None},
        external_ids={"google_resource": name},
        risks=risks,
    )
