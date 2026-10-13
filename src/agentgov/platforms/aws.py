"""Agents on AWS: Amazon Bedrock agents, and AgentCore's harnesses, runtimes and gateways.

Read-only, with SigV4-signed requests (``agentgov.platforms.aws_auth``), in each
configured region of each account AgentGov can reach: its own credentials' and
those of the roles it assumes. A part is an account's service in a region
(``111122223333/us-east-1/bedrock-agents``): a region that doesn't offer a
service is skipped, and one that refuses is reported without holding up the rest.

* Amazon Bedrock agents (Agents for Amazon Bedrock, which AWS now calls Agents
  Classic): each agent's working draft, its action groups, knowledge bases and
  aliases (:func:`bedrock_agent`).
* AgentCore: managed harnesses (:func:`harness`), and the agent runtimes that
  don't back one (:func:`agent_runtime`), with each runtime's resource policy.
* AgentCore gateways, the MCP servers AgentCore hosts in front of tools
  (:func:`agentcore_gateway`), with their targets: a part of their own, so that
  credentials allowed to read agents but not gateways leave the agents read.
* Amazon Quick's agents, the chat agents people build in Amazon Quick (the
  QuickSight API): their instructions, spaces, action connectors and who they are
  shared with (:func:`quick_agent`); an account that doesn't use Quick is skipped.
* AWS Agent Registry's agents and MCP servers (:func:`registry_record`): those
  registered by hand, and the AgentCore runtimes and gateways an organisation's
  registry detects in its member accounts. Those of accounts AgentGov reads itself
  are left to that read, which has all of them; the others are known only from the
  registry, so that one account's registry shows the whole organisation.

``AGENTGOV_AWS_READ`` chooses which of these are read. Secrets never leave AWS: of
environment variables and remote MCP servers' headers AgentGov keeps the names, and
of those servers' URLs the host.
"""

from __future__ import annotations

import json
import re
import socket
import time
from collections import Counter
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx

from agentgov.config import Settings
from agentgov.platforms.aws_auth import Session, sign
from agentgov.platforms.base import Found, Inventory, PlatformError, Risk

BEDROCK_AGENTS = "bedrock-agents"
AGENTCORE = "agentcore"
GATEWAYS = "agentcore-gateways"
QUICK = "quick"
REGISTRY = "agent-registry"
# Each kind of list is paged this far at most.
MAX_PAGES = 50


def _capped(what: str) -> str:
    """Why a list read only up to MAX_PAGES pages fails: the part it is in wasn't read in
    full, so its agents are left as the last full read saw them (agentgov.platforms.base)."""
    return f"more than {MAX_PAGES} pages of {what}: the rest weren't read"


# Throttled or failing requests are tried again after these pauses (seconds).
RETRIES = (0.5, 1.0, 2.0)
# Environment variables whose names say they hold a secret, unless their value refers to one.
SECRET_NAME = re.compile(r"(secret|passw(or)?d|token|api[_-]?key|private[_-]?key|credential)", re.I)
SECRET_REFERENCE = re.compile(r"^(arn:aws[\w-]*:(secretsmanager|ssm):|\{\{resolve:)")
# Bedrock's built-in action groups: (what it is, how risky, the finding's severity).
BUILT_IN = {
    "AMAZON.UserInput": ("Asks the user", None, None),
    "AMAZON.CodeInterpreter": ("Code interpreter", "warning", "medium"),
    "ANTHROPIC.Computer": ("Computer use", "serious", "high"),
    "ANTHROPIC.Bash": ("Shell", "serious", "high"),
    "ANTHROPIC.TextEditor": ("Text editor", "serious", "high"),
}
HARNESS_TOOLS = {
    "remote_mcp": ("Remote MCP server", None, None),
    "agentcore_gateway": ("AgentCore gateway", None, None),
    "inline_function": ("Function the caller runs", None, None),
    "agentcore_browser": ("Browser", "warning", "medium"),
    "agentcore_code_interpreter": ("Code interpreter", "warning", "medium"),
}


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443)
    except OSError:
        return False
    return True


class AwsConnector:
    """Reads the agents in the configured regions of each reachable AWS account."""

    def __init__(
        self,
        settings: Settings,
        *,
        http: httpx.Client | None = None,
        env: dict[str, str] | None = None,
        resolves: Callable[[str], bool] = _resolves,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.http = http or httpx.Client(timeout=30)
        self.regions = settings.aws_region_list()
        base = Session(self.http, env=env, region=self.regions[0])
        self.sessions = [base] + [
            Session(
                self.http,
                region=self.regions[0],
                role_arn=arn,
                base=base,
                external_id=settings.aws_external_id,
            )
            for arn in settings.aws_role_arn_list()
        ]
        self.kinds = settings.aws_kind_list()
        # The accounts AgentGov reads itself: its roles' (in their ARNs), and its own
        # credentials' once STS has said which that is.
        self.accounts = {s.role_arn.split(":")[4] for s in self.sessions if s.role_arn}
        self._resolves = resolves
        self._sleep = sleep

    def inventory(self) -> Inventory:
        inventory = Inventory()
        for session in self.sessions:
            try:
                account = session.account()
            except PlatformError as exc:
                inventory.failed[session.role_arn or "AgentGov's AWS credentials"] = str(exc)
                continue
            self.accounts.add(account)
            for region in self.regions:
                api = _Api(self, session, region)
                for service, read in (
                    (BEDROCK_AGENTS, _bedrock),
                    (AGENTCORE, _agentcore),
                    (GATEWAYS, _gateways),
                    (QUICK, _quick),
                    (REGISTRY, _registry),
                ):
                    if service not in self.kinds:
                        continue
                    part = f"{account}/{region}/{service}"
                    try:
                        inventory.found += read(api, account, region, part)
                    except _NotOffered:
                        pass
                    except PlatformError as exc:
                        inventory.failed[part] = str(exc)
                        continue
                    inventory.read.add(part)
        if inventory.failed and not inventory.read:
            raise PlatformError(inventory.failures())
        return inventory


BEDROCK = ("bedrock", "bedrock-agent")
CONTROL = ("bedrock-agentcore", "bedrock-agentcore-control")


def _refused(exc: PlatformError) -> str | None:
    """Why one agent's details couldn't be read, when that leaves the rest readable: AWS
    refused (a key of yours it may not use, say). Anything else stops the part."""
    if exc.status == 403:
        return str(exc)
    raise exc


# A resource policy AgentGov may not read: who may call the resource is unknown, so the
# findings about it stay as they were rather than close.
UNREAD_POLICY = "its resource policy, which says who may call it, couldn't be read"


def _partial(found: Found, why: str) -> Found:
    found.complete = False
    found.missing.append(why)
    found.details["facts"].append({"label": "Not read in full", "value": why, "tone": "warning"})
    return found


def _bedrock(api: _Api, account: str, region: str, part: str) -> list[Found]:
    found = []
    for summary in api.pages(*BEDROCK, "POST", "/agents/", "agentSummaries", body={}):
        agent_id = quote(str(summary["agentId"]), safe="")
        draft = f"/agents/{agent_id}/agentversions/DRAFT"
        agent: dict[str, Any] = {}
        groups: list[dict[str, Any]] = []
        knowledge: list[dict[str, Any]] = []
        aliases: list[dict[str, Any]] = []
        why = None
        try:
            agent = api.call(*BEDROCK, "GET", f"/agents/{agent_id}/").get("agent") or {}
            for group in api.pages(
                *BEDROCK, "POST", f"{draft}/actiongroups/", "actionGroupSummaries", body={}
            ):
                group_id = quote(str(group["actionGroupId"]), safe="")
                detail = api.call(*BEDROCK, "GET", f"{draft}/actiongroups/{group_id}/")
                groups.append(detail.get("agentActionGroup") or group)
            knowledge = list(
                api.pages(
                    *BEDROCK,
                    "POST",
                    f"{draft}/knowledgebases/",
                    "agentKnowledgeBaseSummaries",
                    body={},
                )
            )
            aliases = list(
                api.pages(
                    *BEDROCK,
                    "POST",
                    f"/agents/{agent_id}/agentaliases/",
                    "agentAliasSummaries",
                    body={},
                )
            )
        except PlatformError as exc:
            if exc.status == 404:
                continue  # deleted since it was listed
            why = _refused(exc)
        item = bedrock_agent(
            {**summary, **agent}, groups, knowledge, aliases, account, region, part
        )
        found.append(_partial(item, why) if why else item)
    return found


def _agentcore(api: _Api, account: str, region: str, part: str) -> list[Found]:
    found = []
    backing: set[str] = set()
    for summary in api.pages(*CONTROL, "GET", "/harnesses", "harnesses", query=True):
        why = None
        try:
            detail = (
                api.call(
                    *CONTROL, "GET", f"/harnesses/{quote(str(summary['harnessId']), safe='')}"
                ).get("harness")
                or {}
            )
        except PlatformError as exc:
            if exc.status == 404:
                continue
            detail, why = {}, _refused(exc)
        record = {**summary, **detail}
        runtime_arn = (
            (record.get("environment") or {}).get("agentCoreRuntimeEnvironment") or {}
        ).get("agentRuntimeArn")
        if runtime_arn:
            backing.add(runtime_arn)
        item = harness(record, account, region, part)
        found.append(_partial(item, why) if why else item)
    for summary in api.pages(*CONTROL, "POST", "/runtimes/", "agentRuntimes", query=True):
        if summary.get("agentRuntimeArn") in backing:
            continue  # its harness stands for it
        runtime_id = quote(str(summary["agentRuntimeId"]), safe="")
        why = None
        try:
            runtime = {**summary, **api.call(*CONTROL, "GET", f"/runtimes/{runtime_id}/")}
        except PlatformError as exc:
            if exc.status == 404:
                continue
            runtime, why = dict(summary), _refused(exc)
        if runtime.get("agentRuntimeArn") in backing:
            continue
        policy = None
        if why is None and runtime.get("agentRuntimeArn") and not _jwt(runtime):
            policy = api.resource_policy(*CONTROL, runtime["agentRuntimeArn"])
            if policy is None:
                why = UNREAD_POLICY
        item = agent_runtime(runtime, account, region, part, policy=policy)
        found.append(_partial(item, why) if why else item)
    return found


def _gateways(api: _Api, account: str, region: str, part: str) -> list[Found]:
    found = []
    for summary in api.pages(*CONTROL, "GET", "/gateways/", "items", query=True):
        gateway_id = quote(str(summary["gatewayId"]), safe="")
        why = None
        targets: list[dict[str, Any]] = []
        try:
            gateway = {**summary, **api.call(*CONTROL, "GET", f"/gateways/{gateway_id}/")}
        except PlatformError as exc:
            if exc.status == 404:
                continue  # deleted since it was listed
            gateway, why = dict(summary), _refused(exc)
        if why is None:
            try:
                for target in api.pages(
                    *CONTROL, "GET", f"/gateways/{gateway_id}/targets/", "items", query=True
                ):
                    target_id = quote(str(target["targetId"]), safe="")
                    path = f"/gateways/{gateway_id}/targets/{target_id}/"
                    targets.append({**target, **api.call(*CONTROL, "GET", path)})
            except PlatformError as exc:
                if exc.status == 404:
                    continue
                why = _refused(exc)
        policy = None
        if why is None and gateway.get("authorizerType") == "AWS_IAM" and gateway.get("gatewayArn"):
            policy = api.resource_policy(*CONTROL, gateway["gatewayArn"])
            if policy is None:
                why = UNREAD_POLICY
        item = agentcore_gateway(gateway, targets, account, region, part, policy=policy)
        found.append(_partial(item, why) if why else item)
    return found


QUICKSIGHT = ("quicksight", "quicksight")
# Answers to ListAgents that mean the account doesn't use Amazon Quick in the region.
NO_QUICK = ("UnsupportedUserEditionException", "PreconditionNotMetException", "ResourceNotFound")


def _quick(api: _Api, account: str, region: str, part: str) -> list[Found]:
    base = f"/accounts/{quote(account, safe='')}"
    summaries: list[dict[str, Any]] = []
    token = None
    try:
        for _ in range(MAX_PAGES):
            params = {"max-results": 100, **({"next-token": token} if token else {})}
            page = api.call(*QUICKSIGHT, "GET", f"{base}/agents", params=params)
            summaries += [a for a in page.get("AgentSummaries") or [] if isinstance(a, dict)]
            token = page.get("NextToken")
            if not token:
                break
        else:
            raise PlatformError(_capped("Amazon Quick's agents"))
    except PlatformError as exc:
        if exc.status == 404 or any(kind in str(exc) for kind in NO_QUICK):
            raise _NotOffered(str(exc)) from exc
        raise
    connectors: dict[str, dict[str, Any] | None] = {}
    found = []
    for summary in summaries:
        agent_id = quote(str(summary["AgentId"]), safe="")
        why = None
        try:
            agent = {
                **summary,
                **(api.call(*QUICKSIGHT, "GET", f"{base}/agents/{agent_id}").get("Agent") or {}),
            }
        except PlatformError as exc:
            if exc.status == 404:
                continue
            agent, why = dict(summary), _refused(exc)
        permissions = None
        try:
            permissions = (
                api.call(*QUICKSIGHT, "GET", f"{base}/agents/{agent_id}/permissions").get(
                    "Permissions"
                )
                or []
            )
        except PlatformError as exc:
            why = why or _refused(exc)
        for arn in agent.get("ActionConnectors") or []:
            if arn in connectors:
                continue
            connector_id = quote(str(arn).rsplit("/", 1)[-1], safe="")
            try:
                connectors[arn] = (
                    api.call(*QUICKSIGHT, "GET", f"{base}/action-connectors/{connector_id}").get(
                        "ActionConnector"
                    )
                    or {}
                )
            except PlatformError as exc:
                connectors[arn] = None
                if exc.status != 404:
                    why = why or _refused(exc)
        mine = {arn: connectors.get(arn) for arn in agent.get("ActionConnectors") or []}
        item = quick_agent(agent, permissions, mine, account, region, part)
        found.append(_partial(item, why) if why else item)
    return found


# AWS Agent Registry signs as agent-registry. Its records that are agents, or the MCP servers
# they use: skills and custom entries aren't.
REGISTRY_SIGNING = "agent-registry"
RECORD_TYPES = ("AGENT", "MCP", "GATEWAY")
# What its auto-detection catalogs, and the part that reads it in its own account.
DETECTED = {
    "AWS::BedrockAgentCore::Runtime": AGENTCORE,
    "AWS::BedrockAgentCore::Gateway": GATEWAYS,
}
# A registry whose records can't be listed yet, or any more.
UNLISTED = ("CREATING", "CREATE_FAILED", "DELETING")


def _registry(api: _Api, account: str, region: str, part: str) -> list[Found]:
    endpoint = (REGISTRY_SIGNING, f"agent-registry-control.{region}.api.aws")
    found = []
    for registry in api.pages(*endpoint, "POST", "/registries-list", "registries", body={}):
        if registry.get("status") in UNLISTED:
            continue
        base = f"/registries/{quote(str(registry['registryId']), safe='')}"
        try:
            records = list(
                api.pages(*endpoint, "POST", f"{base}/records-list", "registryRecords", body={})
            )
        except PlatformError as exc:
            if exc.status == 404:
                continue  # deleted since it was listed
            raise
        kept = [
            r
            for r in records
            if r.get("recordType") in RECORD_TYPES and not _read_directly(api.connector, r)
        ]
        # A name with several versions is a record for each.
        names = Counter(str(r.get("name")) for r in kept)
        for summary in kept:
            why = None
            try:
                path = f"{base}/records/{quote(str(summary['recordId']), safe='')}"
                record = {**summary, **api.call(*endpoint, "GET", path)}
            except PlatformError as exc:
                if exc.status == 404:
                    continue
                record, why = dict(summary), _refused(exc)
            versions = names[str(summary.get("name"))]
            item = registry_record(record, registry, account, region, part, versions=versions)
            found.append(_partial(item, why) if why else item)
    return found


def _read_directly(connector: AwsConnector, record: dict[str, Any]) -> bool:
    """Whether a record the registry detected is a runtime or gateway AgentGov reads in its
    own account: that read has all of it, and the record only some."""
    for source in record.get("provenanceSummaryList") or []:
        if not isinstance(source, dict):
            continue
        arn = str(source.get("sourceId") or "").split(":")
        kind = DETECTED.get(str(source.get("sourceType")))
        if (
            kind in connector.kinds
            and len(arn) > 5
            and arn[4] in connector.accounts
            and arn[3] in connector.regions
        ):
            return True
    return False


class _NotOffered(Exception):
    """The region doesn't offer the service: its endpoint has no address."""


class _Api:
    """Signed REST-JSON calls to one region's AWS services."""

    def __init__(self, connector: AwsConnector, session: Session, region: str) -> None:
        self.connector = connector
        self.session = session
        self.region = region

    def call(
        self,
        service: str,
        endpoint: str,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # A service's endpoint in the region's amazonaws.com, or a host of its own.
        host = endpoint if "." in endpoint else f"{endpoint}.{self.region}.amazonaws.com"
        url = f"https://{host}{path}"
        if params:
            url += "?" + urlencode(params)
        content = json.dumps(body).encode() if body is not None else b""
        headers = {"content-type": "application/json"} if body is not None else {}
        for attempt, pause in enumerate((*RETRIES, None)):
            signed = sign(
                method,
                url,
                region=self.region,
                service=service,
                credentials=self.session.credentials(),
                body=content,
                headers=headers,
            )
            try:
                resp = self.connector.http.request(method, url, content=content, headers=signed)
            except httpx.ConnectError as exc:
                if not self.connector._resolves(host):
                    raise _NotOffered(host) from exc
                raise PlatformError(f"{host} is unreachable: {exc}") from exc
            except httpx.HTTPError as exc:
                raise PlatformError(f"{host} is unreachable: {exc}") from exc
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError as exc:
                    raise PlatformError(f"{host} answered {path} with no JSON") from exc
                return data if isinstance(data, dict) else {}
            if (resp.status_code == 429 or resp.status_code >= 500) and pause is not None:
                self.connector._sleep(pause * (attempt + 1))
                continue
            raise PlatformError(_error(resp, host), status=resp.status_code)
        raise AssertionError("unreachable")

    def pages(
        self,
        service: str,
        endpoint: str,
        method: str,
        path: str,
        key: str,
        *,
        body: dict[str, Any] | None = None,
        query: bool = False,
    ) -> Iterator[dict[str, Any]]:
        """Every item of a paged list, ``nextToken`` in the body or (``query``) the URL."""
        token = None
        for _ in range(MAX_PAGES):
            if query:
                params = {"maxResults": 100, **({"nextToken": token} if token else {})}
                page = self.call(service, endpoint, method, path, params=params)
            else:
                request = {**(body or {}), "maxResults": 100}
                if token:
                    request["nextToken"] = token
                page = self.call(service, endpoint, method, path, body=request)
            for item in page.get(key) or []:
                if isinstance(item, dict):
                    yield item
            token = page.get("nextToken")
            if not token:
                return
        raise PlatformError(_capped(path))

    def resource_policy(self, service: str, endpoint: str, arn: str) -> dict[str, Any] | None:
        """A resource's policy: ``{}`` when it has none, None when AgentGov may not read it."""
        try:
            text = self.call(
                service, endpoint, "GET", f"/resourcepolicy/{quote(arn, safe='')}"
            ).get("policy")
        except PlatformError as exc:
            if exc.status == 404:
                return {}
            if exc.status == 403:
                return None
            raise
        try:
            policy = json.loads(text) if text else {}
        except ValueError:
            return None
        return policy if isinstance(policy, dict) else None


def _error(resp: httpx.Response, host: str) -> str:
    kind = resp.headers.get("x-amzn-errortype", "").split(":")[0]
    try:
        body = resp.json()
    except ValueError:
        body = {}
    message = ""
    if isinstance(body, dict):
        message = body.get("message") or body.get("Message") or ""
        kind = kind or str(body.get("__type", "")).rsplit("#", 1)[-1]
    detail = ": ".join(part for part in (kind, message) if part) or resp.text[:200]
    return f"{host} refused ({resp.status_code}): {detail}"


# --------------------------------------------------------------- what each one reports


def _fact(label: str, value: Any, **extra: Any) -> dict[str, Any] | None:
    if value in (None, "", [], {}):
        return None
    return {"label": label, "value": str(value), **extra}


def _facts(*facts: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [f for f in facts if f]


def _secrets(variables: dict[str, Any]) -> list[str]:
    """The names of environment variables that look like they hold a secret in plain text."""
    return sorted(
        name
        for name, value in variables.items()
        if SECRET_NAME.search(name) and value and not SECRET_REFERENCE.match(str(value))
    )


def _jwt(record: dict[str, Any]) -> dict[str, Any]:
    return (record.get("authorizerConfiguration") or {}).get("customJWTAuthorizer") or {}


def _authentication(name: str, jwt: dict[str, Any]) -> tuple[dict[str, Any] | None, list[Risk]]:
    """The fact that says how callers are checked, and the risk when it lets anyone's token
    from the identity provider in: AWS documents audiences and clients as what tells
    tokens apart (inbound-jwt-authorizer)."""
    if not jwt:
        return _fact("Authentication", "AWS credentials (IAM, SigV4)"), []
    narrowed = [
        label
        for label, key in (("audiences", "allowedAudience"), ("clients", "allowedClients"))
        if jwt.get(key)
    ]
    if narrowed:
        text = f"Tokens from {jwt.get('discoveryUrl')}, for its allowed {' and '.join(narrowed)}"
        return _fact("Authentication", text), []
    text = f"Tokens from {jwt.get('discoveryUrl')}, whatever they were issued for"
    risk = Risk(
        "platform.weak_authentication",
        "medium",
        f"{name} takes tokens issued for any application",
        f"Its JWT authorizer checks neither audiences nor clients, so a token "
        f"{jwt.get('discoveryUrl')} issued to another application or user gets in.",
        "Set the allowed audiences or clients on its inbound authorization in AgentCore.",
        {"discovery_url": jwt.get("discoveryUrl")},
    )
    return _fact("Authentication", text, tone="warning"), [risk]


def _secret_risk(name: str, variables: dict[str, Any]) -> list[Risk]:
    secrets = _secrets(variables)
    if not secrets:
        return []
    return [
        Risk(
            "platform.plain_secret",
            "high",
            f"{name} keeps secrets in its environment variables",
            "These variables' names say they hold secrets, and their values are plain text that "
            "anyone who may read its configuration sees: " + ", ".join(secrets) + ".",
            "Keep them in AWS Secrets Manager or AgentCore Identity's credential providers, and "
            "read them at run time.",
            {"variables": secrets},
        )
    ]


def _tool_risk(name: str, risky: list[tuple[str, str]]) -> list[Risk]:
    if not risky:
        return []
    severity = "high" if any(level == "high" for _, level in risky) else "medium"
    return [
        Risk(
            "platform.risky_tool",
            severity,
            f"{name} can run code or work a computer",
            "Its tools act on what it is asked, so a prompt injection acts too: "
            + ", ".join(tool for tool, _ in risky)
            + ".",
            "Keep these tools to agents that need them, behind a guardrail, or confirm the agent "
            "needs them and ask an approver to accept its risk.",
            {"tools": [tool for tool, _ in risky]},
        )
    ]


def _open_to_anyone(policy: dict[str, Any]) -> bool:
    """Whether a resource policy lets any AWS principal in, with no condition narrowing it."""
    statements = policy.get("Statement") or []
    for statement in [statements] if isinstance(statements, dict) else statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if isinstance(principal, dict):
            principal = principal.get("AWS")
        if principal in ("*", ["*"]) and not statement.get("Condition"):
            return True
    return False


def bedrock_agent(
    agent: dict[str, Any],
    groups: list[dict[str, Any]],
    knowledge: list[dict[str, Any]],
    aliases: list[dict[str, Any]],
    account: str,
    region: str,
    part: str,
) -> Found:
    """An Amazon Bedrock agent (GetAgent over its ListAgents summary), as of its working
    draft: its action groups, knowledge bases and aliases."""
    name = str(agent.get("agentName") or agent["agentId"])
    arn = agent.get("agentArn") or f"arn:aws:bedrock:{region}:{account}:agent/{agent['agentId']}"
    guardrail = agent.get("guardrailConfiguration") or {}
    tools, risky = [], []
    for group in groups:
        if group.get("actionGroupState") == "DISABLED":
            continue
        signature = group.get("parentActionSignature")
        executor = group.get("actionGroupExecutor") or {}
        functions = [
            str(f.get("name")) for f in (group.get("functionSchema") or {}).get("functions") or []
        ]
        detail = None
        if signature in BUILT_IN:
            kind, tone, level = BUILT_IN[signature]
            if level:
                risky.append((kind, level))
        elif executor.get("customControl") == "RETURN_CONTROL":
            kind, tone = "Run by the calling application", None
            detail = "Bedrock hands each call back to the application that invoked the agent"
        else:
            kind, tone = "Lambda", None
            detail = executor.get("lambda")
        if functions:
            detail = "; ".join(filter(None, [detail, "functions: " + ", ".join(functions)]))
        elif group.get("apiSchema"):
            detail = "; ".join(filter(None, [detail, "an OpenAPI schema"]))
        tool = {"name": group.get("actionGroupName") or group.get("actionGroupId"), "kind": kind}
        tools.append({**tool, "detail": detail, **({"tone": tone} if tone else {})})
    routes = [
        f"{a.get('agentAliasName')} → version "
        + ", ".join(str(r.get("agentVersion")) for r in a.get("routingConfiguration") or [])
        for a in aliases
        if a.get("aliasInvocationState", "ACCEPT_INVOCATIONS") == "ACCEPT_INVOCATIONS"
    ]
    memory = (agent.get("memoryConfiguration") or {}).get("enabledMemoryTypes") or []
    has_guardrail = bool(guardrail.get("guardrailIdentifier"))
    facts = _facts(
        _fact("Service", "Agents for Amazon Bedrock (Agents Classic, in maintenance)"),
        _fact("Account", account, code=True),
        _fact("Region", region),
        _fact("Status", agent.get("agentStatus")),
        _fact("Model", agent.get("foundationModel"), code=True),
        _fact(
            "Guardrail",
            f"{guardrail.get('guardrailIdentifier')} (version {guardrail.get('guardrailVersion')})"
            if has_guardrail
            else "None",
            **({} if has_guardrail else {"tone": "warning"}),
        ),
        _fact("Runs as", agent.get("agentResourceRoleArn"), code=True),
        _fact(
            "Works with other agents",
            {"SUPERVISOR": "As a supervisor", "SUPERVISOR_ROUTER": "As a routing supervisor"}.get(
                str(agent.get("agentCollaboration"))
            ),
        ),
        _fact("Memory", ", ".join(memory)),
        _fact("Knowledge bases", len(knowledge) or None),
        _fact("Aliases", "; ".join(routes)),
        _fact("Encryption key", agent.get("customerEncryptionKeyArn") or "AWS owned", code=True),
        _fact("Changed", agent.get("updatedAt")),
    )
    risks = _tool_risk(name, risky)
    if not has_guardrail:
        risks.append(
            Risk(
                "platform.no_guardrail",
                "medium",
                f"{name} has no Bedrock guardrail",
                "Nothing filters what the agent is asked or answers: harmful content, prompt "
                "attacks or sensitive information.",
                "Associate an Amazon Bedrock guardrail with the agent, or confirm none is "
                "needed and ask an approver to accept its risk.",
            )
        )
    return Found(
        external_id=arn,
        name=name,
        kind="Amazon Bedrock agent",
        part=part,
        description=agent.get("description"),
        details={
            "facts": facts,
            "tools": tools,
            "status": agent.get("agentStatus"),
            "model": agent.get("foundationModel"),
            "guardrail": guardrail.get("guardrailIdentifier"),
            "role": agent.get("agentResourceRoleArn"),
            "region": region,
            "account": account,
        },
        external_ids={"aws_arn": arn},
        risks=risks,
        instructions=agent.get("instruction"),
    )


def _model(model: dict[str, Any]) -> str | None:
    for key, provider in (
        ("bedrockModelConfig", "Amazon Bedrock"),
        ("openAiModelConfig", "OpenAI"),
        ("geminiModelConfig", "Google Gemini"),
        ("liteLlmModelConfig", "LiteLLM"),
    ):
        if model.get(key):
            return f"{provider}: {model[key].get('modelId')}"
    return None


def harness(record: dict[str, Any], account: str, region: str, part: str) -> Found:
    """An AgentCore harness: AWS's managed agent (GetHarness over its ListHarnesses summary)."""
    name = str(record.get("harnessName") or record["harnessId"])
    arn = (
        record.get("arn")
        or f"arn:aws:bedrock-agentcore:{region}:{account}:harness/{record['harnessId']}"
    )
    environment = (record.get("environment") or {}).get("agentCoreRuntimeEnvironment") or {}
    network = (environment.get("networkConfiguration") or {}).get("networkMode")
    tools, risky = [], []
    for tool in record.get("tools") or []:
        kind, tone, level = HARNESS_TOOLS.get(str(tool.get("type")), (tool.get("type"), None, None))
        config = tool.get("config") or {}
        detail = None
        if config.get("remoteMcp"):
            remote = config["remoteMcp"]
            parts = urlsplit(str(remote.get("url") or ""))
            # The URL's path or query, and the headers' values, may carry credentials.
            detail = f"{parts.scheme}://{parts.hostname}" if parts.hostname else None
            if remote.get("headers"):
                detail = "; ".join(
                    filter(None, [detail, "headers: " + ", ".join(sorted(remote["headers"]))])
                )
        elif config.get("agentCoreGateway"):
            detail = config["agentCoreGateway"].get("gatewayArn")
        if level:
            risky.append((str(kind), level))
        tools.append(
            {
                "name": tool.get("name") or kind,
                "kind": kind,
                "detail": detail,
                **({"tone": tone} if tone else {}),
            }
        )
    variables = record.get("environmentVariables") or {}
    jwt = _jwt(record)
    authentication, auth_risks = _authentication(name, jwt)
    memory = record.get("memory") or {}
    facts = _facts(
        _fact("Account", account, code=True),
        _fact("Region", region),
        _fact("Status", record.get("status")),
        _fact("Model", _model(record.get("model") or {}), code=True),
        authentication,
        _fact("Runs as", record.get("executionRoleArn"), code=True),
        _fact("Runtime", environment.get("agentRuntimeArn"), code=True),
        _fact("Outbound network", {"PUBLIC": "The internet", "VPC": "Your VPC"}.get(str(network))),
        _fact(
            "Tools it may use",
            ", ".join(record["allowedTools"]) if record.get("allowedTools") else "All of its tools",
        ),
        _fact(
            "Memory", "Off" if memory.get("disabled") is not None else ("On" if memory else None)
        ),
        _fact("Hooks", len(record.get("hooks") or []) or None),
        _fact("Environment variables", ", ".join(sorted(variables))),
        _fact("Version", record.get("harnessVersion")),
        _fact("Changed", record.get("updatedAt")),
    )
    prompts = [str(p.get("text")) for p in record.get("systemPrompt") or [] if isinstance(p, dict)]
    return Found(
        external_id=arn,
        name=name,
        kind="AgentCore harness",
        part=part,
        details={
            "facts": facts,
            "tools": tools,
            "status": record.get("status"),
            "model": _model(record.get("model") or {}),
            "authentication": "jwt" if jwt else "iam",
            "role": record.get("executionRoleArn"),
            "runtime": environment.get("agentRuntimeArn"),
            "environment_variables": sorted(variables),
            "region": region,
            "account": account,
        },
        external_ids={"aws_arn": arn},
        risks=auth_risks + _secret_risk(name, variables) + _tool_risk(name, risky),
        instructions="\n\n".join(p for p in prompts if p.strip()) or None,
    )


# What a runtime is, by the protocol it serves.
RUNTIME_KINDS = {"MCP": "AgentCore runtime (MCP server)", "A2A": "AgentCore runtime (A2A agent)"}


def agent_runtime(
    runtime: dict[str, Any],
    account: str,
    region: str,
    part: str,
    *,
    policy: dict[str, Any] | None = None,
) -> Found:
    """An AgentCore agent runtime (GetAgentRuntime over its ListAgentRuntimes summary). Its
    resource ``policy``: ``{}`` for none, None when it wasn't read."""
    name = str(runtime.get("agentRuntimeName") or runtime["agentRuntimeId"])
    arn = runtime.get("agentRuntimeArn") or (
        f"arn:aws:bedrock-agentcore:{region}:{account}:runtime/{runtime['agentRuntimeId']}"
    )
    protocol = (runtime.get("protocolConfiguration") or {}).get("serverProtocol") or "HTTP"
    network = (runtime.get("networkConfiguration") or {}).get("networkMode")
    jwt = _jwt(runtime)
    authentication, risks = _authentication(name, jwt)
    variables = runtime.get("environmentVariables") or {}
    artifact = runtime.get("agentRuntimeArtifact") or {}
    container = (artifact.get("containerConfiguration") or {}).get("containerUri")
    code = artifact.get("codeConfiguration") or {}
    mmds = (runtime.get("metadataConfiguration") or {}).get("requireMMDSV2")
    anyone = bool(policy) and _open_to_anyone(policy or {})
    if jwt:
        policy_fact = None  # a runtime that takes tokens must let "*" in: tokens decide
    elif anyone:
        policy_fact = _fact("Resource policy", "Lets any AWS account in", tone="serious")
    elif policy == {}:
        policy_fact = _fact("Resource policy", "None")
    else:
        policy_fact = _fact(
            "Resource policy", "Narrows who may invoke it" if policy else "AgentGov may not read it"
        )
    facts = _facts(
        _fact("Account", account, code=True),
        _fact("Region", region),
        _fact("Status", runtime.get("status")),
        _fact("Protocol", protocol),
        authentication,
        policy_fact,
        _fact("Outbound network", {"PUBLIC": "The internet", "VPC": "Your VPC"}.get(str(network))),
        _fact("Runs as", runtime.get("roleArn"), code=True),
        _fact(
            "Workload identity",
            (runtime.get("workloadIdentityDetails") or {}).get("workloadIdentityArn"),
            code=True,
        ),
        _fact(
            "Instance metadata",
            "MMDSv2 only" if mmds else "MMDSv1 allowed",
            **({} if mmds else {"tone": "warning"}),
        ),
        _fact("Container", container, code=True),
        _fact("Code", code.get("runtime")),
        _fact("Environment variables", ", ".join(sorted(variables))),
        _fact("Version", runtime.get("agentRuntimeVersion")),
        _fact("Changed", runtime.get("lastUpdatedAt")),
    )
    if anyone:
        risks.append(
            Risk(
                "platform.no_authentication",
                "high",
                f"{name} lets any AWS account invoke it",
                "Its resource policy allows any AWS principal, with no condition narrowing it "
                "to your organisation or accounts: anyone with AWS credentials may call it.",
                "Name the accounts or principals that may invoke it in its resource policy, or "
                "add a condition such as aws:PrincipalOrgID.",
            )
        )
    return Found(
        external_id=arn,
        name=name,
        kind=RUNTIME_KINDS.get(protocol, "AgentCore agent runtime"),
        part=part,
        description=runtime.get("description"),
        details={
            "facts": facts,
            "status": runtime.get("status"),
            "protocol": protocol,
            "network": network,
            "authentication": "jwt" if jwt else "iam",
            "role": runtime.get("roleArn"),
            "environment_variables": sorted(variables),
            "region": region,
            "account": account,
        },
        external_ids={"aws_arn": arn},
        risks=risks + _secret_risk(name, variables),
    )


# What a gateway's target is, by where its configuration says it sends calls.
TARGETS = {
    ("mcp", "lambda"): "Lambda function",
    ("mcp", "openApiSchema"): "OpenAPI",
    ("mcp", "smithyModel"): "Smithy model",
    ("mcp", "mcpServer"): "MCP server",
    ("mcp", "apiGateway"): "API Gateway",
    ("mcp", "connector"): "Connector",
    ("http", "agentcoreRuntime"): "AgentCore runtime",
    ("http", "passthrough"): "Passthrough",
    ("http", "connector"): "HTTP connector",
    ("inference", "provider"): "Model provider",
    ("inference", "connector"): "Model connector",
}
# How a gateway signs in to a target.
OUTBOUND = {
    "GATEWAY_IAM_ROLE": "as the gateway's role",
    "OAUTH": "with OAuth",
    "API_KEY": "with an API key",
    "CALLER_IAM_CREDENTIALS": "as the caller (AWS credentials)",
    "JWT_PASSTHROUGH": "with the caller's token",
}


def _host(url: Any) -> str | None:
    """A URL's scheme and host: its path or query may carry credentials."""
    parts = urlsplit(str(url or ""))
    return f"{parts.scheme}://{parts.hostname}" if parts.hostname else None


def _target(target: dict[str, Any]) -> dict[str, Any]:
    """One gateway target as a tool: what it is, where it sends calls and how it signs in."""
    config = target.get("targetConfiguration") or {}
    kind, spec = target.get("targetType") or "Target", {}
    for (family, key), label in TARGETS.items():
        if isinstance((config.get(family) or {}).get(key), dict):
            kind, spec = label, config[family][key]
            break
    where = (
        spec.get("lambdaArn")
        or spec.get("arn")
        or _host(spec.get("endpoint"))
        or ("/".join(filter(None, [spec.get("restApiId"), spec.get("stage")])) or None)
        or (spec.get("source") or {}).get("connectorId")
        or ((spec.get("s3") or {}).get("uri"))
    )
    if kind == "Passthrough" and spec.get("protocolType"):
        kind = f"Passthrough ({spec['protocolType']})"
    providers = [
        str(c.get("credentialProviderType"))
        for c in target.get("credentialProviderConfigurations") or []
        if isinstance(c, dict)
    ]
    signs = ", ".join(OUTBOUND.get(p, p) for p in providers) or "with no authorization"
    status = target.get("status")
    detail = " · ".join(
        filter(None, [where, signs, None if status in (None, "READY") else str(status)])
    )
    return {
        "name": str(target.get("name") or target.get("targetId")),
        "kind": kind,
        "detail": detail,
        **({"tone": "warning"} if not providers else {}),
    }


def _open_gateway(name: str, host: str | None) -> Risk:
    return Risk(
        "platform.no_authentication",
        "high",
        f"{name} lets anyone call its tools",
        f"It has no inbound authorization, so anyone who can reach {host or 'its URL'} may list "
        "and call its tools, which reach its targets with the gateway's own credentials.",
        "Give it a JWT authorizer or AWS IAM authorization: AWS advises against gateways "
        "without one beyond testing.",
    )


def agentcore_gateway(
    gateway: dict[str, Any],
    targets: list[dict[str, Any]],
    account: str,
    region: str,
    part: str,
    *,
    policy: dict[str, Any] | None = None,
) -> Found:
    """An AgentCore gateway: an MCP server in front of its targets (GetGateway over its
    ListGateways summary, and GetGatewayTarget for each target). Its resource ``policy``:
    ``{}`` for none, None when it wasn't read."""
    name = str(gateway.get("name") or gateway["gatewayId"])
    arn = gateway.get("gatewayArn") or (
        f"arn:aws:bedrock-agentcore:{region}:{account}:gateway/{gateway['gatewayId']}"
    )
    authorizer = str(gateway.get("authorizerType") or "")
    jwt = _jwt(gateway)
    risks: list[Risk] = []
    policy_fact = None
    if authorizer == "NONE":
        authentication = _fact("Authentication", "None: anyone who can reach it", tone="serious")
        risks.append(_open_gateway(name, _host(gateway.get("gatewayUrl"))))
    elif jwt or authorizer in ("CUSTOM_JWT", "AUTHENTICATE_ONLY"):
        authentication, auth_risks = _authentication(name, jwt)
        risks += auth_risks
        if authorizer == "AUTHENTICATE_ONLY" and authentication:
            authentication["value"] += ", passed on to its targets"
    else:
        authentication, _ = _authentication(name, {})
        if policy and _open_to_anyone(policy):
            policy_fact = _fact("Resource policy", "Lets any AWS account in", tone="serious")
            risks.append(
                Risk(
                    "platform.no_authentication",
                    "high",
                    f"{name} lets any AWS account call its tools",
                    "Its resource policy allows any AWS principal, with no condition narrowing it "
                    "to your organisation or accounts: anyone with AWS credentials may call it.",
                    "Name the accounts or principals that may invoke it in its resource policy, "
                    "or add a condition such as aws:PrincipalOrgID.",
                )
            )
        elif policy == {}:
            policy_fact = _fact("Resource policy", "None")
        else:
            policy_fact = _fact(
                "Resource policy",
                "Narrows who may invoke it" if policy else "AgentGov may not read it",
            )
    engine = gateway.get("policyEngineConfiguration") or {}
    waf = gateway.get("wafConfiguration") or {}
    mcp = (gateway.get("protocolConfiguration") or {}).get("mcp") or {}
    facts = _facts(
        _fact("Account", account, code=True),
        _fact("Region", region),
        _fact("Status", gateway.get("status")),
        _fact("URL", gateway.get("gatewayUrl"), code=True),
        authentication,
        policy_fact,
        _fact(
            "Policy engine",
            {"ENFORCE": "Decides each tool call", "LOG_ONLY": "Logs only, decides nothing"}.get(
                str(engine.get("mode")), "None"
            ),
            **({"tone": "warning"} if engine.get("mode") == "LOG_ONLY" else {}),
        ),
        _fact("Interceptors", len(gateway.get("interceptorConfigurations") or []) or None),
        _fact(
            "Errors",
            "Detailed (DEBUG): callers see the gateway's internals"
            if gateway.get("exceptionLevel") == "DEBUG"
            else None,
            tone="warning",
        ),
        _fact(
            "Web ACL",
            None
            if not gateway.get("webAclArn")
            else (
                "Lets calls through when it fails"
                if waf.get("failureMode") == "FAIL_OPEN"
                else "Stops calls when it fails"
            ),
            **({"tone": "warning"} if waf.get("failureMode") == "FAIL_OPEN" else {}),
        ),
        _fact("Runs as", gateway.get("roleArn"), code=True),
        _fact("Tool search", "Semantic" if mcp.get("searchType") == "SEMANTIC" else None),
        _fact("Encryption key", gateway.get("kmsKeyArn"), code=True),
        _fact("Changed", gateway.get("updatedAt")),
    )
    return Found(
        external_id=arn,
        name=name,
        kind="AgentCore gateway (MCP server)",
        part=part,
        description=gateway.get("description"),
        details={
            "facts": facts,
            "tools": [_target(t) for t in targets],
            "status": gateway.get("status"),
            "authentication": authorizer.lower() or None,
            "role": gateway.get("roleArn"),
            "region": region,
            "account": account,
        },
        external_ids={"aws_arn": arn},
        risks=risks,
        # What it tells the agents that use it, as an MCP server's instructions.
        instructions=mcp.get("instructions") or None,
    )


# How an Amazon Quick action connector signs in to the system it acts on, and whether that
# one credential stands for everyone who uses the agent.
QUICK_AUTH = {
    "OAUTH2_AUTHORIZATION_CODE": ("as each user (OAuth)", False),
    "OAUTH2_CLIENT_CREDENTIALS": ("with one shared OAuth client", True),
    "API_KEY": ("with one shared API key", True),
    "BASIC": ("with one shared user name and password", True),
    "IAM": ("with an IAM role", True),
    "NONE": ("with no authentication", False),
}
UPPER = {"CRM", "HTTP", "S3", "SAP", "HR", "AWS"}


def _words(value: Any) -> str:
    """An enum value in words: SALESFORCE_CRM is Salesforce CRM."""
    return " ".join(w if w in UPPER else w.capitalize() for w in str(value or "").split("_") if w)


def quick_agent(
    agent: dict[str, Any],
    permissions: list[dict[str, Any]] | None,
    connectors: dict[str, dict[str, Any] | None],
    account: str,
    region: str,
    part: str,
) -> Found:
    """An Amazon Quick agent (DescribeAgent over its ListAgents summary), with who it is shared
    with (None when unread) and its action connectors (None for one that wasn't read)."""
    name = str(agent.get("Name") or agent["AgentId"])
    arn = agent.get("Arn") or f"arn:aws:quicksight:{region}:{account}:agent/{agent['AgentId']}"
    principals = [str(p.get("Principal")) for p in permissions or [] if isinstance(p, dict)]
    namespaces = sorted(p.rsplit("/", 1)[-1] for p in principals if ":namespace/" in p and "/" in p)
    risks: list[Risk] = []
    if namespaces:
        risks.append(
            Risk(
                "platform.shared_with_everyone",
                "medium",
                f"{name} is shared with everyone in Amazon Quick",
                "It is shared with whole namespaces, every user in them: "
                + ", ".join(namespaces)
                + ".",
                "Share it with the users and groups that need it, or confirm everyone should "
                "have it and ask an approver to accept its risk.",
                {"namespaces": namespaces},
            )
        )
    tools, shared = [], []
    for connector_arn, connector in connectors.items():
        if connector is None:
            tools.append(
                {
                    "name": connector_arn.rsplit("/", 1)[-1],
                    "kind": "Action connector",
                    "detail": "AgentGov may not read it",
                }
            )
            continue
        auth = str((connector.get("AuthenticationConfig") or {}).get("AuthenticationType") or "")
        how, one = QUICK_AUTH.get(auth, (auth.lower() or None, False))
        label = str(connector.get("Name") or connector_arn.rsplit("/", 1)[-1])
        if one:
            shared.append(label)
        actions = len(connector.get("EnabledActions") or [])
        tools.append(
            {
                "name": label,
                "kind": _words(connector.get("Type")) or "Action connector",
                "detail": " · ".join(
                    filter(
                        None,
                        [
                            how,
                            f"{actions} action{'s' if actions != 1 else ''}" if actions else None,
                            "through a VPC connection"
                            if connector.get("VpcConnectionArn")
                            else None,
                        ],
                    )
                ),
                **({"tone": "warning"} if one or auth == "NONE" else {}),
            }
        )
    if shared:
        risks.append(
            Risk(
                "platform.maker_credentials",
                "medium",
                f"{name} acts with one shared credential",
                "These action connectors sign in with one credential for everyone who uses the "
                "agent, so its users act there with that credential's access, not their own: "
                + ", ".join(sorted(shared))
                + ".",
                "Use connectors that sign in as each user (OAuth authorization code), or confirm "
                "the shared access is intended and ask an approver to accept its risk.",
                {"connectors": sorted(shared)},
            )
        )
    prompt = agent.get("CustomPromptInterface") or {}
    if permissions is None:
        who = "AgentGov may not read who may use it"
    elif namespaces:
        who = "Everyone in " + ", ".join(namespaces)
    else:
        users = sum(1 for p in principals if ":user/" in p)
        groups = sum(1 for p in principals if ":group/" in p)
        who = (
            ", ".join(
                filter(
                    None,
                    [
                        f"{users} user{'s' if users != 1 else ''}" if users else None,
                        f"{groups} group{'s' if groups != 1 else ''}" if groups else None,
                    ],
                )
            )
            or "Only its owners"
        )
    facts = _facts(
        _fact("Account", account, code=True),
        _fact("Region", region),
        _fact(
            "Lifecycle",
            {"PUBLISHED": "Published", "PREVIEW": "Preview"}.get(str(agent.get("AgentLifecycle"))),
        ),
        _fact("Status", agent.get("AgentStatus")),
        _fact("Created by", agent.get("Creator")),
        _fact("Shared with", who, **({"tone": "warning"} if namespaces else {})),
        _fact("Spaces", len(agent.get("Spaces") or []) or None),
        _fact("Changed", agent.get("UpdatedAt")),
    )
    instructions = "\n\n".join(
        str(prompt[key]) for key in ("Identity", "CustomInstructions") if prompt.get(key)
    )
    return Found(
        external_id=arn,
        name=name,
        kind="Amazon Quick agent",
        part=part,
        description=agent.get("Description"),
        details={
            "facts": facts,
            "tools": tools,
            "status": agent.get("AgentStatus"),
            "region": region,
            "account": account,
        },
        external_ids={"aws_arn": arn},
        risks=risks,
        instructions=instructions or None,
    )


# How the registry words a record's status.
RECORD_STATUS = {
    "DRAFT": "Draft",
    "PENDING_APPROVAL": "Waiting for approval",
    "APPROVED": "Approved",
    "REJECTED": "Rejected",
    "DEPRECATED": "Deprecated",
    "CREATING": "Being created",
    "UPDATING": "Being updated",
    "CREATE_FAILED": "Couldn't be created",
    "UPDATE_FAILED": "Couldn't be updated",
}
# The protocols a record's descriptors describe.
DESCRIPTORS = {"a2aAgentCard": "A2A", "mcpServer": "MCP", "http": "HTTP", "agui": "AG-UI"}
# How an A2A agent card says callers sign in: its schemes' types (A2A 0.3), or their names
# (A2A 1.0).
SCHEMES = {
    "apiKey": "API key",
    "http": "HTTP authentication",
    "oauth2": "OAuth 2.0",
    "openIdConnect": "OpenID Connect",
    "mutualTLS": "Mutual TLS",
    "apiKeySecurityScheme": "API key",
    "httpAuthSecurityScheme": "HTTP authentication",
    "oauth2SecurityScheme": "OAuth 2.0",
    "openIdConnectSecurityScheme": "OpenID Connect",
    "mtlsSecurityScheme": "Mutual TLS",
}


def _json(text: Any) -> Any:
    """A descriptor's data: JSON in a string, or None when it isn't."""
    try:
        return json.loads(text) if isinstance(text, str) else None
    except ValueError:
        return None


def _short(text: Any, limit: int = 200) -> str | None:
    words = " ".join(str(text or "").split())
    return (words if len(words) <= limit else words[: limit - 1] + "…") or None


def _items(value: Any) -> list[dict[str, Any]]:
    """The objects in a list a descriptor's data has (people write those by hand)."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _schemes(card: dict[str, Any]) -> list[str]:
    schemes = card.get("securitySchemes")
    found = []
    for scheme in schemes.values() if isinstance(schemes, dict) else []:
        if isinstance(scheme, dict):
            kind = scheme.get("type") or next(iter(scheme), None)
            found.append(SCHEMES.get(str(kind), str(kind)))
    return sorted(set(found))


def registry_record(
    record: dict[str, Any],
    registry: dict[str, Any],
    account: str,
    region: str,
    part: str,
    *,
    versions: int = 1,
) -> Found:
    """A record of AWS Agent Registry (GetRegistryRecord over its ListRegistryRecords summary)
    in ``account``'s ``registry``: an agent or MCP server registered by hand, or an AgentCore
    runtime or gateway the registry detected in an account AgentGov doesn't read itself, known
    by its own ARN. ``versions``: how many records have its name, one for each version."""
    sources = [
        p
        for p in record.get("provenance") or record.get("provenanceSummaryList") or []
        if isinstance(p, dict) and p.get("sourceId")
    ]
    source = sources[0] if sources else {}
    detected = DETECTED.get(str(source.get("sourceType")))
    source_arn = str(source.get("sourceId") or "")
    arn_parts = source_arn.split(":")
    # The account of the runtime or gateway it detected.
    owner = arn_parts[4] if detected and len(arn_parts) > 5 else None
    origin = source.get("sourceDetails") or {}
    runtime = origin.get("agentcoreRuntime") or {}
    gateway = origin.get("agentcoreGateway") or {}
    descriptors = record.get("descriptors") or {}
    card = _json((descriptors.get("a2aAgentCard") or {}).get("data"))
    card = card if isinstance(card, dict) else {}
    mcp = descriptors.get("mcpServer") or {}
    server = _json(mcp.get("data"))
    server = server if isinstance(server, dict) else {}

    label = str(record.get("name") or record["recordId"])
    if owner and label.startswith("aws-autodetected-"):
        label = source_arn.rsplit("/", 1)[-1]  # its ID, not the name the registry made up
    name = str(record.get("displayName") or label)
    if versions > 1 and record.get("recordVersion"):
        name = f"{name} ({record['recordVersion']})"

    risks: list[Risk] = []
    authentication = None
    if detected == GATEWAYS or record.get("recordType") == "GATEWAY":
        kind = "AgentCore gateway (MCP server)"
        protocol = None
        authorizer = str(gateway.get("authorizerType") or "")
        jwt = _jwt(gateway)
        if authorizer == "NONE":
            authentication = _fact(
                "Authentication", "None: anyone who can reach it", tone="serious"
            )
        elif jwt or authorizer in ("CUSTOM_JWT", "AUTHENTICATE_ONLY"):
            authentication = _fact("Authentication", f"Tokens from {jwt.get('discoveryUrl')}")
        elif authorizer == "AWS_IAM":
            authentication = _fact("Authentication", "AWS credentials (IAM, SigV4)")
    elif detected == AGENTCORE:
        protocol = (runtime.get("protocolConfiguration") or {}).get("serverProtocol")
        kind = RUNTIME_KINDS.get(str(protocol), "AgentCore agent runtime")
        jwt = _jwt(runtime)
        if jwt:
            authentication = _fact("Authentication", f"Tokens from {jwt.get('discoveryUrl')}")
        elif runtime:
            authentication = _fact("Authentication", "AWS credentials (IAM, SigV4)")
    else:
        kind = (
            "MCP server"
            if record.get("recordType") == "MCP"
            else "Agent registered in AWS Agent Registry"
        )
        protocol = ", ".join(word for key, word in DESCRIPTORS.items() if descriptors.get(key))
        if card:
            schemes = _schemes(card)
            authentication = _fact(
                "Authentication",
                "Declared in its agent card: " + ", ".join(schemes)
                if schemes
                else "None declared in its agent card",
            )

    urls = [
        ((d.get("source") or {}).get("fromUrl") or {}).get("url")
        for d in descriptors.values()
        if isinstance(d, dict)
    ]
    urls += [card.get("url")] + [
        i.get("url")
        for i in _items(card.get("supportedInterfaces")) + _items(card.get("additionalInterfaces"))
    ]
    urls += [r.get("url") for r in _items(server.get("remotes"))]
    hosts = sorted({h for h in map(_host, urls) if h})
    if authentication and authentication.get("tone") == "serious":
        risks.append(_open_gateway(name, hosts[0] if hosts else None))

    listed = _json(((mcp.get("additionalData") or {}).get("tools") or {}).get("data"))
    listed = listed.get("tools") if isinstance(listed, dict) else listed
    tools = [
        {"name": str(t["name"]), "kind": "MCP tool", "detail": _short(t.get("description"))}
        for t in _items(listed)
        if t.get("name")
    ]
    skills = [
        str(s.get("name") or s.get("id"))
        for s in _items(card.get("skills"))
        if s.get("name") or s.get("id")
    ]
    identity = (runtime or gateway).get("workloadIdentityDetails") or {}
    status = str(record.get("status") or "")
    creator = record.get("createdBy")
    facts = _facts(
        # Where the runtime or gateway is; of what was registered by hand, the registry says.
        _fact("Account", owner, code=True),
        _fact("Region", region if owner else None),
        _fact(
            "Registry",
            f"{registry.get('name') or registry.get('registryId')} ({account}, {region})",
        ),
        _fact(
            "Registry status",
            RECORD_STATUS.get(status, status),
            **({"tone": "warning"} if status == "REJECTED" else {}),
        ),
        _fact(
            "Known from",
            "The registry's auto-detection only: AgentGov doesn't read it in its own account"
            if owner
            else None,
        ),
        _fact("Protocol", protocol),
        authentication,
        _fact("Workload identity", identity.get("workloadIdentityArn"), code=True),
        _fact("Endpoints", ", ".join(hosts), code=True),
        _fact("Skills", ", ".join(skills)),
        _fact("Version", record.get("recordVersion")),
        _fact(
            "Registered from account",
            creator if not owner and creator not in (None, account) else None,
            code=True,
        ),
        _fact("Changed", record.get("updatedAt")),
    )
    arn = record.get("recordArn") or (
        f"arn:aws:agent-registry:{region}:{account}:registry/{registry.get('registryId')}"
        f"/record/{record['recordId']}"
    )
    external_id = source_arn if owner else arn
    return Found(
        external_id=external_id,
        name=name,
        kind=kind,
        part=part,
        description=record.get("description")
        or card.get("description")
        or server.get("description"),
        details={
            "facts": facts,
            **({"tools": tools} if tools else {}),
            "status": status or None,
            "registry": registry.get("registryArn"),
            "record": arn,
            "region": region,
            "account": owner or account,
        },
        external_ids={"aws_arn": external_id},
        risks=risks,
    )
