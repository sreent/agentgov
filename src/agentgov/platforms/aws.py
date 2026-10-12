"""Agents on AWS: Amazon Bedrock agents and Amazon Bedrock AgentCore's harnesses and runtimes.

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

Secrets never leave AWS: of environment variables and remote MCP servers'
headers AgentGov keeps the names, and of those servers' URLs the host.
"""

from __future__ import annotations

import json
import re
import socket
import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx

from agentgov.config import Settings
from agentgov.platforms.aws_auth import Session, sign
from agentgov.platforms.base import Found, Inventory, PlatformError, Risk

BEDROCK_AGENTS = "bedrock-agents"
AGENTCORE = "agentcore"
# Each kind of list is paged this far at most.
MAX_PAGES = 50
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
            for region in self.regions:
                api = _Api(self, session, region)
                for service, read in ((BEDROCK_AGENTS, _bedrock), (AGENTCORE, _agentcore)):
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


def _partial(found: Found, why: str) -> Found:
    found.complete = False
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
        item = agent_runtime(runtime, account, region, part, policy=policy)
        found.append(_partial(item, why) if why else item)
    return found


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
        host = f"{endpoint}.{self.region}.amazonaws.com"
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
            "needs them and dismiss this finding.",
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
                "needed and dismiss this finding.",
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
    kinds = {"MCP": "AgentCore runtime (MCP server)", "A2A": "AgentCore runtime (A2A agent)"}
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
        kind=kinds.get(protocol, "AgentCore agent runtime"),
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
