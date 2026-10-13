"""Agents on Salesforce: Agentforce agents, in one org.

Read-only, with SOQL through the REST API, as the user an External Client App runs as
(the client credentials flow) or as a named user (the JWT bearer flow):

* each agent (``BotDefinition`` of type ``ExternalCopilot``, a service agent, or
  ``InternalCopilot``, an employee agent) and its active version (``BotVersion``);
* its topics (``GenAiPluginDefinition``), their instructions and their actions
  (``GenAiFunctionDefinition``), through the version's planner
  (``GenAiPlannerDefinition``);
* the user a service agent runs as, and what that user may do (``PermissionSetAssignment``);
* who an employee agent is given to (``SetupEntityAccess``), and how many people that is.

Einstein Bots (``BotDefinition`` of type ``Bot``) aren't agents and aren't read. The org is
one part (``contoso.my.salesforce.com/agents``).
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt

from agentgov.config import Settings
from agentgov.platforms.base import Found, Inventory, PlatformError, Risk

AGENTS = "agents"
OLDEST_API = 60.0  # BotDefinition and the GenAi* objects
KINDS = {
    "ExternalCopilot": "Agentforce service agent",
    "InternalCopilot": "Agentforce employee agent",
}
# What a running user may do that lets a prompt injection reach far beyond the agent's job.
BROAD = {
    "PermissionsModifyAllData": ("modify all data", "high"),
    "PermissionsViewAllData": ("view all data", "high"),
    "PermissionsManageUsers": ("manage users", "high"),
    "PermissionsAuthorApex": ("author Apex", "high"),
    "PermissionsModifyMetadata": ("modify metadata", "high"),
    "PermissionsCustomizeApplication": ("customize the application", "medium"),
}
# Actions that reach outside Salesforce.
EXTERNAL = {"externalService", "mcpTool", "api", "executeIntegrationProcedure", "slack"}
# An employee agent given to at least this share of the org's people is everyone's.
EVERYONE = 0.9
MAX_PAGES = 50
RETRIES = (0.5, 1.0, 2.0)


class SalesforceConnector:
    """Reads the Agentforce agents in the org at ``AGENTGOV_SALESFORCE_URL``."""

    def __init__(
        self,
        settings: Settings,
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.http = http or httpx.Client(timeout=30)
        self.url = str(settings.salesforce_url).rstrip("/")
        self.host = urlsplit(self.url).hostname or self.url
        self.client_id = str(settings.salesforce_client_id)
        self.client_secret = settings.salesforce_client_secret
        self.username = settings.salesforce_username
        self.key_file = settings.salesforce_private_key_file
        self._sleep = sleep
        self._lock = threading.Lock()
        self._token: str | None = None
        self._instance = self.url
        self._version: str | None = None

    def inventory(self) -> Inventory:
        part = f"{self.host}/{AGENTS}"
        try:
            found = self._agents()
        except PlatformError as exc:
            raise PlatformError(f"{part}: {exc}") from exc
        for item in found:
            item.part = part
        return Inventory(found=found, read={part})

    # -- tokens -------------------------------------------------------------------

    def _new_token(self) -> str:
        token_url = f"{self.url}/services/oauth2/token"
        if self.client_secret:
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        else:
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": self._assertion(),
            }
        try:
            resp = self.http.post(token_url, data=data)
        except httpx.HTTPError as exc:
            raise PlatformError(f"{self.host} is unreachable: {exc}") from exc
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code != 200 or not isinstance(body, dict) or not body.get("access_token"):
            detail = (
                body.get("error_description") or body.get("error")
                if isinstance(body, dict)
                else None
            )
            raise PlatformError(
                f"Salesforce refused AgentGov's credentials ({resp.status_code}): "
                f"{detail or resp.text[:200]}",
                status=resp.status_code,
            )
        instance = str(body.get("instance_url") or self.url).rstrip("/")
        if urlsplit(instance).scheme != "https":
            raise PlatformError(
                f"Salesforce answered with an instance that isn't HTTPS: {instance}"
            )
        self._instance = instance
        return str(body["access_token"])

    def _assertion(self) -> str:
        """A JWT for the bearer flow, signed with the app's certificate's key."""
        try:
            key = Path(str(self.key_file)).read_text()
        except OSError as exc:
            raise PlatformError(f"can't read the Salesforce private key: {exc}") from exc
        # Sandboxes sign in at test.salesforce.com, production orgs at login.
        audience = (
            "https://test.salesforce.com"
            if ".sandbox." in self.host
            else "https://login.salesforce.com"
        )
        try:
            return jwt.encode(
                {
                    "iss": self.client_id,
                    "sub": self.username,
                    "aud": audience,
                    "exp": int(time.time()) + 180,
                },
                key,
                algorithm="RS256",
            )
        except (ValueError, TypeError) as exc:
            raise PlatformError(f"the Salesforce private key can't sign: {exc}") from exc

    def _bearer(self, *, renew: bool = False) -> str:
        with self._lock:
            if self._token is None or renew:
                self._token = self._new_token()
            return self._token

    # -- calls --------------------------------------------------------------------

    def _get(self, path_or_url: str, params: dict[str, str] | None = None) -> Any:
        url = path_or_url if path_or_url.startswith("https://") else self._instance + path_or_url
        renewed = False
        attempt = 0
        while True:
            token = self._bearer()
            try:
                resp = self.http.get(
                    url, params=params, headers={"Authorization": f"Bearer {token}"}
                )
            except httpx.HTTPError as exc:
                raise PlatformError(f"{self.host} is unreachable: {exc}") from exc
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError as exc:
                    raise PlatformError(f"{url} answered with no JSON") from exc
            if resp.status_code == 401 and not renewed:  # the session expired
                self._bearer(renew=True)
                renewed = True
                continue
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < len(RETRIES):
                self._sleep(RETRIES[attempt])
                attempt += 1
                continue
            raise SalesforceError(resp)

    def _api(self) -> str:
        """The newest REST API version the org offers, as a path prefix."""
        if self._version is None:
            versions = self._get("/services/data/")
            numbers = sorted(
                (float(v["version"]) for v in versions if isinstance(v, dict) and "version" in v),
                reverse=True,
            )
            if not numbers or numbers[0] < OLDEST_API:
                raise PlatformError(
                    f"the org's newest API version is {numbers[0] if numbers else 'unknown'}; "
                    f"reading agents needs {OLDEST_API} or later"
                )
            self._version = f"/services/data/v{numbers[0]:.1f}"
        return self._version

    def query(self, soql: str) -> list[dict[str, Any]]:
        """Every record a SOQL query returns, page by page."""
        page = self._get(f"{self._api()}/query", {"q": soql})
        records = list(page.get("records") or [])
        for _ in range(MAX_PAGES):
            if page.get("done", True) or not page.get("nextRecordsUrl"):
                return records
            page = self._get(str(page["nextRecordsUrl"]))
            records += page.get("records") or []
        raise PlatformError(f"too many records for: {soql[:80]}")

    def maybe(self, soql: str) -> list[dict[str, Any]] | None:
        """A query's records, or None when the org has no such object or field (an older
        release, or a feature that's off) or AgentGov's user may not read it."""
        try:
            return self.query(soql)
        except SalesforceError as exc:
            if exc.code in ("INVALID_TYPE", "INVALID_FIELD", "INSUFFICIENT_ACCESS") or (
                exc.status == 403 and exc.code != "REQUEST_LIMIT_EXCEEDED"
            ):
                return None
            raise

    def count(self, soql: str) -> int:
        page = self._get(f"{self._api()}/query", {"q": soql})
        return int(page.get("totalSize") or 0)

    # -- the agents ---------------------------------------------------------------

    def _agents(self) -> list[Found]:
        agents = self.query(
            "SELECT Id, DeveloperName, MasterLabel, Type, AgentType, AgentTemplate, "
            "Description, BotUserId, BotUser.Username, CreatedDate, LastModifiedDate "
            "FROM BotDefinition WHERE Type IN ('ExternalCopilot', 'InternalCopilot')"
        )
        if not agents:
            return []
        ids = [str(a["Id"]) for a in agents]
        versions = _by(
            self.query(
                _soql(
                    "SELECT Id, BotDefinitionId, VersionNumber, Status FROM BotVersion "
                    "WHERE BotDefinitionId IN ({agents})",
                    agents=ids,
                )
            ),
            "BotDefinitionId",
        )
        chosen = {agent_id: _version(rows) for agent_id, rows in versions.items()}
        planners = self.maybe(
            "SELECT Id, DeveloperName, LinkedBotVersionId FROM GenAiPlannerDefinition "
            "WHERE LinkedBotVersionId != null"
        )
        topics = self.maybe(
            "SELECT Id, DeveloperName, MasterLabel, Description, Scope, PlannerId, ParentId "
            "FROM GenAiPluginDefinition"
        )
        actions = self.maybe(
            "SELECT Id, DeveloperName, MasterLabel, InvocationTarget, InvocationTargetType, "
            "IsConfirmationRequired, PluginId, PlannerId, ParentId FROM GenAiFunctionDefinition"
        )
        links = self.maybe("SELECT Id, PlannerId, Plugin FROM GenAiPlannerFunctionDef") or []
        steps = self.maybe(
            "SELECT GenAiPluginDefinitionId, Description, SortOrder FROM GenAiPluginInstructionDef"
        )
        plan = Plans(planners, topics, actions, links, steps)
        users = [str(a["BotUserId"]) for a in agents if a.get("BotUserId")]
        powers = self._powers(users) if users else {}
        access = self._access([str(a["Id"]) for a in agents if a.get("Type") == "InternalCopilot"])
        found = []
        for a in agents:
            unread = [] if plan.complete else ["its topics and actions"]
            if a.get("BotUserId") and powers is None:
                unread.append("what its user may do")
            if a.get("Type") == "InternalCopilot" and access is None:
                unread.append("who has it")
            found.append(
                agentforce_agent(
                    a,
                    chosen.get(str(a["Id"])),
                    plan,
                    (powers or {}).get(str(a.get("BotUserId") or "")) or [],
                    (access or {}).get(str(a["Id"])),
                    self.host,
                    unread=unread,
                )
            )
        return found

    def _powers(self, users: list[str]) -> dict[str, list[tuple[str, str, str]]] | None:
        """What each running user may do of BROAD, and through which permission set:
        {user: [(permission, severity, set label)]}, or None when it can't be read."""
        rows = self.maybe(
            _soql(
                "SELECT AssigneeId, PermissionSet.Label, PermissionSet.IsOwnedByProfile, "
                "PermissionSet.Profile.Name, PermissionSet.PermissionsModifyAllData, "
                "PermissionSet.PermissionsViewAllData, PermissionSet.PermissionsManageUsers, "
                "PermissionSet.PermissionsAuthorApex, PermissionSet.PermissionsModifyMetadata, "
                "PermissionSet.PermissionsCustomizeApplication FROM PermissionSetAssignment "
                "WHERE AssigneeId IN ({users})",
                users=users,
            )
        )
        if rows is None:
            return None
        powers: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        for row in rows:
            grant = row.get("PermissionSet") or {}
            label = _grant(grant)
            for name, (words, severity) in BROAD.items():
                if grant.get(name):
                    powers[str(row["AssigneeId"])].append((words, severity, label))
        return powers

    def _access(self, agent_ids: list[str]) -> dict[str, Access] | None:
        """Who each employee agent is given to, and how many people that is."""
        if not agent_ids:
            return {}
        rows = self.maybe(
            _soql(
                "SELECT ParentId, Parent.Label, Parent.IsOwnedByProfile, Parent.Profile.Name, "
                "SetupEntityId FROM SetupEntityAccess WHERE SetupEntityType = 'BotDefinition' "
                "AND SetupEntityId IN ({agents})",
                agents=agent_ids,
            )
        )
        if rows is None:
            return None
        people = self.count(
            "SELECT COUNT() FROM User WHERE IsActive = true AND UserType = 'Standard'"
        )
        found: dict[str, Access] = {}
        for agent_id, grants in _by(rows, "SetupEntityId").items():
            sets = sorted({str(g["ParentId"]) for g in grants})
            given = self.query(
                _soql(
                    "SELECT COUNT_DISTINCT(AssigneeId) n FROM PermissionSetAssignment "
                    "WHERE PermissionSetId IN ({sets}) AND Assignee.IsActive = true "
                    "AND Assignee.UserType = 'Standard'",
                    sets=sets,
                )
            )
            found[agent_id] = Access(
                grants=sorted({_grant(g.get("Parent") or {}) for g in grants}),
                people=int((given[0] if given else {}).get("n") or 0),
                everyone=people,
            )
        return found


class Access:
    def __init__(self, *, grants: list[str], people: int, everyone: int) -> None:
        self.grants, self.people, self.everyone = grants, people, everyone

    @property
    def is_everyone(self) -> bool:
        return self.everyone > 0 and self.people >= EVERYONE * self.everyone


class Plans:
    """Each agent version's topics, their instructions and their actions."""

    def __init__(
        self,
        planners: list[dict[str, Any]] | None,
        topics: list[dict[str, Any]] | None,
        actions: list[dict[str, Any]] | None,
        links: list[dict[str, Any]],
        steps: list[dict[str, Any]] | None,
    ) -> None:
        self.complete = planners is not None and topics is not None and actions is not None
        self.planner = {
            str(p["LinkedBotVersionId"]): str(p["Id"]) for p in planners or [] if p.get("Id")
        }
        # A topic or action belongs to a planner directly, through a link record that owns
        # it, or by name through a link record (one from the org's library).
        owner = {str(link["Id"]): str(link.get("PlannerId")) for link in links}
        named: dict[str, set[str]] = defaultdict(set)
        for link in links:
            if link.get("Plugin"):
                named[str(link["Plugin"])].add(str(link.get("PlannerId")))

        def planners_of(row: dict[str, Any]) -> set[str]:
            found = {str(row["PlannerId"])} if row.get("PlannerId") else set()
            if row.get("ParentId"):
                parent = str(row["ParentId"])
                found.add(owner.get(parent, parent))
            return found | named.get(str(row.get("DeveloperName")), set())

        self.topics: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for topic in topics or []:
            for planner in planners_of(topic):
                self.topics[planner].append(topic)
        topic_planners = {str(t["Id"]): planners_of(t) for t in topics or []}
        self.actions: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for action in actions or []:
            mine = planners_of(action) | topic_planners.get(str(action.get("PluginId")), set())
            for planner in mine:
                self.actions[planner].append(action)
        self.steps: dict[str, list[str]] = defaultdict(list)
        for step in sorted(steps or [], key=lambda s: s.get("SortOrder") or 0):
            if step.get("Description"):
                self.steps[str(step["GenAiPluginDefinitionId"])].append(str(step["Description"]))

    def of(self, version_id: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        planner = self.planner.get(str(version_id)) if version_id else None
        if planner is None:
            return [], []
        return self.topics.get(planner, []), self.actions.get(planner, [])


class SalesforceError(PlatformError):
    """Salesforce's answer to a call it refused, with its error code."""

    def __init__(self, resp: httpx.Response) -> None:
        try:
            body = resp.json()
        except ValueError:
            body = None
        first = body[0] if isinstance(body, list) and body and isinstance(body[0], dict) else {}
        self.code = str(first.get("errorCode") or "")
        detail = ": ".join(filter(None, [self.code, first.get("message") or resp.text[:200]]))
        super().__init__(
            f"Salesforce refused ({resp.status_code}): {detail}", status=resp.status_code
        )


def _soql(template: str, **ids: Iterable[str]) -> str:
    """A query with lists of record IDs put in. Salesforce's IDs are letters and digits,
    so nothing in them needs escaping; anything else is left out."""
    return template.format(
        **{key: ", ".join(f"'{i}'" for i in values if i.isalnum()) for key, values in ids.items()}
    )


def _by(rows: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get(key):
            grouped[str(row[key])].append(row)
    return grouped


def _version(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The active version, or else the newest."""
    active = [r for r in rows if r.get("Status") == "Active"]
    pool = active or rows
    return max(pool, key=lambda r: r.get("VersionNumber") or 0) if pool else None


def _grant(permission_set: dict[str, Any]) -> str:
    if permission_set.get("IsOwnedByProfile"):
        profile = (permission_set.get("Profile") or {}).get("Name")
        return f"the {profile} profile" if profile else "a profile"
    return str(permission_set.get("Label") or "a permission set")


# --------------------------------------------------------------- what each one reports


def _fact(label: str, value: Any, **extra: Any) -> dict[str, Any] | None:
    if value in (None, "", [], {}):
        return None
    return {"label": label, "value": str(value), **extra}


def agentforce_agent(
    agent: dict[str, Any],
    version: dict[str, Any] | None,
    plan: Plans,
    powers: list[tuple[str, str, str]],
    access: Access | None,
    host: str,
    *,
    unread: list[str],
) -> Found:
    """One Agentforce agent with its version's topics and actions, what of BROAD its running
    user may do (``powers``) and, for an employee agent, who has it (``access``); ``unread``
    names what couldn't be read, whose findings are then left as they were."""
    name = str(agent.get("MasterLabel") or agent.get("DeveloperName"))
    service = agent.get("Type") == "ExternalCopilot"
    user = (agent.get("BotUser") or {}).get("Username")
    risks: list[Risk] = []
    if powers:
        severity = "high" if any(s == "high" for _, s, _ in powers) else "medium"
        can = sorted({words for words, _, _ in powers})
        through = sorted({label for _, _, label in powers})
        risks.append(
            Risk(
                "platform.broad_identity",
                severity,
                f"{name} runs as a user who can {_and(can)}",
                f"It runs as {user or 'its agent user'}, who may {_and(can)} through "
                f"{_and(through)}, so whatever a conversation talks it into can reach that far.",
                "Give the agent user only the permission sets its topics need (Salesforce's "
                "Agentforce Service Agent User set, and access to the objects its actions use).",
                {"user": user, "permissions": can, "through": through},
            )
        )
    if access is not None and access.is_everyone:
        risks.append(
            Risk(
                "platform.shared_with_everyone",
                "medium",
                f"{name} is given to almost everyone in the org",
                f"{access.people} of the org's {access.everyone} people have it, through "
                f"{_and(access.grants)}.",
                "Give it through a permission set assigned to the people who need it, or "
                "confirm everyone should have it and ask an approver to accept its risk.",
                {"people": access.people, "of": access.everyone, "through": access.grants},
            )
        )
    topics, actions = plan.of(version.get("Id") if version else None)
    by_topic = {str(t["Id"]): str(t.get("MasterLabel") or t.get("DeveloperName")) for t in topics}
    tools = []
    for action in sorted(actions, key=lambda a: str(a.get("MasterLabel") or "")):
        kind = str(action.get("InvocationTargetType") or "action")
        topic = by_topic.get(str(action.get("PluginId")))
        detail = " · ".join(
            filter(
                None,
                [
                    str(action.get("InvocationTarget") or ""),
                    f"in {topic}" if topic else None,
                    "asks before it acts" if action.get("IsConfirmationRequired") else None,
                    "reaches outside Salesforce" if kind in EXTERNAL else None,
                ],
            )
        )
        tools.append(
            {
                "name": str(action.get("MasterLabel") or action.get("DeveloperName")),
                "kind": kind,
                "detail": detail,
                **({"tone": "warning"} if kind in EXTERNAL else {}),
            }
        )
    instructions = "\n\n".join(
        "\n".join(
            filter(
                None,
                [
                    f"Topic: {t.get('MasterLabel') or t.get('DeveloperName')}",
                    f"Scope: {t['Scope']}" if t.get("Scope") else None,
                    *(f"- {step}" for step in plan.steps.get(str(t["Id"]), [])),
                ],
            )
        )
        for t in topics
    )
    kind = KINDS.get(str(agent.get("Type")), "Agentforce agent")
    agent_type = _words(agent.get("AgentType"))
    same_type = bool(agent_type) and str(agent_type).lower() == kind.lower()
    status = None
    if version:
        active = "active" if version.get("Status") == "Active" else "not active"
        status = f"Version {version.get('VersionNumber')}, {active}"
    if access is None:
        who = None
    elif access.grants:
        who = f"{access.people} of {access.everyone} people, through {_and(access.grants)}"
    else:
        who = "No one has been given it"
    facts = [
        f
        for f in (
            _fact("Org", host, code=True),
            _fact("Agent type", None if same_type else agent_type),
            _fact("Template", agent.get("AgentTemplate")),
            _fact("Version", status),
            _fact(
                "Runs as",
                user if service else "The person using it",
                **({"tone": "warning"} if powers else {}),
            ),
            _fact(
                "Its user may",
                ", ".join(sorted({w for w, _, _ in powers})).capitalize() if powers else None,
                **({"tone": "serious"} if powers else {}),
            ),
            _fact(
                "Who has it",
                who,
                **({"tone": "warning"} if access and access.is_everyone else {}),
            ),
            _fact(
                "Topics",
                ", ".join(sorted(by_topic.values())) if topics else None,
            ),
            _fact("Not read", _and(unread).capitalize() if unread else None, tone="warning"),
            _fact("Created", agent.get("CreatedDate")),
            _fact("Changed", agent.get("LastModifiedDate")),
        )
        if f
    ]
    return Found(
        external_id=str(agent["Id"]),
        name=name,
        kind=kind,
        part="",
        description=agent.get("Description"),
        details={
            "facts": facts,
            "tools": tools,
            "developer_name": agent.get("DeveloperName"),
            "agent_type": agent.get("AgentType"),
            "running_user": user,
        },
        external_ids={"salesforce_id": str(agent["Id"])},
        risks=risks,
        instructions=instructions or None,
        complete=not unread,
        missing=[f"{_and(unread)} couldn't be read"] if unread else [],
    )


def _words(value: Any) -> str | None:
    """A picklist value in words: AgentforceServiceAgent is Agentforce Service Agent."""
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", str(value)) if value else None


def _and(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]
