"""Microsoft 365, Copilot Studio and the Microsoft services around them.

Two ways in:

* :class:`MicrosoftApp` reads with an app-only token: AgentGov's Entra app
  registration and the application permissions an admin granted it. Each
  integration needs its own permission, and runs only when the app has it:

  - the Microsoft 365 agent catalog (``CopilotPackages.Read.All``; Microsoft also
    requires a Microsoft Agent 365 licence), whose package details include a
    declarative agent's manifest and so its instructions;
  - and the others in ``agentgov.platforms.connections``.

* :class:`MicrosoftAdmin` acts as a signed-in administrator, for the admin APIs
  Microsoft opens only to people (see ``agentgov.identity.delegation``).
"""

from __future__ import annotations

import base64
import json
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx

from agentgov.config import Settings
from agentgov.platforms.base import PlatformError

# Agents are the packages Microsoft 365 Copilot can host.
AGENTS_FILTER = "supportedHosts/any(h:h eq 'Copilot')"
MAX_PAGES = 200
DECLARATIVE_AGENT = "declarativeagent"
# Entra object IDs: what may go into a Graph $filter.
GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
# Requests Graph takes in one $batch, at most.
BATCH = 20
USER_FIELDS = "id,displayName,mail,userPrincipalName"
# Application permissions that also say whether a user's account is enabled; the others
# (User.ReadBasic.All) read only who they are.
USER_ROLES = frozenset(
    {"User.Read.All", "User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"}
)
USERS_HINT = (
    " (AgentGov's app needs User.Read.All or User.ReadBasic.All with admin consent; an "
    "administrator signed in with Microsoft, the delegated permission User.ReadBasic.All)"
)


def token_roles(token: str) -> frozenset[str] | None:
    """The application permissions in an Entra access token (its ``roles`` claim).

    The token came straight from Entra over TLS and only decides which reads to
    try, so its signature isn't checked here. ``None`` when it isn't a JWT.
    """
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return None
    roles = claims.get("roles") if isinstance(claims, dict) else None
    return frozenset(r for r in roles if isinstance(r, str)) if isinstance(roles, list) else None


class MicrosoftApp:
    """Microsoft Graph with AgentGov's app registration (client credentials)."""

    def __init__(self, settings: Settings, *, http: httpx.Client | None = None) -> None:
        self.settings = settings
        self._http = http or httpx.Client(timeout=30)
        self._token: str | None = None
        self._token_expires = 0.0

    @property
    def graph(self) -> str:
        return self.settings.graph_url.rstrip("/")

    def _access_token(self) -> str:
        if self._token and time.monotonic() < self._token_expires:
            return self._token
        s = self.settings
        url = f"{s.entra_login_url.rstrip('/')}/{s.m365_tenant_id}/oauth2/v2.0/token"
        try:
            resp = self._http.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": s.m365_client_id,
                    "client_secret": s.m365_client_secret,
                    "scope": f"{self.graph}/.default",
                },
            )
        except httpx.HTTPError as exc:
            raise PlatformError(f"Microsoft Entra ID is unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise PlatformError(
                f"Microsoft Entra ID refused the app's credentials: {_error(resp)}",
                status=resp.status_code,
            )
        body = resp.json()
        self._token = body["access_token"]
        self._token_expires = time.monotonic() + max(int(body.get("expires_in", 3600)) - 120, 60)
        return self._token

    def granted(self, *, refresh: bool = False) -> frozenset[str] | None:
        """The application permissions the app holds (``None``: Entra didn't say).

        ``refresh`` gets a new token, which picks up permissions granted since.
        """
        if refresh:
            self._token = None
        return token_roles(self._access_token())

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        body: Any = None,
        hint: str = "",
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            resp = self._http.request(
                method,
                url,
                params=params,
                json=body,
                headers={"Authorization": f"Bearer {self._access_token()}", **(headers or {})},
            )
        except httpx.HTTPError as exc:
            raise PlatformError(f"Microsoft Graph is unreachable: {exc}") from exc
        if resp.status_code >= 300:
            extra = hint if resp.status_code in (401, 403) else ""
            raise PlatformError(
                f"Microsoft Graph answered {_error(resp)}{extra}", status=resp.status_code
            )
        if not resp.content:
            return {}
        try:
            data = resp.json()
        except ValueError as exc:
            raise PlatformError("Microsoft Graph answered with something other than JSON") from exc
        if not isinstance(data, dict):
            raise PlatformError("Microsoft Graph answered with something other than an object")
        return data

    def get(
        self,
        url: str,
        params: dict[str, str] | None = None,
        *,
        hint: str = "",
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return self._request("GET", url, params=params, hint=hint, headers=headers)

    def post(self, url: str, body: Any, *, hint: str = "") -> dict[str, Any]:
        return self._request("POST", url, body=body, hint=hint)

    def all_pages(
        self,
        url: str,
        params: dict[str, str] | None = None,
        *,
        hint: str = "",
        what: str = "results",
        limit: int = MAX_PAGES,
        headers: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Every item of a Graph collection, following ``@odata.nextLink``."""
        found: list[dict[str, Any]] = []
        next_url: str | None = url
        for _ in range(limit):
            if next_url is None:
                return found
            body = self.get(next_url, params, hint=hint, headers=headers)
            found.extend(item for item in body.get("value", []) if isinstance(item, dict))
            # Paging is server-driven: follow the opaque next link exactly as given.
            next_url, params = body.get("@odata.nextLink"), None
        raise PlatformError(f"stopped after {limit} pages of {what}")

    # -- the Microsoft 365 agent catalog -------------------------------------------

    CATALOG_HINT = (
        " (the app needs CopilotPackages.Read.All with admin consent, and the "
        "tenant a Microsoft Agent 365 licence)"
    )

    @property
    def _packages_url(self) -> str:
        return f"{self.graph}/v1.0/copilot/admin/catalog/packages"

    def agents(self) -> list[dict[str, Any]]:
        """Every agent in the organisation's catalog (all pages)."""
        return self.all_pages(
            self._packages_url,
            {"$filter": AGENTS_FILTER},
            hint=self.CATALOG_HINT,
            what="the agent catalog",
        )

    def package(self, package_id: str) -> dict[str, Any]:
        """One package's details, with its elements' definitions."""
        url = f"{self._packages_url}/{quote(package_id, safe='')}"
        return self.get(url, hint=self.CATALOG_HINT)

    # -- Microsoft Entra Agent ID -----------------------------------------------------

    IDENTITY_FIELDS = (
        "id,displayName,accountEnabled,agentIdentityBlueprintId,createdByAppId,"
        "createdDateTime,disabledByMicrosoftStatus,tags"
    )

    def agent_identities(self) -> list[dict[str, Any]]:
        """Every agent identity in the tenant (100 a page, Graph's maximum)."""
        return self.all_pages(
            f"{self.graph}/v1.0/servicePrincipals/microsoft.graph.agentIdentity",
            {"$select": self.IDENTITY_FIELDS, "$top": "100"},
            hint=" (the app needs AgentIdentity.Read.All with admin consent)",
            what="agent identities",
        )

    # -- Microsoft Entra users ---------------------------------------------------------------

    def users(
        self, object_ids: list[str], *, roles: frozenset[str] | None = None
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Users by object ID (see :func:`lookup_users`); whether their accounts are enabled
        when the app's permission says (``roles``, as granted)."""
        enabled = roles is None or bool(USER_ROLES & roles)
        return lookup_users(
            lambda url, body: self.post(url, body, hint=USERS_HINT),
            self.graph,
            object_ids,
            enabled=enabled,
        )

    def users_by_email(
        self, emails: list[str], *, roles: frozenset[str] | None = None
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Users by email address (see :func:`lookup_by_email`)."""
        enabled = roles is None or bool(USER_ROLES & roles)
        return lookup_by_email(
            lambda url, body: self.post(url, body, hint=USERS_HINT),
            self.graph,
            emails,
            enabled=enabled,
        )

    # -- Microsoft Entra ID Governance: access packages -----------------------------------

    ENTITLEMENT_HINT = (
        " (the app needs EntitlementManagement.Read.All with admin consent, and the tenant a "
        "Microsoft Agent 365 licence)"
    )
    MANAGE_HINT = (
        " (managing needs EntitlementManagement.ReadWrite.All with admin consent, or the "
        "Access package assignment manager role in the package's catalog)"
    )

    @property
    def _entitlement(self) -> str:
        return f"{self.graph}/v1.0/identityGovernance/entitlementManagement"

    def access_packages(self) -> list[dict[str, Any]]:
        """Every access package, with its assignment policies (who may hold it)."""
        return self.all_pages(
            f"{self._entitlement}/accessPackages",
            {"$expand": "assignmentPolicies"},
            hint=self.ENTITLEMENT_HINT,
            what="access packages",
        )

    def package_assignments(self, package_id: str) -> list[dict[str, Any]]:
        """A package's assignments, with whom each is for (expired ones included)."""
        if not GUID.match(package_id):
            raise PlatformError(f"{package_id!r} is not an access package ID")
        return self.all_pages(
            f"{self._entitlement}/assignments",
            {"$filter": f"accessPackage/id eq '{package_id}'", "$expand": "target"},
            hint=self.ENTITLEMENT_HINT,
            what="access package assignments",
        )

    def assign_package(self, *, target_id: str, policy_id: str, package_id: str) -> dict[str, Any]:
        """Ask Entra to assign a package to a directory object (adminAdd)."""
        body = {
            "requestType": "adminAdd",
            "assignment": {
                "targetId": target_id,
                "assignmentPolicyId": policy_id,
                "accessPackageId": package_id,
            },
        }
        return self.post(f"{self._entitlement}/assignmentRequests", body, hint=self.MANAGE_HINT)

    def remove_assignment(self, assignment_id: str) -> dict[str, Any]:
        """Ask Entra to remove an assignment (adminRemove)."""
        body = {"requestType": "adminRemove", "assignment": {"id": assignment_id}}
        return self.post(f"{self._entitlement}/assignmentRequests", body, hint=self.MANAGE_HINT)

    # -- Microsoft Purview audit log -----------------------------------------------------

    AUDIT_HINT = " (the app needs AuditLogsQuery.Read.All with admin consent)"

    def start_audit_query(
        self,
        name: str,
        start: str,
        end: str,
        *,
        record_types: list[str] | None = None,
        operations: list[str] | None = None,
    ) -> str:
        """Ask Purview to search the audit log; returns the query's ID (it runs for minutes)."""
        body: dict[str, Any] = {
            "@odata.type": "#microsoft.graph.security.auditLogQuery",
            "displayName": name,
            "filterStartDateTime": start,
            "filterEndDateTime": end,
        }
        if record_types:
            body["recordTypeFilters"] = record_types
        if operations:
            body["operationFilters"] = operations
        url = f"{self.graph}/v1.0/security/auditLog/queries"
        query = self.post(url, body, hint=self.AUDIT_HINT)
        if not query.get("id"):
            raise PlatformError("Purview accepted the audit search but gave it no ID")
        return str(query["id"])

    def audit_query_status(self, query_id: str) -> str:
        url = f"{self.graph}/v1.0/security/auditLog/queries/{quote(query_id, safe='')}"
        query = self.get(url, hint=self.AUDIT_HINT)
        # The documented example wraps the query in "value".
        if isinstance(query.get("value"), dict):
            query = query["value"]
        return str(query.get("status") or "unknown")

    def audit_records(self, query_id: str, *, limit: int = MAX_PAGES) -> list[dict[str, Any]]:
        url = f"{self.graph}/v1.0/security/auditLog/queries/{quote(query_id, safe='')}/records"
        return self.all_pages(url, hint=self.AUDIT_HINT, what="audit records", limit=limit)

    # -- Microsoft Defender ------------------------------------------------------------

    def alerts_since(self, since: str) -> list[dict[str, Any]]:
        """Defender alerts created or updated since ``since`` (ISO 8601)."""
        return self.all_pages(
            f"{self.graph}/v1.0/security/alerts_v2",
            {"$filter": f"lastUpdateDateTime ge {since}"},
            hint=" (the app needs SecurityAlert.Read.All with admin consent)",
            what="Defender alerts",
            # Security for AI's detections use enum members added after the API shipped.
            headers={"Prefer": "include-unknown-enum-members"},
        )


# The Power Platform inventory query for Copilot Studio agents, a page at a time.
INVENTORY_QUERY = {
    "TableName": "PowerPlatformResources",
    "Clauses": [
        {
            "$type": "where",
            "FieldName": "type",
            "Operator": "==",
            "Values": ["'microsoft.copilotstudio/agents'"],
        }
    ],
}
INVENTORY_PAGE = 1000
POWER_PLATFORM_HINT = (
    " (you need the AI administrator, Power Platform administrator or Global administrator "
    "role, and AgentGov's app registration the Power Platform API permissions "
    "CopilotStudio.AdminActions.Invoke and ResourceQuery.Resources.Read)"
)
POLICY_HINT = (
    " (you need the Power Platform administrator role, and AgentGov's app registration the "
    "Power Platform API permission EnvironmentManagement.Groups.Read)"
)
PP_API_VERSION = "2024-10-01"
GRAPH_HINT = (
    " (you need an admin role such as AI administrator, AgentGov's app registration the "
    "delegated permission CopilotPackages.ReadWrite.All, and the tenant a Microsoft Agent 365 "
    "licence)"
)


class MicrosoftAdmin:
    """Admin actions Microsoft accepts only from a signed-in administrator.

    Each call takes that administrator's access token (see
    ``agentgov.identity.delegation``); AgentGov never holds an application
    permission for them.
    """

    def __init__(self, settings: Settings, *, http: httpx.Client | None = None) -> None:
        self.settings = settings
        self._http = http or httpx.Client(timeout=30)

    def _call(
        self,
        url: str,
        token: str,
        *,
        what: str,
        hint: str,
        body: Any = None,
        method: str = "POST",
    ) -> dict[str, Any]:
        try:
            resp = self._http.request(
                method,
                url,
                json=body if method != "GET" else None,
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as exc:
            raise PlatformError(f"{what}: Microsoft is unreachable: {exc}") from exc
        if resp.status_code >= 300:
            extra = hint if resp.status_code in (401, 403) else ""
            raise PlatformError(
                f"{what}: Microsoft answered {_error(resp)}{extra}", status=resp.status_code
            )
        try:
            data = resp.json() if resp.content else {}
        except ValueError:
            data = {}
        return data if isinstance(data, dict) else {}

    def quarantine(
        self, token: str, environment_id: str, bot_id: str, *, quarantined: bool
    ) -> None:
        """Quarantine a Copilot Studio agent (blocked on every channel), or release it."""
        action = "SetAsQuarantined" if quarantined else "SetAsUnquarantined"
        base = self.settings.power_platform_url.rstrip("/")
        url = (
            f"{base}/copilotstudio/environments/{quote(environment_id, safe='')}"
            f"/bots/{quote(bot_id, safe='')}/api/botQuarantine/{action}?api-version=1"
        )
        verb = "quarantine" if quarantined else "release"
        self._call(
            url,
            token,
            what=f"Could not {verb} the agent in Copilot Studio",
            hint=POWER_PLATFORM_HINT,
        )

    def copilot_studio_agents(self, token: str) -> list[dict[str, Any]]:
        """Every Copilot Studio agent in the Power Platform inventory (all pages)."""
        url = (
            f"{self.settings.power_platform_url.rstrip('/')}"
            "/resourcequery/resources/query?api-version=2024-10-01"
        )
        rows: list[dict[str, Any]] = []
        skip_token = ""
        for _ in range(MAX_PAGES):
            body = self._call(
                url,
                token,
                what="Could not read the Power Platform inventory",
                hint=POWER_PLATFORM_HINT,
                body={
                    **INVENTORY_QUERY,
                    "Options": {"Top": INVENTORY_PAGE, "Skip": 0, "SkipToken": skip_token},
                },
            )
            rows.extend(r for r in body.get("data") or [] if isinstance(r, dict))
            skip_token = body.get("skipToken") or ""
            if not skip_token:
                return rows
        raise PlatformError(f"stopped after {MAX_PAGES} pages of the Power Platform inventory")

    def users(self, token: str, object_ids: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
        """Users by object ID, as the signed-in administrator (User.ReadBasic.All, which
        doesn't say whose account is enabled)."""
        return lookup_users(
            lambda url, body: self._call(
                url, token, what="Could not look up users", hint=USERS_HINT, body=body
            ),
            self.settings.graph_url.rstrip("/"),
            object_ids,
            enabled=False,
        )

    def users_by_email(
        self, token: str, emails: list[str]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Users by email address, as the signed-in administrator."""
        return lookup_by_email(
            lambda url, body: self._call(
                url, token, what="Could not look up users", hint=USERS_HINT, body=body
            ),
            self.settings.graph_url.rstrip("/"),
            emails,
            enabled=False,
        )

    def block_package(self, token: str, package_id: str, *, blocked: bool) -> None:
        """Block a Microsoft 365 agent for everyone in the organisation, or unblock it."""
        action = "block" if blocked else "unblock"
        url = (
            f"{self.settings.graph_url.rstrip('/')}/beta/copilot/admin/catalog/packages/"
            f"{quote(package_id, safe='')}/{action}"
        )
        self._call(
            url, token, what=f"Could not {action} the agent in Microsoft 365", hint=GRAPH_HINT
        )

    # -- Power Platform advanced connector policies ---------------------------------

    def _pp(self, path: str, **params: str) -> str:
        query = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
        base = self.settings.power_platform_url.rstrip("/")
        return f"{base}{path}?api-version={PP_API_VERSION}" + (f"&{query}" if query else "")

    def environment_groups(self, token: str) -> list[dict[str, Any]]:
        """The tenant's environment groups."""
        groups: list[dict[str, Any]] = []
        url: str | None = self._pp("/environmentmanagement/environmentGroups")
        for _ in range(MAX_PAGES):
            if url is None:
                return groups
            body = self._call(
                url,
                token,
                what="Could not list the environment groups",
                hint=POLICY_HINT,
                method="GET",
            )
            groups.extend(g for g in body.get("value") or [] if isinstance(g, dict))
            url = body.get("@odata.nextLink")
        raise PlatformError(f"stopped after {MAX_PAGES} pages of environment groups")

    def connector_policies(self, token: str) -> list[dict[str, Any]]:
        body = self._call(
            self._pp("/governance/ruleBasedPolicies"),
            token,
            what="Could not read the connector policies",
            hint=POLICY_HINT,
            method="GET",
        )
        return [p for p in body.get("value") or [] if isinstance(p, dict)]

    def save_connector_policy(
        self, token: str, policy_id: str | None, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Create the policy, or update its rule sets (others it holds are left alone)."""
        if policy_id is None:
            url, method = self._pp("/governance/ruleBasedPolicies"), "POST"
        else:
            url = self._pp(f"/governance/ruleBasedPolicies/{quote(policy_id, safe='')}")
            method = "PATCH"
        return self._call(
            url,
            token,
            what="Could not save the connector policy",
            hint=POLICY_HINT,
            body=body,
            method=method,
        )

    def policy_assignments(self, token: str, scope: str, scope_id: str) -> list[dict[str, Any]]:
        """Connector policy assignments of an environment group or environment."""
        kind = "environmentGroups" if scope == "group" else "environments"
        body = self._call(
            self._pp(
                f"/governance/ruleBasedPolicies/{kind}/{quote(scope_id, safe='')}/assignments",
                includeRuleSetCounts="true",
            ),
            token,
            what="Could not read the connector policy assignments",
            hint=POLICY_HINT,
            method="GET",
        )
        return [a for a in body.get("value") or [] if isinstance(a, dict)]

    def assign_policy(self, token: str, policy_id: str, scope: str, scope_id: str) -> None:
        kind = "environmentGroups" if scope == "group" else "environments"
        self._call(
            self._pp(
                f"/governance/ruleBasedPolicies/{quote(policy_id, safe='')}/{kind}/"
                f"{quote(scope_id, safe='')}/assignments"
            ),
            token,
            what="Could not apply the connector policy",
            hint=POLICY_HINT,
            body={},
        )


def lookup_users(
    send: Callable[[str, dict[str, Any]], dict[str, Any]],
    graph: str,
    object_ids: list[str],
    *,
    enabled: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Users by their Entra object IDs, 20 to a Graph $batch: those found, and the IDs
    Graph has no user for (deleted, or never a person). A lookup Graph turned away for
    now (throttled, or failed) is neither, and is tried again next time; one refused for
    want of a permission stops them all.

    ``send`` posts a body to a URL and returns Graph's answer; ``enabled`` asks whether
    each account is enabled too, which User.ReadBasic.All doesn't allow.
    """
    fields = USER_FIELDS + (",accountEnabled" if enabled else "")
    wanted = [i for i in dict.fromkeys(object_ids) if GUID.match(i)]
    found: list[dict[str, Any]] = []
    missing: list[str] = []
    for start in range(0, len(wanted), BATCH):
        chunk = wanted[start : start + BATCH]
        body = {
            "requests": [
                {"id": str(n), "method": "GET", "url": f"/users/{oid}?$select={fields}"}
                for n, oid in enumerate(chunk)
            ]
        }
        answer = send(f"{graph}/v1.0/$batch", body)
        for item in answer.get("responses") or []:
            try:
                oid = chunk[int(item.get("id"))]
            except (TypeError, ValueError, IndexError):
                continue
            status = item.get("status")
            user = item.get("body")
            if status == 200 and isinstance(user, dict):
                found.append(user)
            elif status == 404:
                missing.append(oid)
            elif status in (401, 403):
                error = (user or {}).get("error") if isinstance(user, dict) else None
                detail = error.get("message") if isinstance(error, dict) else None
                raise PlatformError(
                    f"Microsoft Graph refused to read users: {status}: {detail or 'forbidden'}"
                    f"{USERS_HINT}",
                    status=status,
                )
    return found, missing


def lookup_by_email(
    send: Callable[[str, dict[str, Any]], dict[str, Any]],
    graph: str,
    emails: list[str],
    *,
    enabled: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Users by email address or user principal name, 20 to a Graph $batch: those found,
    and the addresses no user has. As :func:`lookup_users`, a lookup Graph turned away for
    now is neither, and one refused for want of a permission stops them all."""
    fields = USER_FIELDS + (",accountEnabled" if enabled else "")
    wanted = [e for e in dict.fromkeys(e.strip().lower() for e in emails) if "@" in e]
    found: list[dict[str, Any]] = []
    missing: list[str] = []
    for start in range(0, len(wanted), BATCH):
        chunk = wanted[start : start + BATCH]
        requests = []
        for n, email in enumerate(chunk):
            value = email.replace("'", "''")  # OData quotes a quote by doubling it
            where = quote(f"mail eq '{value}' or userPrincipalName eq '{value}'", safe="")
            requests.append(
                {"id": str(n), "method": "GET", "url": f"/users?$filter={where}&$select={fields}"}
            )
        answer = send(f"{graph}/v1.0/$batch", {"requests": requests})
        for item in answer.get("responses") or []:
            try:
                email = chunk[int(item.get("id"))]
            except (TypeError, ValueError, IndexError):
                continue
            status, body = item.get("status"), item.get("body")
            if status == 200 and isinstance(body, dict):
                users = [u for u in body.get("value") or [] if isinstance(u, dict)]
                if users:
                    found.append(users[0])
                else:
                    missing.append(email)
            elif status in (401, 403):
                error = body.get("error") if isinstance(body, dict) else None
                detail = error.get("message") if isinstance(error, dict) else None
                raise PlatformError(
                    f"Microsoft Graph refused to read users: {status}: {detail or 'forbidden'}"
                    f"{USERS_HINT}",
                    status=status,
                )
    return found, missing


def is_declarative(package: dict[str, Any]) -> bool:
    return any(str(t).lower() == DECLARATIVE_AGENT for t in package.get("elementTypes") or [])


def declarative_instructions(detail: dict[str, Any]) -> str | None:
    """The instructions in a package's declarative agent manifests, when Graph includes them."""
    texts = []
    for group in detail.get("elementDetails") or []:
        if not isinstance(group, dict) or str(group.get("elementType", "")).lower() != (
            DECLARATIVE_AGENT
        ):
            continue
        for element in group.get("elements") or []:
            definition = element.get("definition") if isinstance(element, dict) else None
            if isinstance(definition, str):
                try:
                    definition = json.loads(definition)
                except ValueError:
                    continue
            if isinstance(definition, dict) and isinstance(definition.get("instructions"), str):
                texts.append(definition["instructions"].strip())
    return "\n\n".join(t for t in texts if t) or None


def _error(resp: httpx.Response) -> str:
    """Graph errors are {"error": {"message": ...}}; Entra's are {"error": "...", ...}."""
    detail = None
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        error = body.get("error")
        detail = error.get("message") if isinstance(error, dict) else None
        detail = (
            detail or body.get("error_description") or (error if isinstance(error, str) else None)
        )
    return f"{resp.status_code}: {detail or resp.text[:200]}"
