"""Who may call what (docs/threat-model.md#who-may-call-what): every route of the API, tried as
anyone, as a person without a role, as each role for every team and for one team only, on one
team's objects and on another team's.

tests/authz_matrix.txt says who gets through each route: AgentGov's access reference. A
change in who may call what, a new route or a route gone fails here until that file says so:
``python -m tests.test_authz_matrix`` writes it, to review as a change in who may do what.
Some rules hold whatever the file says: nobody unauthenticated gets past the public routes, a
person reaches only what is theirs, a role for one team never reaches another team's agents
nor sees them in what it reads, an auditor changes nothing, components reach only the
internal routes, and nothing answers with a server error.

"Gets through" means the request passed AgentGov's authentication and its role and team
checks: it reached the work the route does, whether that then succeeded or not (a body
that isn't valid answers 422 to whoever may call the route, and 401 or 403 to whoever may
not). An object out of a role's reach is "not found" for it, as if it didn't exist.
"""

from __future__ import annotations

import json
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from agentgov import ids, migrations
from agentgov.api.app import api_routes, create_app
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.models import AdminSession, ApiKey, ApprovalRequest
from agentgov.registry import findings, issues, model_usage
from agentgov.runtime import Runtime
from tests.test_models import access_log, logs
from tests.test_sso import CLIENT_SECRET, ISSUER, FakeProvider, cli_session

MATRIX = Path(__file__).with_name("authz_matrix.txt")
ADMIN_TOKEN, SERVICE_TOKEN = "matrix-admin-token", "matrix-service-token"
ROLES = ("admin", "approver", "secops", "auditor", "registrar")
# The team the roles for one team are held for, and another team.
OURS, THEIRS = "sales", "hr"
PRINCIPALS = (
    "anyone",
    "person",
    *ROLES,
    "service",
    *(f"{role}@{OURS}" for role in ROLES),
)
TEAM_PRINCIPALS = tuple(p for p in PRINCIPALS if "@" in p)
WRITES = ("POST", "PUT", "PATCH", "DELETE")

# Routes for anyone, each for a reason.
PUBLIC = {
    "GET /": "redirects to the admin UI",
    "GET /healthz": "liveness",
    "GET /readyz": "readiness",
    "GET /v1/info": "what clients need to start: versions, the sign-in and token endpoints",
    "GET /v1/delegations/jwks": "public keys agents check delegations with",
    "GET /oauth2/jwks": "public keys MCP servers check identity assertions with",
    "GET /.well-known/oauth-authorization-server": "the identity assertion issuer's metadata",
    "POST /oauth2/token": "identity assertions, for agents that authenticate in the request",
    "GET /.well-known/authzen-configuration": "AuthZEN metadata (the evaluations need a role)",
    "GET /registry/v0.1/servers": "the MCP registry, for developers' MCP clients",
    "GET /registry/v0.1/servers/{name:path}/versions": "the MCP registry",
    "GET /registry/v0.1/servers/{name:path}/versions/{version}": "the MCP registry",
    "POST /integrations/copilot-studio/validate": "Copilot Studio, with Entra ID's token",
    "POST /integrations/copilot-studio/analyze-tool-execution": "the same",
}
# The single sign-on flow (tests/test_sso.py), and the API's own documentation: not probed.
UNPROBED_PREFIXES = ("/auth/", "/docs", "/redoc", "/openapi.json")

# Read-only questions some roles ask with POST.
READ_LIKE = {
    "POST /v1/policies/evaluate": "what a policy would decide",
    "POST /v1/rules/preview": "which agents a rule would match",
    "POST /v1/instructions/check": "what the instruction checks would find in a text",
    "POST /access/v1/evaluation": "AuthZEN: what AgentGov would decide",
    "POST /access/v1/evaluations": "AuthZEN, several at once",
}


@dataclass
class Seeded:
    """What the probes name: each team's objects, the principals' credentials, and things
    the routes that remove or end something can take without touching the others."""

    tokens: dict[str, str] = field(default_factory=dict)
    agent: dict[str, str] = field(default_factory=dict)
    finding: dict[str, str] = field(default_factory=dict)
    approval: dict[str, str] = field(default_factory=dict)
    assignment: dict[str, str] = field(default_factory=dict)
    checkpoint: int = 1
    decoy_key: str = ""
    decoy_session: str = ""

    def theirs(self) -> set[str]:
        """What names the other team's agent: no role for our team should see any of it."""
        return {
            f"{THEIRS}-bot",
            self.agent[THEIRS],
            self.finding[THEIRS],
            self.approval[THEIRS],
            self.assignment[THEIRS],
            f"owner@{THEIRS}.example.com",
        }


def settings_for(path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{path}",
        admin_token=ADMIN_TOKEN,
        service_token=SERVICE_TOKEN,
        posture_interval_seconds=0,
        oidc_issuer=ISSUER,
        oidc_client_secret=CLIENT_SECRET,
    )


def client_for(path: Path, provider: FakeProvider, *, raises: bool = True) -> TestClient:
    settings = settings_for(path)
    runtime = Runtime(
        settings, oidc_http=httpx.Client(transport=httpx.MockTransport(provider.handle))
    )
    app = create_app(settings, runtime=runtime, background=False)
    return TestClient(app, raise_server_exceptions=raises)


def _ok(resp: httpx.Response) -> Any:
    assert resp.status_code < 300, f"{resp.request.method} {resp.request.url}: {resp.text}"
    return resp.json() if resp.content else None


def seed(client: TestClient, provider: FakeProvider) -> Seeded:
    """Two teams with an agent each (ours, sales, and theirs, hr), with an issue, an approval
    request and an access request each; what else the routes name; and a credential for each
    principal."""
    admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    seeded = Seeded()

    def post(path: str, body: dict[str, Any]) -> Any:
        return _ok(client.post(path, json=body, headers=admin))

    for team in (OURS, THEIRS, "ops"):
        post("/v1/teams", {"name": team})
    _ok(client.patch("/v1/teams/ops", json={"default": True}, headers=admin))
    post("/v1/toolservers", {"name": "crm", "url": "http://127.0.0.1:9/mcp"})
    post("/v1/models/providers", {"name": "openai", "kind": "openai"})
    post(
        "/v1/identity-issuers",
        {"name": "cluster", "kind": "kubernetes", "issuer": "https://k8s.example.com"},
    )
    post("/v1/destinations", {"name": "siem", "kind": "webhook", "url": "http://127.0.0.1:9/h"})
    rego = 'package agentgov.custom.extra\n\ndeny contains msg if { false; msg := "no" }\n'
    post("/v1/policies", {"name": "extra", "rego": rego})
    post(
        "/v1/rules",
        {
            "name": "inactive-agents",
            "conditions": {"inactive_days": 30},
            "action": "block",
            "after_days": 7,
        },
    )
    post(
        "/v1/access-packages",
        {"name": "crm-write", "permissions": [{"server": "crm", "tools": ["update"]}]},
    )
    # The secops role does what the hand-off allows: everything, here, so that its role is
    # what decides.
    _ok(client.put("/v1/features/security-operations", json={"mode": "decide"}, headers=admin))
    rt = client.app.state.rt  # type: ignore[attr-defined]
    for team in (OURS, THEIRS):
        post("/v1/blueprints", {"name": f"{team}-bp", "team": team})
        owner = "pat@example.com" if team == OURS else f"owner@{THEIRS}.example.com"
        made = post(
            "/v1/agents",
            {
                "name": f"{team}-bot",
                "blueprint": f"{team}-bp",
                "owner": owner,
                "sponsors": [owner],
                "approve": True,
            },
        )
        seeded.agent[team] = made["id"]
        put = client.put(
            f"/v1/agents/{team}-bot/instructions", json={"text": "Help customers."}, headers=admin
        )
        _ok(put)
        asked = post(
            "/v1/access-assignments",
            {"agent": f"{team}-bot", "package": "crm-write", "reason": "a ticket"},
        )
        seeded.assignment[team] = asked["id"]
        now = ids.utcnow()
        with rt.db.session() as s:
            raised, _ = findings.raise_finding(
                s,
                type="test.thing",
                severity="medium",
                subject=made["id"],
                agent_id=made["id"],
                title=f"Something about {team}-bot",
            )
            seeded.finding[team] = raised.id
            approval = f"apr_{team}_matrix"
            s.add(
                ApprovalRequest(
                    id=approval,
                    agent_id=made["id"],
                    agent_name=f"{team}-bot",
                    action="tools/call",
                    resource="crm/update",
                    arguments_hash="h",
                    status="pending",
                    requested_at=now,
                    expires_at=now + timedelta(hours=1),
                )
            )
            seeded.approval[team] = approval
    # Each issue to its agent's owner and sponsor (as the issues job does); and each agent's
    # model calls, metered.
    with rt.db.session() as s:
        issues.route(s, rt.settings)
        model_usage.ingest_logs(s, logs(*(access_log(agent_id=i) for i in seeded.agent.values())))
    seeded.checkpoint = int(post("/v1/ledger/checkpoints", {})["seq"])
    for role in ROLES:
        made = post("/v1/apikeys", {"name": f"{role}-key", "role": role})
        seeded.tokens[role] = made["token"]
        made = post("/v1/apikeys", {"name": f"{role}-{OURS}", "role": role, "team": OURS})
        seeded.tokens[f"{role}@{OURS}"] = made["token"]
    seeded.tokens["service"] = SERVICE_TOKEN
    post("/v1/apikeys", {"name": "decoy", "role": "auditor"})
    post("/v1/access/grants", {"email": "grant@example.com", "role": "auditor"})
    # pat@example.com, without a role: the owner and sponsor of our agent.
    person = cli_session(client, provider, sub="pat", email="pat@example.com", roles=[])
    seeded.tokens["person"] = person["token"]
    cli_session(client, provider, sub="decoy", email="decoy@example.com", roles=[])
    with rt.db.session() as s:
        seeded.decoy_key = s.scalars(select(ApiKey.id).where(ApiKey.name == "decoy")).one()
        seeded.decoy_session = s.scalars(
            select(AdminSession.id).where(AdminSession.subject == "decoy")
        ).one()
    return seeded


# --------------------------------------------------------------------------- routes


@dataclass(frozen=True)
class Probe:
    method: str
    path: str
    # Whose object the route is given (OURS or THEIRS), for routes about one agent or team.
    team: str | None = None

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}" + (f" ({self.team})" if self.team else "")

    @property
    def route(self) -> str:
        return f"{self.method} {self.path}"


def routes(app: Any) -> list[tuple[str, str]]:
    """Every API route, as (method, path), whichever framework serves it."""
    return api_routes(app)


# Routes whose body names one agent.
BODY_BOUND = {"POST /v1/access-assignments"}


def team_bound(method: str, path: str) -> bool:
    """Whether a route is about one agent or team, or what hangs off an agent. (Blueprints
    aren't a team's: every role reads them, docs/administration.md#roles-for-one-team.)"""
    return path.startswith(("/v1/agents/{ref}", "/v1/teams/{ref}")) or (
        "{finding_id}" in path
        or "{approval_id}" in path
        or path.startswith("/v1/access-assignments/{assignment_id}")
        or f"{method} {path}" in BODY_BOUND
    )


def probes(app: Any) -> list[Probe]:
    """What to try, in an order where nothing tried removes what a later probe names: reads,
    then changes, then removals; on the other team's objects first."""
    rank = {"GET": 0, "HEAD": 0, "POST": 1, "PUT": 1, "PATCH": 1, "DELETE": 2}
    found = []
    for method, path in routes(app):
        if path.startswith(UNPROBED_PREFIXES) or f"{method} {path}" in PUBLIC:
            continue
        teams = (THEIRS, OURS) if team_bound(method, path) else (None,)
        found += [Probe(method, path, team) for team in teams]
    return sorted(found, key=lambda p: (rank[p.method], p.path, p.team != THEIRS))


ACTIONS = {
    "/v1/agents/{ref}/{action}": "block",
    "/v1/findings/{finding_id}/{action}": "resolve",
    "/v1/destinations/{ref}/{action}": "test",
    "/v1/identity-issuers/{ref}/{action}": "block",
    "/v1/models/providers/{ref}/{action}": "block",
    "/v1/toolservers/{ref}/{action}": "block",
    "/v1/access-assignments/{assignment_id}/{action}": "approve",
}
REFS = {
    "/v1/toolservers/": "crm",
    "/v1/models/providers/": "openai",
    "/v1/identity-issuers/": "cluster",
    "/v1/destinations/": "siem",
    "/v1/policies/": "extra",
    "/v1/rules/": "inactive-agents",
    "/v1/access-packages/": "crm-write",
}


def url(probe: Probe, seeded: Seeded) -> str:
    team = probe.team or OURS
    path = probe.path.replace("{action}", ACTIONS.get(probe.path, "x"))
    ref = next((name for prefix, name in REFS.items() if path.startswith(prefix)), "x")
    if path.startswith("/v1/agents/{ref}"):
        ref = f"{team}-bot"
    elif path.startswith("/v1/teams/{ref}"):
        ref = team
    elif path.startswith("/v1/blueprints/{ref}"):
        ref = f"{OURS}-bp"
    assignment = (
        seeded.assignment[team] if path.startswith("/v1/access-assignments/") else "missing"
    )
    for name, value in {
        "{ref}": ref,
        "{finding_id}": seeded.finding[team],
        "{approval_id}": seeded.approval[team],
        "{assignment_id}": assignment,
        "{seq}": str(seeded.checkpoint),
        "{key}": "least-privilege",
        "{name}": "monitor",
        "{type_}": "test.thing",
        "{tool}": "update",
        "{subject:path}": "decoy",
        "{source}": "aws",
        "{session_id}": seeded.decoy_session,
        "{email}": "grant@example.com",
        "{role}": "auditor",
        "{key_id}": seeded.decoy_key,
        "{connector_id}": "shared_x",
        "{verdict}": "approve",
    }.items():
        path = path.replace(name, value)
    return path


def body(probe: Probe) -> dict[str, Any] | None:
    """What a probe sends: an empty object for the routes that take one (to whoever may call
    them, it answers 422 or does nothing), or what the route's own checks need to run."""
    if probe.method in ("GET", "HEAD", "DELETE"):
        return None
    team = probe.team or OURS
    return {
        "POST /v1/findings/bulk": {"action": "resolve", "findings": []},
        "POST /v1/approvals/{approval_id}/{verdict}": {"reason": "probe"},
        "POST /v1/access-assignments": {
            "agent": f"{team}-bot",
            "package": "crm-write",
            "reason": "probe",
        },
        "POST /v1/findings/{finding_id}/exception": {"reason": "probe"},
    }.get(probe.route, {})


# --------------------------------------------------------------------------- observe


@dataclass
class Observed:
    seeded: Seeded
    # Who gets through each probe.
    through: dict[str, set[str]] = field(default_factory=dict)
    # Bodies of what got through, for the leak check: (probe, principal) -> text.
    bodies: dict[tuple[str, str], str] = field(default_factory=dict)
    # Server errors: "probe as principal: status".
    errors: list[str] = field(default_factory=list)
    # Each answer: (probe, principal) -> status.
    statuses: dict[tuple[str, str], int] = field(default_factory=dict)
    # The routes there are, and the probes tried.
    all_routes: set[str] = field(default_factory=set)
    tried: list[Probe] = field(default_factory=list)


def observe(workdir: Path) -> Observed:
    provider = FakeProvider()
    template = workdir / "template.db"
    db = Database(f"sqlite:///{template}")
    migrations.upgrade(db.engine)
    db.dispose()
    with client_for(template, provider) as client:
        seeded = seed(client, provider)
        app = client.app
    db = Database(f"sqlite:///{template}")
    with db.engine.connect() as connection:
        connection.connection.dbapi_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.dispose()
    seen = Observed(seeded=seeded, tried=probes(app))
    seen.all_routes = {f"{m} {p}" for m, p in routes(app)}
    for probe in seen.tried:
        seen.through.setdefault(probe.key, set())
    # The admin first: an object an admin finds is one a 404 hides from the others.
    for principal in ("admin", *(p for p in PRINCIPALS if p != "admin")):
        copy = workdir / f"{principal.replace('@', '-')}.db"
        shutil.copyfile(template, copy)
        token = seeded.tokens.get(principal)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        with client_for(copy, provider, raises=False) as client:
            for probe in seen.tried:
                resp = client.request(
                    probe.method, url(probe, seeded), json=body(probe), headers=headers
                )
                status = resp.status_code
                seen.statuses[(probe.key, principal)] = status
                if status >= 500:
                    seen.errors.append(f"{probe.key} as {principal}: {status} {resp.text[:200]}")
                hidden = status == 404 and seen.statuses[(probe.key, "admin")] != 404
                if status in (401, 403) or hidden:
                    continue
                seen.through[probe.key].add(principal)
                if status < 300:
                    seen.bodies[(probe.key, principal)] = resp.text
    return seen


def render(seen: Observed) -> str:
    lines = [
        "# Who gets through each route of AgentGov's API. tests/test_authz_matrix.py checks it",
        "# and `python -m tests.test_authz_matrix` writes it: review a change here as a change",
        "# in who may do what. Everyone not listed is refused (401 or 403), or, for an object",
        "# out of their reach, told it doesn't exist (404).",
        "#",
        f"# Principals: {' '.join(PRINCIPALS)}.",
        f"# person: someone signed in without a role (here the owner and sponsor of {OURS}-bot).",
        f"# role@{OURS}: a role for team {OURS} only. ({OURS}) and ({THEIRS}): the route is given",
        f"# an object of team {OURS}, or of another team.",
        "#",
        "# Public routes, not listed: " + ", ".join(sorted(PUBLIC)) + ".",
        "",
    ]
    width = max(len(probe.key) for probe in seen.tried)
    for probe in seen.tried:
        who = [p for p in PRINCIPALS if p in seen.through[probe.key]] or ["nobody"]
        lines.append(f"{probe.key:<{width}}  {' '.join(who)}".rstrip())
    return "\n".join(lines) + "\n"


def parse(text: str) -> dict[str, set[str]]:
    out = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        method, path, *rest = line.split()
        team = None
        if rest and rest[0].startswith("("):
            team, rest = rest[0].strip("()"), rest[1:]
        key = f"{method} {path}" + (f" ({team})" if team else "")
        out[key] = set(rest) - {"nobody"}
    return out


@pytest.fixture(scope="module")
def seen(tmp_path_factory: pytest.TempPathFactory) -> Observed:
    return observe(tmp_path_factory.mktemp("authz"))


# --------------------------------------------------------------------------- the rules


def reached(seen: Observed, principal: str) -> set[str]:
    return {key for key, who in seen.through.items() if principal in who}


def test_nothing_answers_with_a_server_error(seen: Observed) -> None:
    assert seen.errors == []


def test_every_route_is_public_on_purpose_or_probed(seen: Observed) -> None:
    probed = {probe.route for probe in seen.tried}
    left = {
        route
        for route in seen.all_routes - probed - set(PUBLIC)
        if not route.split(" ", 1)[1].startswith(UNPROBED_PREFIXES)
    }
    assert left == set()
    assert set(PUBLIC) <= seen.all_routes, set(PUBLIC) - seen.all_routes


def test_nobody_unauthenticated_gets_past_the_public_routes(seen: Observed) -> None:
    assert reached(seen, "anyone") == set()


# What everyone signed in reaches: who they are, and what is sent to them.
SIGNED_IN = {
    "GET /v1/me",
    "GET /v1/me/approvals",
    "GET /v1/me/issues",
    "GET /v1/inbox",
    "GET /v1/access-packages",
    "GET /v1/access-packages/{ref}",
}


# What a person without a role reaches besides SIGNED_IN: their own agent's issues, rules,
# access requests and attestation. Never another team's agent's.
PERSON = {
    f"GET /v1/findings/{{finding_id}} ({OURS})",
    f"GET /v1/agents/{{ref}}/access-packages ({OURS})",
    f"GET /v1/agents/{{ref}}/rules ({OURS})",
    f"GET /v1/access-assignments/{{assignment_id}} ({OURS})",
    f"POST /v1/agents/{{ref}}/attest ({OURS})",
    f"POST /v1/findings/{{finding_id}}/acknowledge ({OURS})",
    f"POST /v1/findings/{{finding_id}}/exception ({OURS})",
    f"POST /v1/findings/{{finding_id}}/not-mine ({OURS})",
    f"POST /v1/findings/{{finding_id}}/recheck ({OURS})",
    "POST /v1/findings/bulk",
    f"POST /v1/access-assignments ({OURS})",
}


def test_a_person_reaches_only_what_is_theirs(seen: Observed) -> None:
    assert reached(seen, "person") - PERSON - SIGNED_IN == set()


def test_a_role_for_one_team_never_reaches_another_teams_agents(seen: Observed) -> None:
    for principal in (*TEAM_PRINCIPALS, "person"):
        assert {key for key in reached(seen, principal) if key.endswith(f"({THEIRS})")} == set(), (
            principal
        )


def test_nor_sees_them_in_what_it_reads(seen: Observed) -> None:
    theirs = seen.seeded.theirs()
    leaks = [
        f"{key} as {principal}: {sorted(m for m in theirs if m in text)}"
        for (key, principal), text in seen.bodies.items()
        if (principal in TEAM_PRINCIPALS or principal == "person")
        and any(marker in text for marker in theirs)
    ]
    assert leaks == []


def test_an_auditor_changes_nothing(seen: Observed) -> None:
    for principal in ("auditor", f"auditor@{OURS}"):
        changes = {
            key
            for key in reached(seen, principal)
            if key.split()[0] in WRITES and " ".join(key.split()[:2]) not in READ_LIKE
        }
        assert changes == set(), principal


# Components (OPA, the governance processor, the OTel Collector, the gateway's sidecar).
SERVICE = {
    "GET /v1/gateway/config",
    "GET /v1/opa/bundles/agentgov.tar.gz",
    "POST /v1/opa/logs",
    "POST /v1/opa/status",
    "POST /v1/otlp/v1/logs",
    "POST /v1/otlp/v1/traces",
    "POST /v1/internal/approvals/check",
    "POST /v1/internal/catalog",
    "POST /v1/internal/components",
    "POST /v1/internal/decisions",
    "POST /v1/internal/observe",
    "POST /v1/discovery/import",
    "POST /access/v1/evaluation",
    "POST /access/v1/evaluations",
}


def test_components_reach_only_the_internal_routes(seen: Observed) -> None:
    assert reached(seen, "service") - SERVICE - SIGNED_IN == set()


# What the data plane reports: the decisions, observations, decision logs and telemetry the
# evidence ledger and the inventory are built from.
REPORTS = {route for route in SERVICE if route.startswith("POST") and "/access/v1/" not in route}
REPORTS -= {"POST /v1/discovery/import"}


def test_only_components_report_what_the_data_plane_did(seen: Observed) -> None:
    """Not even an administrator writes decisions or observations as if a component had (with
    mutual TLS, the service role is the internal port's alone)."""
    assert {route: sorted(seen.through[route]) for route in REPORTS} == {
        route: ["service"] for route in REPORTS
    }


# A registrar (CI pipelines, developers) registers agents and tool servers for review, and
# asks for access packages for agents (an approver decides).
REGISTRAR = {
    "POST /v1/agents",
    "POST /v1/toolservers",
    "POST /v1/discovery/import",
    "POST /v1/mcp/sightings",
    "POST /v1/instructions/check",
    f"POST /v1/access-assignments ({OURS})",
    f"POST /v1/access-assignments ({THEIRS})",
}


def test_a_registrar_only_registers(seen: Observed) -> None:
    for principal in ("registrar", f"registrar@{OURS}"):
        assert reached(seen, principal) - REGISTRAR - SIGNED_IN == set(), principal


def test_the_matrix_is_as_reviewed(seen: Observed) -> None:
    """tests/authz_matrix.txt is current: `python -m tests.test_authz_matrix` writes it."""
    written = parse(MATRIX.read_text()) if MATRIX.exists() else {}
    now = parse(render(seen))
    changed = {
        key: (sorted(written.get(key, set())), sorted(now.get(key, set())))
        for key in written.keys() | now.keys()
        if written.get(key) != now.get(key)
    }
    assert changed == {}, "who may call these changed (written, now): " + json.dumps(
        changed, indent=1
    )


def main(argv: list[str], write: Callable[[str], Any] = MATRIX.write_text) -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as workdir:
        seen = observe(Path(workdir))
    if seen.errors:
        print("\n".join(seen.errors), file=sys.stderr)
    write(render(seen))
    print(f"wrote {MATRIX}", file=sys.stderr)
    return 1 if seen.errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
