"""Declarative manifests: manage the registry as code (GitOps).

```yaml
apiVersion: agentgov/v1alpha1
kind: Agent            # Feature | Destination | Team | IdentityIssuer | Blueprint |
                       # ToolServer | ModelProvider | AccessPackage | Policy |
                       # ManagementRule | Agent
metadata:
  name: support-bot
spec:
  blueprint: customer-support
  owner: cx-platform
  sponsors: [alice@example.com]
  status: active       # optional desired state
  instructions: |      # optional: the agent's system prompt, checked for unsafe content
    You help customers with their orders...
```

A ``Feature`` sets how strictly one of AgentGov's features applies
(docs/features.md): ``metadata.name`` is the feature, ``spec.mode`` its mode.

Applying is idempotent: unchanged resources are reported as ``unchanged``.
Resources are applied in dependency order (features first, then destinations, the teams
that post to them, identity issuers, blueprints, tool servers, model providers and the access
packages that name blueprints, policies, and the management rules that name teams, before
the agents that reference them).
"""

from __future__ import annotations

from typing import Any

import yaml
from sqlalchemy.orm import Session

from agentgov.config import Settings
from agentgov.models import ACTIVE, BLOCKED, PENDING, Agent, AgentInstructions
from agentgov.registry import (
    access_packages,
    agents,
    blueprints,
    destinations,
    features,
    identity_issuers,
    instructions,
    model_providers,
    policies,
    rules,
    teams,
    toolservers,
)
from agentgov.registry.errors import NotFound, ValidationError

API_VERSION = "agentgov/v1alpha1"
ORDER = [
    "Feature",
    "Destination",
    "Team",
    "IdentityIssuer",
    "Blueprint",
    "ToolServer",
    "ModelProvider",
    "AccessPackage",
    "Policy",
    "ManagementRule",
    "Agent",
]


def parse(text: str) -> list[dict[str, Any]]:
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise ValidationError(f"invalid YAML: {exc}") from exc
    for i, doc in enumerate(docs):
        validate(doc, i)
    return docs


def validate(doc: Any, index: int = 0) -> None:
    if not isinstance(doc, dict):
        raise ValidationError(f"document {index} is not a mapping")
    if doc.get("apiVersion") != API_VERSION:
        raise ValidationError(f"document {index}: apiVersion must be {API_VERSION}")
    if doc.get("kind") not in ORDER:
        raise ValidationError(f"document {index}: kind must be one of {', '.join(ORDER)}")
    name = (doc.get("metadata") or {}).get("name")
    if not isinstance(name, str) or not name:
        raise ValidationError(f"document {index}: metadata.name is required")
    if not isinstance(doc.get("spec", {}), dict):
        raise ValidationError(f"document {index}: spec must be a mapping")


def _spec(doc: dict[str, Any]) -> dict[str, Any]:
    spec = dict(doc.get("spec") or {})
    spec["name"] = doc["metadata"]["name"]
    if "labels" in doc["metadata"] and "labels" not in spec:
        spec["labels"] = doc["metadata"]["labels"]
    return spec


def apply(
    session: Session, settings: Settings, docs: list[dict[str, Any]], *, actor: str
) -> list[dict[str, str]]:
    results = []
    for doc in sorted(docs, key=lambda d: ORDER.index(d["kind"])):
        kind, spec = doc["kind"], _spec(doc)
        name = spec["name"]
        action = {
            "Feature": _feature,
            "Destination": _destination,
            "Team": _team,
            "IdentityIssuer": _identity_issuer,
            "Blueprint": _blueprint,
            "ToolServer": _toolserver,
            "ModelProvider": _model_provider,
            "AccessPackage": _access_package,
            "Policy": _policy,
            "ManagementRule": _rule,
            "Agent": _agent,
        }[kind](session, settings, spec, actor)
        results.append({"kind": kind, "name": name, "action": action})
    return results


def _feature(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    if set(spec) - {"name", "mode", "labels"}:
        raise ValidationError(f"feature {spec['name']}: spec takes only mode")
    try:
        changed = features.set_mode(session, settings, spec["name"], spec.get("mode"), actor=actor)
    except NotFound as exc:
        raise ValidationError(str(exc)) from None
    return "configured" if changed else "unchanged"


def _destination(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    desired = spec.pop("status", destinations.ACTIVE)
    if desired not in (destinations.ACTIVE, destinations.PAUSED):
        raise ValidationError(f"destination {spec['name']}: status must be active or paused")
    try:
        destination = destinations.get(session, spec["name"])
    except NotFound:
        destinations.create(session, {**spec, "status": desired}, actor=actor)
        return "created"
    spec.pop("backfill", None)  # where a new destination starts in the ledger
    changed = destinations.update(session, destination, spec, actor=actor)
    action = "configured" if changed else "unchanged"
    if destination.status != desired:
        verb = "pause" if desired == destinations.PAUSED else "resume"
        destinations.set_status(session, destination, verb, actor=actor)
        action = "configured"
    return action


def _team(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    spec.pop("labels", None)
    team = teams.find(session, spec["name"])
    if team is None:
        teams.create(session, spec, actor=actor)
        return "created"
    return "configured" if teams.update_team(session, team, spec, actor=actor) else "unchanged"


def _identity_issuer(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    desired = spec.pop("status", identity_issuers.APPROVED)
    if desired not in (identity_issuers.APPROVED, BLOCKED):
        raise ValidationError(f"identity issuer {spec['name']}: status must be approved or blocked")
    try:
        issuer = identity_issuers.get(session, spec["name"])
        changed = identity_issuers.update(session, issuer, spec, actor=actor)
        action = "configured" if changed else "unchanged"
    except NotFound:
        issuer = identity_issuers.create(session, spec, actor=actor)
        action = "created"
    if issuer.status != desired:
        verb = "block" if desired == BLOCKED else "unblock"
        identity_issuers.set_status(session, issuer, verb, actor=actor)
        action = "configured" if action == "unchanged" else action
    return action


def _blueprint(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    try:
        bp = blueprints.get(session, spec["name"])
    except NotFound:
        blueprints.create(session, spec, actor=actor)
        return "created"
    return "configured" if blueprints.update(session, bp, spec, actor=actor) else "unchanged"


def _toolserver(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    desired = spec.pop("status", None)
    try:
        ts = toolservers.get(session, spec["name"])
        action = "configured" if toolservers.update(session, ts, spec, actor=actor) else "unchanged"
    except NotFound:
        ts = toolservers.create(session, spec, actor=actor, approve=desired != PENDING)
        action = "created"
    if desired == BLOCKED and ts.status != BLOCKED:
        toolservers.set_status(session, ts, "block", actor=actor)
        action = "configured"
    elif desired == "approved" and ts.status != "approved":
        toolservers.set_status(
            session, ts, "approve" if ts.status == PENDING else "unblock", actor=actor
        )
        action = "configured"
    return action


def _model_provider(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    desired = spec.pop("status", model_providers.APPROVED)
    if desired not in (model_providers.APPROVED, BLOCKED):
        raise ValidationError(f"model provider {spec['name']}: status must be approved or blocked")
    try:
        provider = model_providers.get(session, spec["name"])
        changed = model_providers.update(session, provider, spec, actor=actor)
        action = "configured" if changed else "unchanged"
    except NotFound:
        provider = model_providers.create(session, spec, actor=actor)
        action = "created"
    if provider.status != desired:
        verb = "block" if desired == BLOCKED else "unblock"
        model_providers.set_status(session, provider, verb, actor=actor)
        action = "configured" if action == "unchanged" else action
    return action


def _access_package(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    try:
        package = access_packages.get(session, spec["name"])
    except NotFound:
        access_packages.create(session, spec, actor=actor)
        return "created"
    changed = access_packages.update(session, package, spec, actor=actor)
    return "configured" if changed else "unchanged"


def _rule(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    try:
        rule = rules.get(session, spec["name"])
    except NotFound:
        rules.create(session, spec, actor=actor)
        return "created"
    return "configured" if rules.update(session, rule, spec, actor=actor) else "unchanged"


def _policy(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    try:
        policy = policies.get(session, spec["name"])
    except NotFound:
        policies.create(session, spec, actor=actor)
        return "created"
    return "configured" if policies.update(session, policy, spec, actor=actor) else "unchanged"


def _instructions(
    session: Session, settings: Settings, agent: Agent, text: Any, actor: str
) -> bool:
    """Apply ``spec.instructions``; returns whether they changed."""
    if text is None:
        return False
    before = session.get(AgentInstructions, f"{agent.id}:registered")
    digest = before.sha256 if before is not None else None
    row = instructions.report(
        session,
        agent,
        source="registered",
        text=text,
        actor=actor,
        classify=bool(settings.guardian_url),
    )
    return row.sha256 != digest


def _agent(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    desired = spec.pop("status", ACTIVE)
    text = spec.pop("instructions", None)
    if desired not in (ACTIVE, PENDING, BLOCKED):
        raise ValidationError(f"agent {spec['name']}: status must be active, pending or blocked")
    try:
        agent = agents.get(session, spec["name"])
    except NotFound:
        agent = agents.register(session, settings, spec, actor=actor, approve=desired == ACTIVE)
        _instructions(session, settings, agent, text, actor)
        if desired == BLOCKED:
            agents.transition(session, settings, agent, "block", actor=actor, reason="manifest")
        return "created"
    action = "configured" if agents.update(session, agent, spec, actor=actor) else "unchanged"
    if _instructions(session, settings, agent, text, actor):
        action = "configured"
    if desired == ACTIVE and agent.status in (PENDING, BLOCKED):
        verb = "approve" if agent.status == PENDING else "unblock"
        agents.transition(session, settings, agent, verb, actor=actor, reason="manifest")
        action = "configured"
    elif desired == BLOCKED and agent.status in (PENDING, ACTIVE):
        agents.transition(session, settings, agent, "block", actor=actor, reason="manifest")
        action = "configured"
    return action


def export(session: Session) -> list[dict[str, Any]]:
    # Features administrators chose; the deployment's pins belong to the deployment.
    docs: list[dict[str, Any]] = [
        _doc("Feature", key, {"mode": mode}) for key, mode in features.chosen(session).items()
    ]
    # Where events and alerts go; their credentials are files, never exported.
    for destination in destinations.list_all(session):
        spec = {"kind": destination.kind}
        defaults = {
            "description": "",
            "url": None,
            "format": "json" if destination.kind == destinations.WEBHOOK else None,
            "events": destinations.default_events(destination.kind),
            "min_severity": destinations.default_severity(destination.kind),
            "labels": {},
        }
        for key, default in defaults.items():
            value = getattr(destination, key)
            if value not in (default, None):
                spec[key] = value
        spec["status"] = destination.status
        docs.append(_doc("Destination", destination.name, spec))
    for team in teams.list_all(session):
        d = teams.to_dict(team)
        spec = {k: d[k] for k in teams.FIELDS if d[k] not in ("", [], False)}
        docs.append(_doc("Team", team.name, spec))
    for issuer in identity_issuers.list_all(session):
        d = identity_issuers.to_dict(issuer)
        spec = {k: d[k] for k in identity_issuers.FIELDS if d[k] not in (None, "", {}, False)}
        spec["status"] = issuer.status
        docs.append(_doc("IdentityIssuer", issuer.name, spec))
    for bp in blueprints.list_all(session):
        d = blueprints.to_dict(bp)
        docs.append(_doc("Blueprint", bp.name, {k: d[k] for k in blueprints.FIELDS}))
    # How a server is used is written out only where it differs from the default: on the
    # gateway, not listed for developers, no authorization server of its own.
    unless = {
        "gateway": True,
        "developers": False,
        "registry_name": None,
        "packages": [],
        "authorization_server": None,
        "oauth_client_id": None,
    }
    for ts in toolservers.list_all(session):
        d = toolservers.to_dict(ts)
        spec = {k: d[k] for k in toolservers.FIELDS if k not in unless or d[k] != unless[k]}
        if not d["url"]:
            spec.pop("url")
        spec["status"] = ts.status
        docs.append(_doc("ToolServer", ts.name, spec))
    for provider in model_providers.list_all(session):
        d = model_providers.to_dict(provider)
        spec = {k: d[k] for k in model_providers.FIELDS if d[k] not in (None, "", {}, [])}
        if not provider.key_file:
            spec.pop("key_file", None)  # the default path follows the name
        spec["status"] = provider.status
        docs.append(_doc("ModelProvider", provider.name, spec))
    for package in access_packages.list_all(session):
        d = access_packages.to_dict(session, package)
        spec = {k: d[k] for k in access_packages.FIELDS if d[k] not in ("", [], {}, None)}
        spec["approval"] = d["approval"]
        docs.append(_doc("AccessPackage", package.name, spec))
    for policy in policies.list_all(session):
        docs.append(
            _doc(
                "Policy",
                policy.name,
                {"description": policy.description, "enabled": policy.enabled, "rego": policy.rego},
            )
        )
    for rule in rules.list_all(session):
        d = rules.to_dict(session, rule)
        spec = {
            k: d[k]
            for k in rules.FIELDS
            if k in ("conditions", "action") or d[k] != rules.DEFAULTS.get(k)
        }
        docs.append(_doc("ManagementRule", rule.name, spec))
    for agent in agents.list_agents(session):
        if agent.status not in (ACTIVE, PENDING, BLOCKED):
            continue
        d = agents.to_dict(agent)
        spec = {k: d[k] for k in agents.EDITABLE if k in d and d[k] not in (None, [], {})}
        if spec.get("client_type") == "service":
            del spec["client_type"]  # the default
        if d["workload_identity"]:
            spec["workload_identity"] = d["workload_identity"]
        spec["status"] = agent.status
        registered = session.get(AgentInstructions, f"{agent.id}:registered")
        if registered is not None and not registered.truncated:
            spec["instructions"] = registered.text
        docs.append(_doc("Agent", agent.name, spec))
    return docs


def _doc(kind: str, name: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {"apiVersion": API_VERSION, "kind": kind, "metadata": {"name": name}, "spec": spec}


def dump(docs: list[dict[str, Any]]) -> str:
    return yaml.safe_dump_all(docs, sort_keys=False)
