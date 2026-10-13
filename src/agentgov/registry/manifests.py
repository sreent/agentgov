"""Declarative manifests: manage the registry as code (GitOps).

```yaml
apiVersion: agentgov/v1alpha1
kind: Agent            # Feature | FindingType | Destination | Team | IdentityIssuer |
                       # Blueprint | ToolServer | ModelProvider | AccessPackage | Policy |
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
(docs/features.md): ``metadata.name`` is the feature, ``spec.mode`` its mode, and for a
control ``spec.scopes`` its exceptions, its mode for the agents in a scope
(docs/features.md#exceptions).

A ``FindingType`` says how one type of finding is handled (docs/issues.md#kinds-of-issues):
``metadata.name`` is the type, such as ``agent.no_owner``; ``spec.mode`` on or off, and
``spec.severity`` its severity here.

Applying is idempotent: unchanged resources are reported as ``unchanged``.
Resources are applied in dependency order (features first, then destinations, the teams
that post to them, identity issuers, blueprints, tool servers, model providers and the access
packages that name blueprints, policies, and the management rules that name teams, before
the agents that reference them); features' exceptions, which may name teams and blueprints,
last.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import yaml
from sqlalchemy.orm import Session

from agentgov.config import Settings
from agentgov.models import ACTIVE, BLOCKED, PENDING, Agent, AgentInstructions, FindingType
from agentgov.registry import (
    access_packages,
    agents,
    blueprints,
    classification,
    destinations,
    features,
    finding_types,
    identity_issuers,
    instructions,
    model_providers,
    policies,
    rules,
    teams,
    toolservers,
)
from agentgov.registry.errors import NotFound, RegistryError, ValidationError

API_VERSION = "agentgov/v1alpha1"
ORDER = [
    "Feature",
    "FindingType",
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
    # Features' exceptions, set last: they may name teams and blueprints applied here.
    later: list[tuple[dict[str, str], dict[str, Any]]] = []
    for doc in sorted(docs, key=lambda d: ORDER.index(d["kind"])):
        kind, spec = doc["kind"], _spec(doc)
        name = spec["name"]
        with _about(kind, name):
            action = {
                "Feature": _feature,
                "FindingType": _finding_type,
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
        if kind == "Feature" and "scopes" in spec:
            later.append((results[-1], spec))
    for result, spec in later:
        with _about("Feature", spec["name"]):
            if _feature_scopes(session, settings, spec, actor):
                result["action"] = "configured"
    return results


@contextmanager
def _about(kind: str, name: str) -> Iterator[None]:
    """What goes wrong applying a document names it: in a long manifest, "there is no team
    x" alone doesn't say where."""
    try:
        yield
    except RegistryError as exc:
        what = f"{re.sub(r'(?<!^)(?=[A-Z])', ' ', kind).lower()} {name}"
        if str(exc).startswith(what):
            raise
        raise type(exc)(f"{what}: {exc}") from None


def _feature(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    """A feature's mode. Its exceptions are set after the other documents
    (``_feature_scopes``), once the teams and blueprints they name are there."""
    if set(spec) - {"name", "mode", "scopes", "labels"}:
        raise ValidationError(f"feature {spec['name']}: spec takes only mode and scopes")
    if "mode" not in spec and "scopes" not in spec:
        raise ValidationError(f"feature {spec['name']}: spec needs mode, scopes or both")
    changed = False
    try:
        if "mode" in spec:
            changed = features.set_mode(session, settings, spec["name"], spec["mode"], actor=actor)
    except NotFound as exc:
        raise ValidationError(str(exc)) from None
    return "configured" if changed else "unchanged"


def _feature_scopes(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> bool:
    try:
        return features.set_scopes(session, settings, spec["name"], spec["scopes"], actor=actor)
    except NotFound as exc:
        raise ValidationError(str(exc)) from None


def _finding_type(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    if set(spec) - {"name", "mode", "severity", "labels"}:
        raise ValidationError(f"finding type {spec['name']}: spec takes only mode and severity")
    if "mode" not in spec and "severity" not in spec:
        raise ValidationError(f"finding type {spec['name']}: spec needs mode, severity or both")
    row = session.get(FindingType, spec["name"])
    before = (row.mode, row.severity) if row is not None else None
    after = finding_types.configure(
        session, spec["name"], {k: spec[k] for k in ("mode", "severity") if k in spec}, actor=actor
    )
    return "unchanged" if before == (after["mode"], after["severity"]) else "configured"


def _destination(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    desired = spec.pop("status", destinations.ACTIVE)
    if desired not in (destinations.ACTIVE, destinations.PAUSED):
        raise ValidationError(f"destination {spec['name']}: status must be active or paused")
    try:
        destination = destinations.get(session, spec["name"])
    except NotFound:
        destinations.create(session, {**spec, "status": desired}, actor=actor, settings=settings)
        return "created"
    spec.pop("backfill", None)  # where a new destination starts in the ledger
    if "tickets" in spec and isinstance(spec["tickets"], dict):
        # The manifest says all of a desk's ticket settings: what it leaves out goes.
        spec["tickets"] = {**{k: None for k in destination.tickets or {}}, **spec["tickets"]}
    changed = destinations.update(session, destination, spec, actor=actor, settings=settings)
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
        changed = model_providers.update(session, provider, spec, actor=actor, settings=settings)
        action = "configured" if changed else "unchanged"
    except NotFound:
        provider = model_providers.create(session, spec, actor=actor, settings=settings)
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
    # Its classification, when the manifest gives one (none: it is left as it is).
    classified = spec.pop("classification", None)
    if desired not in (ACTIVE, PENDING, BLOCKED):
        raise ValidationError(f"agent {spec['name']}: status must be active, pending or blocked")
    if classified is not None:
        classification.normalize(classified)  # before anything is changed
    try:
        agent = agents.get(session, spec["name"])
    except NotFound:
        agent = agents.register(session, settings, spec, actor=actor, approve=desired == ACTIVE)
        _instructions(session, settings, agent, text, actor)
        if classified is not None:
            classification.classify(session, agent, classified, actor=actor)
        if desired == BLOCKED:
            agents.transition(session, settings, agent, "block", actor=actor, reason="manifest")
        return "created"
    action = "configured" if agents.update(session, agent, spec, actor=actor) else "unchanged"
    if _instructions(session, settings, agent, text, actor):
        action = "configured"
    if classified is not None and classification.classify(session, agent, classified, actor=actor):
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
        _doc("Feature", key, spec) for key, spec in features.chosen(session).items()
    ]
    # How types of findings are handled here.
    docs += [
        _doc(
            "FindingType",
            row.type,
            {"mode": row.mode, **({"severity": row.severity} if row.severity else {})},
        )
        for row in finding_types.chosen(session)
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
            "tickets": {},
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
        # Whether the gateway takes its tokens, as set (its dict says how that goes too).
        d = {**identity_issuers.to_dict(issuer), "gateway": bool(issuer.gateway)}
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
        if agent.classification:
            spec["classification"] = {
                k: agent.classification.get(k, "") for k in classification.FIELDS
            }
        registered = session.get(AgentInstructions, f"{agent.id}:registered")
        if registered is not None and not registered.truncated:
            spec["instructions"] = registered.text
        docs.append(_doc("Agent", agent.name, spec))
    return docs


def _doc(kind: str, name: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {"apiVersion": API_VERSION, "kind": kind, "metadata": {"name": name}, "spec": spec}


def dump(docs: list[dict[str, Any]]) -> str:
    return yaml.safe_dump_all(docs, sort_keys=False)
