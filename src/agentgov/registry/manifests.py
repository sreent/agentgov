"""Declarative manifests: manage the registry as code (GitOps).

```yaml
apiVersion: agentgov/v1alpha1
kind: Agent            # Blueprint | ToolServer | Policy | Agent
metadata:
  name: support-bot
spec:
  blueprint: customer-support
  owner: cx-platform
  sponsors: [alice@example.com]
  status: active       # optional desired state
```

Applying is idempotent: unchanged resources are reported as ``unchanged``.
Resources are applied in dependency order (blueprints and tool servers
before the agents and policies that reference them).
"""

from __future__ import annotations

from typing import Any

import yaml
from sqlalchemy.orm import Session

from agentgov.config import Settings
from agentgov.models import ACTIVE, BLOCKED, PENDING
from agentgov.registry import agents, blueprints, policies, toolservers
from agentgov.registry.errors import NotFound, ValidationError

API_VERSION = "agentgov/v1alpha1"
ORDER = ["Blueprint", "ToolServer", "Policy", "Agent"]


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
            "Blueprint": _blueprint,
            "ToolServer": _toolserver,
            "Policy": _policy,
            "Agent": _agent,
        }[kind](session, settings, spec, actor)
        results.append({"kind": kind, "name": name, "action": action})
    return results


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


def _policy(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    try:
        policy = policies.get(session, spec["name"])
    except NotFound:
        policies.create(session, spec, actor=actor)
        return "created"
    return "configured" if policies.update(session, policy, spec, actor=actor) else "unchanged"


def _agent(session: Session, settings: Settings, spec: dict[str, Any], actor: str) -> str:
    desired = spec.pop("status", ACTIVE)
    if desired not in (ACTIVE, PENDING, BLOCKED):
        raise ValidationError(f"agent {spec['name']}: status must be active, pending or blocked")
    try:
        agent = agents.get(session, spec["name"])
    except NotFound:
        agent = agents.register(session, settings, spec, actor=actor, approve=desired == ACTIVE)
        if desired == BLOCKED:
            agents.transition(session, settings, agent, "block", actor=actor, reason="manifest")
        return "created"
    action = "configured" if agents.update(session, agent, spec, actor=actor) else "unchanged"
    if desired == ACTIVE and agent.status in (PENDING, BLOCKED):
        verb = "approve" if agent.status == PENDING else "unblock"
        agents.transition(session, settings, agent, verb, actor=actor, reason="manifest")
        action = "configured"
    elif desired == BLOCKED and agent.status in (PENDING, ACTIVE):
        agents.transition(session, settings, agent, "block", actor=actor, reason="manifest")
        action = "configured"
    return action


def export(session: Session) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for bp in blueprints.list_all(session):
        d = blueprints.to_dict(bp)
        docs.append(_doc("Blueprint", bp.name, {k: d[k] for k in blueprints.FIELDS}))
    for ts in toolservers.list_all(session):
        d = toolservers.to_dict(ts)
        spec = {k: d[k] for k in toolservers.FIELDS}
        spec["status"] = ts.status
        docs.append(_doc("ToolServer", ts.name, spec))
    for policy in policies.list_all(session):
        docs.append(
            _doc(
                "Policy",
                policy.name,
                {"description": policy.description, "enabled": policy.enabled, "rego": policy.rego},
            )
        )
    for agent in agents.list_agents(session):
        if agent.status not in (ACTIVE, PENDING, BLOCKED):
            continue
        d = agents.to_dict(agent)
        spec = {k: d[k] for k in agents.EDITABLE if k in d and d[k] not in (None, [], {})}
        spec["status"] = agent.status
        docs.append(_doc("Agent", agent.name, spec))
    return docs


def _doc(kind: str, name: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {"apiVersion": API_VERSION, "kind": kind, "metadata": {"name": name}, "spec": spec}


def dump(docs: list[dict[str, Any]]) -> str:
    return yaml.safe_dump_all(docs, sort_keys=False)
