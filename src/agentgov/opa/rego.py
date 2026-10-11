"""Validation of organisation Rego modules before they are distributed.

A module that fails to compile would stop OPA from activating *any* new bundle
(including urgent registry changes such as blocking an agent), so custom
policies are compiled together with the library and smoke-evaluated before
they are accepted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from agentgov.opa.bundle import SYSTEM_LOG_REGO, custom_package, library_files
from agentgov.registry.errors import ValidationError

_PACKAGE = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*$", re.MULTILINE)

SMOKE_INPUTS: list[dict[str, Any]] = [
    {
        "phase": "request",
        "method": "tools/call",
        "agent": {"client_id": "agent-smoke-test"},
        "resource": {"server": "smoke", "name": "tool"},
        "arguments": {"text": "hello", "amount": 10},
        "detections": {"categories": [], "entities": [], "prompt_injection": False},
    },
    {
        "phase": "response",
        "method": "tools/call",
        "agent": {"client_id": "agent-smoke-test"},
        "resource": {"server": "smoke", "name": "tool"},
        "result": {"content": [{"type": "text", "text": "ok"}]},
        "detections": {"categories": ["pii"], "entities": ["EMAIL_ADDRESS"]},
    },
    # A Copilot Studio agent's tool call (threat detection), decided by its own package.
    {
        "platform": "copilot-studio",
        "agent": {"platform_id": "smoke-bot", "environment_id": "smoke-env", "published": True},
        "user": {"id": "smoke-user"},
        "tool": {"id": "smoke-tool", "type": "ConnectorTool", "name": "tool"},
        "arguments": {"text": "hello", "amount": 10},
        "detections": {"categories": [], "entities": [], "prompt_injection": False},
    },
    # A prompt to a model provider, decided by agentgov.models.
    {
        "kind": "model",
        "phase": "request",
        "agent": {"client_id": "agent-smoke-test"},
        "provider": "smoke",
        "model": "smoke-model",
        "detections": {"categories": ["pii"], "entities": ["EMAIL_ADDRESS"]},
        "tool_calls": False,
    },
]


def _decision_for(sample: dict[str, Any]) -> str:
    if sample.get("platform") == "copilot-studio":
        return "data.agentgov.copilotstudio.decision"
    if sample.get("kind") == "model":
        return "data.agentgov.models.decision"
    return "data.agentgov.mcp.decision"


def opa_binary() -> str | None:
    return shutil.which(os.environ.get("AGENTGOV_OPA_BINARY", "opa"))


def _format_errors(output: str) -> str:
    try:
        errors = json.loads(output).get("errors", [])
    except (ValueError, AttributeError):
        return output.strip()[:2000]
    lines = []
    for err in errors:
        loc = err.get("location") or {}
        lines.append(f"line {loc.get('row', '?')}: {err.get('message')} ({err.get('code')})")
    return "; ".join(lines)


def check_custom_policy(
    name: str, rego: str, *, others: dict[str, str], registry: dict[str, Any]
) -> None:
    """Raise ValidationError unless ``rego`` compiles and evaluates cleanly.

    ``others`` are the other enabled custom modules keyed by bundle path and
    ``registry`` is the current registry snapshot used for smoke evaluation.
    """
    expected = custom_package(name)
    match = _PACKAGE.search(rego)
    if match is None or match.group(1) != expected:
        raise ValidationError(f"policy {name!r} must declare `package {expected}`")
    binary = opa_binary()
    if binary is None:
        raise ValidationError(
            "the opa binary is needed to validate policies; install it or set AGENTGOV_OPA_BINARY"
        )
    with tempfile.TemporaryDirectory(prefix="agentgov-rego-") as tmp:
        root = Path(tmp) / "bundle"
        modules = {
            **library_files(),
            "system/log.rego": SYSTEM_LOG_REGO,
            **others,
            f"agentgov/custom/{name}.rego": rego,
        }
        for path, source in modules.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source)
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [binary, "check", "--strict", "--format", "json", str(root)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if proc.returncode != 0:
            raise ValidationError(
                f"policy {name!r} does not compile: {_format_errors(proc.stdout or proc.stderr)}"
            )
        data_file = Path(tmp) / "data.json"
        data_file.write_text(json.dumps({"registry": registry}))
        for sample in SMOKE_INPUTS:
            input_file = Path(tmp) / "input.json"
            input_file.write_text(json.dumps(sample))
            proc = subprocess.run(  # noqa: S603
                [
                    binary,
                    "eval",
                    "--format",
                    "json",
                    "--data",
                    str(root),
                    "--data",
                    str(data_file),
                    "--input",
                    str(input_file),
                    _decision_for(sample),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.returncode != 0 or '"errors"' in proc.stdout:
                raise ValidationError(
                    f"policy {name!r} fails at evaluation time: "
                    f"{_format_errors(proc.stdout or proc.stderr)}"
                )
            _check_rule_shapes(name, binary, root, data_file, input_file)


def _check_rule_shapes(
    name: str, binary: str, root: Path, data_file: Path, input_file: Path
) -> None:
    """deny/require_approval/redact must be sets, or the library silently ignores them."""
    proc = subprocess.run(  # noqa: S603
        [
            binary,
            "eval",
            "--format",
            "json",
            "--data",
            str(root),
            "--data",
            str(data_file),
            "--input",
            str(input_file),
            "data." + custom_package(name),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    try:
        value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError):
        return
    for rule in ("deny", "require_approval", "redact"):
        if rule in value and not isinstance(value[rule], list):
            example = f"`{rule} contains msg if {{ ... }}`"
            raise ValidationError(f"policy {name!r}: `{rule}` must be a set rule, e.g. {example}")
