"""What AgentGov's platform connectors share: their errors, and what they report.

A connector reads the agents on one platform (AWS, Google Cloud, Salesforce,
Databricks; Microsoft's have connectors of their own) and reports each one as
:class:`Found`: the platform's view of it, and the risky settings it has, which
become findings on the agent. It reads the platform and changes nothing there.

A platform is read in parts (an AWS account's region, a Google Cloud project's
location, a Databricks workspace): a part that can't be read is reported in
:attr:`Inventory.failed`, and its agents are left as the last sync saw them,
neither gone nor cleared of findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class PlatformError(Exception):
    """A platform could not be read or changed; the message says why.

    ``status`` is the platform's HTTP status, when it answered.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Risk:
    """A risky setting on an agent, raised as a finding of ``type`` (``platform.*``)."""

    type: str
    severity: str
    title: str
    description: str = ""
    remediation: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Found:
    """One agent as its platform reports it.

    ``external_id`` is unique and stable on the platform (an ARN, a resource name);
    ``kind`` says what it is there (an Amazon Bedrock agent, an AgentCore runtime)
    and becomes the registry agent's platform; ``part`` is the part of the platform
    it was read from. ``details`` is what the agent's platform page shows: settings
    only, never secrets.
    """

    external_id: str
    name: str
    kind: str
    part: str
    details: dict[str, Any]
    description: str | None = None
    external_ids: dict[str, str] = field(default_factory=dict)
    risks: list[Risk] = field(default_factory=list)
    # Its instructions (system prompt), which AgentGov checks as it does every agent's.
    instructions: str | None = None
    # False when some of it couldn't be read: its findings are then left as they were.
    complete: bool = True
    # What of it couldn't be read, and why: its findings say so while they wait.
    missing: list[str] = field(default_factory=list)
    # Who made it, by email address, when the platform says: whom adopting it suggests as
    # its owner (registry.people).
    maker: str | None = None
    # True when the platform has it stopped (disabled, deactivated), False when it runs, None
    # when the platform doesn't say: blocked in AgentGov, it is stopped there or not.
    stopped: bool | None = None


@dataclass
class Inventory:
    """What one sync read: the agents found, and the parts that couldn't be read."""

    found: list[Found] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    # The parts read in full, so that agents gone from them are known to be gone.
    read: set[str] = field(default_factory=set)

    def failures(self) -> str:
        """The parts that couldn't be read, grouped by why: ``a, b: why; c: why else``."""
        grouped: dict[str, list[str]] = {}
        for part, error in sorted(self.failed.items()):
            grouped.setdefault(error, []).append(part)
        return "; ".join(f"{', '.join(parts)}: {error}" for error, parts in grouped.items())
