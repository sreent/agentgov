"""The connectors that read agents on other platforms, each where it is configured.

Each one reads one platform (``agentgov.registry.platforms.INVENTORY_SOURCES``)
and returns an :class:`~agentgov.platforms.base.Inventory`; the runtime records
it in the registry, on a schedule and on demand.
"""

from __future__ import annotations

from typing import Protocol

import httpx

from agentgov.config import Settings
from agentgov.platforms.aws import AwsConnector
from agentgov.platforms.base import Inventory


class Connector(Protocol):
    def inventory(self) -> Inventory:
        """Read the platform's agents; raises PlatformError when it can't be read at all."""
        ...


def connectors(settings: Settings, *, http: httpx.Client | None = None) -> dict[str, Connector]:
    """The configured connectors, by source."""
    found: dict[str, Connector] = {}
    if settings.aws_region_list():
        found["aws"] = AwsConnector(settings, http=http)
    return found
