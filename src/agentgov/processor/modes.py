"""Feature modes as the processor reads them from OPA (``data.registry.features``)."""

from __future__ import annotations

import asyncio
import logging
import math
import time

from agentgov.opa.client import OpaClient, OpaError
from agentgov.registry.features import CATALOG

log = logging.getLogger(__name__)


class FeatureModes:
    """The modes of AgentGov's features (``agentgov.registry.features``).

    An administrator's change reaches OPA with its next bundle, and the processor
    within ``MAX_AGE`` seconds of that. Until OPA answers, and while it doesn't,
    the modes last read stand: the control plane's, which it gives with its answer to
    each of the processor's reports, or at first the features' defaults.
    """

    MAX_AGE = 5.0

    def __init__(self, opa: OpaClient) -> None:
        self.opa = opa
        self._modes = {f.key: f.default for f in CATALOG}
        self._read_at = -math.inf
        self._lock = asyncio.Lock()

    def _fresh(self) -> bool:
        return time.monotonic() - self._read_at < self.MAX_AGE

    def last(self) -> dict[str, str]:
        """The modes last read, without asking OPA (where asking can't be waited for)."""
        return self._modes

    def learn(self, values: object) -> None:
        """The modes as the control plane gave them, with its answer to the processor's
        report (agentgov.processor.health): what the processor knows of them while OPA
        can't be asked, from its start on."""
        if isinstance(values, dict):
            known = {f.key for f in CATALOG}
            self._modes = {
                **self._modes,
                **{k: v for k, v in values.items() if k in known and isinstance(v, str)},
            }

    async def current(self) -> dict[str, str]:
        if self._fresh():
            return self._modes
        async with self._lock:
            if not self._fresh():
                try:
                    result, _ = await self.opa.evaluate("registry/features", {})
                except OpaError as exc:
                    log.warning("could not read feature modes from OPA: %s", exc)
                else:
                    if isinstance(result, dict):
                        self._modes = {**self._modes, **result}
                self._read_at = time.monotonic()
        return self._modes
