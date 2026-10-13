"""Feature modes as the processor reads them from OPA (``data.registry.features``), and
each caller's own (``data.agentgov.context.caller_modes``, docs/features.md#exceptions)."""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections import OrderedDict
from typing import Any

from agentgov.opa.client import OpaClient, OpaError
from agentgov.registry.features import CATALOG

log = logging.getLogger(__name__)
KNOWN = {f.key for f in CATALOG}


def _modes(values: object) -> dict[str, str]:
    """The feature modes in ``values``, leaving out anything else."""
    if not isinstance(values, dict):
        return {}
    return {k: v for k, v in values.items() if k in KNOWN and isinstance(v, str)}


class FeatureModes:
    """The modes of AgentGov's features (``agentgov.registry.features``).

    An administrator's change reaches OPA with its next bundle, and the processor
    within ``MAX_AGE`` seconds of that. Until OPA answers, and while it doesn't,
    the modes last read stand: the control plane's, which it gives with its answer to
    each of the processor's reports, or at first the features' defaults.

    A control can have exceptions, another mode for some agents: :meth:`for_caller` gives
    the modes for one caller, read from OPA at most every ``MAX_AGE`` seconds for each.
    """

    MAX_AGE = 5.0
    # Callers whose own modes are kept, at most: the least recently seen go first.
    MAX_CALLERS = 10_000

    def __init__(self, opa: OpaClient) -> None:
        self.opa = opa
        self._modes = {f.key: f.default for f in CATALOG}
        self._read_at = -math.inf
        self._lock = asyncio.Lock()
        self._callers: OrderedDict[tuple[str, str], tuple[float, dict[str, str]]] = OrderedDict()

    def _fresh(self) -> bool:
        return time.monotonic() - self._read_at < self.MAX_AGE

    @staticmethod
    def _key(identity: dict[str, Any] | None) -> tuple[str, str] | None:
        if not identity or not (identity.get("agent_id") or identity.get("client_id")):
            return None
        return str(identity.get("agent_id") or ""), str(identity.get("client_id") or "")

    def last(self, identity: dict[str, Any] | None = None) -> dict[str, str]:
        """The modes last read, for ``identity`` if it called before, without asking OPA
        (where asking can't be waited for)."""
        key = self._key(identity)
        hit = self._callers.get(key) if key is not None else None
        return hit[1] if hit is not None else self._modes

    def learn(self, values: object) -> None:
        """The modes as the control plane gave them, with its answer to the processor's
        report (agentgov.processor.health): what the processor knows of them while OPA
        can't be asked, from its start on."""
        self._modes = {**self._modes, **_modes(values)}

    async def current(self) -> dict[str, str]:
        """The features' modes, as they are for an agent without exceptions."""
        if self._fresh():
            return self._modes
        async with self._lock:
            if not self._fresh():
                try:
                    result, _ = await self.opa.evaluate("registry/features", {})
                except OpaError as exc:
                    log.warning("could not read feature modes from OPA: %s", exc)
                else:
                    self._modes = {**self._modes, **_modes(result)}
                self._read_at = time.monotonic()
        return self._modes

    async def for_caller(self, identity: dict[str, Any] | None) -> dict[str, str]:
        """The modes for the agent ``identity`` names: the features', but where an
        exception's scope takes it in or a label exempts it. A caller AgentGov can't tell,
        or one OPA can't be asked about, has the features' modes (or its last known)."""
        base = await self.current()
        key = self._key(identity)
        if key is None:
            return base
        hit = self._callers.get(key)
        if hit is not None and time.monotonic() - hit[0] < self.MAX_AGE:
            self._callers.move_to_end(key)
            return hit[1]
        try:
            result, _ = await self.opa.evaluate(
                "agentgov/context/caller_modes", {"agent": dict(identity or {})}
            )
        except OpaError as exc:
            log.warning("could not read a caller's modes from OPA: %s", exc)
            modes = hit[1] if hit is not None else base
        else:
            modes = {**base, **_modes(result)}
        self._callers[key] = (time.monotonic(), modes)
        self._callers.move_to_end(key)
        while len(self._callers) > self.MAX_CALLERS:
            self._callers.popitem(last=False)
        return modes
