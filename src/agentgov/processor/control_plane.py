"""The processor's client for the control plane's internal API."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)


class ControlPlaneError(RuntimeError):
    pass


class ControlPlaneClient:
    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        http: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._http = http or httpx.AsyncClient(timeout=timeout)

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = await self._http.post(
                f"{self.base_url}{path}", json=payload, headers=self._headers
            )
        except httpx.HTTPError as exc:
            raise ControlPlaneError(f"control plane unreachable: {exc}") from exc
        if resp.status_code >= 400:
            raise ControlPlaneError(f"{path} returned {resp.status_code}: {resp.text[:200]}")
        return resp.json() if resp.content else {}

    async def check_approval(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._post("/v1/internal/approvals/check", payload)

    async def report_catalog(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._post("/v1/internal/catalog", payload)

    async def observe(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._post("/v1/internal/observe", payload)

    async def record_decisions(
        self, records: list[dict[str, Any]], *, dropped: int = 0
    ) -> dict[str, Any]:
        """Send decision records; ``dropped`` says how many were lost since the last batch,
        for the ledger to record the gap."""
        payload: dict[str, Any] = {"records": records}
        if dropped:
            payload["dropped"] = dropped
        return await self._post("/v1/internal/decisions", payload)

    async def report_component(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._post("/v1/internal/components", payload)


class DecisionRecorder:
    """Ships decision records to the ledger in batches, off the request path.

    Records wait in a bounded queue and are retried with backoff while the
    control plane is unavailable; if the queue overflows, the oldest records
    are dropped, and the next batch tells the control plane how many, which the
    ledger records (``decisions.dropped``): the gap is in the evidence.
    """

    def __init__(
        self, client: ControlPlaneClient, *, max_queue: int = 10_000, batch: int = 100
    ) -> None:
        self.client = client
        self.batch = batch
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=max_queue)
        self._task: asyncio.Task[None] | None = None
        self.dropped = 0
        # Of those, how many the control plane was told of.
        self.reported = 0

    def record(self, record: dict[str, Any]) -> None:
        while True:
            try:
                self._queue.put_nowait(record)
                return
            except asyncio.QueueFull:
                self._queue.get_nowait()
                self.dropped += 1
                log.error("decision queue full; dropped %d record(s) so far", self.dropped)

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="decision-recorder")

    async def _drain(self) -> list[dict[str, Any]]:
        items = [await self._queue.get()]
        while len(items) < self.batch and not self._queue.empty():
            items.append(self._queue.get_nowait())
        return items

    async def _send(self, items: list[dict[str, Any]]) -> None:
        delay = 0.5
        while True:
            lost = self.dropped - self.reported
            try:
                if lost:
                    await self.client.record_decisions(items, dropped=lost)
                    self.reported += lost
                else:
                    await self.client.record_decisions(items)
                return
            except ControlPlaneError as exc:
                log.warning("recording %d decision(s) failed, retrying: %s", len(items), exc)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)

    async def _run(self) -> None:
        while True:
            await self._send(await self._drain())

    async def flush(self) -> None:
        """Send everything queued so far (used by tests and on shutdown)."""
        while not self._queue.empty():
            items = []
            while not self._queue.empty() and len(items) < self.batch:
                items.append(self._queue.get_nowait())
            await self._send(items)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        await self.flush()
