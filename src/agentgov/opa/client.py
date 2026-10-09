"""Async client for OPA's Data API."""

from __future__ import annotations

from typing import Any

import httpx


class OpaError(RuntimeError):
    pass


class OpaClient:
    def __init__(
        self, base_url: str, *, http: httpx.AsyncClient | None = None, timeout: float = 2.0
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._http = http or httpx.AsyncClient(timeout=timeout)

    async def evaluate(self, path: str, input_doc: dict[str, Any]) -> tuple[Any, str | None]:
        """Evaluate ``data.<path>`` and return ``(result, decision_id)``.

        An undefined result is an error: policies always define their outputs, so
        "undefined" means the bundle is missing or broken and callers fail closed.
        """
        try:
            resp = await self._http.post(
                f"{self.base_url}/v1/data/{path}", json={"input": input_doc}
            )
        except httpx.HTTPError as exc:
            raise OpaError(f"OPA unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise OpaError(f"OPA returned {resp.status_code}: {resp.text[:200]}")
        body = resp.json()
        if "result" not in body:
            raise OpaError(f"data.{path.replace('/', '.')} is undefined (is the bundle loaded?)")
        return body["result"], body.get("decision_id")
