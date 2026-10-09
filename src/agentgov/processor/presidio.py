"""PII detection with Microsoft Presidio's analyzer service."""

from __future__ import annotations

from typing import Any

import httpx

from agentgov.processor.detectors import PII, Path, Span


class PresidioError(RuntimeError):
    pass


class PresidioClient:
    def __init__(
        self,
        base_url: str,
        thresholds: dict[str, float],
        *,
        max_chars: int = 16000,
        http: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.thresholds = thresholds
        self.max_chars = max_chars
        self._http = http or httpx.AsyncClient(timeout=timeout)

    async def find_pii(self, strings: list[tuple[Path, str]]) -> tuple[list[Span], bool]:
        """Return PII spans and whether some text exceeded the analysis budget."""
        if not self.thresholds:
            return [], False
        batch: list[tuple[Path, str]] = []
        total, skipped = 0, False
        for path, text in strings:
            if len(text.strip()) < 5:
                continue  # too short to hold an email, phone or card number
            if total + len(text) > self.max_chars:
                skipped = True
                continue
            batch.append((path, text))
            total += len(text)
        if not batch:
            return [], skipped
        payload: dict[str, Any] = {
            "text": [text for _, text in batch],
            "language": "en",
            "entities": sorted(self.thresholds),
            "score_threshold": min(self.thresholds.values()),
        }
        try:
            resp = await self._http.post(f"{self.base_url}/analyze", json=payload)
        except httpx.HTTPError as exc:
            raise PresidioError(f"Presidio unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise PresidioError(f"Presidio returned {resp.status_code}: {resp.text[:200]}")
        results = resp.json()
        if len(batch) == 1 and results and isinstance(results[0], dict):
            results = [results]  # older analyzers answer a single text with a flat list
        spans = []
        for (path, _), items in zip(batch, results, strict=False):
            for item in items or []:
                entity = item.get("entity_type")
                if item.get("score", 0) >= self.thresholds.get(entity, 1.1):
                    spans.append(Span(path, item["start"], item["end"], entity, PII, item["score"]))
        return spans, skipped
