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
        try:
            results = resp.json()
        except ValueError:
            raise PresidioError(f"Presidio's answer isn't JSON: {resp.text[:200]}") from None
        # Older analyzers answer a single text with a flat list.
        if (
            isinstance(results, list)
            and len(batch) == 1
            and all(isinstance(r, dict) for r in results)
        ):
            results = [results]
        # An answer it can't read is Presidio failing (AGENTGOV_PRESIDIO_FAILURE_MODE), not
        # Presidio finding nothing.
        if not isinstance(results, list) or len(results) != len(batch):
            raise PresidioError("Presidio's answer doesn't match the texts it was sent")
        spans = []
        for (path, _), items in zip(batch, results, strict=True):
            if not isinstance(items, list) or not all(_finding(item) for item in items):
                raise PresidioError(f"Presidio's answer can't be read: {str(items)[:200]}")
            for item in items:
                entity = item["entity_type"]
                if item["score"] >= self.thresholds.get(entity, 1.1):
                    spans.append(Span(path, item["start"], item["end"], entity, PII, item["score"]))
        return spans, skipped


def _finding(item: Any) -> bool:
    """Whether ``item`` is one of Presidio's findings: an entity type, where it starts and
    ends, and a score."""
    return (
        isinstance(item, dict)
        and isinstance(item.get("entity_type"), str)
        and all(
            isinstance(item.get(k), int) and not isinstance(item.get(k), bool)
            for k in ("start", "end")
        )
        and isinstance(item.get("score"), int | float)
    )
