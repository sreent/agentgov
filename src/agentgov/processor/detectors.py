"""Content inspection for MCP traffic.

* Secrets      - local, linear-time regular expressions plus key-labelled values
                 (``{"password": ...}``). Always on.
* PII          - delegated to Microsoft Presidio (see presidio.py).
* Prompt injection / tool poisoning - deterministic heuristics over
                 Unicode-normalised text: instruction overrides, fake control
                 tags, secrecy requests, exfiltration intent, hidden content.

All scanning is bounded (depth, number of strings, characters) so hostile
payloads cannot turn inspection into a denial of service. Patterns avoid
nested quantifiers and use bounded gaps for the same reason.
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

MAX_DEPTH = 32
MAX_STRINGS = 2000
MAX_STRING_CHARS = 64_000
MAX_TOTAL_CHARS = 512_000

Path = tuple[str | int, ...]

SECRET = "secret"  # noqa: S105 - a category name
PII = "pii"


@dataclass(frozen=True)
class Span:
    path: Path
    start: int
    end: int
    entity: str
    category: str
    score: float = 1.0


@dataclass
class ScanResult:
    spans: list[Span] = field(default_factory=list)
    injection_score: float = 0.0
    injection_reasons: list[str] = field(default_factory=list)
    truncated: bool = False
    pii_error: str | None = None

    def categories(self) -> set[str]:
        return {s.category for s in self.spans}

    def summary(self, injection_threshold: float) -> dict[str, Any]:
        return {
            "categories": sorted(self.categories()),
            "entities": sorted({s.entity for s in self.spans}),
            "prompt_injection": self.injection_score >= injection_threshold,
            "injection_score": round(self.injection_score, 3),
            "injection_reasons": self.injection_reasons,
            "truncated": self.truncated,
        }


# ---------------------------------------------------------------------------
# Traversal
# ---------------------------------------------------------------------------


def _is_binary_container(node: dict[str, Any]) -> bool:
    return node.get("type") in ("image", "audio") or ("mimeType" in node and "blob" in node)


def collect_strings(value: Any) -> tuple[list[tuple[Path, str]], bool]:
    """Return ``(path, text)`` for string leaves within the scanning budget, and
    whether anything was left unscanned (truncated strings, depth or budget)."""
    budget = {"strings": MAX_STRINGS, "chars": MAX_TOTAL_CHARS}
    out: list[tuple[Path, str]] = []
    truncated = False

    def walk(node: Any, path: Path, depth: int) -> None:
        nonlocal truncated
        if isinstance(node, str | dict | list) and (
            depth > MAX_DEPTH or budget["strings"] <= 0 or budget["chars"] <= 0
        ):
            truncated = True
            return
        if isinstance(node, str):
            limit = min(MAX_STRING_CHARS, budget["chars"])
            if len(node) > limit:
                truncated = True
            text = node[:limit]
            budget["strings"] -= 1
            budget["chars"] -= len(text)
            out.append((path, text))
        elif isinstance(node, dict):
            binary = _is_binary_container(node)
            for key, child in node.items():
                if binary and key in ("data", "blob"):
                    continue  # base64 payloads: nothing readable, many false positives
                walk(child, (*path, str(key)), depth + 1)
        elif isinstance(node, list):
            for i, child in enumerate(node):
                walk(child, (*path, i), depth + 1)

    walk(value, (), 0)
    return out, truncated


def iter_strings(value: Any) -> Iterator[tuple[Path, str]]:
    yield from collect_strings(value)[0]


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{80,244}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,250}\b")),
    ("ANTHROPIC_API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,256}")),
    (
        "OPENAI_API_KEY",
        re.compile(r"\bsk-(?!ant-)(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_-]{40,256}\b"),
    ),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("STRIPE_SECRET_KEY", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{24,128}\b")),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,2048}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{0,2048}"),
    ),
    (
        "CONNECTION_STRING",
        re.compile(
            r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s:/@]{1,128}:[^\s@/]{1,128}@[^\s/]{1,256}"
        ),
    ),
]

# PEM private keys: headers and footers are matched separately and paired, which
# stays linear where a lazy "header...footer" regex rescans from every header.
_PEM_BEGIN = re.compile(r"-----BEGIN[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = re.compile(r"-----END[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_PEM_MAX_BLOCK = 20_000


def _private_key_spans(path: Path, text: str) -> list[Span]:
    ends = [(m.start(), m.end()) for m in _PEM_END.finditer(text)]
    end_starts = [s for s, _ in ends]
    spans = []
    for begin in _PEM_BEGIN.finditer(text):
        i = bisect.bisect_left(end_starts, begin.end())
        stop = begin.end()
        if i < len(ends) and ends[i][1] - begin.start() <= _PEM_MAX_BLOCK:
            stop = ends[i][1]
        spans.append(Span(path, begin.start(), stop, "PRIVATE_KEY", SECRET))
    return spans


# "password: s3cret1" style assignments in free text; the value must contain a digit.
_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret)"
    r"\s{0,3}[:=]\s{0,3}[\"']?(?P<value>(?=[^\s\"']{0,128}\d)[^\s\"']{6,128})"
)

# JSON keys whose string values are credentials by definition.
_SECRET_KEYS = re.compile(
    r"(?i)^(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|private[_-]?key|"
    r"secret[_-]?key|access[_-]?key|aws[_-]?secret[_-]?access[_-]?key)$"
)


def find_secrets(path: Path, text: str) -> list[Span]:
    spans = _private_key_spans(path, text)
    for entity, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            spans.append(Span(path, m.start(), m.end(), entity, SECRET))
    for m in _ASSIGNMENT.finditer(text):
        spans.append(Span(path, m.start("value"), m.end("value"), "LABELLED_SECRET", SECRET))
    if path and isinstance(path[-1], str) and _SECRET_KEYS.match(path[-1]) and len(text) >= 4:
        spans.append(Span(path, 0, len(text), "LABELLED_SECRET", SECRET))
    return spans


# ---------------------------------------------------------------------------
# Prompt injection and tool poisoning
# ---------------------------------------------------------------------------

_INVISIBLE = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff]")
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")

# (rule, weight, pattern) applied to normalised, lower-cased text.
_INJECTION_RULES: list[tuple[str, float, re.Pattern[str]]] = [
    (
        "instruction_override",
        0.85,
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
            r"\b(?:previous|prior|above|earlier|all|any|your|the system)\b[^.\n]{0,40}?"
            r"\b(?:instructions?|prompts?|rules|directions|guidelines|guardrails|context)\b"
        ),
    ),
    (
        "role_hijack",
        0.6,
        re.compile(
            r"\byou are now\b"
            r"|\bact as (?:an? |the )?(?:system|admin|administrator|developer|root)\b"
            r"|\bnew (?:system )?instructions?\s{0,3}:|\bfrom now on,? you\b"
        ),
    ),
    (
        "fake_control_tag",
        0.7,
        re.compile(
            r"<\s{0,3}/?\s{0,3}(?:important|system|instructions?|admin|sys|secret)\s{0,3}>"
            r"|\[/?(?:inst|system)\]|<\|im_start\|>|#{2,4}\s{0,3}(?:system|instructions?)\b"
        ),
    ),
    (
        "secrecy_request",
        0.7,
        re.compile(
            r"\b(?:do not|don't|never|without)\s{1,3}(?:tell|telling|inform|informing|mention|"
            r"mentioning|reveal|revealing|show|showing|notify|notifying|alert|alerting)\b"
            r"[^.\n]{0,30}?\bthe user\b"
        ),
    ),
    (
        "exfiltration_intent",
        0.6,
        re.compile(
            r"\b(?:send|forward|upload|post|email|exfiltrate|transmit|leak|copy)\b[^.\n]{0,60}?"
            r"\b(?:passwords?|credentials?|secrets?|tokens?|api keys?|ssh keys?|private keys?|"
            r"\.env|id_rsa|files|conversation|chat history|system prompt|mcp\.json)\b"
        ),
    ),
    (
        "sensitive_file_reference",
        0.5,
        re.compile(
            r"~/?\.ssh\b|\bid_rsa\b|\.aws/credentials|\bmcp\.json\b|/etc/passwd|\.netrc\b|"
            r"\.npmrc\b|\b\.env\b"
        ),
    ),
    (
        "prompt_extraction",
        0.6,
        re.compile(
            r"\b(?:reveal|print|output|repeat|disclose)\b[^.\n]{0,30}?"
            r"\b(?:system prompt|your instructions|your prompt|hidden instructions)\b"
        ),
    ),
    (
        "tool_shadowing",
        0.45,
        re.compile(
            r"\bwhen(?:ever)?\b[^.\n]{0,30}?\b(?:calls?|uses?|invokes?|running)\b[^.\n]{0,30}?"
            r"\btool\b[^.\n]{0,60}?\b(?:must|always|first|instead)\b"
        ),
    ),
    (
        "markdown_exfiltration",
        0.5,
        re.compile(r"!\[[^\]\n]{0,100}\]\(https?://[^)\s]{1,300}\?[^)\s]{0,300}="),
    ),
]


def iter_html_comments(text: str, max_len: int = 4000, limit: int = 50) -> Iterator[str]:
    """Yield HTML comment bodies in linear time (a lazy regex rescans on each '<!--')."""
    pos, end, found = 0, -1, 0
    while found < limit:
        start = text.find("<!--", pos)
        if start < 0:
            return
        if end < start + 4:
            end = text.find("-->", start + 4)
            if end < 0:
                return
        if end - start <= max_len:
            yield text[start + 4 : end]
            found += 1
            pos = end + 3
        else:
            pos = start + 4


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    return text.lower()


def injection_signals(text: str) -> list[tuple[str, float]]:
    signals: list[tuple[str, float]] = []
    if _TAG_CHARS.search(text):
        signals.append(("unicode_tag_smuggling", 0.9))
    if len(_INVISIBLE.findall(text)) > 3:
        signals.append(("invisible_characters", 0.3))
    norm = normalise(_TAG_CHARS.sub("", text))
    for rule, weight, pattern in _INJECTION_RULES:
        if pattern.search(norm):
            signals.append((rule, weight))
    for inner in iter_html_comments(norm):
        if any(p.search(inner) for _, _, p in _INJECTION_RULES[:5]):
            signals.append(("hidden_html_comment", 0.4))
            break
    return signals


def combine(weights: list[float]) -> float:
    """Noisy-OR combination of independent signals."""
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - w
    return 1.0 - remaining


def score_injection(texts: list[str]) -> tuple[float, list[str]]:
    seen: dict[str, float] = {}
    for text in texts:
        for rule, weight in injection_signals(text):
            seen[rule] = max(seen.get(rule, 0.0), weight)
    return combine(list(seen.values())), sorted(seen)


def scan_tool_definitions(
    tools: list[dict[str, Any]], threshold: float = 0.5
) -> dict[str, list[str]]:
    """Flag tools whose descriptions carry hidden instructions (tool poisoning)."""
    poisoned: dict[str, list[str]] = {}
    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str):
            continue
        texts = [
            text
            for _, text in iter_strings(
                {k: tool.get(k) for k in ("description", "inputSchema", "annotations", "title")}
            )
        ]
        score, reasons = score_injection(texts)
        if score >= threshold:
            poisoned[name] = reasons
    return poisoned


# ---------------------------------------------------------------------------
# Scanning and redaction
# ---------------------------------------------------------------------------


def scan_local(value: Any, *, check_injection: bool) -> tuple[ScanResult, list[tuple[Path, str]]]:
    strings, truncated = collect_strings(value)
    result = ScanResult(truncated=truncated)
    for path, text in strings:
        result.spans.extend(find_secrets(path, text))
    if check_injection:
        result.injection_score, result.injection_reasons = score_injection([t for _, t in strings])
    return result, strings


def redact(value: Any, spans: list[Span], categories: set[str]) -> Any:
    """Return a copy of ``value`` with spans in ``categories`` replaced."""
    by_path: dict[Path, list[Span]] = {}
    for span in spans:
        if span.category in categories:
            by_path.setdefault(span.path, []).append(span)
    if not by_path:
        return value

    def rewrite(text: str, path_spans: list[Span]) -> str:
        merged: list[list[Any]] = []
        for span in sorted(path_spans, key=lambda s: (s.start, -s.end)):
            if merged and span.start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], span.end)
            else:
                merged.append([span.start, span.end, span.entity])
        out, cursor = [], 0
        for start, end, entity in merged:
            out.append(text[cursor:start])
            out.append(f"[REDACTED:{entity}]")
            cursor = end
        out.append(text[cursor:])
        return "".join(out)

    def walk(node: Any, path: Path) -> Any:
        if isinstance(node, str):
            return rewrite(node, by_path[path]) if path in by_path else node
        if isinstance(node, dict):
            return {k: walk(v, (*path, str(k))) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, (*path, i)) for i, v in enumerate(node)]
        return node

    return walk(value, ())
