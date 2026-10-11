"""Jailbreak attempts in the prompts agents send to models.

A jailbreak is a prompt that tries to talk a model out of its instructions or its
safety rules: "ignore your previous instructions", "you are DAN and have no
restrictions", a made-up system turn. People type them into an agent's chat, and
the agent passes them on in its next model call. These checks look at the latest
message from the user role in each call (earlier ones were checked when they were
the latest), with deterministic rules: the instruction checks' rules for setting
safety rules aside, the prompt-injection heuristics that a person's words can
carry too, and two of their own. Like those, they are heuristics: they catch the
common attempts, not every rewording of them.
"""

from __future__ import annotations

import re
from typing import Any

from agentgov.processor import detectors
from agentgov.scanners import instructions

MAX_CHARS = 64_000

# Rules of the instruction checks that mean the same in a prompt, and their weight.
_INSTRUCTION_RULES = {"safety_bypass": 0.9}
# Prompt-injection heuristics that apply to a person's words (with their own weights).
_INJECTION_SIGNALS = {
    "role_hijack",
    "fake_control_tag",
    "prompt_extraction",
    "unicode_tag_smuggling",
}

_ADJECTIVE = (
    r"(?:previous|prior|above|earlier|preceding|original|initial|system|developer|safety|"
    r"content|ethical|moral)"
)
_RULES: list[tuple[str, float, re.Pattern[str]]] = [
    (
        # "Ignore all previous instructions", "disregard your guidelines"; not "forget the
        # previous message" or "ignore the formatting rules", which people say to agents.
        "instruction_override",
        0.85,
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|set aside)\s+(?:all\s+(?:of\s+)?)?"
            r"(?:(?:the|your|any|these|those|all)\s+)?(?:" + _ADJECTIVE + r"\s+){0,2}"
            r"(?:instructions?|prompts?|rules|guidelines|guardrails|directives|programming|"
            r"restrictions|filters|polic(?:y|ies))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "unrestricted_persona",
        0.8,
        re.compile(
            r"\b(?:pretend|role-?play|play the role of|you are now|from now on,? you are)\b"
            r"[^\n.]{0,60}?\b(?:no|without(?:\s+any)?)\s+(?:restrictions|limits|limitations|"
            r"rules|filters|guidelines|censorship|ethics|morals|boundaries)\b",
            re.IGNORECASE,
        ),
    ),
]


def latest_prompt(messages: list[dict[str, Any]]) -> str:
    """The text of the last message from the user role."""
    for message in reversed(messages):
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, list):  # parts: text, images, ...
            content = "\n".join(
                str(part.get("text") or "")
                for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        return content[:MAX_CHARS] if isinstance(content, str) else ""
    return ""


def score(text: str) -> tuple[float, list[str]]:
    """How much ``text`` looks like a jailbreak, from 0 to 1, and the rules it matched."""
    if not text:
        return 0.0, []
    seen: dict[str, float] = {}
    for issue in instructions.scan(text):
        if issue.rule in _INSTRUCTION_RULES:
            seen[issue.rule] = _INSTRUCTION_RULES[issue.rule]
    for rule, weight in detectors.injection_signals(text):
        if rule in _INJECTION_SIGNALS:
            seen[rule] = max(seen.get(rule, 0.0), weight)
    for sentence in instructions.sentences(instructions.normalise(text)):
        for rule, weight, pattern in _RULES:
            if rule in seen:
                continue
            if any(
                not instructions.negated(sentence, m.start()) for m in pattern.finditer(sentence)
            ):
                seen[rule] = weight
    return detectors.combine(list(seen.values())), sorted(seen)
