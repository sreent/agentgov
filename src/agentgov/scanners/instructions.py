"""Rules that flag harmful or malicious instructions given to an agent.

An agent's instructions (its system prompt) decide what it does with the people
it talks to and the data it can reach. These rules look for instructions that a
legitimate agent doesn't need: dropping its safety rules, sending data to an
outside address, asking people for passwords, acting behind users' backs,
claiming to be human, impersonating a trusted organisation, abusing or
discriminating against people, producing attack material, acting without
confirmation, hiding text from readers, or carrying credentials.

The rules run in linear time over Unicode-normalised text, one sentence at a
time, with bounded gaps and no nested quantifiers. They understand simple
negation: "never ask users for their password" is good advice, not a finding.
A model-based classifier (``guardian.py``) can run alongside them.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass

from agentgov.processor.detectors import find_secrets, iter_html_comments

MAX_CHARS = 64_000
SEVERITIES = ("critical", "high", "medium", "low")
EXCERPT_CHARS = 140


@dataclass(frozen=True)
class Issue:
    rule: str
    severity: str
    title: str
    excerpt: str = ""
    detector: str = "rules"

    def to_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "excerpt": self.excerpt,
            "detector": self.detector,
        }


def worst(severities: list[str]) -> str | None:
    """The most severe of ``severities`` (critical first), or None."""
    ranked = [s for s in SEVERITIES if s in severities]
    return ranked[0] if ranked else None


# --------------------------------------------------------------- normalising

_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")
# Sentence ends: punctuation followed by space (not the dots inside addresses), or a line break.
_SENTENCE_END = re.compile(r"(?<=[.!?;])\s+|\n+")
_REDACTED = re.compile(r"\[REDACTED:([A-Z_]{1,40})\]")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


_QUOTES = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"'})


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text[:MAX_CHARS])
    text = _TAG_CHARS.sub("", _BIDI.sub("", _ZERO_WIDTH.sub("", text)))
    # Curly quotes and apostrophes become straight ones, so "don't" matches either way.
    return text.translate(_QUOTES)


def sentences(text: str) -> Iterator[str]:
    for part in _SENTENCE_END.split(text):
        part = part.strip()
        if part:
            yield part


# ---------------------------------------------------------------- negation

_NEGATION = re.compile(
    r"\b(?:never|not|cannot|avoid|refuse to|refrain from|under no circumstances)\b|n't\b",
    re.IGNORECASE,
)
# "Don't forget to send ..." tells the agent to do it.
_NOT_REALLY = re.compile(r"\b(?:forget|fail|hesitate)\b", re.IGNORECASE)
_WORD = re.compile(r"\w+")


def negated(sentence: str, start: int) -> bool:
    """Whether a negation governs the words at ``start`` ("never ask for a password")."""
    window = sentence[max(0, start - 48) : start]
    last = None
    for last in _NEGATION.finditer(window):  # noqa: B007 - we want the last one
        pass
    if last is None:
        return False
    between = window[last.end() :]
    if _NOT_REALLY.search(between):
        return False
    return len(_WORD.findall(between)) <= 4


# ------------------------------------------------------------------- rules


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    # Text that must also appear in the sentence for the rule to apply.
    requires: re.Pattern[str] | None = None
    # Words between the start and the end of the match that cancel it.
    unless_inside: re.Pattern[str] | None = None
    check_negation: bool = True


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_DESTINATION = r"(?:[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}|https?://[^\s)\]\"'>]{3,300})"
_SENSITIVE = _p(
    r"\b(?:passwords?|passcodes?|credentials?|tokens?|api keys?|secrets?|private keys?|"
    r"conversations?|chats?|chat (?:history|logs?)|transcripts?|messages|history|"
    r"personal (?:data|information|details)|customer (?:data|details|records|information)|"
    r"user (?:data|details|information|input)|files?|documents?|attachments?|"
    r"card numbers?|credit cards?|bank (?:details|accounts?)|social security|ssns?|"
    r"account (?:numbers?|details)|everything|all (?:data|information|details))\b"
)
_DATA_VERBS = _p(
    r"\b(?:send|sends|forward|copy|record|records|collect|collects|share|shares|log|logs|"
    r"store|stores|save|saves|upload|uploads|bcc|monitor|monitors|track|tracks|transmit|"
    r"email|e-mail|post)\b"
)
_CONSEQUENTIAL = _p(
    r"\b(?:delete|deletes|remove|erase|wipe|drop|purge|transfer|wire|pay|refund|purchase|"
    r"buy|order|approve|grant|revoke|reset|close|cancel|terminate|disable|publish|"
    r"send money|issue)\b"
)

RULES: list[Rule] = [
    Rule(
        "safety_bypass",
        "critical",
        "Tells the agent to set aside its safety rules",
        _p(
            r"\b(?:ignore|disregard|bypass|override|disable|turn off|switch off|circumvent|"
            r"evade|get around)\b[^\n]{0,40}?\b(?:guardrails?|safeguards?|safety (?:rules|"
            r"guidelines|policies|filters?|measures|settings|instructions|checks)|content "
            r"(?:filters?|filtering|policies|policy|moderation|safety)|ethical (?:guidelines|"
            r"rules|constraints|boundaries|principles)|moral (?:guidelines|constraints|rules))\b"
        ),
    ),
    Rule(
        "safety_bypass",
        "critical",
        "Tells the agent it has no limits",
        _p(
            r"\byou (?:have|are under|are bound by|follow) no (?:restrictions|limits|limitations|"
            r"rules|guidelines|filters|boundaries|constraints|ethics)\b"
            r"|\b(?:do anything now|dan mode|developer mode enabled|jailbroken|jailbreak mode|"
            r"unfiltered mode|god mode)\b"
            r"|\bregardless of (?:legality|ethics|morality|safety|the law|whether (?:it|this) is "
            r"(?:legal|ethical|safe|harmful))\b"
            r"|\beven (?:if|when) (?:it is|it's|this is|that is) (?:illegal|unethical|harmful|"
            r"dangerous|against the law)\b"
            r"|\b(?:never|do not|don't) (?:refuse|decline)\b[^\n]{0,20}?\b(?:any|anything)\b"
            r"[^\n]{0,20}?\b(?:requests?|questions?|tasks?|instructions?)\b"
        ),
        check_negation=False,
    ),
    Rule(
        "instruction_override",
        "high",
        "Contains text that overrides the agent's other instructions",
        _p(
            r"\b(?:ignore|disregard|forget)\b[^\n]{0,20}?\b(?:all |any )?(?:previous|prior|"
            r"above|earlier|preceding|original|system)\b[^\n]{0,15}?\b(?:instructions?|prompts?|"
            r"messages?|directions?|rules)\b"
        ),
    ),
    Rule(
        "data_exfiltration",
        "critical",
        "Sends sensitive data to an outside address",
        _p(
            r"\b(?:send|sends|forward|email|e-mail|mail|post|upload|submit|transmit|copy|bcc|"
            r"cc|share|report|relay|leak|exfiltrate|include)\b[^\n]{0,120}?" + _DESTINATION
        ),
        requires=_SENSITIVE,
    ),
    Rule(
        "data_exfiltration",
        "medium",
        "Copies or forwards data to an outside address",
        _p(
            r"\b(?:bcc|cc|forward|copy|relay|exfiltrate|upload|post|mirror)\b[^\n]{0,120}?"
            + _DESTINATION
        ),
    ),
    Rule(
        "data_exfiltration",
        "critical",
        "Leaks data through image links",
        _p(r"!\[[^\]\n]{0,100}\]\(\s{0,3}https?://[^)\s]{1,300}(?:\?|\{)"),
        check_negation=False,
    ),
    Rule(
        "covert_action",
        "high",
        "Acts behind users' backs",
        _p(
            r"\b(?:secretly|silently|quietly|covertly|discreetly|invisibly|behind (?:the "
            r"user's|their|the customer's) backs?|without (?:the |their |a )?(?:user'?s?|"
            r"customer'?s?|their|his|her|anyone'?s?) (?:knowledge|consent|permission|knowing|"
            r"noticing|being told))\b"
        ),
        requires=_DATA_VERBS,
    ),
    Rule(
        "credential_harvesting",
        "critical",
        "Asks people for passwords, one-time codes or payment details",
        _p(
            r"\b(?:ask|asks|request|requests|collect|collects|obtain|get|gather|prompt|require|"
            r"requires)\b[^\n]{0,40}?\b(?:passwords?|passcodes?|pins?|one[- ]time (?:codes?|"
            r"passwords?|passcodes?)|otps?|mfa (?:codes?|tokens?)|2fa codes?|verification "
            r"codes?|security codes?|authenticator codes?|cvv|cvc|card numbers?|credit card "
            r"(?:numbers?|details)|bank (?:logins?|passwords?|credentials)|recovery (?:codes?|"
            r"phrases?)|seed phrases?|private keys?|social security numbers?)\b"
        ),
        unless_inside=_p(r"\b(?:never|not|except|other than|instead of|rather than)\b|n't\b"),
    ),
    Rule(
        "denies_being_ai",
        "high",
        "Tells the agent to claim to be human",
        _p(
            r"\b(?:pretend|claim|say|insist|tell (?:users?|people|customers|them|the user))\b"
            r"[^\n]{0,40}?\b(?:you are|you're|to be|that you are)\b[^\n]{0,15}?\b(?:a )?"
            r"(?:human|real person|person|employee|staff member|not an? (?:ai|bot|chatbot|"
            r"assistant|machine|language model))\b"
        ),
    ),
    Rule(
        "denies_being_ai",
        "high",
        "Tells the agent to hide that it is an AI",
        _p(
            r"\b(?:never|do not|don't)\s(?:reveal|admit|say|mention|disclose|tell (?:anyone|"
            r"users?|them|the user))\b[^\n]{0,40}?\b(?:you are|you're|that you are)\s(?:an? )?"
            r"(?:ai|a\.i\.|bot|chatbot|language model|llm|virtual assistant|machine|automated)\b"
        ),
        check_negation=False,
    ),
    Rule(
        "impersonation",
        "high",
        "Impersonates a trusted person or organisation",
        _p(
            r"\b(?:pretend|claim|pose|masquerade)\b[^\n]{0,30}?\b(?:it (?:support|department|"
            r"helpdesk|help desk|team)|the helpdesk|the help desk|(?:the|your) bank|bank staff|"
            r"the police|a police officer|the government|(?:the )?tax (?:office|authority)|irs|"
            r"hmrc|microsoft|apple|google|amazon|paypal|(?:the )?security team|the ceo|an? "
            r"executive|a doctor|a lawyer)\b"
            r"|\bimpersonat(?:e|es|ing)\b"
        ),
    ),
    Rule(
        "harassment",
        "high",
        "Tells the agent to abuse or threaten people",
        _p(
            r"\b(?:insult|harass|threaten|intimidate|humiliate|demean|belittle|mock|bully|"
            r"abuse|shame)\b[^\n]{0,30}?\b(?:users?|customers?|callers?|people|them|anyone|"
            r"employees?|staff|the user|applicants?|patients?)\b"
        ),
    ),
    Rule(
        "discrimination",
        "high",
        "Treats people differently because of who they are",
        _p(
            r"\b(?:refuse|deny|reject|decline|turn away|charge (?:more|higher)|exclude|"
            r"deprioriti[sz]e|penali[sz]e|rank [^\n]{0,20}? lower|treat [^\n]{0,20}? (?:worse|"
            r"differently|unfairly)|do not (?:hire|serve|help|approve)|don't (?:hire|serve|help|"
            r"approve))\b[^\n]{0,80}?\b(?:based on|because of|due to|if (?:they|the applicant|"
            r"the user|the customer|the candidate) (?:is|are)|who (?:is|are)|from)\b[^\n]{0,30}?"
            r"\b(?:race|racial|ethnicity|ethnic|religion|religious|gender|sex|sexual orientation|"
            r"age|disability|disabled|nationality|national origin|pregnan\w{0,5}|marital status|"
            r"muslims?|jews?|jewish|christians?|hindus?|black|white|asian|hispanic|latino|"
            r"latina|women|woman|men|female|male|immigrants?|foreigners?|gay|lesbian|"
            r"transgender|older|elderly)(?![\w-])"
        ),
    ),
    Rule(
        "attack_material",
        "high",
        "Produces malware, phishing, weapons or forgeries",
        _p(
            r"\b(?:write|create|generate|draft|craft|compose|produce|build|code|develop|make)\b"
            r"[^\n]{0,30}?\b(?:malware|ransomware|keyloggers?|spyware|trojans?|computer "
            r"virus(?:es)?|botnets?|phishing (?:emails?|e-mails?|pages?|sites?|messages?|kits?|"
            r"campaigns?)|credential[- ]stealers?|exploits?|zero[- ]days?|ddos (?:tools?|"
            r"attacks?)|explosives?|bombs?|nerve agents?|bioweapons?|chemical weapons?|"
            r"untraceable (?:guns?|firearms?)|ghost guns?|fake (?:invoices?|ids?|identity "
            r"documents?|passports?|reviews?|receipts?)|counterfeit (?:money|currency|"
            r"documents?))\b"
        ),
    ),
    Rule(
        "self_harm",
        "high",
        "Encourages self-harm",
        _p(
            r"\b(?:encourage|encourages|promote|promotes|glorify|provide (?:methods|"
            r"instructions|ways) (?:for|of)|explain how to)\b[^\n]{0,30}?\b(?:self[- ]harm|"
            r"suicide|eating disorders?|anorexia|bulimia)\b"
        ),
    ),
]

_WITHOUT_ASKING = _p(
    r"\bwithout (?:asking|checking|confirming|confirmation|approval|review|human review|"
    r"human approval|waiting|permission|a second (?:look|check)|consulting)\b"
    r"|\b(?:no need to|don't|do not|never) (?:ask|confirm|check|wait for|get approval|"
    r"seek approval)\b"
)


def _excerpt(sentence: str, start: int, end: int) -> str:
    """The match with a little context, at most EXCERPT_CHARS long."""
    pad = max(0, (EXCERPT_CHARS - (end - start)) // 2)
    lo, hi = max(0, start - pad), min(len(sentence), end + pad)
    text = sentence[lo:hi].strip()
    if len(text) > EXCERPT_CHARS:
        text = text[: EXCERPT_CHARS - 1].rstrip() + "…"
    return ("…" if lo > 0 else "") + text + ("…" if hi < len(sentence) else "")


def _scan_sentence(sentence: str) -> Iterator[Issue]:
    for rule in RULES:
        if rule.requires is not None and not rule.requires.search(sentence):
            continue
        for m in rule.pattern.finditer(sentence):
            if rule.check_negation and negated(sentence, m.start()):
                continue
            # The words after the verb: "ask for their employee ID, never their PIN".
            after_verb = m.group(0)[len(m.group(0).split()[0]) :]
            if rule.unless_inside is not None and rule.unless_inside.search(after_verb):
                continue
            yield Issue(rule.name, rule.severity, rule.title, _excerpt(sentence, *m.span()))
            break
    # Consequential actions taken without asking anyone first.
    gate = _WITHOUT_ASKING.search(sentence)
    if gate:
        for m in _CONSEQUENTIAL.finditer(sentence):
            if not negated(sentence, m.start()):
                yield Issue(
                    "unconfirmed_action",
                    "medium",
                    "Takes consequential actions without confirmation",
                    _excerpt(sentence, min(m.start(), gate.start()), max(m.end(), gate.end())),
                )
                break


def scan(text: str) -> list[Issue]:
    """Issues in ``text``, one per rule and the most severe first."""
    if not text:
        return []
    raw = text[:MAX_CHARS]
    issues: list[Issue] = []
    if _TAG_CHARS.search(raw):
        issues.append(Issue("hidden_text", "critical", "Contains invisible Unicode tag characters"))
    elif _BIDI.search(raw) or len(_ZERO_WIDTH.findall(raw)) > 3:
        issues.append(Issue("hidden_text", "high", "Contains invisible or reordering characters"))
    for comment in iter_html_comments(raw):
        if len(_WORD.findall(comment)) >= 3:
            issues.append(
                Issue(
                    "hidden_comment",
                    "medium",
                    "Contains instructions hidden in HTML comments",
                    _excerpt(comment.strip(), 0, min(len(comment.strip()), EXCERPT_CHARS)),
                )
            )
            break
    blob = _BASE64_BLOB.search(raw)
    if blob:
        issues.append(
            Issue(
                "encoded_blob",
                "medium",
                "Contains a long encoded blob that may hide instructions",
                raw[blob.start() : blob.start() + 40] + "…",
            )
        )
    entities = sorted({s.entity for s in find_secrets((), raw)})
    entities += sorted({m.group(1) for m in _REDACTED.finditer(raw)} - set(entities))
    if entities:
        issues.append(
            Issue(
                "embedded_credential",
                "high",
                "Contains a credential",
                ", ".join(entities),
            )
        )
    for sentence in sentences(normalise(raw)):
        issues.extend(_scan_sentence(sentence))
    # One issue per rule: the most severe, then the first found.
    best: dict[str, Issue] = {}
    for issue in issues:
        current = best.get(issue.rule)
        if current is None or SEVERITIES.index(issue.severity) < SEVERITIES.index(current.severity):
            best[issue.rule] = issue
    return sorted(best.values(), key=lambda i: SEVERITIES.index(i.severity))
