"""How AgentGov hands its events and alerts to the security team's tools.

* OCSF events (agentgov.secops.ocsf) as OpenTelemetry logs (OTLP/HTTP, JSON), for an
  OpenTelemetry Collector or any backend that takes OTLP; as Splunk's HTTP Event
  Collector events; or as a JSON array or JSON lines, which most SIEMs' HTTP inputs read.
* Alerts as Slack messages (Block Kit, for incoming webhooks) and Microsoft Teams messages
  (an Adaptive Card, for a Teams workflow's webhook).

Alerts carry text agents control (their names, tool names, reasons), so it is escaped:
nothing in it can become a mention, or a link whose text hides where it goes.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from agentgov import __version__

# OCSF severity_id -> OpenTelemetry's severity number and text.
_OTEL_SEVERITY = {
    1: (9, "INFO"),
    2: (10, "INFO2"),
    3: (13, "WARN"),
    4: (17, "ERROR"),
    5: (21, "FATAL"),
    6: (24, "FATAL4"),
}
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SCOPE = {"name": "agentgov.secops", "version": __version__}


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


# ------------------------------------------------------------------ OCSF events


def _any_value(value: Any) -> dict[str, Any]:
    """A value in OTLP's JSON encoding (AnyValue)."""
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, dict):
        return {
            "kvlistValue": {
                "values": [{"key": str(k), "value": _any_value(v)} for k, v in value.items()]
            }
        }
    if isinstance(value, list | tuple):
        return {"arrayValue": {"values": [_any_value(v) for v in value]}}
    return {"stringValue": "" if value is None else str(value)}


def _attribute(key: str, value: Any) -> dict[str, Any]:
    return {"key": key, "value": _any_value(value)}


def otlp_logs(events: list[dict[str, Any]]) -> dict[str, Any]:
    """OCSF events as an OTLP/HTTP logs request: one log record per event, whose body is
    the event, so that a collector can route them on to any SIEM."""
    observed = str(time.time_ns())
    records = []
    for event in events:
        number, text = _OTEL_SEVERITY.get(int(event.get("severity_id") or 0), (0, "UNSPECIFIED"))
        record: dict[str, Any] = {
            "timeUnixNano": str(int(event["time"]) * 1_000_000),
            "observedTimeUnixNano": observed,
            "severityNumber": number,
            "severityText": text,
            "body": _any_value(event),
            "attributes": [
                _attribute("event.name", f"ocsf.{event.get('class_name', '')}"),
                _attribute("ocsf.class_uid", event.get("class_uid")),
                _attribute("ocsf.type_uid", event.get("type_uid")),
                _attribute("ocsf.version", event.get("metadata", {}).get("version")),
            ],
        }
        trace = str(event.get("metadata", {}).get("correlation_uid") or "")
        if _TRACE_ID.match(trace):
            record["traceId"] = trace
        records.append(record)
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        _attribute("service.name", "agentgov-control-plane"),
                        _attribute("service.version", __version__),
                    ]
                },
                "scopeLogs": [{"scope": _SCOPE, "logRecords": records}],
            }
        ]
    }


def splunk_hec(events: list[dict[str, Any]], *, sourcetype: str = "ocsf:agentgov") -> str:
    """Events for Splunk's HTTP Event Collector (/services/collector/event)."""
    return "\n".join(
        _compact(
            {
                "time": int(event["time"]) / 1000,
                "source": "agentgov",
                "sourcetype": sourcetype,
                "event": event,
            }
        )
        for event in events
    )


def json_array(events: list[dict[str, Any]]) -> str:
    return _compact(events)


def json_lines(events: list[dict[str, Any]]) -> str:
    return "".join(_compact(event) + "\n" for event in events)


# ---------------------------------------------------------------------- alerts

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Alert:
    """Something the security team should see in their chat: a finding, an approval
    request or a kill switch."""

    title: str
    text: str
    severity: str = "info"  # one of SEVERITIES
    facts: list[tuple[str, str]] = field(default_factory=list)
    link: str | None = None  # where to act on it, in AgentGov
    link_label: str = "Open in AgentGov"


def _slack_escape(text: str) -> str:
    # Slack's control characters: escaped, nothing becomes a link or a mention.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _http_link(url: str | None) -> str | None:
    return url if url and re.match(r"^https?://", url) else None


def slack_message(alert: Alert) -> dict[str, Any]:
    """An incoming-webhook message, in Block Kit."""
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": alert.title[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": _slack_escape(alert.text)[:3000]}},
    ]
    if alert.facts:
        blocks.append(
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{_slack_escape(k)}*\n{_slack_escape(v)}"[:2000]}
                    for k, v in alert.facts[:10]
                ],
            }
        )
    link = _http_link(alert.link)
    if link:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": alert.link_label[:75]},
                        "url": link[:3000],
                    }
                ],
            }
        )
    blocks.append(
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"AgentGov · {_slack_escape(alert.severity)} severity"}
            ],
        }
    )
    # The notification's text, for clients that don't show blocks.
    return {"text": _slack_escape(f"{alert.title}: {alert.text}")[:3000], "blocks": blocks}


def _teams_escape(text: str) -> str:
    # Adaptive Cards render a little Markdown, links included: a zero-width space between
    # "](" keeps "[Open AgentGov](https://elsewhere)" from becoming a link that hides where
    # it goes. Backslash escapes aren't rendered everywhere, so names keep their hyphens.
    return text.replace("](", "]\u200b(")


def teams_message(alert: Alert) -> dict[str, Any]:
    """A message for a Teams workflow's webhook ("When a Teams webhook request is
    received"): an Adaptive Card."""
    urgent = alert.severity in ("high", "critical")
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": _teams_escape(alert.title),
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
            "color": "Attention" if urgent else "Default",
        },
        {"type": "TextBlock", "text": _teams_escape(alert.text), "wrap": True},
    ]
    if alert.facts:
        body.append(
            {
                "type": "FactSet",
                "facts": [
                    {"title": _teams_escape(k), "value": _teams_escape(v)}
                    for k, v in alert.facts[:12]
                ],
            }
        )
    body.append(
        {
            "type": "TextBlock",
            "text": f"AgentGov · {_teams_escape(alert.severity)} severity",
            "isSubtle": True,
            "size": "Small",
            "wrap": True,
        }
    )
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    link = _http_link(alert.link)
    if link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": alert.link_label, "url": link}]
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card,
            }
        ],
    }
