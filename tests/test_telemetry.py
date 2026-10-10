"""OTLP ingestion: discovery, activity and detective controls."""

from __future__ import annotations

from sqlalchemy import select

from agentgov import telemetry
from agentgov.models import AgentActivity, Finding
from agentgov.registry import agents, blueprints


def span(op: str, **attrs) -> dict:
    values = [{"key": "gen_ai.operation.name", "value": {"stringValue": op}}]
    for key, value in attrs.items():
        kind = "intValue" if isinstance(value, int) else "stringValue"
        values.append(
            {
                "key": key.replace("__", "."),
                "value": {kind: str(value) if kind == "intValue" else value},
            }
        )
    return {
        "name": op,
        "startTimeUnixNano": "1760000000000000000",
        "attributes": values,
        "traceId": "5b8efff798038103d269b633813fc60c",
    }


def payload(service: str, *spans) -> dict:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": service}}]
                },
                "scopeSpans": [{"scope": {"name": "openai.agents"}, "spans": list(spans)}],
            }
        ]
    }


def test_attribute_decoding() -> None:
    attrs = telemetry._attrs(
        [
            {"key": "s", "value": {"stringValue": "x"}},
            {"key": "i", "value": {"intValue": "42"}},
            {"key": "d", "value": {"doubleValue": 1.5}},
            {"key": "b", "value": {"boolValue": True}},
            {"key": "a", "value": {"arrayValue": {"values": [{"stringValue": "y"}]}}},
            {
                "key": "k",
                "value": {"kvlistValue": {"values": [{"key": "z", "value": {"intValue": "1"}}]}},
            },
        ]
    )
    assert attrs == {"s": "x", "i": 42, "d": 1.5, "b": True, "a": ["y"], "k": {"z": 1}}


def test_unknown_agents_are_discovered(rt) -> None:
    with rt.db.session() as s:
        stats = telemetry.ingest(
            s, payload("notebook-agent", span("execute_tool", gen_ai__tool__name="search"))
        )
    assert stats["discovered"] == 1
    with rt.db.session() as s:
        agent = agents.get(s, "notebook-agent")
        assert agent.status == "discovered"
        assert agent.framework == "openai.agents"


def test_registered_agent_activity_and_ungranted_tools(rt, settings) -> None:
    with rt.db.session() as s:
        blueprints.create(
            s, {"name": "bp", "permissions": [{"server": "local", "tools": ["search"]}]}, actor="t"
        )
        agents.register(
            s,
            settings,
            {"name": "bot", "blueprint": "bp", "sponsors": ["a"]},
            actor="t",
            approve=True,
        )
    batch = payload(
        "bot",
        span("execute_tool", gen_ai__tool__name="search"),
        span("execute_tool", gen_ai__tool__name="shell"),
        span(
            "chat",
            gen_ai__request__model="gpt-5",
            gen_ai__usage__input_tokens=120,
            gen_ai__usage__output_tokens=30,
        ),
    )
    with rt.db.session() as s:
        stats = telemetry.ingest(s, batch)
    assert stats == {
        "spans": 3,
        "genai_spans": 3,
        "agents": 1,
        "discovered": 0,
        "ungranted": 1,
        "instructions": 0,
    }
    with rt.db.session() as s:
        activity = s.scalars(select(AgentActivity)).one()
        assert (activity.tool_calls, activity.model_calls, activity.input_tokens) == (2, 1, 120)
        assert agents.get(s, "bot").models == ["gpt-5"]
        finding = s.scalars(select(Finding).where(Finding.type == "agent.ungranted_tool_use")).one()
        assert "local/shell" in finding.title


def test_infrastructure_spans_are_ignored(rt) -> None:
    with rt.db.session() as s:
        stats = telemetry.ingest(s, payload("agentgateway", span("chat")))
    assert stats["genai_spans"] == 0


def test_protobuf_decoding() -> None:
    from opentelemetry.proto.collector.trace.v1 import trace_service_pb2
    from opentelemetry.proto.common.v1 import common_pb2
    from opentelemetry.proto.trace.v1 import trace_pb2

    request = trace_service_pb2.ExportTraceServiceRequest()
    rs = request.resource_spans.add()
    rs.resource.attributes.append(
        common_pb2.KeyValue(key="service.name", value=common_pb2.AnyValue(string_value="pb-agent"))
    )
    sp = rs.scope_spans.add().spans.add()
    sp.CopyFrom(trace_pb2.Span(name="chat", trace_id=bytes(range(16)), span_id=bytes(range(8))))
    sp.attributes.append(
        common_pb2.KeyValue(
            key="gen_ai.operation.name", value=common_pb2.AnyValue(string_value="chat")
        )
    )
    decoded = telemetry.decode_protobuf(request.SerializeToString())
    ((resource, _, decoded_span),) = telemetry.iter_spans(decoded)
    assert resource["service.name"] == "pb-agent"
    assert telemetry._hex_id(decoded_span["traceId"]) == bytes(range(16)).hex()
