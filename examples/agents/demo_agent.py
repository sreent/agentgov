"""Walk through AgentGov's controls with a real MCP client.

Run against the reference stack (deploy/compose) after applying the example
manifests:

    pip install -e ".[demo]"
    python examples/agents/demo_agent.py

Each run registers a fresh agent from the customer-support blueprint, so the
registry lifecycle (request -> approval -> identity) is part of the demo and
risk signals from earlier runs do not carry over.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import sys
import time
from typing import Any

import httpx
import httpx2
from mcp import Client, MCPError
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Implementation, TextContent

CONTROL_PLANE = os.environ.get("AGENTGOV_URL", "http://localhost:8000")
ADMIN_TOKEN = os.environ.get("AGENTGOV_TOKEN", "dev-admin-token")
GATEWAY = os.environ.get("AGENTGOV_GATEWAY", "http://localhost:8080")
OTLP_HTTP = os.environ.get("OTLP_HTTP", "http://localhost:4318")

BOLD, DIM, GREEN, RED, YELLOW, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[0m",
)


def admin(method: str, path: str, **kwargs: Any) -> Any:
    resp = httpx.request(
        method,
        CONTROL_PLANE + path,
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        timeout=30,
        **kwargs,
    )
    resp.raise_for_status()
    return resp.json()


def step(title: str) -> None:
    print(f"\n{BOLD}{title}{RESET}")


UNEXPECTED: list[str] = []


def show(label: str, ok: bool, detail: str) -> None:
    colour = GREEN if ok else RED
    print(f"  {colour}{label}{RESET} {detail}")
    if not ok:
        UNEXPECTED.append(f"{label} {detail}")


def wait_for_gateway(server: str = "crm", timeout: float = 60) -> None:
    """agentgateway reloads its generated config a moment after manifests are applied."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.post(f"{GATEWAY}/mcp/{server}", timeout=5).status_code != 404:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise SystemExit(f"gateway route /mcp/{server} did not appear; did you apply the manifests?")


async def call(client: Client, tool: str, args: dict[str, Any]) -> tuple[bool, Any]:
    """Call a tool and return ``(allowed, payload_or_message)``.

    agentgateway reports a refused *call* as an ``isError`` result (so the model
    can read why) and a withheld *result* as a JSON-RPC error.
    """
    try:
        result = await client.call_tool(tool, args)
    except MCPError as exc:
        return False, exc.message
    if result.is_error:
        return False, " ".join(b.text for b in result.content if isinstance(b, TextContent))
    return True, result.structured_content or [
        b.text for b in result.content if isinstance(b, TextContent)
    ]


def report(allowed: bool, payload: Any, *, expect_allowed: bool) -> None:
    label = "allowed" if allowed else "refused"
    text = json.dumps(payload) if allowed else str(payload)
    show(label, allowed == expect_allowed, text)


def register_agent() -> tuple[str, str]:
    name = f"demo-agent-{secrets.token_hex(3)}"
    agent = admin(
        "POST",
        "/v1/agents",
        json={
            "name": name,
            "description": "Demo agent created by examples/agents/demo_agent.py",
            "blueprint": "customer-support",
            "owner": "cx-platform",
            "sponsors": ["alice@example.com"],
            "framework": "mcp-python-sdk",
            "environment": "prod",
        },
    )
    print(f"  registered {name}: {agent['status']} (requests start pending, like Agent 365)")
    agent = admin("POST", f"/v1/agents/{name}/approve", json={"reason": "demo"})
    print(f"  approved by an administrator: {agent['status']}")
    creds = admin("POST", f"/v1/agents/{name}/credentials", json={})
    token = httpx.post(
        creds["token_endpoint"],
        data={"grant_type": "client_credentials"},
        auth=(creds["client_id"], creds["client_secret"]),
        timeout=30,
    ).json()["access_token"]
    print(f"  Keycloak issued an access token to OAuth client {creds['client_id']}")
    return name, token


async def run_scenarios(name: str, token: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=60.0)) as http:
        transport = streamable_http_client(f"{GATEWAY}/mcp/crm", http_client=http)
        async with Client(
            transport, client_info=Implementation(name=name, version="1.0.0")
        ) as client:
            step("2. Least privilege: the agent only sees tools its blueprint grants")
            tools = [t.name for t in (await client.list_tools()).tools]
            show("visible:", True, ", ".join(tools))
            hidden = "export_customers (not granted), summarize_ticket (poisoned description)"
            print(f"  {DIM}hidden: {hidden}{RESET}")

            step("3. Data loss prevention: personal data in results is masked (Presidio)")
            allowed, payload = await call(client, "get_customer", {"customer_id": "c-001"})
            report(allowed, payload, expect_allowed=True)

            step("4. Credentials never leave: secrets in tool arguments are blocked")
            allowed, payload = await call(
                client,
                "add_note",
                {
                    "customer_id": "c-001",
                    "text": "Use AWS key AKIAIOSFODNN7EXAMPLE to pull their invoices",
                },
            )
            report(allowed, payload, expect_allowed=False)

            step("5. Indirect prompt injection: poisoned tool results are withheld")
            allowed, payload = await call(client, "get_customer_notes", {"customer_id": "c-002"})
            report(allowed, payload, expect_allowed=False)

            step("6. Ungranted tools are refused even when called directly")
            allowed, payload = await call(client, "export_customers", {})
            report(allowed, payload, expect_allowed=False)

            step("7. Human in the loop: destructive tools wait for an approver")
            allowed, payload = await call(client, "delete_customer", {"customer_id": "c-003"})
            report(allowed, payload, expect_allowed=False)
            match = re.search(r"apr_[0-9a-f]{16}", str(payload))
            if match:
                decided = admin(
                    "POST",
                    f"/v1/approvals/{match.group()}/approve",
                    json={"note": "verified with the customer"},
                )
                print(
                    f"  {YELLOW}approver{RESET} {decided['decided_by']} approved "
                    f"{match.group()}; the agent retries the same call"
                )
                allowed, payload = await call(client, "delete_customer", {"customer_id": "c-003"})
                print(
                    f"  {DIM}(the CRM is in-memory: after the first run it answers "
                    f"'No customer with id', which is the server's own error){RESET}"
                )
                report(allowed, payload, expect_allowed=True)

            step("8. Kill switch: blocking the agent takes effect everywhere within a second")
            started = time.monotonic()
            admin("POST", f"/v1/agents/{name}/block", json={"reason": "demo kill switch"})
            allowed = True
            while allowed and time.monotonic() - started < 30:
                allowed, payload = await call(client, "get_customer", {"customer_id": "c-001"})
            elapsed = time.monotonic() - started
            report(allowed, f"{payload} ({elapsed:.2f}s after the block)", expect_allowed=False)


def shadow_agent() -> None:
    step("9. Shadow AI: telemetry from an unregistered agent is discovered")
    service = f"notebook-agent-{secrets.token_hex(2)}"
    span = {
        "traceId": secrets.token_hex(16),
        "spanId": secrets.token_hex(8),
        "name": "execute_tool web_search",
        "kind": 1,
        "startTimeUnixNano": str(time.time_ns()),
        "endTimeUnixNano": str(time.time_ns()),
        "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
            {"key": "gen_ai.tool.name", "value": {"stringValue": "web_search"}},
        ],
    }
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": service}}]
                },
                "scopeSpans": [{"scope": {"name": "openai.agents"}, "spans": [span]}],
            }
        ]
    }
    httpx.post(f"{OTLP_HTTP}/v1/traces", json=payload, timeout=10).raise_for_status()
    for _ in range(20):
        found = [
            a
            for a in admin("GET", "/v1/agents", params={"status": "discovered"})
            if a["name"] == service
        ]
        if found:
            show(
                "discovered:",
                True,
                f"{service} (source {found[0]['source']}, risk {found[0]['risk']['level']})",
            )
            return
        time.sleep(0.5)
    show("not discovered", False, service)


def evidence(name: str) -> None:
    step("10. Evidence: every decision is in a hash-chained, verifiable ledger")
    verify = admin("GET", "/v1/ledger/verify")
    show(
        "chain valid" if verify["valid"] else "chain BROKEN",
        verify["valid"],
        f"{verify['checked']} entries",
    )
    for entry in reversed(admin("GET", "/v1/ledger", params={"agent": name, "limit": 8})):
        print(
            f"  {DIM}#{entry['seq']} {entry['type']:<20} {entry.get('resource') or '':<28} "
            f"{entry.get('decision') or '':<17} {(entry.get('reason') or '')[:60]}{RESET}"
        )


def main() -> None:
    wait_for_gateway()
    step("1. Registration: a new agent is requested, approved and given an identity")
    name, token = register_agent()
    try:
        asyncio.run(run_scenarios(name, token))
    finally:
        shadow_agent()
        evidence(name)
        admin("POST", f"/v1/agents/{name}/delete", json={"reason": "demo finished"})
        print(f"\n{DIM}{name} soft-deleted (restorable for 30 days).{RESET}")
        print(f"{DIM}Open {CONTROL_PLANE}/ui for the admin view.{RESET}")
    if UNEXPECTED:
        print(f"\n{RED}{len(UNEXPECTED)} unexpected outcome(s){RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
