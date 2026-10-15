"""The HTTP layer on Django (agentgov.web) while routes move to it from FastAPI: it answers
as FastAPI did, its views run side by side, and each path has one framework."""

from __future__ import annotations

import asyncio
import re
import threading
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from django.test import RequestFactory
from fastapi import Body
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from ninja import Body as NinjaBody
from pydantic import BaseModel, Field

from agentgov import web
from agentgov.api.app import create_app
from agentgov.web import api as web_api
from tests.conftest import ADMIN


class Color(Enum):
    RED = "red"


def test_json_is_written_as_fastapi_wrote_it() -> None:
    values: list[Any] = [
        {"at": datetime(2026, 10, 15, 8, 0, 0, 123456, tzinfo=UTC)},
        {"at": datetime(2026, 10, 15, 8, 0, tzinfo=timezone(timedelta(hours=2)))},
        {"at": datetime(2026, 10, 15, 8, 0), "day": date(2026, 10, 15)},
        {"name": "Zoë ✓", "n": 3, "x": 2.5, "ok": True, "none": None},
        {"money": Decimal("12"), "price": Decimal("2.50"), "color": Color.RED},
        {"id": UUID("12345678-1234-5678-1234-567812345678"), "tags": ["a", ("b", "c")]},
        [{"nested": {"deeper": [1, {"at": datetime(2026, 1, 1, tzinfo=UTC)}]}}],
    ]
    for value in values:
        assert web_api.dumps(value) == JSONResponse(jsonable_encoder(value)).body, value


def test_sync_views_run_side_by_side() -> None:
    # Two requests that each wait for the other: one at a time (as Django runs a sync view
    # under ASGI), the first would wait alone until the barrier gave up.
    barrier = threading.Barrier(2, timeout=5)
    router = web_api.Router()

    @router.get("/wait")
    def wait(request: Any) -> dict[str, bool]:
        barrier.wait()
        return {"ok": True}

    api = web_api.API(urls_namespace="test-side-by-side", docs_url=None, openapi_url=None)
    api.add_router("", router)
    view = next(p.callback for p in api.urls[0] if str(p.pattern) == "wait")

    async def both() -> list[Any]:
        factory = RequestFactory()
        return await asyncio.gather(view(factory.get("/wait")), view(factory.get("/wait")))

    assert [r.status_code for r in asyncio.run(both())] == [200, 200]


class Inner(BaseModel):
    when: int


class Thing(BaseModel):
    name: str = Field(min_length=1)
    count: int = 0
    inner: Inner | None = None


JSON = {"content-type": "application/json"}

# (path, body, headers): GET without a body, POST with one.
REQUESTS: list[tuple[str, bytes | None, dict[str, str]]] = [
    ("/parity/thing", b'{"name": "a", "count": 2}', JSON),
    ("/parity/thing", b'{"name": ""}', JSON),
    ("/parity/thing", b'{"count": "x"}', JSON),
    ("/parity/thing", b'{"name": "a", "inner": {"when": "y"}}', JSON),
    ("/parity/thing", b'{"name": "a", "inner": []}', JSON),
    ("/parity/thing", b"[]", JSON),
    ("/parity/thing", b"", {}),
    ("/parity/thing", b"not json", JSON),
    ("/parity/thing", b'{"name": ', JSON),
    ("/parity/thing", b"\xff\xfe", JSON),
    # Only a body that says it is JSON is read as JSON (a form posted from a page isn't).
    ("/parity/thing", b'{"name": "a"}', {"content-type": "text/plain"}),
    ("/parity/thing", b'{"name": "a"}', {}),
    ("/parity/thing", b'{"name": "a"}', {"content-type": "application/merge-patch+json"}),
    ("/parity/two", b'{"reason": "x", "until": 3}', JSON),
    ("/parity/two", b'{"reason": "x"}', JSON),
    ("/parity/two", b'{"reason": "x", "until": "z"}', JSON),
    ("/parity/two", b"", {}),
    ("/parity/query?limit=3&state=open", None, {}),
    ("/parity/query?limit=many", None, {}),
    ("/parity/query", None, {}),
    ("/parity/boom", None, {}),
]


def test_requests_are_answered_as_fastapi_answered_them(settings) -> None:
    # The same routes on both frameworks, sent the same requests, give the same answers, byte
    # for byte: what each accepts, and how it says what it refuses.
    fastapi = create_app(settings, background=False).fastapi

    @fastapi.post("/parity/thing")
    def thing(payload: Thing) -> Thing:
        return payload

    @fastapi.post("/parity/two")
    def two(reason: str = Body(), until: int = Body()) -> dict[str, Any]:
        return {"reason": reason, "until": until}

    @fastapi.get("/parity/query")
    def query(limit: int, state: str | None = None) -> dict[str, Any]:
        return {"limit": limit, "state": state}

    @fastapi.get("/parity/boom")
    def boom() -> None:
        raise RuntimeError("boom")

    router = web_api.Router()

    @router.post("/parity/thing")
    def ninja_thing(request: Any, payload: Thing) -> Thing:
        return thing(payload)

    @router.post("/parity/two")
    def ninja_two(
        request: Any, reason: str = NinjaBody(...), until: int = NinjaBody(...)
    ) -> dict[str, Any]:
        return two(reason, until)

    @router.get("/parity/query")
    def ninja_query(request: Any, limit: int, state: str | None = None) -> dict[str, Any]:
        return query(limit, state)

    @router.get("/parity/boom")
    def ninja_boom(request: Any) -> None:
        boom()

    api = web_api.API(urls_namespace="test-parity", docs_url=None, openapi_url=None)
    api.add_router("", router)
    views = {str(p.pattern): p.callback for p in api.urls[0]}
    client = TestClient(fastapi, raise_server_exceptions=False)
    factory = RequestFactory()
    for path, body, headers in REQUESTS:
        method = "GET" if body is None else "POST"
        before = client.request(method, path, content=body, headers=headers)
        request = factory.generic(
            method, path, data=body or b"", content_type=headers.get("content-type", "")
        )
        after = asyncio.run(views[path.split("?")[0].lstrip("/")](request))
        assert (after.status_code, after["content-type"], after.content) == (
            before.status_code,
            before.headers["content-type"],
            before.content,
        ), (path, body, headers)


def test_each_path_has_one_framework(settings) -> None:
    # A path Django serves that FastAPI's patterns also match (or the other way round) would
    # change hands by accident: routes move a whole path at a time.
    app = create_app(settings, background=False)

    def flat(found: list[Any]) -> Any:
        for route in found:
            if type(route).__name__ == "_IncludedRouter":
                yield from flat(route.original_router.routes)
            else:
                yield route

    fastapi = [r for r in flat(app.fastapi.routes) if isinstance(r, APIRoute)]

    def sample(path: str) -> str:
        return re.sub(r"\{[^}]+\}", "x", path)

    for route in fastapi:
        assert not web.serves(sample(route.path)), f"{route.path}: Django serves it too"
    moved = list(web_api.routes())
    assert moved
    for _method, path in moved:
        assert web.serves(sample(path)), path
        assert not any(r.path_regex.match(sample(path)) for r in fastapi), (
            f"{path}: FastAPI's routes match it too"
        )


def test_moved_routes_answer_as_before(settings) -> None:
    with TestClient(create_app(settings, background=False)) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").json()["status"] == "ready"
        denied = client.get("/v1/me")
        assert (denied.status_code, denied.json()) == (
            401,
            {"detail": "missing or invalid bearer token"},
        )
        assert denied.headers["www-authenticate"] == "Bearer"
        assert denied.headers["content-type"] == "application/json"
        assert client.get("/v1/me", headers=ADMIN).json()["actor"] == "admin:bootstrap"
        wrong = client.post("/healthz")
        assert (wrong.status_code, wrong.json(), wrong.headers["allow"]) == (
            405,
            {"detail": "Method Not Allowed"},
            "GET",
        )
        info = client.get("/v1/info")
        assert info.headers["content-length"] == str(len(info.content))
        # A path with a slash too many, or one too few, is sent to the one served.
        moved = client.get("/healthz/?x=1", follow_redirects=False)
        assert (moved.status_code, moved.headers["location"]) == (
            307,
            "http://testserver/healthz?x=1",
        )
        assert client.get("/healthz/").json() == {"status": "ok"}
        assert client.get("/v1/me/", headers=ADMIN, follow_redirects=False).status_code == 307
        assert client.get("/v1/nothing/", follow_redirects=False).status_code == 404
        # The API's description lists every route, whichever framework serves it.
        paths = client.get("/openapi.json").json()["paths"]
        assert {"/v1/me", "/healthz", "/v1/agents"} <= set(paths)
        # "/" is still the admin UI's.
        assert client.get("/", follow_redirects=False).headers["location"] == "/ui/"
