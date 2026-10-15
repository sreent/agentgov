"""The HTTP layer on Django (agentgov.web): it answers as FastAPI did when it served the API
(tests/fastapi_answers.py), its views run side by side, and a request goes to the route
FastAPI would have taken."""

from __future__ import annotations

import asyncio
import re
import threading
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from types import ModuleType
from typing import Any
from uuid import UUID

import pytest
from django import urls as django_urls
from django.test import RequestFactory
from ninja import Body
from pydantic import BaseModel, Field
from starlette.testclient import TestClient

from agentgov.api.app import create_app
from agentgov.web import api as web_api
from tests.conftest import ADMIN
from tests.fastapi_answers import ANSWERS, WRITTEN


class Color(Enum):
    RED = "red"


VALUES: dict[str, Any] = {
    "at": datetime(2026, 10, 15, 8, 0, 0, 123456, tzinfo=UTC),
    "local": datetime(2026, 10, 15, 8, 0, tzinfo=timezone(timedelta(hours=2))),
    "naive": datetime(2026, 10, 15, 8, 0),
    "day": date(2026, 10, 15),
    "took": timedelta(minutes=5),
    "name": "Zoë ✓\u2028\x01\n",
    "n": 3,
    "x": 2.5,
    "cost": 1.2e-05,
    "big": 1e20,
    "ok": True,
    "none": None,
    "money": Decimal("12"),
    "price": Decimal("2.50"),
    "color": Color.RED,
    "id": UUID("12345678-1234-5678-1234-567812345678"),
    "tags": ["a", ("b", "c")],
    "nested": [{"deeper": [1, {"at": datetime(2026, 1, 1, tzinfo=UTC)}]}],
}


# What errors carry, as FastAPI wrote it (tests/fastapi_answers.py's WRITTEN).
ERRORS: list[Any] = [
    VALUES,
    *({key: value} for key, value in VALUES.items()),
    [{"detail": "no", "errors": [{"loc": ["body", 0], "input": {}}]}],
]


def test_errors_are_written_as_fastapi_wrote_them() -> None:
    # Errors went out through FastAPI's JSONResponse, after its encoder; routes' answers
    # through pydantic (test_requests_are_answered_as_fastapi_answered_them).
    assert len(ERRORS) == len(WRITTEN)
    for value, written in zip(ERRORS, WRITTEN, strict=True):
        assert web_api.json_response(value).content == written, value


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

POST = "POST"
GET = "GET"

# (method, path, body, headers)
REQUESTS: list[tuple[str, str, bytes, dict[str, str]]] = [
    (POST, "/parity/thing", b'{"name": "a", "count": 2}', JSON),
    (POST, "/parity/thing", b'{"name": ""}', JSON),
    (POST, "/parity/thing", b'{"count": "x"}', JSON),
    (POST, "/parity/thing", b'{"name": "a", "inner": {"when": "y"}}', JSON),
    (POST, "/parity/thing", b'{"name": "a", "inner": []}', JSON),
    (POST, "/parity/thing", b"[]", JSON),
    (POST, "/parity/thing", b"", {}),
    (POST, "/parity/thing", b"not json", JSON),
    (POST, "/parity/thing", b'{"name": ', JSON),
    (POST, "/parity/thing", b"\xff\xfe", JSON),
    # Only a body that says it is JSON is read as JSON (a form posted from a page isn't).
    (POST, "/parity/thing", b'{"name": "a"}', {"content-type": "text/plain"}),
    (POST, "/parity/thing", b'{"name": "a"}', {}),
    (POST, "/parity/thing", b'{"name": "a"}', {"content-type": "application/merge-patch+json"}),
    (POST, "/parity/two", b'{"reason": "x", "until": 3}', JSON),
    (POST, "/parity/two", b'{"reason": "x"}', JSON),
    (POST, "/parity/two", b'{"reason": "x", "until": "z"}', JSON),
    (POST, "/parity/two", b"", {}),
    (GET, "/parity/query?limit=3&state=open", b"", {}),
    (GET, "/parity/query?limit=many", b"", {}),
    (GET, "/parity/query", b"", {}),
    (GET, "/parity/boom", b"", {}),
    (GET, "/parity/values", b"", {}),
    (POST, "/parity/items", b'{"name": "a"}', JSON),
    ("DELETE", "/parity/items/a", b"", {}),
    # Two routes for a path: the first with its method serves it, else the first says
    # which methods it takes.
    (POST, "/parity/items/preview", b"{}", JSON),
    (GET, "/parity/items/preview", b"", {}),
    ("PUT", "/parity/items/preview", b"", {}),
    ("PUT", "/parity/items/a", b"", {}),
    (GET, "/parity/items/a/b/c/versions", b"", {}),
    (GET, "/parity/items/a/b/versions/2", b"", {}),
    # The answers routes make themselves.
    (GET, "/parity/made/json", b"", {}),
    (GET, "/parity/made/raw", b"", {}),
    (GET, "/parity/made/csv", b"", {}),
    (GET, "/parity/made/empty", b"", {}),
    (GET, "/parity/made/text", b"", {}),
    (GET, "/parity/made/stream", b"", {}),
    (GET, "/parity/made/redirect", b"", {}),
    (GET, "/parity/made/cookies", b"", {}),
]


def test_requests_are_answered_as_fastapi_answered_them() -> None:
    # The same routes as FastAPI had, sent the same requests, give the answers it gave, byte
    # for byte: what each accepts, how it says what it refuses, and which route serves.
    router = web_api.Router()

    @router.get("/parity/made/{kind}")
    def made(request: Any, kind: str) -> Any:
        return {
            "json": lambda: web_api.json_response({"a": "é"}, 202, headers={"X-Made": "1"}),
            "raw": lambda: web_api.raw_response(
                b"\x00\x01",
                media_type="application/timestamp-reply",
                headers={"Content-Disposition": 'attachment; filename="a.tsr"'},
            ),
            "csv": lambda: web_api.raw_response("é,1\n", media_type="text/csv"),
            "empty": lambda: web_api.raw_response(status_code=202),
            "text": lambda: web_api.text_response("a: 1\n", media_type="application/yaml"),
            "stream": lambda: web_api.stream_response(
                iter([b"a\n", "é\n"]), media_type="text/plain"
            ),
            "redirect": lambda: web_api.redirect_response("/ui/a b?c=d"),
            "cookies": cookies,
        }[kind]()

    def cookies() -> Any:
        resp = web_api.redirect_response("/ui/", status_code=302)
        web_api.set_cookie(resp, "a", "1", max_age=600, httponly=True, secure=True, path="/auth")
        web_api.set_cookie(resp, "s", "t", max_age=3600, httponly=True, samesite="strict", path="/")
        web_api.delete_cookie(resp, "old", path="/auth")
        return resp

    @router.post("/parity/thing")
    def thing(request: Any, payload: Thing) -> Thing:
        return payload

    @router.post("/parity/two")
    def two(request: Any, reason: str = Body(...), until: int = Body(...)) -> dict[str, Any]:
        return {"reason": reason, "until": until}

    @router.get("/parity/query")
    def query(request: Any, limit: int, state: str | None = None) -> dict[str, Any]:
        return {"limit": limit, "state": state}

    @router.get("/parity/boom")
    def boom(request: Any) -> None:
        raise RuntimeError("boom")

    @router.get("/parity/values")
    def values(request: Any) -> dict[str, Any]:
        return VALUES

    @router.post("/parity/items", status_code=201)
    def make(request: Any, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        return {"made": body}

    @router.post("/parity/items/preview")
    def preview(request: Any, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        return {"preview": body}

    @router.get("/parity/items/{ref}")
    def read(request: Any, ref: str) -> dict[str, Any]:
        return {"read": ref}

    @router.delete("/parity/items/{ref}", status_code=204)
    def remove(request: Any, ref: str) -> None:
        del ref

    @router.get("/parity/items/{path:name}/versions/{version}")
    def version(request: Any, name: str, version: str) -> dict[str, Any]:
        return {"name": name, "version": version}

    @router.get("/parity/items/{path:name}/versions")
    def versions(request: Any, name: str) -> dict[str, Any]:
        return {"name": name}

    api = web_api.API(urls_namespace="test-parity", docs_url=None, openapi_url=None)
    api.add_router("", router)
    urls = ModuleType("parity_urls")
    urls.urlpatterns = [django_urls.path("", api.urls)]  # type: ignore[attr-defined]
    factory = RequestFactory()
    assert len(REQUESTS) == len(ANSWERS)
    for method, url, body, headers in REQUESTS:
        before = ANSWERS[(method, url, body, tuple(sorted(headers.items())))]
        request = factory.generic(
            method, url, data=body, content_type=headers.get("content-type", "")
        )
        request.urlconf = urls
        found = django_urls.get_resolver(urls).resolve(request.path_info)
        after = asyncio.run(_sent(found.func(request, **found.kwargs)))
        assert after == before, (method, url, body, headers)


async def _sent(view: Any) -> tuple[int, dict[str, str], bytes, list[str]]:
    response = await view
    if response.streaming:
        content = b"".join([part async for part in response])
    else:
        content = response.content
    headers = {name.lower(): value for name, value in response.headers.items()}
    # As Django's ASGI handler writes its cookies.
    cookies = [_undated(c.output(header="").strip()) for c in response.cookies.values()]
    return response.status_code, dict(sorted(headers.items())), content, cookies


def _undated(cookie: str) -> str:
    # A cookie deleted expires as it is written: a second apart, both are right.
    return re.sub(r"expires=[^;]+", "expires=...", cookie)


def test_the_first_route_written_for_a_request_serves_it() -> None:
    # As FastAPI routed: of the routes that take the request's path and method, the first
    # written serves it.
    served = {(path, method) for method, path in web_api.routes()}
    written = [(p, m) for p, m in web_api.WRITTEN if (web_api.as_written(p), m) in served]
    pattern = {p: _pattern(p) for p, _ in written}
    literals = {s for p, _ in written for s in p.split("/") if s and "{" not in s}
    for path, method in written:
        for sample in _samples(path, literals):
            first = next(p for p, m in written if m == method and pattern[p].match(sample[1:]))
            request = RequestFactory().generic(method, sample)
            view, _ = web_api._route(request)
            assert view.path_view._find_operation(request).path == first, (method, sample)


def _pattern(path: str) -> Any:
    route = re.sub(r"\{(?:(\w+):)?(\w+)\}", lambda m: f"<{m[1] + ':' if m[1] else ''}{m[2]}>", path)
    return django_urls.resolvers.RoutePattern(route[1:], is_endpoint=True)


def _samples(path: str, literals: set[str]) -> set[str]:
    """``path`` with its parameters filled in, and with each a literal of another path."""
    found = {re.sub(r"\{[^}]+\}", "x", path)}
    for name in re.findall(r"\{[^}]+\}", path):
        for literal in literals:
            found.add(re.sub(r"\{[^}]+\}", "x", path.replace(name, literal, 1)))
    return found


def test_the_app_answers_as_before(settings) -> None:
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
        twice = client.get("/healthz//", follow_redirects=False)
        assert twice.headers["location"] == "http://testserver/healthz"
        assert client.get("/v1/me/", headers=ADMIN, follow_redirects=False).status_code == 307
        assert client.get("/v1/nothing/", follow_redirects=False).status_code == 404
        # The API's description lists every route, whichever framework serves it.
        paths = client.get("/openapi.json").json()["paths"]
        assert {"/v1/me", "/healthz", "/v1/agents"} <= set(paths)
        # "/" is still the admin UI's, and what isn't the API's is its files, or not found.
        root = client.get("/", follow_redirects=False)
        assert (root.status_code, root.headers["location"]) == (307, "/ui/")
        assert client.post("/").headers["allow"] == "GET"
        ui = client.get("/ui", follow_redirects=False)
        assert (ui.status_code, ui.headers["location"]) == (307, "http://testserver/ui/")
        for method, path, status, detail in (
            ("GET", "/nothing", 404, "Not Found"),
            ("GET", "/ui/nothing.js", 404, "Not Found"),
            ("GET", "/ui/../pyproject.toml", 404, "Not Found"),
            ("POST", "/ui/", 405, "Method Not Allowed"),
        ):
            answer = client.request(method, path)
            assert (answer.status_code, answer.json()) == (status, {"detail": detail}), path
        assert client.post("/ui/").headers["allow"] == "GET, HEAD"
        page = client.get("/ui/")
        assert page.headers["content-security-policy"].startswith("default-src 'self'")
        # HEAD as GET: the built UI's tag, or none for the page saying it isn't built.
        head = client.head("/ui/")
        assert (head.status_code, head.headers.get("etag")) == (200, page.headers.get("etag"))


class _Runtime:
    """What the app asks of the runtime while it runs."""

    def __init__(self, fails: Exception | None = None) -> None:
        self.fails = fails
        self.calls: list[str] = []

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self.calls.append("start")
        if self.fails:
            raise self.fails

    def stop(self) -> None:
        self.calls.append("stop")


def test_the_runtime_runs_while_the_app_does(settings) -> None:
    rt = _Runtime()
    with TestClient(create_app(settings, runtime=rt)) as client:  # type: ignore[arg-type]
        assert rt.calls == ["start"]
        assert client.get("/healthz").status_code == 200
    assert rt.calls == ["start", "stop"]
    # A runtime that can't start stops the server from starting, saying why.
    failing = _Runtime(fails=RuntimeError("the database is unreachable"))
    with (
        pytest.raises(RuntimeError, match="the database is unreachable"),
        TestClient(create_app(settings, runtime=failing)),  # type: ignore[arg-type]
    ):
        pass
    assert failing.calls == ["start"]
