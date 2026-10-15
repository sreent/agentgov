"""The API's Django Ninja application: routers whose views run in a thread pool, JSON as
FastAPI wrote it, and the same error shapes ({"detail": ...})."""

from __future__ import annotations

import dataclasses
import json
import logging
import re
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Any
from uuid import UUID

from asgiref.sync import sync_to_async
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.urls import URLResolver, get_resolver
from ninja import NinjaAPI
from ninja import Router as NinjaRouter
from ninja.constants import NOT_SET
from ninja.errors import HttpError, ValidationError, ValidationErrorContext
from ninja.operation import PathView
from ninja.parser import Parser as NinjaParser
from ninja.renderers import BaseRenderer
from pydantic import BaseModel, TypeAdapter
from starlette.exceptions import HTTPException

from agentgov import __version__
from agentgov.registry.errors import RegistryError

log = logging.getLogger(__name__)

# The views' threads: Django runs a sync view under ASGI in one thread for every request,
# one request at a time, so ours run here instead, as many at once as FastAPI's did.
VIEWS = ThreadPoolExecutor(max_workers=40, thread_name_prefix="agentgov-view")


# --------------------------------------------------------------------------- JSON


def jsonable(value: Any) -> Any:
    """``value`` as JSON can hold it, as FastAPI's ``jsonable_encoder`` made it."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, dict):
        return {jsonable(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [jsonable(v) for v in value]
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, Enum):
        return jsonable(value.value)
    if isinstance(value, UUID | PurePath):
        return str(value)
    if isinstance(value, Decimal):
        return int(value) if value.as_tuple().exponent >= 0 else float(value)  # type: ignore[operator]
    if isinstance(value, bytes):
        return value.decode()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return jsonable(dataclasses.asdict(value))
    raise TypeError(f"{type(value).__name__} isn't JSON")


def dumps(value: Any) -> bytes:
    """A route's answer as FastAPI wrote it, with pydantic's JSON: compact, in UTF-8, times
    in UTC ending in Z."""
    return _ANSWER.dump_json(value, by_alias=True)


_ANSWER: TypeAdapter[Any] = TypeAdapter(Any)


def json_response(
    value: Any, status: int = 200, headers: dict[str, str] | None = None
) -> HttpResponse:
    """An answer written as FastAPI's JSONResponse wrote it: its errors, and the answers
    routes made themselves."""
    body = json.dumps(jsonable(value), ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    return HttpResponse(
        body.encode(), status=status, content_type="application/json", headers=headers
    )


class Renderer(BaseRenderer):
    media_type = "application/json"

    def render(self, request: HttpRequest, data: Any, *, response_status: int) -> Any:
        return dumps(data)


class Parser(NinjaParser):
    """Request bodies read as FastAPI read them: as JSON when the request says that is what it
    sends, else as the bytes they are, which a model refuses (a form posted from a page, say)."""

    def parse_body(self, request: HttpRequest) -> Any:
        kind, _, subtype = (request.content_type or "").lower().partition("/")
        if kind == "application" and (subtype == "json" or subtype.endswith("+json")):
            return json.loads(request.body)
        return request.body


# -------------------------------------------------------------------------- views


class ThreadedPathView(PathView):
    """A path's view, always async: its sync operations run in the views' thread pool, its
    async ones on the server's event loop (where the runtime's waiters are)."""

    def get_view(self) -> Callable[..., Any]:
        async def view(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            operation = self._find_operation(request)
            if operation is None:
                # As FastAPI routed: to the first route with the path and the method, else
                # the first with the path says which methods it takes.
                routed = _route(request)
                if routed is not None:
                    other, found = routed
                    return await other(request, **found)
                response = self._not_allowed()
            elif operation.is_async:
                response = await operation.run(request, *args, **kwargs)
            else:
                run = sync_to_async(operation.run, thread_sensitive=False, executor=VIEWS)
                response = await run(request, *args, **kwargs)
            if _has_body(response) and not response.has_header("Content-Length"):
                # As FastAPI sent every answer it had whole (Django leaves it to middleware).
                response["Content-Length"] = str(len(response.content))
            return response

        view.csrf_exempt = True  # type: ignore[attr-defined]  # the API checks its own (auth)
        view.path_view = self  # type: ignore[attr-defined]
        return view

    def _not_allowed(self) -> HttpResponse:
        # As FastAPI answered, with the methods of the path's first route.
        allowed = ", ".join(self.operations[0].methods)
        return json_response({"detail": "Method Not Allowed"}, 405, headers={"Allow": allowed})

    def clone(self) -> ThreadedPathView:
        cloned = ThreadedPathView()
        cloned.is_async = self.is_async
        cloned.url_name = self.url_name
        cloned.operations = [op.clone() for op in self.operations]
        return cloned


# A view, and what it reads from the path.
Found = tuple[Callable[..., Any], dict[str, Any]]

# Every route as written, (path, method), in order. Django finds a path's routes together,
# where the path was first written, and FastAPI took each route in turn: the two agree while
# no path's routes are written around those of another path that takes the same requests
# (tests/test_web.py).
WRITTEN: list[tuple[str, str]] = []


def _route(request: HttpRequest) -> Found | None:
    """The first route, in Django's order, that takes the request's path and method."""
    resolver = get_resolver(getattr(request, "urlconf", None))
    for view, kwargs in _matching([resolver], request.path_info):
        path_view = getattr(view, "path_view", None)
        if path_view is not None and path_view._find_operation(request) is not None:
            return view, kwargs
    return None


def _matching(patterns: list[Any], path: str) -> Iterator[Found]:
    """Every view whose pattern matches ``path``, in Django's order (it serves the first)."""
    for pattern in patterns:
        if isinstance(pattern, URLResolver):
            match = pattern.pattern.match(path)
            if match:
                rest, _, kwargs = match
                for view, found in _matching(pattern.url_patterns, rest):
                    yield view, {**kwargs, **found}
        elif hit := pattern.resolve(path):
            yield hit.func, hit.kwargs


def _has_body(response: HttpResponseBase) -> bool:
    status = response.status_code
    return not response.streaming and status >= 200 and status not in (204, 304)


class Router(NinjaRouter):
    """A group of the API's routes, with threaded views. A route names the status of its
    answers as with FastAPI, ``@router.post(path, status_code=201)``; 204 answers have no
    body."""

    def add_api_operation(self, path: str, methods: list[str], view_func: Any, **kw: Any) -> None:
        if path not in self.path_operations:
            self.path_operations[path] = ThreadedPathView()
        super().add_api_operation(path, methods, view_func, **kw)
        WRITTEN.extend((path, method) for method in methods)

    def get(self, path: str, *, status_code: int = 200, **kw: Any) -> Callable[[Any], Any]:
        return _answering(super().get(path, **kw), status_code)

    def post(self, path: str, *, status_code: int = 200, **kw: Any) -> Callable[[Any], Any]:
        return _answering(super().post(path, **kw), status_code)

    def put(self, path: str, *, status_code: int = 200, **kw: Any) -> Callable[[Any], Any]:
        return _answering(super().put(path, **kw), status_code)

    def patch(self, path: str, *, status_code: int = 200, **kw: Any) -> Callable[[Any], Any]:
        return _answering(super().patch(path, **kw), status_code)

    def delete(self, path: str, *, status_code: int = 200, **kw: Any) -> Callable[[Any], Any]:
        return _answering(super().delete(path, **kw), status_code)


def _answering(register: Callable[[Any], Any], status_code: int) -> Callable[[Any], Any]:
    if status_code == 200:
        return register

    def decorator(view_func: Any) -> Any:
        register(view_func)
        # Ninja answers with the status its one response is for.
        view_func._ninja_operation.response_models = {
            status_code: None if status_code == 204 else NOT_SET
        }
        return view_func

    return decorator


# ------------------------------------------------------------------------- errors


def _registry_error(request: HttpRequest, exc: RegistryError) -> HttpResponse:
    return json_response({"detail": str(exc)}, exc.status_code)


def _http_error(request: HttpRequest, exc: HTTPException) -> HttpResponse:
    # Raised by what both frameworks share (agentgov.api.auth).
    return json_response({"detail": exc.detail}, exc.status_code, headers=exc.headers)


def _ninja_error(request: HttpRequest, exc: HttpError) -> HttpResponse:
    cause = exc.__cause__  # set only when a body couldn't be read
    if isinstance(cause, json.JSONDecodeError):
        # A body that isn't the JSON it says it is, refused as FastAPI refused it.
        error = {
            "type": "json_invalid",
            "loc": ["body", cause.pos],
            "msg": "JSON decode error",
            "input": {},
            "ctx": {"error": cause.msg},
        }
        return json_response({"detail": f"{cause.pos}: JSON decode error", "errors": [error]}, 422)
    if cause is not None:
        return json_response({"detail": "There was an error parsing the body"}, 400)
    return json_response({"detail": str(exc)}, exc.status_code)


def _validation_error(request: HttpRequest, exc: ValidationError) -> HttpResponse:
    # As FastAPI answered: the same shape as every other error, with the field errors kept.
    errors = [_field_error(e) for e in exc.errors]
    message = "; ".join(
        ".".join(str(p) for p in e["loc"] if p != "body") + f": {e.get('msg')}" for e in errors
    )
    return json_response({"detail": message or "invalid request", "errors": errors}, 422)


def _field_error(error: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in error.items() if k in ("type", "loc", "msg", "input", "ctx")}
    out["loc"] = list(error.get("loc", ()))
    return jsonable(out)


def _server_error(request: HttpRequest, exc: Exception) -> HttpResponse:
    log.exception("%s %s failed", request.method, request.path, exc_info=exc)
    return HttpResponse(
        b"Internal Server Error", status=500, content_type="text/plain; charset=utf-8"
    )


class API(NinjaAPI):
    """An API that reads and writes JSON, and says what it refuses, as FastAPI did."""

    def __init__(self, **kw: Any) -> None:
        kw.setdefault("renderer", Renderer())
        kw.setdefault("parser", Parser())
        super().__init__(**kw)

    def get_content_type(self) -> str:
        return "application/json"  # as FastAPI wrote it, without a charset

    def set_default_exception_handlers(self) -> None:
        super().set_default_exception_handlers()
        self.add_exception_handler(RegistryError, _registry_error)
        self.add_exception_handler(HTTPException, _http_error)
        self.add_exception_handler(HttpError, _ninja_error)
        self.add_exception_handler(ValidationError, _validation_error)
        self.add_exception_handler(Exception, _server_error)

    def validation_error_from_error_contexts(
        self, error_contexts: list[ValidationErrorContext]
    ) -> ValidationError:
        errors = []
        for context in error_contexts:
            model = context.model
            source = model.__ninja_param_source__
            # A body read into one parameter is the body itself: ["body", "name"], not
            # ["body", "payload", "name"].
            single = getattr(model, "__read_from_single_attr__", None)
            for error in context.pydantic_validation_error.errors(include_url=False):
                loc = model.__ninja_flatten_map_reverse__.get(error["loc"], error["loc"])
                whole = 1
                if source == "body" and single and loc[:1] == (single,):
                    loc, whole = loc[1:], 0
                error["loc"] = (source, *loc)
                if error["type"] == "missing" and len(loc) == whole:
                    error["input"] = None  # a parameter that wasn't sent, not the others
                if error["type"] == "model_type":
                    # FastAPI read objects from their attributes too, and said so.
                    error.pop("ctx", None)
                    error["type"] = "model_attributes_type"
                    error["msg"] = (
                        "Input should be a valid dictionary or object to extract fields from"
                    )
                if isinstance(error.get("ctx", {}).get("error"), Exception):
                    error["ctx"]["error"] = {}  # as FastAPI's encoder wrote an exception
                errors.append(dict(error))
        return ValidationError(errors)


api = API(
    title="AgentGov control plane",
    version=__version__,
    # FastAPI serves /docs while routes move, with these routes in it (agentgov.api.app).
    docs_url=None,
    openapi_url=None,
    urls_namespace="agentgov",
)


def routes() -> Iterator[tuple[str, str]]:
    """Every route Django serves, as (method, path), its paths written as FastAPI wrote them
    (``{name:path}``, where Django has ``{path:name}``)."""
    for prefix, router in api._routers:
        for path, view in router.path_operations.items():
            full = as_written("/" + (prefix.strip("/") + "/" + path.lstrip("/")).strip("/"))
            for operation in view.operations:
                for method in operation.methods:
                    yield method, full


def as_written(path: str) -> str:
    """A path as FastAPI wrote it: ``{name:path}`` where Django has ``{path:name}``."""
    return re.sub(r"\{path:(\w+)\}", r"{\1:path}", path)
