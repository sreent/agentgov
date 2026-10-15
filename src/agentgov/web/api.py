"""The API's Django Ninja application: routers whose views run in a thread pool, JSON as
FastAPI wrote it, and the same error shapes ({"detail": ...})."""

from __future__ import annotations

import dataclasses
import json
import logging
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Any
from uuid import UUID

from agentgov.web import configure

configure()

from asgiref.sync import sync_to_async  # noqa: E402
from django.http import HttpRequest, HttpResponse  # noqa: E402
from ninja import NinjaAPI  # noqa: E402
from ninja import Router as NinjaRouter  # noqa: E402
from ninja.errors import HttpError, ValidationError, ValidationErrorContext  # noqa: E402
from ninja.operation import PathView  # noqa: E402
from ninja.parser import Parser as NinjaParser  # noqa: E402
from ninja.renderers import BaseRenderer  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from starlette.exceptions import HTTPException  # noqa: E402

from agentgov import __version__  # noqa: E402
from agentgov.registry.errors import RegistryError  # noqa: E402

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
    """JSON as FastAPI's JSONResponse wrote it: compact, in UTF-8."""
    return json.dumps(
        jsonable(value), ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode()


def json_response(
    value: Any, status: int = 200, headers: dict[str, str] | None = None
) -> HttpResponse:
    return HttpResponse(
        dumps(value), status=status, content_type="application/json", headers=headers
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
                response = self._not_allowed()
            elif operation.is_async:
                response = await operation.run(request, *args, **kwargs)
            else:
                run = sync_to_async(operation.run, thread_sensitive=False, executor=VIEWS)
                response = await run(request, *args, **kwargs)
            if not response.streaming and not response.has_header("Content-Length"):
                # As FastAPI sent every answer it had whole (Django leaves it to middleware).
                response["Content-Length"] = str(len(response.content))
            return response

        view.csrf_exempt = True  # type: ignore[attr-defined]  # the API checks its own (auth)
        return view

    def _not_allowed(self) -> HttpResponse:
        # As FastAPI answered.
        allowed = sorted({m for op in self.operations for m in op.methods})
        return json_response(
            {"detail": "Method Not Allowed"}, 405, headers={"Allow": ", ".join(allowed)}
        )

    def clone(self) -> ThreadedPathView:
        cloned = ThreadedPathView()
        cloned.is_async = self.is_async
        cloned.url_name = self.url_name
        cloned.operations = [op.clone() for op in self.operations]
        return cloned


class Router(NinjaRouter):
    """A group of the API's routes, with threaded views."""

    def add_api_operation(self, path: str, methods: list[str], view_func: Any, **kw: Any) -> None:
        if path not in self.path_operations:
            self.path_operations[path] = ThreadedPathView()
        super().add_api_operation(path, methods, view_func, **kw)


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
    """Every route Django serves, as (method, path)."""
    for prefix, router in api._routers:
        for path, view in router.path_operations.items():
            for operation in view.operations:
                for method in operation.methods:
                    yield method, "/" + (prefix.strip("/") + "/" + path.lstrip("/")).strip("/")
