"""Django's ASGI handler, with what it doesn't do itself (``agentgov.web.handler``).

* A route that faces the internet checks its caller from the headers before anything reads
  the body, and reads only so much of it (``before_body``): Django reads every body whole
  before a view runs.
* What a route leaves to do once its answer has gone (``after``) runs then, in the views'
  threads, as FastAPI's background tasks did: before the request ends.
* An exception a route didn't handle is raised again once its 500 has gone, as FastAPI
  did: for the server to log, and test clients to raise.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, NamedTuple

from asgiref.sync import sync_to_async
from django.core.handlers.asgi import ASGIHandler
from django.http import HttpResponseBase

from agentgov.web.api import FAILED, VIEWS, json_response, sized

log = logging.getLogger(__name__)
_AFTER = "_agentgov_after"

Receive = Callable[[], Awaitable[dict[str, Any]]]


class _Early(NamedTuple):
    check: Callable[[dict[str, Any]], HttpResponseBase | None]
    max_bytes: int


_EARLY: dict[tuple[str, str], _Early] = {}


def before_body(
    method: str,
    path: str,
    check: Callable[[dict[str, Any]], HttpResponseBase | None],
    max_bytes: int,
) -> None:
    """Have ``check`` look at a request's ASGI scope before its body is read: the answer it
    gives, if any, goes back at once. The body is then read up to ``max_bytes`` (413)."""
    _EARLY[(method, path)] = _Early(check, max_bytes)


def after(response: HttpResponseBase, task: Callable[[], Any]) -> None:
    """Run ``task`` once ``response`` has gone."""
    setattr(response, _AFTER, [*getattr(response, _AFTER, ()), task])


class _TooLarge(Exception):
    pass


class Handler(ASGIHandler):
    async def handle(self, scope: dict[str, Any], receive: Receive, send: Any) -> None:
        early = _EARLY.get((scope["method"], scope["path"]))
        if early is not None:
            check = sync_to_async(early.check, thread_sensitive=False, executor=VIEWS)
            answer = await check(scope)
            if answer is not None:
                await self.send_response(sized(answer), send)
                return
            receive = _at_most(receive, early.max_bytes)
        try:
            await super().handle(scope, receive, send)
        except _TooLarge:
            refused = json_response({"detail": "the request is too large"}, 413)
            await self.send_response(sized(refused), send)

    async def send_response(self, response: HttpResponseBase, send: Any) -> None:
        await self._send(response, send)
        failure = getattr(response, FAILED, None)
        if failure is not None:
            raise failure

    async def _send(self, response: HttpResponseBase, send: Any) -> None:
        tasks = getattr(response, _AFTER, ())
        if not tasks:
            await super().send_response(response, send)
            return

        # The answer goes whole (it says how long it is), but the request ends only once the
        # tasks are done: until then Django doesn't take the client to have gone, and cancel.
        async def all_but_the_end(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.body" and not message.get("more_body"):
                message = {**message, "more_body": True}
            await send(message)

        await super().send_response(response, all_but_the_end)
        for task in tasks:
            # Done, whatever becomes of the request.
            await asyncio.shield(asyncio.wrap_future(VIEWS.submit(_quietly, task)))
        await send({"type": "http.response.body", "body": b"", "more_body": False})


def _quietly(task: Callable[[], Any]) -> None:
    try:
        task()
    except Exception:  # the answer has gone: nobody to tell but the log
        log.exception("a task after an answer failed")


def _at_most(receive: Receive, limit: int) -> Receive:
    read = 0

    async def receive_at_most() -> dict[str, Any]:
        nonlocal read
        message = await receive()
        if message["type"] == "http.request":
            read += len(message.get("body", b""))
            if read > limit:
                raise _TooLarge
        return message

    return receive_at_most
