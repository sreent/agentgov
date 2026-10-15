"""The version an edit was made from (registry/versions): ``If-Match: "3"``."""

from __future__ import annotations

from starlette.exceptions import HTTPException
from starlette.requests import Request


def if_match(request: Request) -> int | None:
    """The version named by If-Match (``"3"``, or weak, ``W/"3"``); None without one, or
    for ``*``."""
    raw = request.headers.get("if-match")
    if raw is None or raw.strip() in ("", "*"):
        return None
    tag = raw.split(",")[0].strip().removeprefix("W/").strip('"')
    try:
        return int(tag)
    except ValueError:
        raise HTTPException(
            400, 'If-Match takes the version the edit was made from, such as "3"'
        ) from None
