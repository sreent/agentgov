"""Agent instructions (system prompts) and what scanning finds in them."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from ninja import Body

from agentgov.api.auth import READ_ROLES
from agentgov.registry import instructions
from agentgov.registry.errors import ValidationError
from agentgov.web.api import Router
from agentgov.web.auth import require, runtime

router = Router(tags=["instructions"])


def classifier(rt: Any) -> dict[str, Any]:
    g = rt.guardian
    return {
        "enabled": g is not None,
        "model": g.model if g else None,
        "criteria": g.criteria if g else [],
    }


@router.post("/v1/instructions/check", auth=require(*READ_ROLES, "registrar"))
def check_instructions(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Check instructions without storing them, for example in a CI pipeline.

    With the classifier configured this waits for its verdicts unless
    ``classifier`` is false."""
    rt = runtime(request)
    classify = body.get("classifier", True)
    if not isinstance(classify, bool):
        raise ValidationError("classifier must be true or false")
    result = instructions.check(body.get("text"), rt.guardian, classify=classify)
    return {**result, "classifier": {**classifier(rt), **result["classifier"]}}
