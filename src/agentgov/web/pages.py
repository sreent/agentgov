"""The pages around the API: "/", the API's description (/openapi.json), and its
documentation to read and try (/docs, /redoc)."""

from __future__ import annotations

from functools import cache
from typing import Any

from django.http import HttpRequest, HttpResponse

from agentgov.web.api import Router, api, json_response, raw_response, redirect_response

router = Router()

DESCRIPTION = (
    "Open-source AI agent governance: registry, lifecycle, policy distribution and evidence, "
    "composed from Keycloak, OPA, agentgateway, Presidio and OpenTelemetry."
)
SWAGGER = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5"
REDOC = "https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"


@router.get("/", include_in_schema=False)
def root(request: HttpRequest) -> HttpResponse:
    return redirect_response("/ui/")


@cache
def _description() -> dict[str, Any]:
    schema = api.get_openapi_schema(path_prefix="")
    schema["info"]["description"] = DESCRIPTION
    return schema


@router.get("/openapi.json", include_in_schema=False)
def description(request: HttpRequest) -> HttpResponse:
    return json_response(_description())


@router.get("/docs", include_in_schema=False)
def swagger(request: HttpRequest) -> HttpResponse:
    return raw_response(
        f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{api.title} - Swagger UI</title>
<link rel="stylesheet" href="{SWAGGER}/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="{SWAGGER}/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({{
  url: "/openapi.json",
  dom_id: "#swagger-ui",
  layout: "BaseLayout",
  deepLinking: true,
  showExtensions: true,
  showCommonExtensions: true,
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
}})
</script>
</body>
</html>
""",
        media_type="text/html",
    )


@router.get("/redoc", include_in_schema=False)
def redoc(request: HttpRequest) -> HttpResponse:
    return raw_response(
        f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{api.title} - ReDoc</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body {{ margin: 0; padding: 0; }}</style>
</head>
<body>
<redoc spec-url="/openapi.json"></redoc>
<script src="{REDOC}"></script>
</body>
</html>
""",
        media_type="text/html",
    )
