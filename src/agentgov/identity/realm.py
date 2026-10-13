"""AgentGov's Keycloak realm, made for an installation (docs/deploy/server.md).

The realm in deploy/compose/keycloak is the one the evaluation stack imports: it sends
administrators back to http://localhost:8000 after they sign in, and comes with the demo's
people (whose password everybody knows) and the demo app they sign in to. An installation
others rely on wants it at its own address, and without them. The Helm chart does the same
to the copy it carries (deploy/helm/agentgov/templates/keycloak.yaml).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

# Where the realm sends administrators back to, as it comes.
LOCAL_URL = "http://localhost:8000"
# The demo's app people sign in to, which goes with the demo's people.
DEMO_APP = "agentgov-demo-chat"


def for_installation(
    realm: dict[str, Any], *, public_url: str | None = None, demo_users: bool = True
) -> dict[str, Any]:
    """The realm with its sign-in redirects at ``public_url`` (the control plane's address),
    and, without ``demo_users``, only the service accounts' users and no demo app."""
    if public_url is not None:
        parts = urlsplit(public_url)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.path not in ("", "/"):
            raise ValueError(
                f"{public_url!r} isn't the control plane's address, such as "
                "https://agentgov.example.com"
            )
        text = json.dumps(realm).replace(LOCAL_URL, public_url.rstrip("/"))
        realm = json.loads(text)
    else:
        realm = json.loads(json.dumps(realm))
    if not demo_users:
        realm["users"] = [u for u in realm.get("users", []) if "serviceAccountClientId" in u]
        realm["clients"] = [c for c in realm.get("clients", []) if c.get("clientId") != DEMO_APP]
    return realm
