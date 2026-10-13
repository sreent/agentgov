#!/usr/bin/env python3
"""Check a running inventory stack (deploy/compose/docker-compose.inventory.yml): the control
plane applied the inventory starting point, so the gateway's features are off and the
inventory's on, and it reads its platforms' state. scripts/ci.sh --e2e runs it.

  AGENTGOV_URL=http://localhost:8000 AGENTGOV_TOKEN=... scripts/check-inventory.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Any

OFF = ("mcp-gateway", "model-gateway", "a2a-gateway", "least-privilege", "data-protection")
ON = ("discovery", "posture-checks", "issues", "management-rules")


def get(path: str) -> Any:
    # The control plane the person running it names: http(s) only.
    url = f"{os.environ.get('AGENTGOV_URL', 'http://localhost:8000').rstrip('/')}{path}"
    if not url.startswith(("http://", "https://")):
        raise SystemExit(f"AGENTGOV_URL must be http(s): {url}")
    request = urllib.request.Request(  # noqa: S310
        url, headers={"Authorization": f"Bearer {os.environ['AGENTGOV_TOKEN']}"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
        return json.load(response)


def main() -> int:
    listed = get("/v1/features")
    features = listed if isinstance(listed, list) else listed["features"]
    modes = {f["key"]: f["mode"] for f in features}
    wrong = [f"{key} is {modes.get(key)}" for key in OFF if modes.get(key) != "off"]
    wrong += [f"{key} is off" for key in ON if modes.get(key) in (None, "off")]
    if wrong:
        print(f"the inventory starting point isn't in place: {'; '.join(wrong)}")
        return 1
    get("/v1/platforms")
    print("inventory stack: the gateway's features off, the inventory's on")
    return 0


if __name__ == "__main__":
    sys.exit(main())
