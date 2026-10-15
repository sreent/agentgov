#!/usr/bin/env python3
"""A control plane for the admin UI's browser tests (ui/e2e): a database of its own in a
temporary folder, a known admin token, and the examples' manifests applied. Playwright
starts it (ui/playwright.config.ts) and stops it when the tests end.

    python scripts/ui-test-server.py [--port 8765] [--log FILE]

It applies the manifests to a first server on another port, then serves on --port: the
tests start once that port answers, so they never see a half-applied inventory. With
--log, the control plane's output goes to FILE (Playwright's: ui/test-results/
control-plane.log), and if it doesn't start, the end of it to standard error.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from importlib.resources import files
from pathlib import Path
from types import FrameType

ROOT = Path(__file__).resolve().parent.parent
# The tests' own admin token (ui/e2e/fixtures.ts), on a control plane only they reach.
ADMIN_TOKEN = "ui-test-admin-token"  # noqa: S105


def wait_ready(url: str, server: subprocess.Popen[bytes], timeout: float = 60) -> str | None:
    """None once the control plane answers at url, else what went wrong."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server.poll() is not None:
            return f"the control plane stopped (exit {server.returncode})"
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310
                if resp.status == 200:
                    return None
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.3)
    return f"the control plane didn't answer at {url}"


def fail(problem: str, log: Path | None) -> None:
    """Stop with the problem, and the end of the control plane's log."""
    if log is not None and log.exists():
        tail = log.read_text(errors="replace").splitlines()[-40:]
        problem += f"; the end of {log}:\n" + "\n".join(tail)
    sys.exit(problem)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--log", type=Path, help="Where the control plane's output goes.")
    args = parser.parse_args()
    # The admin UI the control plane serves: built from ui/ into the package.
    if not (files("agentgov") / "ui" / "index.html").is_file():
        sys.exit("The admin UI isn't built: run npm run build in ui/ first.")
    agentgov = shutil.which("agentgov", path=str(Path(sys.executable).parent)) or "agentgov"
    work = Path(tempfile.mkdtemp(prefix="agentgov-ui-test-"))
    # Nothing from the developer's own settings: the tests expect this setup alone.
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTGOV_")}
    env |= {
        "AGENTGOV_DATABASE_URL": f"sqlite:///{work}/agentgov.db",
        "AGENTGOV_ADMIN_TOKEN": ADMIN_TOKEN,
        "AGENTGOV_SERVICE_TOKEN": "ui-test-service-token",
        "AGENTGOV_PUBLIC_URL": f"http://127.0.0.1:{args.port}",
    }
    log = None
    if args.log is not None:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        log = args.log.open("ab")
    server: subprocess.Popen[bytes] | None = None

    def start(port: int) -> subprocess.Popen[bytes]:
        return subprocess.Popen(  # noqa: S603
            [agentgov, "server", "--host", "127.0.0.1", "--port", str(port)],
            env=env,
            stdout=log,
            stderr=log,
        )

    def stop(*_: object) -> None:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
        shutil.rmtree(work, ignore_errors=True)

    def on_signal(signum: int, _frame: FrameType | None) -> None:
        stop()
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    try:
        seed_port = args.port + 1
        server = start(seed_port)
        if problem := wait_ready(f"http://127.0.0.1:{seed_port}/readyz", server):
            fail(problem, args.log)
        seeding = {"AGENTGOV_URL": f"http://127.0.0.1:{seed_port}", "AGENTGOV_TOKEN": ADMIN_TOKEN}
        applied = subprocess.run(  # noqa: S603
            [agentgov, "apply", "-f", str(ROOT / "examples" / "manifests")],
            env=env | seeding,
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
        if applied.returncode:
            fail(f"agentgov apply failed (exit {applied.returncode})", args.log)
        stop_seed, server = server, None
        stop_seed.terminate()
        stop_seed.wait(timeout=10)
        server = start(args.port)
        if problem := wait_ready(f"http://127.0.0.1:{args.port}/readyz", server):
            fail(problem, args.log)
        where = f"; its log is {args.log}" if args.log else ""
        print(f"AgentGov for the UI tests at http://127.0.0.1:{args.port}/ui/{where}", flush=True)
        server.wait()
    finally:
        stop()


if __name__ == "__main__":
    main()
