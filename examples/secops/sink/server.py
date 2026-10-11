"""A stand-in for the security team's tools in the AgentGov demo: it receives what AgentGov
hands off, as a SIEM, Slack and Microsoft Teams would, and shows what arrived.

    POST /v1/logs                    OpenTelemetry logs (OTLP/HTTP, JSON), as a collector would
    POST /services/collector/event   Splunk's HTTP Event Collector (Authorization: Splunk <token>)
    POST /webhook                    OCSF events as a JSON array or as JSON lines
    POST /slack/<anything>           a Slack incoming webhook
    POST /teams/<anything>           a Teams workflow's webhook (an Adaptive Card message)
    GET  /received?kind=<kind>       what arrived, newest last (kind: otlp, hec, webhook,
                                     slack or teams; all of them without)
    GET  /received?path=<path>       what one webhook got: one channel, such as
                                     /slack/T0000/B0000/demo-only

It also stands in for a time-stamping authority (RFC 3161), for the ledger's checkpoints
(docs/evidence.md), with the openssl command and a key it makes when it first signs:

    POST /tsa                        a TimeStampReq; answers a TimeStampResp
    GET  /tsa/cert                   its certificate, to verify its time-stamps with

Not for real use: it keeps everything in memory and anyone can read it.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("PORT", "9300"))
HEC_TOKEN = os.environ.get("HEC_TOKEN", "demo-hec-token")
MAX = 2000  # kept per kind
received: dict[str, list] = {"otlp": [], "hec": [], "webhook": [], "slack": [], "teams": []}
# The chats' messages by webhook path too: each path is a channel.
by_path: dict[str, list] = {}
lock = threading.Lock()


TSA_CONFIG = """[ tsa ]
default_tsa = demo
[ demo ]
serial = {dir}/serial
signer_cert = {dir}/tsa.crt
signer_key = {dir}/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1.1
digests = sha256
accuracy = secs:1
ordering = yes
ess_cert_id_alg = sha256
"""
tsa_lock = threading.Lock()
tsa_home: str | None = None


def tsa() -> str:
    """The stand-in authority's key, certificate and configuration, made once."""
    global tsa_home
    if tsa_home is None:
        home = tempfile.mkdtemp(prefix="tsa-")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", f"{home}/tsa.key", "-out", f"{home}/tsa.crt", "-days", "3650",
             "-subj", "/CN=AgentGov demo time-stamping authority",
             "-addext", "extendedKeyUsage=critical,timeStamping"],
            check=True, capture_output=True,
        )  # fmt: skip
        Path(home, "serial").write_text("01\n")
        Path(home, "tsa.cnf").write_text(TSA_CONFIG.format(dir=home))
        tsa_home = home
    return tsa_home


def timestamp(query: bytes) -> bytes:
    with tsa_lock, tempfile.TemporaryDirectory() as work:
        home = tsa()
        Path(work, "query.tsq").write_bytes(query)
        subprocess.run(
            ["openssl", "ts", "-reply", "-config", f"{home}/tsa.cnf",
             "-queryfile", f"{work}/query.tsq", "-out", f"{work}/reply.tsr"],
            check=True, capture_output=True,
        )  # fmt: skip
        return Path(work, "reply.tsr").read_bytes()


def keep(kind: str, items: list, path: str | None = None) -> None:
    with lock:
        received[kind].extend(items)
        del received[kind][:-MAX]
        if path:
            channel = by_path.setdefault(path, [])
            channel.extend(items)
            del channel[:-MAX]


def otlp_records(body: dict) -> list:
    """Each log record's body and attributes, decoded from OTLP's JSON encoding."""

    def value(v: dict):
        if "kvlistValue" in v:
            pairs = v["kvlistValue"].get("values", [])
            return {kv["key"]: value(kv.get("value", {})) for kv in pairs}
        if "arrayValue" in v:
            return [value(x) for x in v["arrayValue"].get("values", [])]
        for key in ("stringValue", "boolValue", "doubleValue"):
            if key in v:
                return v[key]
        return int(v["intValue"]) if "intValue" in v else None

    out = []
    for resource_logs in body.get("resourceLogs", []):
        for scope_logs in resource_logs.get("scopeLogs", []):
            for record in scope_logs.get("logRecords", []):
                attributes = record.get("attributes", [])
                out.append(
                    {
                        "body": value(record.get("body", {})),
                        "attributes": {a["key"]: value(a["value"]) for a in attributes},
                        "severity": record.get("severityText"),
                    }
                )
    return out


def json_lines(text: str) -> list:
    """Splunk's HEC and JSON lines: JSON objects one after another."""
    decoder, items, i = json.JSONDecoder(), [], 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        item, i = decoder.raw_decode(text, i)
        items.append(item)
    return items


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: object, content_type: str = "application/json") -> None:
        if isinstance(body, bytes):
            data = body
        else:
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if url.path == "/healthz":
            self._send(200, {"status": "ok"})
        elif url.path == "/tsa/cert":
            with tsa_lock:
                self._send(200, Path(tsa(), "tsa.crt").read_bytes(), "application/x-pem-file")
        elif url.path == "/received":
            query = parse_qs(url.query)
            kind, path = query.get("kind", [None])[0], query.get("path", [None])[0]
            with lock:
                if path:
                    self._send(200, by_path.get(path, []))
                else:
                    self._send(200, received.get(kind, []) if kind else received)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if path == "/tsa":
            try:
                self._send(200, timestamp(body), "application/timestamp-reply")
            except (OSError, subprocess.CalledProcessError) as exc:
                self._send(503, {"error": f"can't time-stamp: {exc}"})
            return
        raw = body.decode()
        try:
            if path == "/v1/logs":
                keep("otlp", otlp_records(json.loads(raw)))
                self._send(200, {"partialSuccess": {}})
            elif path == "/services/collector/event":
                if self.headers.get("Authorization") != f"Splunk {HEC_TOKEN}":
                    self._send(401, {"text": "Invalid token", "code": 4})
                    return
                keep("hec", json_lines(raw))
                self._send(200, {"text": "Success", "code": 0})
            elif path == "/webhook":
                data = json.loads(raw) if raw.lstrip().startswith("[") else json_lines(raw)
                keep("webhook", data)
                self._send(200, {"received": len(data)})
            elif path.startswith("/slack/"):
                keep("slack", [json.loads(raw)], path)
                self._send(200, "ok", "text/plain")
            elif path.startswith("/teams/"):
                keep("teams", [json.loads(raw)], path)
                self._send(202, "", "text/plain")
            else:
                self._send(404, {"error": "not found"})
        except (ValueError, KeyError, TypeError) as exc:
            self._send(400, {"error": f"unreadable: {exc}"})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    print(f"security operations sink on port {PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # noqa: S104
