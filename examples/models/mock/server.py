"""A stand-in model provider for the AgentGov demo, speaking OpenAI's chat API.

It answers with an echo of the last message, so the demo shows what reached the
provider (personal data masked by the gateway), and it accepts only the API key
the gateway holds (MOCK_MODEL_KEY), so the agent never needs it. Asked for "the
deploy key", it leaks a fake credential: the gateway withholds that answer.

Standard library only; no real model is called.
"""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = os.environ.get("MOCK_MODEL_KEY", "demo-model-key")
LEAK = "The deploy key is AKIAIOSFODNN7EXAMPLE."  # AWS's documented example key


def answer(messages: list[dict]) -> str:
    last = str((messages or [{}])[-1].get("content") or "")
    return LEAK if "deploy key" in last.lower() else f"You said: {last}"


def tokens(text: str) -> int:
    return max(1, len(text.split()))


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict | str, content_type: str = "application/json") -> None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:
        if not self.path.endswith("/chat/completions"):
            self._send(404, {"error": {"message": "not found"}})
            return
        if self.headers.get("Authorization") != f"Bearer {KEY}":
            self._send(401, {"error": {"message": "invalid API key", "type": "auth"}})
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        messages = body.get("messages") or []
        text = answer(messages)
        usage = {
            "prompt_tokens": sum(tokens(str(m.get("content") or "")) for m in messages),
            "completion_tokens": tokens(text),
        }
        usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
        reply = {
            "id": f"chatcmpl-{time.time_ns()}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model") or "mock",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": usage,
        }
        if not body.get("stream"):
            self._send(200, reply)
            return
        chunk = {**reply, "object": "chat.completion.chunk"}
        events = [
            {**chunk, "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]},
            {**chunk, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        ]
        if (body.get("stream_options") or {}).get("include_usage"):
            events.append({**chunk, "choices": [], "usage": usage})
        stream = "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"
        self._send(200, stream, "text/event-stream")

    def log_message(self, fmt: str, *args: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9100), Handler).serve_forever()  # noqa: S104
