"""A stand-in workload identity issuer for the AgentGov demo: what a Kubernetes cluster is
to the service account tokens of its pods.

It publishes its signing keys as a cluster's API server does, OpenID Connect discovery
at /.well-known/openid-configuration and the keys at /openid/v1/jwks, and it issues
tokens as Kubernetes' TokenRequest API does (``kubectl create token``): for a service
account, with the audience asked for, for minutes. Keycloak checks the tokens against
the keys, so an agent authenticates with its token instead of a client secret.

    POST /token {"subject": "system:serviceaccount:agents:support-bot",
                 "audience": "http://localhost:8180/realms/agentgov"}

Not for real use: anyone who can reach it gets a token for any subject.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

# As its tokens name it, and as Keycloak reaches it.
ISSUER = os.environ.get("ISSUER", "http://workload-issuer:9200").rstrip("/")
PORT = int(os.environ.get("PORT", "9200"))
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KEY_ID = uuid.uuid4().hex
JWK = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key())), "kid": KEY_ID}
JWK.update(use="sig", alg="RS256")
MAX_SECONDS = 3600  # Keycloak takes tokens valid for an hour at most


def token(subject: str, audience: str, seconds: int) -> str:
    now = int(time.time())
    claims: dict = {
        "iss": ISSUER,
        "sub": subject,
        "aud": [audience],
        "iat": now,
        "nbf": now,
        "exp": now + seconds,
        "jti": str(uuid.uuid4()),
    }
    # A service account's namespace and name, as Kubernetes adds them.
    parts = subject.split(":")
    if len(parts) == 4 and parts[:2] == ["system", "serviceaccount"]:
        uid = str(uuid.uuid5(uuid.NAMESPACE_URL, subject))
        claims["kubernetes.io"] = {
            "namespace": parts[2],
            "serviceaccount": {"name": parts[3], "uid": uid},
        }
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KEY_ID})


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/.well-known/openid-configuration":
            self._send(
                200,
                {
                    "issuer": ISSUER,
                    "jwks_uri": f"{ISSUER}/openid/v1/jwks",
                    "response_types_supported": ["id_token"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        elif self.path == "/openid/v1/jwks":
            self._send(200, {"keys": [JWK]})
        elif self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/token":
            self._send(404, {"error": "not found"})
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            subject, audience = str(body["subject"]), str(body["audience"])
            seconds = min(int(body.get("expiration_seconds", 600)), MAX_SECONDS)
        except (ValueError, KeyError, TypeError):
            self._send(400, {"error": 'send {"subject": "...", "audience": "..."}'})
            return
        self._send(200, {"token": token(subject, audience, seconds), "expires_in": seconds})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    print(f"workload issuer {ISSUER} on port {PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # noqa: S104
