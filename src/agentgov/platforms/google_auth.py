"""Google Cloud access tokens, without Google's client libraries.

Credentials come from where Google's libraries look for them (Application
Default Credentials):

* the file ``GOOGLE_APPLICATION_CREDENTIALS`` names: a service account key, or a
  workload identity federation configuration (``external_account``), which trades
  a token from another identity provider (EKS, AKS, any OIDC issuer) for a Google
  one, without a key;
* gcloud's application default credentials (``gcloud auth application-default
  login``), to try it on your machine as yourself;
* otherwise the metadata server: GKE's Workload Identity, or a VM's service account.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import jwt

from agentgov.platforms.base import PlatformError

SCOPE = "https://www.googleapis.com/auth/cloud-platform"
METADATA = "http://metadata.google.internal/computeMetadata/v1"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - a grant type
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 - a token type
# Tokens are renewed this many seconds before they expire.
EARLY = 300


class GoogleCredentials:
    """An access token for Google Cloud's APIs, renewed as it expires."""

    def __init__(self, http: httpx.Client, *, env: Mapping[str, str] | None = None) -> None:
        self.http = http
        self.env = os.environ if env is None else env
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires = 0.0
        self._config: dict[str, Any] | None = None

    def token(self) -> str:
        with self._lock:
            if self._token is None or time.monotonic() >= self._expires - EARLY:
                self._token, lifetime = self._fetch()
                self._expires = time.monotonic() + lifetime
            return self._token

    def headers(self) -> dict[str, str]:
        """What to send with each request: the token, and for a person's credentials the
        project their use is counted against (Google's own project otherwise)."""
        headers = {"Authorization": f"Bearer {self.token()}"}
        quota = (self._config or {}).get("quota_project_id")
        if quota:
            headers["x-goog-user-project"] = str(quota)
        return headers

    def _file(self) -> dict[str, Any] | None:
        path = self.env.get("GOOGLE_APPLICATION_CREDENTIALS")
        if not path:
            path = self._gcloud_file()
        if not path:
            return None
        if self._config is None:
            try:
                self._config = json.loads(Path(path).read_text())
            except (OSError, ValueError) as exc:
                raise PlatformError(f"can't read Google credentials from {path}: {exc}") from exc
        return self._config

    def _gcloud_file(self) -> str | None:
        """gcloud's application default credentials, where they exist."""
        folder = self.env.get("CLOUDSDK_CONFIG")
        if not folder and self.env.get("HOME"):
            folder = str(Path(self.env["HOME"]) / ".config" / "gcloud")
        path = Path(folder) / "application_default_credentials.json" if folder else None
        return str(path) if path is not None and path.is_file() else None

    def _fetch(self) -> tuple[str, float]:
        config = self._file()
        if config is None:
            return self._metadata()
        return self._from(config)

    def _from(self, config: dict[str, Any]) -> tuple[str, float]:
        kind = config.get("type")
        if kind == "service_account":
            return self._service_account(config)
        if kind == "external_account":
            return self._external_account(config)
        if kind == "authorized_user":
            return self._authorized_user(config)
        if kind == "impersonated_service_account":
            # gcloud auth application-default login --impersonate-service-account
            source, _ = self._from(config.get("source_credentials") or {})
            return self._impersonate(config.get("service_account_impersonation_url"), source)
        raise PlatformError(
            f"the Google credentials are {kind!r}: use a service account key, a workload "
            "identity federation configuration or gcloud's application default credentials"
        )

    def _post(self, url: str, data: dict[str, str], what: str, **kw: Any) -> dict[str, Any]:
        try:
            resp = self.http.post(url, data=data, **kw)
        except httpx.HTTPError as exc:
            raise PlatformError(f"{what}: {url} is unreachable: {exc}") from exc
        return _json(resp, what)

    def _service_account(self, key: dict[str, Any]) -> tuple[str, float]:
        token_uri = key.get("token_uri") or "https://oauth2.googleapis.com/token"
        now = int(time.time())
        try:
            assertion = jwt.encode(
                {
                    "iss": key["client_email"],
                    "scope": SCOPE,
                    "aud": token_uri,
                    "iat": now,
                    "exp": now + 3600,
                },
                key["private_key"],
                algorithm="RS256",
                headers={"kid": key.get("private_key_id")} if key.get("private_key_id") else None,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise PlatformError(f"the service account key can't sign: {exc}") from exc
        answer = self._post(
            token_uri,
            {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion},
            "Google refused the service account key",
        )
        return _token(answer, "access_token"), float(answer.get("expires_in", 3600))

    def _authorized_user(self, config: dict[str, Any]) -> tuple[str, float]:
        try:
            data = {
                "grant_type": "refresh_token",
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "refresh_token": config["refresh_token"],
            }
        except KeyError as exc:
            raise PlatformError(f"the user's Google credentials lack {exc}") from exc
        answer = self._post(
            config.get("token_uri") or "https://oauth2.googleapis.com/token",
            data,
            "Google refused the user's credentials (gcloud auth application-default login)",
        )
        return _token(answer, "access_token"), float(answer.get("expires_in", 3600))

    def _subject_token(self, source: dict[str, Any]) -> str:
        if source.get("file"):
            try:
                text = Path(source["file"]).read_text()
            except OSError as exc:
                raise PlatformError(f"can't read the token to exchange: {exc}") from exc
        elif source.get("url"):
            try:
                resp = self.http.get(source["url"], headers=source.get("headers") or {})
            except httpx.HTTPError as exc:
                raise PlatformError(f"can't get the token to exchange: {exc}") from exc
            text = resp.text
        else:
            raise PlatformError(
                "the workload identity federation configuration must take its token from a "
                "file or a URL (AWS and executable sources aren't supported)"
            )
        fmt = source.get("format") or {}
        if fmt.get("type") == "json":
            try:
                return str(json.loads(text)[fmt["subject_token_field_name"]])
            except (ValueError, KeyError) as exc:
                raise PlatformError(f"the token to exchange isn't in the JSON: {exc}") from exc
        return text.strip()

    def _external_account(self, config: dict[str, Any]) -> tuple[str, float]:
        answer = self._post(
            config.get("token_url") or "https://sts.googleapis.com/v1/token",
            {
                "grant_type": TOKEN_EXCHANGE,
                "audience": config.get("audience", ""),
                "scope": SCOPE,
                "requested_token_type": ACCESS_TOKEN,
                "subject_token_type": config.get("subject_token_type", ""),
                "subject_token": self._subject_token(config.get("credential_source") or {}),
            },
            "Google's Security Token Service refused the token",
        )
        federated = _token(answer, "access_token")
        impersonate = config.get("service_account_impersonation_url")
        if not impersonate:
            return federated, float(answer.get("expires_in", 3600))
        return self._impersonate(impersonate, federated)

    def _impersonate(self, url: str | None, token: str) -> tuple[str, float]:
        """A token for the service account at ``url``, got with ``token``."""
        if not url:
            raise PlatformError("the Google credentials name no service account to impersonate")
        try:
            resp = self.http.post(
                url, json={"scope": [SCOPE]}, headers={"Authorization": f"Bearer {token}"}
            )
        except httpx.HTTPError as exc:
            raise PlatformError(f"can't impersonate the service account: {exc}") from exc
        impersonated = _json(resp, "Google refused to impersonate the service account")
        return _token(impersonated, "accessToken"), 3600.0

    def _metadata(self) -> tuple[str, float]:
        try:
            resp = self.http.get(
                f"{METADATA}/instance/service-accounts/default/token",
                headers={"Metadata-Flavor": "Google"},
                timeout=3,
            )
        except httpx.HTTPError as exc:
            raise PlatformError(
                "no Google credentials: set GOOGLE_APPLICATION_CREDENTIALS to a workload "
                "identity federation configuration or a service account key, run on GKE with "
                "Workload Identity, or sign in with gcloud auth application-default login"
            ) from exc
        answer = _json(resp, "the metadata server gave no token")
        return _token(answer, "access_token"), float(answer.get("expires_in", 3600))


def _token(answer: dict[str, Any], key: str) -> str:
    token = answer.get(key)
    if not isinstance(token, str) or not token:
        raise PlatformError("Google's answer has no access token")
    return token


def _json(resp: httpx.Response, what: str) -> dict[str, Any]:
    try:
        body = resp.json()
    except ValueError:
        body = None
    if resp.status_code != 200 or not isinstance(body, dict):
        detail = ""
        if isinstance(body, dict):
            error = body.get("error")
            if isinstance(error, dict):
                detail = error.get("message") or ""
            else:
                detail = body.get("error_description") or str(error or "")
        raise PlatformError(
            f"{what} ({resp.status_code}): {detail or resp.text[:200]}", status=resp.status_code
        )
    return body
