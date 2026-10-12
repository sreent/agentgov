"""AWS credentials and request signing (Signature Version 4), without the AWS SDK.

Credentials come from where the AWS SDKs look for them, in this order:

* ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY`` and ``AWS_SESSION_TOKEN``;
* a web identity token (``AWS_ROLE_ARN`` and ``AWS_WEB_IDENTITY_TOKEN_FILE``): IAM
  roles for service accounts on EKS;
* the container credentials endpoint (``AWS_CONTAINER_CREDENTIALS_FULL_URI`` or
  ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI``): EKS Pod Identity and ECS;
* the instance metadata service (IMDSv2): an EC2 instance's role.

:class:`Session` keeps them, renews temporary ones before they expire, and can
assume another role with them (another account's, for example).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import httpx

from agentgov.platforms.base import PlatformError

ALGORITHM = "AWS4-HMAC-SHA256"
# Temporary credentials are renewed this long before they expire.
EARLY = timedelta(minutes=5)
ECS_HOST = "http://169.254.170.2"
# The hosts the container credentials endpoint may be on, over plain HTTP: ECS's and EKS Pod
# Identity's agents, and the loopback.
CONTAINER_HOSTS = {
    "169.254.170.2",
    "169.254.170.23",
    "fd00:ec2::23",
    "127.0.0.1",
    "::1",
    "localhost",
}
IMDS = "http://169.254.169.254"
STS_NS = {"sts": "https://sts.amazonaws.com/doc/2011-06-15/"}


@dataclass(frozen=True)
class Credentials:
    access_key: str
    secret_key: str
    token: str | None = None
    expires: datetime | None = None

    def fresh(self, now: datetime) -> bool:
        return self.expires is None or now < self.expires - EARLY


def _hmac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode(), hashlib.sha256).digest()


def sign(
    method: str,
    url: str,
    *,
    region: str,
    service: str,
    credentials: Credentials,
    body: bytes = b"",
    headers: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """The headers to send with the request (``headers`` and the ones that sign it).

    As the AWS SDKs sign for services other than Amazon S3: the path, already
    percent-encoded in ``url``, is encoded once more."""
    now = now or datetime.now(UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = amz_date[:8]
    parts = urlsplit(url)
    signed = {k.lower(): " ".join(str(v).split()) for k, v in (headers or {}).items()}
    signed["host"] = parts.netloc
    signed["x-amz-date"] = amz_date
    if credentials.token:
        signed["x-amz-security-token"] = credentials.token
    names = sorted(signed)
    query = sorted(
        (quote(unquote(k), safe="-_.~"), quote(unquote(v), safe="-_.~"))
        for k, _, v in (pair.partition("=") for pair in parts.query.split("&") if pair)
    )
    canonical = "\n".join(
        [
            method.upper(),
            quote(parts.path or "/", safe="/~"),
            "&".join(f"{k}={v}" for k, v in query),
            "".join(f"{name}:{signed[name]}\n" for name in names),
            ";".join(names),
            hashlib.sha256(body).hexdigest(),
        ]
    )
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(
        [ALGORITHM, amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()]
    )
    key = _hmac(("AWS4" + credentials.secret_key).encode(), day)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {name: signed[name] for name in names if name != "host"}
    out["authorization"] = (
        f"{ALGORITHM} Credential={credentials.access_key}/{scope}, "
        f"SignedHeaders={';'.join(names)}, Signature={signature}"
    )
    return out


def _expiry(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


class Session:
    """Credentials for one AWS identity, renewed as they expire."""

    def __init__(
        self,
        http: httpx.Client,
        *,
        env: Mapping[str, str] | None = None,
        region: str = "us-east-1",
        role_arn: str | None = None,
        base: Session | None = None,
        external_id: str | None = None,
        session_name: str = "agentgov",
    ) -> None:
        self.http = http
        self.env = os.environ if env is None else env
        self.region = region
        # Assumed with ``base``'s credentials, when set.
        self.role_arn = role_arn
        self.base = base
        self.external_id = external_id
        self.session_name = session_name
        self._lock = threading.Lock()
        self._credentials: Credentials | None = None

    def credentials(self) -> Credentials:
        now = datetime.now(UTC)
        with self._lock:
            if self._credentials is None or not self._credentials.fresh(now):
                self._credentials = self._load()
            return self._credentials

    def _load(self) -> Credentials:
        if self.base is not None and self.role_arn:
            return self._assume_role()
        env = self.env
        if env.get("AWS_ACCESS_KEY_ID") and env.get("AWS_SECRET_ACCESS_KEY"):
            return Credentials(
                env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"], env.get("AWS_SESSION_TOKEN")
            )
        if env.get("AWS_ROLE_ARN") and env.get("AWS_WEB_IDENTITY_TOKEN_FILE"):
            return self._web_identity(env["AWS_ROLE_ARN"], env["AWS_WEB_IDENTITY_TOKEN_FILE"])
        if env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") or env.get(
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
        ):
            return self._container()
        return self._instance()

    def _sts(self) -> str:
        return f"https://sts.{self.region}.amazonaws.com/"

    def _sts_call(self, params: dict[str, str], *, signer: Session | None) -> ET.Element:
        """An STS call, signed with ``signer``'s credentials (unsigned without one)."""
        body = "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in params.items())
        headers = {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
        if signer is not None:
            headers = sign(
                "POST",
                self._sts(),
                region=self.region,
                service="sts",
                credentials=signer.credentials(),
                body=body.encode(),
                headers=headers,
            )
        try:
            resp = self.http.post(self._sts(), content=body.encode(), headers=headers)
        except httpx.HTTPError as exc:
            raise PlatformError(f"AWS STS is unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise PlatformError(
                f"AWS STS refused {params['Action']} ({resp.status_code}): {_sts_error(resp)}",
                status=resp.status_code,
            )
        try:
            # STS's own answer, over TLS; expat resolves no external entities.
            return ET.fromstring(resp.text)  # noqa: S314
        except ET.ParseError as exc:
            raise PlatformError(f"AWS STS answered {params['Action']} with no XML") from exc

    @staticmethod
    def _from_sts(root: ET.Element) -> Credentials:
        found = root.find(".//sts:Credentials", STS_NS)
        if found is None:
            raise PlatformError("AWS STS's answer has no credentials")

        def text(name: str) -> str:
            return found.findtext(f"sts:{name}", default="", namespaces=STS_NS)

        return Credentials(
            text("AccessKeyId"),
            text("SecretAccessKey"),
            text("SessionToken") or None,
            _expiry(text("Expiration") or None),
        )

    def _web_identity(self, role_arn: str, token_file: str) -> Credentials:
        try:
            token = Path(token_file).read_text().strip()
        except OSError as exc:
            raise PlatformError(f"can't read the web identity token {token_file}: {exc}") from exc
        root = self._sts_call(
            {
                "Action": "AssumeRoleWithWebIdentity",
                "Version": "2011-06-15",
                "RoleArn": role_arn,
                "RoleSessionName": self.env.get("AWS_ROLE_SESSION_NAME") or self.session_name,
                "WebIdentityToken": token,
            },
            signer=None,
        )
        return self._from_sts(root)

    def _assume_role(self) -> Credentials:
        assert self.role_arn
        params = {
            "Action": "AssumeRole",
            "Version": "2011-06-15",
            "RoleArn": self.role_arn,
            "RoleSessionName": self.session_name,
        }
        if self.external_id:
            params["ExternalId"] = self.external_id
        return self._from_sts(self._sts_call(params, signer=self.base))

    def account(self) -> str:
        """The AWS account these credentials belong to: an assumed role's is in its ARN,
        others' STS tells (GetCallerIdentity)."""
        if self.base is not None and self.role_arn:
            return self.role_arn.split(":")[4]
        root = self._sts_call({"Action": "GetCallerIdentity", "Version": "2011-06-15"}, signer=self)
        account = root.findtext(".//sts:Account", default="", namespaces=STS_NS)
        if not account:
            raise PlatformError("AWS STS didn't say which account the credentials belong to")
        return account

    def _container(self) -> Credentials:
        env = self.env
        url = env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") or (
            ECS_HOST + env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
        )
        parts = urlsplit(url)
        # As the AWS SDKs do: the token goes over TLS, or to the container hosts AWS uses.
        if parts.scheme != "https" and parts.hostname not in CONTAINER_HOSTS:
            raise PlatformError(
                f"AWS_CONTAINER_CREDENTIALS_FULL_URI must use https or a container credentials "
                f"host ({', '.join(sorted(CONTAINER_HOSTS))}), not {parts.hostname}"
            )
        headers = {}
        token_file = env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
        try:
            if token_file:
                headers["Authorization"] = Path(token_file).read_text().strip()
            elif env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN"):
                headers["Authorization"] = env["AWS_CONTAINER_AUTHORIZATION_TOKEN"]
            resp = self.http.get(url, headers=headers, timeout=5)
        except (OSError, httpx.HTTPError) as exc:
            raise PlatformError(f"can't get credentials from {url}: {exc}") from exc
        if resp.status_code != 200:
            raise PlatformError(f"{url} gave no credentials ({resp.status_code})")
        return _from_json(resp)

    def _instance(self) -> Credentials:
        try:
            token = self.http.put(
                f"{IMDS}/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                timeout=2,
            )
            headers = {"X-aws-ec2-metadata-token": token.text} if token.status_code == 200 else {}
            base = f"{IMDS}/latest/meta-data/iam/security-credentials/"
            role = self.http.get(base, headers=headers, timeout=2)
            if role.status_code != 200 or not role.text.strip():
                raise PlatformError("the instance has no role")
            resp = self.http.get(
                base + role.text.strip().splitlines()[0], headers=headers, timeout=2
            )
        except httpx.HTTPError as exc:
            raise PlatformError(
                "no AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or run with "
                "a role (IAM roles for service accounts or Pod Identity on EKS, an instance role)"
            ) from exc
        if resp.status_code != 200:
            raise PlatformError(
                f"the instance metadata service gave no credentials ({resp.status_code})"
            )
        return _from_json(resp)


def _from_json(resp: httpx.Response) -> Credentials:
    try:
        data = resp.json()
        return Credentials(
            data["AccessKeyId"],
            data["SecretAccessKey"],
            data.get("Token"),
            _expiry(data.get("Expiration")),
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise PlatformError("the credentials endpoint's answer isn't AWS credentials") from exc


def _sts_error(resp: httpx.Response) -> str:
    try:
        root = ET.fromstring(resp.text)  # noqa: S314 - as above
    except ET.ParseError:
        return resp.text[:200]
    code = root.findtext(".//sts:Error/sts:Code", default="", namespaces=STS_NS)
    message = root.findtext(".//sts:Error/sts:Message", default="", namespaces=STS_NS)
    return f"{code}: {message}".strip(": ") or resp.text[:200]
