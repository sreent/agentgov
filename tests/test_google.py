"""Google Cloud: access tokens (agentgov.platforms.google_auth) and the connector
(agentgov.platforms.google)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from agentgov.platforms.base import PlatformError
from agentgov.platforms.google_auth import SCOPE, GoogleCredentials
from tests.conftest import ADMIN

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()
EMAIL = "agentgov-reader@contoso-agents.iam.gserviceaccount.com"


class FakeGoogle:
    """Google's OAuth token endpoint, its Security Token Service, the IAM credentials API
    and a GKE metadata server."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.issued = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if url == "https://oauth2.googleapis.com/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            if form["grant_type"] == "refresh_token":  # a person's, from gcloud
                assert (form["client_id"], form["refresh_token"]) == ("gcloud", "refresh-me")
                return httpx.Response(200, json={"access_token": "user", "expires_in": 3599})
            claims = jwt.decode(
                form["assertion"],
                KEY.public_key(),
                algorithms=["RS256"],
                audience="https://oauth2.googleapis.com/token",
            )
            if claims["iss"] != EMAIL or claims["scope"] != SCOPE:
                return httpx.Response(400, json={"error": "invalid_grant"})
            self.issued += 1
            return httpx.Response(
                200, json={"access_token": f"sa-{self.issued}", "expires_in": 3599}
            )
        if url == "https://sts.googleapis.com/v1/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            if form["subject_token"] != "eks-oidc-token":
                return httpx.Response(
                    400,
                    json={"error": "invalid_grant", "error_description": "The token is invalid"},
                )
            return httpx.Response(200, json={"access_token": "federated", "expires_in": 3600})
        if url.endswith(f"/serviceAccounts/{EMAIL}:generateAccessToken"):
            source = request.headers["authorization"].removeprefix("Bearer ")
            assert source in ("federated", "user")
            return httpx.Response(200, json={"accessToken": f"as-{source}", "expireTime": "x"})
        if request.url.host == "metadata.google.internal":
            assert request.headers["metadata-flavor"] == "Google"
            return httpx.Response(200, json={"access_token": "gke", "expires_in": 3600})
        return httpx.Response(404)


@pytest.fixture
def google() -> FakeGoogle:
    return FakeGoogle()


@pytest.fixture
def http(google: FakeGoogle) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(google.handle))


def write(tmp_path: Path, config: dict) -> dict[str, str]:
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps(config))
    return {"GOOGLE_APPLICATION_CREDENTIALS": str(path)}


def test_a_service_account_key(http, google, tmp_path) -> None:
    env = write(
        tmp_path,
        {
            "type": "service_account",
            "client_email": EMAIL,
            "private_key": PEM,
            "private_key_id": "k1",
        },
    )
    credentials = GoogleCredentials(http, env=env)
    assert credentials.token() == "sa-1"
    assert credentials.token() == "sa-1"  # kept until it nears its expiry
    assert google.issued == 1


def test_workload_identity_federation_without_a_key(http, google, tmp_path) -> None:
    token = tmp_path / "token"
    token.write_text("eks-oidc-token\n")
    env = write(
        tmp_path,
        {
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/1/locations/global/"
            "workloadIdentityPools/eks/providers/agentgov",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1/token",
            "credential_source": {"file": str(token)},
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/"
            f"projects/-/serviceAccounts/{EMAIL}:generateAccessToken",
        },
    )
    assert GoogleCredentials(http, env=env).token() == "as-federated"
    exchange = google.requests[0]
    form = {k: v[0] for k, v in parse_qs(exchange.content.decode()).items()}
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert form["audience"].endswith("/providers/agentgov")


def test_gke_workload_identity(http) -> None:
    assert GoogleCredentials(http, env={}).token() == "gke"


def test_google_says_why_it_refused(http, tmp_path) -> None:
    token = tmp_path / "token"
    token.write_text("someone-elses-token")
    env = write(
        tmp_path,
        {
            "type": "external_account",
            "audience": "//iam.googleapis.com/x",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "credential_source": {"file": str(token)},
        },
    )
    with pytest.raises(PlatformError, match=r"400.*The token is invalid"):
        GoogleCredentials(http, env=env).token()


USER = {
    "type": "authorized_user",
    "client_id": "gcloud",
    "client_secret": "not-really-secret",
    "refresh_token": "refresh-me",
    "quota_project_id": "contoso-agents",
}


def test_gcloud_application_default_credentials(http, tmp_path) -> None:
    folder = tmp_path / ".config" / "gcloud"
    folder.mkdir(parents=True)
    (folder / "application_default_credentials.json").write_text(json.dumps(USER))
    credentials = GoogleCredentials(http, env={"HOME": str(tmp_path)})
    # A person's use is counted against their project, not gcloud's.
    assert credentials.headers() == {
        "Authorization": "Bearer user",
        "x-goog-user-project": "contoso-agents",
    }


def test_gcloud_impersonating_a_service_account(http, tmp_path) -> None:
    env = write(
        tmp_path,
        {
            "type": "impersonated_service_account",
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/"
            f"projects/-/serviceAccounts/{EMAIL}:generateAccessToken",
            "source_credentials": USER,
        },
    )
    credentials = GoogleCredentials(http, env=env)
    assert credentials.headers() == {"Authorization": "Bearer as-user"}


def test_unsupported_credentials(http, tmp_path) -> None:
    env = write(tmp_path, {"type": "external_account_authorized_user"})
    with pytest.raises(PlatformError, match="'external_account_authorized_user'"):
        GoogleCredentials(http, env=env).token()


# ------------------------------------------------------------------- the connector

PROJECT = "contoso-agents"
RUNTIME = "https://us-central1-aiplatform.googleapis.com/v1/projects/contoso-agents/locations"
ENGINES = "projects/123456/locations/us-central1/reasoningEngines"


def engine(id_: str, display: str, spec: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "name": f"{ENGINES}/{id_}",
        "displayName": display,
        "spec": {"agentFramework": "google-adk", **spec},
        "updateTime": "2026-10-01T10:00:00Z",
        **extra,
    }


class FakeGoogleCloud:
    """Agent Runtime in us-central1 (two pages) and europe-west4 (refusing), with a GKE
    metadata server for tokens."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.engines = [
            engine(
                "111",
                "Trip planner",
                {
                    "effectiveIdentity": "service-123456@"
                    "gcp-sa-aiplatform-re.iam.gserviceaccount.com",
                    "deploymentSpec": {
                        "env": [
                            {"name": "OPENAI_API_KEY", "value": "sk-live-very-secret"},
                            {"name": "LOG_LEVEL", "value": "info"},
                        ],
                        "secretEnv": [
                            {"name": "DB_PASSWORD", "secretRef": {"secret": "db", "version": "1"}}
                        ],
                    },
                },
            ),
            engine(
                "222",
                "HR helper",
                {
                    "identityType": "SERVICE_ACCOUNT",
                    "serviceAccount": "123456-compute@developer.gserviceaccount.com",
                    "deploymentSpec": {"pscInterfaceConfig": {"networkAttachment": "na-1"}},
                },
            ),
            engine(
                "333",
                "Claims agent",
                {"identityType": "AGENT_IDENTITY"},
                contextSpec={"memoryBankConfig": {"generationConfig": {}}},
            ),
        ]
        self.policies: dict[str, dict[str, Any]] = {
            f"{ENGINES}/111": {
                "bindings": [
                    {
                        "role": "roles/aiplatform.user",
                        "members": ["allAuthenticatedUsers", "allUsers"],
                    }
                ]
            },
            f"{ENGINES}/333": {
                "bindings": [{"role": "roles/aiplatform.user", "members": ["domain:contoso.com"]}]
            },
        }

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url).split("?")[0]
        if request.url.host == "metadata.google.internal":
            return httpx.Response(200, json={"access_token": "gke", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer gke"
        if url == f"{RUNTIME}/us-central1/reasoningEngines":
            if request.url.params.get("pageToken") == "2":
                return httpx.Response(200, json={"reasoningEngines": self.engines[2:]})
            return httpx.Response(
                200, json={"reasoningEngines": self.engines[:2], "nextPageToken": "2"}
            )
        if url.startswith("https://europe-west4-aiplatform.googleapis.com/"):
            return httpx.Response(
                403,
                json={
                    "error": {
                        "code": 403,
                        "status": "PERMISSION_DENIED",
                        "message": "Permission 'aiplatform.reasoningEngines.list' denied",
                    }
                },
            )
        if url.endswith(":getIamPolicy"):
            # Google's getIamPolicy here takes the policy version as a parameter, no body.
            assert request.method == "POST" and not request.content
            assert request.url.params["options.requestedPolicyVersion"] == "3"
            name = url.split("/v1/", 1)[1].removesuffix(":getIamPolicy")
            if name not in self.policies:
                return httpx.Response(403, json={"error": {"status": "PERMISSION_DENIED"}})
            return httpx.Response(200, json=self.policies[name])
        return httpx.Response(404, json={"error": {"message": f"no {url}"}})


@pytest.fixture
def cloud() -> FakeGoogleCloud:
    return FakeGoogleCloud()


@pytest.fixture
def google_client(settings, cloud) -> Iterator[TestClient]:
    from agentgov.api.app import create_app
    from agentgov.platforms.google import GoogleConnector
    from agentgov.runtime import Runtime

    settings = settings.with_overrides(
        google_cloud_projects=PROJECT, google_cloud_regions="us-central1,europe-west4"
    )
    runtime = Runtime(settings)
    runtime.platforms["google-cloud"] = GoogleConnector(
        settings,
        http=httpx.Client(transport=httpx.MockTransport(cloud.handle)),
        env={},
        sleep=lambda seconds: None,
    )
    with TestClient(create_app(settings, runtime=runtime, background=False)) as client:
        yield client


def _agent(client: TestClient, name: str) -> dict[str, Any]:
    resp = client.get(f"/v1/agents/{name}", headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _findings(client: TestClient, name: str) -> dict[str, dict[str, Any]]:
    view = client.get("/v1/findings", params={"status": "open"}, headers=ADMIN).json()
    items = view["items"] if isinstance(view, dict) else view
    me = _agent(client, name)["id"]
    return {f["type"]: f for f in items if f.get("agent_id") == me}


def _facts(view: dict[str, Any]) -> dict[str, str]:
    return {f["label"]: f["value"] for f in view["facts"]}


def test_agents_on_google_cloud_are_read_into_the_registry(google_client, cloud) -> None:
    resp = google_client.post("/v1/platforms/google-cloud/sync", headers=ADMIN)
    assert resp.status_code == 200, resp.text
    counts = resp.json()
    assert (counts["created"], counts["updated"], counts["failed"]) == (3, 0, 1)

    trip = _agent(google_client, "trip-planner")
    assert trip["source"] == "platform:google-cloud"
    assert trip["platform"] == "Agent Runtime agent"
    facts = _facts(trip["platforms"][0])
    assert facts["Runs as"] == "The project's Agent Runtime service agent"
    assert facts["Who may use it"] == "Anyone"
    assert facts["Network"] == "Google's network and the internet"
    assert facts["Environment variables"] == "LOG_LEVEL, OPENAI_API_KEY"
    assert facts["From Secret Manager"] == "DB_PASSWORD"
    found = _findings(google_client, "trip-planner")
    assert found["platform.no_authentication"]["severity"] == "high"
    assert "anyone on the internet" in found["platform.no_authentication"]["title"]
    assert found["platform.broad_identity"]["severity"] == "medium"
    assert found["platform.plain_secret"]["details"]["variables"] == ["OPENAI_API_KEY"]
    assert "sk-live-very-secret" not in json.dumps(trip)

    # Its IAM policy can't be read: who may use it is unknown, the rest was checked.
    hr = _agent(google_client, "hr-helper")
    facts = _facts(hr["platforms"][0])
    assert facts["Network"] == "A Private Service Connect interface into your network"
    assert facts["Who may use it"] == "AgentGov may not read its IAM policy"
    broad = _findings(google_client, "hr-helper")["platform.broad_identity"]
    assert broad["severity"] == "high" and broad["verified"] is True

    claims = _agent(google_client, "claims-agent")
    facts = _facts(claims["platforms"][0])
    assert facts["Runs as"] == "Its own agent identity"
    assert facts["Memory bank"] == "Kept until deleted"
    found = _findings(google_client, "claims-agent")
    assert "platform.broad_identity" not in found
    assert found["platform.shared_with_everyone"]["details"]["domains"] == ["contoso.com"]

    status = {
        s["source"]: s for s in google_client.get("/v1/platforms", headers=ADMIN).json()["sources"]
    }
    message = status["google-cloud"]["last_sync"]["message"]
    assert "contoso-agents/europe-west4/agent-runtime" in message
    assert "PERMISSION_DENIED" in message


def test_a_fixed_setting_resolves_and_an_unread_policy_keeps_its_finding(
    google_client, cloud
) -> None:
    google_client.post("/v1/platforms/google-cloud/sync", headers=ADMIN)
    # The trip planner gets an identity of its own; the claims agent's policy can't be read.
    cloud.engines[0]["spec"]["serviceAccount"] = (
        "trip-planner@contoso-agents.iam.gserviceaccount.com"
    )
    del cloud.policies[f"{ENGINES}/333"]
    for _ in range(2):  # a finding resolves once two syncs in a row find it fixed
        assert (
            google_client.post("/v1/platforms/google-cloud/sync", headers=ADMIN).status_code == 200
        )
    assert "platform.broad_identity" not in _findings(google_client, "trip-planner")
    shared = _findings(google_client, "claims-agent")["platform.shared_with_everyone"]
    assert shared["verified"] is False


def test_runtime_hosts() -> None:
    from agentgov.platforms.google import runtime_host

    assert runtime_host("europe-west4") == "https://europe-west4-aiplatform.googleapis.com"
    assert runtime_host("eu") == "https://aiplatform.eu.rep.googleapis.com"


def test_google_settings_are_checked() -> None:
    from agentgov.config import Settings

    with pytest.raises(ValueError, match="not a project ID"):
        Settings.from_env({"AGENTGOV_GOOGLE_CLOUD_PROJECTS": "Contoso Agents"})
    with pytest.raises(ValueError, match="not a Google Cloud region"):
        Settings.from_env({"AGENTGOV_GOOGLE_CLOUD_REGIONS": "us-central"})
