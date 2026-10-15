"""API keys expire: as chosen when made, at most AGENTGOV_API_KEY_MAX_DAYS, and a key in
use warns before then (docs/administration.md#signing-in)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from starlette.testclient import TestClient

from agentgov import cli, ids
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.db.models import ApiKey
from agentgov.models import Finding
from agentgov.registry import apikeys
from tests.conftest import ADMIN
from tests.test_cli import _Shared, ok, runner


def make(client: TestClient, **body: Any) -> dict[str, Any]:
    resp = client.post("/v1/apikeys", json={"name": "ci", "role": "auditor", **body}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()


def bearer(key: dict[str, Any]) -> dict[str, str]:
    return {"Authorization": f"Bearer {key['token']}"}


def days_from_now(value: str) -> float:
    return (
        datetime.fromisoformat(value.replace("Z", "+00:00")) - ids.utcnow()
    ).total_seconds() / 86400


def set_key(client: TestClient, key_id: str, **values: Any) -> None:
    with client.app.state.rt.db.transaction():  # type: ignore[attr-defined]
        ApiKey.objects.filter(pk=key_id).update(**values)


def issue(client: TestClient, key_id: str) -> Finding | None:
    with client.app.state.rt.db.session() as s:  # type: ignore[attr-defined]
        found = s.query(Finding).filter(Finding.key == f"{apikeys.EXPIRING}:{key_id}").one_or_none()
        if found is not None:
            s.expunge(found)
        return found


def scan(client: TestClient) -> None:
    client.post("/v1/posture/scan", headers=ADMIN).raise_for_status()


class TestLifetime:
    def test_new_keys_work_for_ninety_days_by_default(self, client) -> None:
        key = make(client)
        assert key["status"] == "active"
        assert 89.9 < days_from_now(key["expires_at"]) <= 90
        created = client.get("/v1/ledger", params={"type": "apikey.created"}, headers=ADMIN)
        assert created.json()[0]["details"]["expires_at"] == key["expires_at"]

    def test_as_chosen_or_never(self, client) -> None:
        assert 6.9 < days_from_now(make(client, expires_in_days=7)["expires_at"]) <= 7
        forever = make(client, expires_in_days=None)
        assert (forever["expires_at"], forever["status"]) == (None, "active")
        for wrong in (0, -1, "30", True, 36501):
            resp = client.post(
                "/v1/apikeys",
                json={"name": "ci", "role": "auditor", "expires_in_days": wrong},
                headers=ADMIN,
            )
            assert resp.status_code == 422, (wrong, resp.text)

    def test_an_expired_key_is_refused_and_says_so(self, client) -> None:
        key = make(client)
        assert client.get("/v1/agents", headers=bearer(key)).status_code == 200
        set_key(client, key["id"], expires_at=ids.utcnow() - timedelta(minutes=1))
        resp = client.get("/v1/agents", headers=bearer(key))
        assert resp.status_code == 401
        assert resp.json()["detail"].startswith("API key ci expired on ")
        [listed] = client.get("/v1/apikeys", headers=ADMIN).json()
        assert listed["status"] == "expired"

    def test_a_maximum_caps_every_key(self, settings: Settings) -> None:
        capped = settings.with_overrides(api_key_days=30, api_key_max_days=60)
        with TestClient(create_app(capped, background=False)) as client:
            assert 29.9 < days_from_now(make(client)["expires_at"]) <= 30
            for wrong in (None, 61):
                resp = client.post(
                    "/v1/apikeys",
                    json={"name": "ci", "role": "auditor", "expires_in_days": wrong},
                    headers=ADMIN,
                )
                assert resp.status_code == 422
                assert "AGENTGOV_API_KEY_MAX_DAYS" in resp.json()["detail"]
            # A key made before, with no expiry, works for the maximum from when it was made.
            old = make(client, expires_in_days=30)
            set_key(
                client,
                old["id"],
                expires_at=None,
                created_at=ids.utcnow() - timedelta(days=61),
            )
            assert client.get("/v1/agents", headers=bearer(old)).status_code == 401
            policy = client.get("/v1/access", headers=ADMIN).json()["api_keys"]
            assert policy == {"default_days": 30, "max_days": 60}

    def test_settings_are_checked(self) -> None:
        with pytest.raises(ValueError, match="AGENTGOV_API_KEY_DAYS"):
            Settings(api_key_days=0).validate()
        with pytest.raises(ValueError, match="can't be more than"):
            Settings(api_key_days=90, api_key_max_days=30).validate()


class TestWarning:
    def test_a_key_in_use_warns_before_it_expires(self, client) -> None:
        key = make(client, expires_in_days=10)
        client.get("/v1/agents", headers=bearer(key)).raise_for_status()
        scan(client)
        found = issue(client, key["id"])
        assert found is not None and found.status == "open" and found.severity == "medium"
        assert found.title.startswith("API key ci expires on ")
        assert "revoke this one" in found.remediation
        # Expired, it still says so: what used it needs a new key.
        set_key(client, key["id"], expires_at=ids.utcnow() - timedelta(days=1))
        scan(client)
        assert issue(client, key["id"]).title.startswith("API key ci expired on ")
        # Revoked, it is over.
        client.delete(f"/v1/apikeys/{key['id']}", headers=ADMIN).raise_for_status()
        assert issue(client, key["id"]).status == "resolved"

    def test_keys_nobody_uses_expire_quietly(self, client) -> None:
        unused = make(client, expires_in_days=10)
        far = make(client, expires_in_days=60)
        client.get("/v1/agents", headers=bearer(far)).raise_for_status()
        old = make(client, expires_in_days=10)
        set_key(client, old["id"], last_used_at=ids.utcnow() - timedelta(days=45))
        scan(client)
        assert issue(client, unused["id"]) is None
        assert issue(client, far["id"]) is None
        assert issue(client, old["id"]) is None


class TestCli:
    def test_create_and_list(self, client, monkeypatch) -> None:
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
        result = runner.invoke(
            cli.app, ["apikeys", "create", "ci", "--role", "auditor", "--expires-in", "30"]
        )
        assert result.exit_code == 0, result.output
        assert ", until 20" in result.stderr
        result = runner.invoke(
            cli.app, ["apikeys", "create", "forever", "--role", "auditor", "--no-expiry"]
        )
        assert "with no expiry" in result.stderr
        listed = ok(runner.invoke(cli.app, ["apikeys", "list"]))
        assert "never" in listed and "active" in listed
