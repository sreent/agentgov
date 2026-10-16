"""Ledger checkpoints in a transparency log (agentgov.transparency): adding them, checking
the log's answers offline, and what assessors get. A log of our own stands in for Rekor v2
(rekor-tiles), answering as it does: a hashedrekord entry, its index, and a proof that it
is in the tree a checkpoint the log signed describes."""

from __future__ import annotations

import base64
import copy
import dataclasses
import io
import json
import zipfile
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from typer.testing import CliRunner

from agentgov import cli, compliance, ledger, transparency
from agentgov.config import Settings
from agentgov.db.models import LedgerCheckpoint
from agentgov.runtime import Runtime
from tests.conftest import ADMIN
from tests.test_cli import _Shared, ok

ORIGIN = "rekor.example.com"
runner = CliRunner()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _leaf(data: bytes) -> bytes:
    return transparency._leaf(data)


def _root(leaves: list[bytes]) -> bytes:
    """A Merkle tree's hash (RFC 6962 section 2.1)."""
    if len(leaves) == 1:
        return _leaf(leaves[0])
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return transparency._node(_root(leaves[:k]), _root(leaves[k:]))


def _path(m: int, leaves: list[bytes]) -> list[bytes]:
    """An entry's audit path, from the leaf up (RFC 6962 section 2.1.1)."""
    if len(leaves) == 1:
        return []
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    if m < k:
        return [*_path(m, leaves[:k]), _root(leaves[k:])]
    return [*_path(m - k, leaves[k:]), _root(leaves[:k])]


class FakeRekor:
    """A Rekor v2 log in memory, signing its checkpoints with an Ed25519 key."""

    def __init__(self, origin: str = ORIGIN) -> None:
        self.origin = origin
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.leaves: list[bytes] = []
        self.requests: list[dict[str, Any]] = []
        self.fail: int | None = None

    def public_pem(self) -> bytes:
        return transparency.public_pem(self.key.public_key())

    def checkpoint(self, size: int, root: bytes) -> str:
        body = f"{self.origin}\n{size}\n{_b64(root)}\n"
        key_id = transparency.note_key_id(self.origin, self.key.public_key())[:4]
        signature = _b64(key_id + self.key.sign(body.encode()))
        return f"{body}\n— {self.origin} {signature}\n"

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v2/log/entries"
        if self.fail is not None:
            return httpx.Response(self.fail, text="reached max pushback; retry")
        req = json.loads(request.content)["hashedRekordRequestV002"]
        self.requests.append(req)
        signature = req["signature"]
        body = {
            "apiVersion": "0.0.2",
            "kind": "hashedrekord",
            "spec": {
                "hashedRekordV002": {
                    "data": {"algorithm": "SHA2_256", "digest": req["digest"]},
                    "signature": {
                        "content": signature["content"],
                        "verifier": {
                            "keyDetails": signature["verifier"]["keyDetails"],
                            "publicKey": signature["verifier"]["publicKey"],
                        },
                    },
                }
            },
        }
        canonical = json.dumps(body, separators=(",", ":")).encode()
        self.leaves.append(canonical)
        index, size = len(self.leaves) - 1, len(self.leaves)
        root = _root(self.leaves)
        key_id = transparency.note_key_id(self.origin, self.key.public_key())
        return httpx.Response(
            201,
            json={
                "logIndex": str(index),
                "logId": {"keyId": _b64(key_id)},
                "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
                "integratedTime": "0",
                "inclusionPromise": None,
                "inclusionProof": {
                    "logIndex": str(index),
                    "rootHash": _b64(root),
                    "treeSize": str(size),
                    "hashes": [_b64(h) for h in _path(index, self.leaves)],
                    "checkpoint": {"envelope": self.checkpoint(size, root)},
                },
                "canonicalizedBody": _b64(canonical),
            },
        )


@pytest.fixture
def log() -> FakeRekor:
    return FakeRekor()


@pytest.fixture
def keys(tmp_path: Path, log: FakeRekor) -> dict[str, Path]:
    key, public = transparency.generate(tmp_path / "transparency")
    log_key = tmp_path / "rekor.pub"
    log_key.write_bytes(log.public_pem())
    return {"key": key, "public": public, "log_key": log_key}


def _client(log: FakeRekor) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(log))


STATEMENT = ledger.statement(7, "ab" * 32)


# ------------------------------------------------------------------ the client


class TestTheLog:
    def test_entries_the_log_holds_check_out(self, log, keys) -> None:
        key = transparency.load_signing_key(keys["key"])
        log_key = transparency.load_log_key(keys["log_key"])
        with _client(log) as http:
            entries = [transparency.add("http://log", STATEMENT, key, http=http) for _ in range(5)]
        # The log only grows: each entry's proof leads to the root of the tree it went into.
        for i, entry in enumerate(entries):
            got = transparency.check(
                entry, STATEMENT, log_key=log_key, origin=ORIGIN, signer=key.public_key()
            )
            assert (got.index, got.tree_size, got.origin) == (i, i + 1, ORIGIN)
        # Each try signs anew, so the same statement twice is two entries, not a refusal.
        assert len({r["signature"]["content"] for r in log.requests}) == 5
        assert log.requests[0]["signature"]["verifier"]["keyDetails"] == "PKIX_ECDSA_P256_SHA_256"

    def test_answers_that_dont_prove_the_entry_are_refused(self, log, keys) -> None:
        key = transparency.load_signing_key(keys["key"])
        log_key = transparency.load_log_key(keys["log_key"])
        with _client(log) as http:
            transparency.add("http://log", STATEMENT, key, http=http)
            entry = transparency.add("http://log", STATEMENT, key, http=http)

        def refused(entry: dict[str, Any], why: str, **kw: Any) -> None:
            args = {"log_key": log_key, "origin": ORIGIN, "signer": key.public_key(), **kw}
            with pytest.raises(transparency.TransparencyError, match=why):
                transparency.check(entry, kw.pop("statement", STATEMENT), **args)

        with pytest.raises(transparency.TransparencyError, match="another statement"):
            transparency.check(
                entry, STATEMENT + b"x", log_key=log_key, origin=ORIGIN, signer=key.public_key()
            )
        refused(entry, "isn't signed by the log other.example", origin="other.example")
        refused(
            entry,
            "isn't signed by the log",
            log_key=ed25519.Ed25519PrivateKey.generate().public_key(),
        )
        refused(
            entry,
            "another key than AgentGov's",
            signer=ec.generate_private_key(ec.SECP256R1()).public_key(),
        )
        tampered = copy.deepcopy(entry)
        body = base64.b64decode(tampered["canonicalizedBody"]).replace(b"SHA2_256", b"SHA2_512")
        tampered["canonicalizedBody"] = _b64(body)
        refused(tampered, "isn't in the tree")
        moved = copy.deepcopy(entry)
        moved["logIndex"] = "0"
        refused(moved, "isn't in the tree")
        forged = copy.deepcopy(entry)
        envelope = forged["inclusionProof"]["checkpoint"]["envelope"]
        forged["inclusionProof"]["checkpoint"]["envelope"] = envelope.replace("\n2\n", "\n3\n", 1)
        refused(forged, "signature doesn't verify")
        refused({"logIndex": "0"}, "missing its proof")

    def test_the_log_refusing_or_unreachable(self, log, keys) -> None:
        key = transparency.load_signing_key(keys["key"])
        log.fail = 503
        with _client(log) as http, pytest.raises(transparency.TransparencyError, match="HTTP 503"):
            transparency.add("http://log", STATEMENT, key, http=http)

        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        with (
            httpx.Client(transport=httpx.MockTransport(down)) as http,
            pytest.raises(transparency.TransparencyError, match="can't be reached"),
        ):
            transparency.add("http://log", STATEMENT, key, http=http)

    def test_keys(self, tmp_path: Path, keys) -> None:
        # A key already there is kept.
        again, _ = transparency.generate(keys["key"].parent)
        assert again.read_bytes() == keys["key"].read_bytes()
        assert keys["key"].stat().st_mode & 0o777 == 0o600
        other = tmp_path / "rsa.pem"
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other.write_bytes(
            rsa_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        with pytest.raises(transparency.TransparencyError, match="isn't an ECDSA P-256 key"):
            transparency.load_signing_key(other)
        with pytest.raises(transparency.TransparencyError, match="isn't an Ed25519 public key"):
            transparency.load_log_key(keys["public"])
        assert transparency.origin_of("https://log2025-1.rekor.sigstore.dev") == (
            "log2025-1.rekor.sigstore.dev"
        )
        # A log of your own: its key, for rekor-tiles, and the public half AgentGov checks with.
        out = ok(runner.invoke(cli.app, ["transparency-key", "--log", str(tmp_path / "log")]))
        assert "log.pem" in out
        log_key = transparency.load_log_key(tmp_path / "log" / "log.pub")
        private = serialization.load_pem_private_key(
            (tmp_path / "log" / "log.pem").read_bytes(), None
        )
        assert transparency.public_pem(private.public_key()) == transparency.public_pem(log_key)
        transparency.generate_log_key(tmp_path / "log")  # kept
        assert transparency.load_log_key(tmp_path / "log" / "log.pub").public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ) == log_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def test_assessors_get_sigstore_formats(self, log, keys) -> None:
        key = transparency.load_signing_key(keys["key"])
        log_key = transparency.load_log_key(keys["log_key"])
        with _client(log) as http:
            entry = transparency.add("http://log", STATEMENT, key, http=http)
        found = transparency.bundle(entry, STATEMENT)
        assert found["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json"
        [tlog] = found["verificationMaterial"]["tlogEntries"]
        assert "inclusionPromise" not in tlog  # null in the log's answer: left out
        signature = found["messageSignature"]
        assert signature["messageDigest"]["algorithm"] == "SHA2_256"
        assert signature["signature"] == log.requests[0]["signature"]["content"]
        root = transparency.trusted_root("https://rekor.example.com", ORIGIN, log_key)
        [described] = root["tlogs"]
        assert described["publicKey"]["keyDetails"] == "PKIX_ED25519"
        assert described["logId"]["keyId"] == entry["logId"]["keyId"]


# ------------------------------------------------------------------- AgentGov


def _settings(settings: Settings, keys: dict[str, Path], **more: Any) -> Settings:
    rekor: dict[str, Any] = {
        "ledger_rekor_url": "https://rekor.example.com",
        "ledger_rekor_signing_key_file": str(keys["key"]),
        "ledger_rekor_log_key_file": str(keys["log_key"]),
    }
    return dataclasses.replace(settings, **{**rekor, **more})


def _runtime(settings: Settings, log: FakeRekor) -> Runtime:
    runtime = Runtime(settings, tlog_http=_client(log))
    runtime.init_db()
    return runtime


class TestCheckpoints:
    def test_checkpoints_go_into_the_log_checked(self, settings, log, keys) -> None:
        rt = _runtime(_settings(settings, keys), log)
        try:
            with rt.db.transaction() as tx:
                ledger.append(tx, type="admin.test", actor="admin:t")
            point = rt.make_checkpoint()
            assert point is not None
            assert point["log"] == {
                "url": "https://rekor.example.com",
                "logged": True,
                "index": 0,
                "logged_at": point["log"]["logged_at"],
                "checked": True,
                "error": None,
            }
            with rt.db.transaction():
                row = LedgerCheckpoint.objects.get(pk=point["seq"])
                statement = ledger.statement(row.seq, row.hash)
                assert row.tlog_entry["logIndex"] == "0"
            # Once in the log, it isn't added again.
            assert rt.log_checkpoints() == 0 and len(log.leaves) == 1
            log_key = transparency.load_log_key(keys["log_key"])
            transparency.check(row.tlog_entry, statement, log_key=log_key, origin=ORIGIN)
        finally:
            rt.db.dispose()

    def test_failures_are_kept_and_tried_again(self, settings, log, keys) -> None:
        rt = _runtime(_settings(settings, keys), log)
        try:
            with rt.db.transaction() as tx:
                ledger.append(tx, type="admin.test", actor="admin:t")
            log.fail = 503
            point = rt.make_checkpoint()
            assert point["log"]["logged"] is False
            assert "HTTP 503" in point["log"]["error"]
            log.fail = None
            assert rt.log_checkpoints() == 1
            with rt.db.transaction():
                row = LedgerCheckpoint.objects.get()
                assert (row.tlog_index, row.tlog_error, row.tlog_checked) == (0, None, True)
        finally:
            rt.db.dispose()

    def test_a_proof_that_doesnt_check_out_is_kept_with_why(self, settings, log, keys) -> None:
        # The log key configured isn't the log's.
        wrong = keys["log_key"].parent / "wrong.pub"
        wrong.write_bytes(
            transparency.public_pem(ed25519.Ed25519PrivateKey.generate().public_key())
        )
        rt = _runtime(_settings(settings, keys, ledger_rekor_log_key_file=str(wrong)), log)
        try:
            with rt.db.transaction() as tx:
                ledger.append(tx, type="admin.test", actor="admin:t")
            point = rt.make_checkpoint()
            assert point["log"]["logged"] is True and point["log"]["checked"] is False
            assert "proof doesn't check out" in point["log"]["error"]
            # The log took it: not added again.
            assert rt.log_checkpoints() == 0
        finally:
            rt.db.dispose()

    def test_without_the_logs_key_entries_are_kept_unchecked(self, settings, log, keys) -> None:
        rt = _runtime(_settings(settings, keys, ledger_rekor_log_key_file=None), log)
        try:
            with rt.db.transaction() as tx:
                ledger.append(tx, type="admin.test", actor="admin:t")
            point = rt.make_checkpoint()
            assert point["log"]["logged"] is True and point["log"]["checked"] is None
        finally:
            rt.db.dispose()

    def test_a_signing_key_that_cant_be_read(self, settings, log, keys, tmp_path) -> None:
        missing = _settings(settings, keys, ledger_rekor_signing_key_file=str(tmp_path / "x.pem"))
        rt = _runtime(missing, log)
        try:
            with rt.db.transaction() as tx:
                ledger.append(tx, type="admin.test", actor="admin:t")
            point = rt.make_checkpoint()
            assert "can't be read" in point["log"]["error"] and log.leaves == []
        finally:
            rt.db.dispose()

    def test_settings(self, settings) -> None:
        with pytest.raises(ValueError, match="http\\(s\\) URL"):
            settings.with_overrides(ledger_rekor_url="rekor.example.com").validate()
        with pytest.raises(ValueError, match="SIGNING_KEY_FILE"):
            settings.with_overrides(ledger_rekor_url="https://rekor.example.com").validate()


class TestForAssessors:
    def test_the_api_cli_and_evidence_pack(
        self, settings, log, keys, tmp_path, monkeypatch
    ) -> None:
        from starlette.testclient import TestClient

        from agentgov.api.app import create_app

        configured = _settings(settings, keys)
        app = create_app(configured, background=False)
        app.state.rt._tlog_http = _client(log)
        with TestClient(app) as client:
            assert client.get("/v1/info").json()["transparency_log"] == "https://rekor.example.com"
            with app.state.rt.db.transaction() as tx:
                ledger.append(tx, type="admin.test", actor="admin:t")
            point = client.post("/v1/ledger/checkpoints", headers=ADMIN).json()
            seq = point["seq"]
            about = client.get("/v1/ledger/transparency-log", headers=ADMIN).json()
            assert about["origin"] == ORIGIN
            assert about["signer_key"] == keys["public"].read_text()
            assert about["log_key"] == keys["log_key"].read_text()
            found = client.get(f"/v1/ledger/checkpoints/{seq}/log-entry", headers=ADMIN)
            assert found.status_code == 200
            assert (
                client.get("/v1/ledger/checkpoints/999/log-entry", headers=ADMIN).status_code == 404
            )

            # agentgov ledger proof writes it all, and verify-log-entry checks it offline.
            monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
            out = ok(runner.invoke(cli.app, ["ledger", "proof", str(seq), "-o", str(tmp_path)]))
            assert "cosign verify-blob" in out
            args = [
                "ledger", "verify-log-entry",
                str(tmp_path / f"checkpoint-{seq}.txt"),
                str(tmp_path / f"checkpoint-{seq}.sigstore.json"),
                "--log-key", str(tmp_path / "rekor.pub"), "--origin", ORIGIN,
                "--key", str(tmp_path / "agentgov-rekor.pub"),
            ]  # fmt: skip
            assert f"verified: entry 0 of {ORIGIN}" in ok(runner.invoke(cli.app, args))
            (tmp_path / f"checkpoint-{seq}.txt").write_text("another statement\n")
            bad = runner.invoke(cli.app, args)
            assert bad.exit_code != 0 and "another statement" in bad.output

            # The evidence pack holds the entry as a bundle, with what checks it.
            pack = client.get("/v1/evidence/pack", headers=ADMIN)
            assert pack.status_code == 200
        with zipfile.ZipFile(io.BytesIO(pack.content)) as z:
            names = set(z.namelist())
            assert {
                f"checkpoints/{seq}.txt",
                f"checkpoints/{seq}.sigstore.json",
                "transparency-log/agentgov.pub",
                "transparency-log/rekor.pub",
                "transparency-log/trusted_root.json",
                "transparency-log/log.json",
            } <= names
            assert "cosign verify-blob" in z.read("README.txt").decode()
            assert json.loads(z.read("transparency-log/log.json"))["origin"] == ORIGIN
            z.extractall(tmp_path / "pack")
        assert compliance.README.count("verify-log-entry") == 1
        # agentgov ledger verify --pack checks each entry too, with the keys in the pack.
        verified = runner.invoke(cli.app, ["ledger", "verify", "--pack", str(tmp_path / "pack")])
        assert verified.exit_code == 0, verified.output
        bundle = tmp_path / "pack" / "checkpoints" / f"{seq}.sigstore.json"
        found = json.loads(bundle.read_text())
        found["verificationMaterial"]["tlogEntries"][0]["logIndex"] = "7"
        bundle.write_text(json.dumps(found))
        broken = runner.invoke(cli.app, ["ledger", "verify", "--pack", str(tmp_path / "pack")])
        assert (
            broken.exit_code == 2 and "transparency log's entry doesn't check out" in broken.output
        )
