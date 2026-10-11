"""Evidence: the ledger's checkpoints, their time-stamps, archives and retention
(docs/evidence.md)."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import shutil
import subprocess
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentgov import ids, ledger, retention
from agentgov import timestamping as tsp
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.models import (
    AgentActivity,
    ApprovalRequest,
    Destination,
    Finding,
    LedgerCheckpoint,
    LedgerEntry,
    ModelUsage,
    Notification,
    RiskSignal,
)
from agentgov.registry import features, findings
from agentgov.runtime import Runtime
from tests.conftest import ADMIN, seed

# ------------------------------------------------------------------ a fake TSA


def _query(data: bytes) -> tuple[bytes, int]:
    """The digest and nonce of a TimeStampReq."""
    req = tsp._children(data, tsp._read(data, 0))
    imprint = tsp._children(data, req[1])
    digest = data[imprint[1].value : imprint[1].end]
    return digest, tsp._int_value(data, req[2])


def tsa_reply(digest: bytes, nonce: int | None, *, status: int = 0) -> bytes:
    """A TimeStampResp as an authority writes one (unsigned: AgentGov leaves the signature
    to whoever verifies it)."""
    if status not in (0, 1):
        why = tsp.tlv(0x30, tsp.tlv(0x0C, b"unsupported algorithm"))
        return tsp.tlv(0x30, tsp.tlv(0x30, tsp.integer(status) + why))
    imprint = tsp.tlv(0x30, tsp.SHA256 + tsp.tlv(0x04, digest))
    info = tsp.tlv(
        0x30,
        tsp.integer(1)
        + tsp.oid("1.2.3.4.1")
        + imprint
        + tsp.integer(7)
        + tsp.tlv(0x18, b"20261011120000Z")
        + tsp.tlv(0x30, tsp.integer(1))  # accuracy
        + (tsp.integer(nonce) if nonce is not None else b""),
    )
    encap = tsp.tlv(0x30, tsp.oid("1.2.840.113549.1.9.16.1.4") + tsp.tlv(0xA0, tsp.tlv(0x04, info)))
    signed = tsp.tlv(0x30, tsp.integer(3) + tsp.tlv(0x31, b"") + encap + tsp.tlv(0x31, b""))
    content = tsp.tlv(0x30, tsp.oid("1.2.840.113549.1.7.2") + tsp.tlv(0xA0, signed))
    return tsp.tlv(0x30, tsp.tlv(0x30, tsp.integer(status)) + content)


class FakeTSA:
    def __init__(self) -> None:
        self.status = 0
        self.wrong_nonce = False
        self.requests: list[bytes] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == tsp.QUERY
        self.requests.append(request.content)
        digest, nonce = _query(request.content)
        body = tsa_reply(digest, nonce + 1 if self.wrong_nonce else nonce, status=self.status)
        return httpx.Response(200, content=body, headers={"content-type": tsp.REPLY})


class TestTimestamping:
    def test_a_granted_stamp(self) -> None:
        tsa = FakeTSA()
        got = tsp.stamp(
            "https://tsa.test/", b"statement", http=httpx.Client(transport=httpx.MockTransport(tsa))
        )
        assert got.time.isoformat() == "2026-10-11T12:00:00+00:00"
        digest, _ = _query(tsa.requests[0])
        assert digest == hashlib.sha256(b"statement").digest()

    def test_refusals_and_mismatches(self) -> None:
        tsa = FakeTSA()
        http = httpx.Client(transport=httpx.MockTransport(tsa))
        tsa.status = 2
        with pytest.raises(tsp.TimestampError, match=r"refused it \(rejection: unsupported"):
            tsp.stamp("https://tsa.test/", b"x", http=http)
        tsa.status, tsa.wrong_nonce = 0, True
        with pytest.raises(tsp.TimestampError, match="nonce"):
            tsp.stamp("https://tsa.test/", b"x", http=http)
        digest = hashlib.sha256(b"x").digest()
        with pytest.raises(tsp.TimestampError, match="another hash"):
            tsp.read_response(tsa_reply(hashlib.sha256(b"y").digest(), 1), digest, 1)
        with pytest.raises(tsp.TimestampError, match="cut short"):
            tsp.read_response(tsa_reply(digest, 1)[:40], digest, 1)
        down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
        with pytest.raises(tsp.TimestampError, match="HTTP 503"):
            tsp.stamp("https://tsa.test/", b"x", http=down)

    @pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl command")
    def test_with_an_openssl_authority(self, tmp_path: Path) -> None:
        """A real authority's answer, signed, read by AgentGov and verified by OpenSSL."""
        key, cert = tmp_path / "tsa.key", tmp_path / "tsa.crt"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
             "-out", cert, "-days", "2", "-subj", "/CN=Test TSA",
             "-addext", "extendedKeyUsage=critical,timeStamping"],
            check=True, capture_output=True,
        )  # fmt: skip
        (tmp_path / "serial").write_text("01\n")
        config = tmp_path / "tsa.cnf"
        config.write_text(
            "[ tsa ]\ndefault_tsa = t\n[ t ]\n"
            f"serial = {tmp_path / 'serial'}\nsigner_cert = {cert}\nsigner_key = {key}\n"
            "signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\n"
            "accuracy = secs:1\nordering = yes\ness_cert_id_alg = sha256\n"
        )

        def authority(request: httpx.Request) -> httpx.Response:
            (tmp_path / "q.tsq").write_bytes(request.content)
            subprocess.run(
                ["openssl", "ts", "-reply", "-config", config, "-queryfile", tmp_path / "q.tsq",
                 "-out", tmp_path / "r.tsr"],
                check=True, capture_output=True,
            )  # fmt: skip
            return httpx.Response(200, content=(tmp_path / "r.tsr").read_bytes())

        statement = ledger.statement(42, "ab" * 32)
        got = tsp.stamp(
            "https://tsa.test/",
            statement,
            http=httpx.Client(transport=httpx.MockTransport(authority)),
        )
        assert abs((got.time - ids.utcnow()).total_seconds()) < 120
        (tmp_path / "statement.txt").write_bytes(statement)
        (tmp_path / "stamp.tsr").write_bytes(got.response)
        verified = subprocess.run(
            ["openssl", "ts", "-verify", "-data", tmp_path / "statement.txt", "-in",
             tmp_path / "stamp.tsr", "-CAfile", cert],
            capture_output=True, text=True,
        )  # fmt: skip
        assert verified.returncode == 0 and "Verification: OK" in verified.stdout


# ------------------------------------------------------------------ checkpoints


def _old_entries(rt: Runtime, count: int, days_ago: int) -> None:
    with rt.db.session() as s:
        for i in range(count):
            ledger.append(
                s, type="test.old", actor="test", ts=ids.utcnow() - timedelta(days=days_ago - i)
            )


@pytest.fixture
def archiving(settings: Settings, tmp_path: Path) -> Iterator[Runtime]:
    keeping = settings.with_overrides(
        ledger_retention_days=183, ledger_archive_dir=str(tmp_path / "archive")
    )
    runtime = Runtime(keeping, tsa_http=httpx.Client(transport=httpx.MockTransport(FakeTSA())))
    runtime.init_db()
    yield runtime
    runtime.db.dispose()


class TestCheckpoints:
    def test_one_per_period_while_the_chain_grows(self, rt: Runtime) -> None:
        _old_entries(rt, 3, 1)
        now = ids.utcnow()
        with rt.db.session() as s:
            first = retention.checkpoint_if_due(s, rt.settings, now)
            assert (first.seq, first.hash) == (3, s.get(LedgerEntry, 3).hash)
        with rt.db.session() as s:
            assert retention.checkpoint_if_due(s, rt.settings, now + timedelta(hours=25)) is None
        _old_entries(rt, 1, 1)
        with rt.db.session() as s:
            assert retention.checkpoint_if_due(s, rt.settings, now + timedelta(hours=1)) is None
            assert retention.checkpoint_if_due(s, rt.settings, now + timedelta(hours=25)).seq == 4

    def test_time_stamped_by_the_authority(self, settings: Settings) -> None:
        tsa = FakeTSA()
        runtime = Runtime(
            settings.with_overrides(ledger_tsa_url="https://tsa.test/"),
            tsa_http=httpx.Client(transport=httpx.MockTransport(tsa)),
        )
        runtime.init_db()
        _old_entries(runtime, 2, 1)
        out = runtime.run_retention()
        assert (out["checkpoint"], out["timestamped"]) == (2, 1)
        with runtime.db.session() as s:
            point = s.get(LedgerCheckpoint, 2)
            assert point.timestamped_at.isoformat() == "2026-10-11T12:00:00+00:00"
            response = base64.b64decode(point.timestamp)
        digest, _ = _query(tsa.requests[0])
        assert digest == hashlib.sha256(ledger.statement(2, point.hash)).digest()
        assert tsp.read_response(response, digest, None).time == point.timestamped_at
        # A refusal is kept on the checkpoint, and tried again.
        tsa.status = 2
        _old_entries(runtime, 1, 1)
        with runtime.db.session() as s:
            ledger.checkpoint(s)
        assert runtime.stamp_checkpoints() == 0
        with runtime.db.session() as s:
            assert "refused" in s.get(LedgerCheckpoint, 3).timestamp_error
        tsa.status = 0
        assert runtime.stamp_checkpoints() == 1
        runtime.db.dispose()


class TestArchives:
    def test_old_entries_are_archived_then_removed(self, archiving: Runtime) -> None:
        rt = archiving
        _old_entries(rt, 5, 300)
        _old_entries(rt, 2, 1)
        with rt.db.session() as s:
            out = retention.archive(s, rt.settings)
        assert (out["from"], out["to"], out["entries"]) == (1, 5, 5)
        path = Path(rt.settings.ledger_archive_dir) / out["archive"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == out["sha256"]
        records = list(retention.read_archive(path))
        assert [r["seq"] for r in records] == [1, 2, 3, 4, 5]
        assert ledger.verify_records(records, start=(0, ledger.GENESIS))["valid"]
        with rt.db.session() as s:
            assert s.scalar(select(LedgerEntry.seq).order_by(LedgerEntry.seq)) == 6
            point = s.get(LedgerCheckpoint, 5)
            assert (point.archive, point.archived_from) == (out["archive"], 1)
            # The chain in the database goes on from the checkpoint, and still verifies.
            result = ledger.verify(s)
            assert (result["valid"], result["from"], result["checked"]) == (True, 5, 8)
            archived = s.scalar(select(LedgerEntry).where(LedgerEntry.type == "ledger.archived"))
            assert archived.details["sha256"] == out["sha256"]
            # The next archive goes on from this one.
            assert retention.archive(s, rt.settings) is None

    def test_what_a_destination_wasnt_sent_stays(self, archiving: Runtime) -> None:
        rt = archiving
        _old_entries(rt, 5, 300)
        with rt.db.session() as s:
            features.set_mode(s, rt.settings, "security-operations", "inform", actor="admin:t")
            s.add(Destination(id="dst_1", name="siem", kind="webhook", url="https://siem.test",
                              events=[], status="active", cursor=3, labels={}))  # fmt: skip
        with rt.db.session() as s:
            assert retention.archive(s, rt.settings)["to"] == 3
        with rt.db.session() as s:
            # Not sent to while security operations are off: they don't hold anything back.
            features.set_mode(s, rt.settings, "security-operations", "off", actor="admin:t")
        with rt.db.session() as s:
            # The rest of the old ones (6 on are recent: the features' changes, the archive).
            assert retention.archive(s, rt.settings)["to"] == 5

    def test_a_broken_chain_isnt_archived(self, archiving: Runtime) -> None:
        rt = archiving
        _old_entries(rt, 4, 300)
        with rt.db.session() as s:
            s.get(LedgerEntry, 2).reason = "edited"
        with rt.db.session() as s:
            assert "doesn't match its hash" in retention.archive(s, rt.settings)["error"]
        with rt.db.session() as s:
            assert s.scalar(select(LedgerEntry.seq).order_by(LedgerEntry.seq)) == 1
            failed = s.scalar(select(Finding).where(Finding.type == retention.ARCHIVE_FAILED))
            assert failed.status == "open" and failed.severity == "high"

    def test_nowhere_to_write(self, archiving: Runtime, tmp_path: Path) -> None:
        blocked = tmp_path / "file"
        blocked.write_text("not a directory")
        rt = archiving
        rt.settings = rt.settings.with_overrides(ledger_archive_dir=str(blocked / "archive"))
        _old_entries(rt, 2, 300)
        with rt.db.session() as s:
            assert retention.archive(s, rt.settings)["error"]
        with rt.db.session() as s:
            assert (
                s.scalar(select(Finding.status).where(Finding.type == retention.ARCHIVE_FAILED))
                == "open"
            )
            # Nothing left the database.
            assert s.get(LedgerEntry, 1) is not None and ledger.verify(s)["from"] == 0

    def test_archives_verify_offline(self, archiving: Runtime, monkeypatch, tmp_path: Path) -> None:
        from agentgov import cli
        from tests.test_cli import runner

        rt = archiving
        _old_entries(rt, 3, 300)
        with rt.db.session() as s:
            first = retention.archive(s, rt.settings)
        _old_entries(rt, 2, 250)
        with rt.db.session() as s:
            # Entries 4 (ledger.archived) to 6, older than the period by now.
            second = retention.archive(s, rt.settings, ids.utcnow() + timedelta(days=200))
        files = [str(Path(rt.settings.ledger_archive_dir) / a["archive"]) for a in (first, second)]
        result = runner.invoke(
            cli.app, ["ledger", "verify", "--file", files[0], "--file", files[1]]
        )
        assert result.exit_code == 0, result.output
        assert "entries 1 to 3" in result.output and "entries 4 to 6" in result.output
        # Out of order, they don't link up; edited, they don't match.
        result = runner.invoke(
            cli.app, ["ledger", "verify", "--file", files[1], "--follows", "00" * 32]
        )
        assert result.exit_code == 2 and "BROKEN at 4" in result.output
        with gzip.open(files[0], "rt") as archived:
            lines = [json.loads(line) for line in archived]
        lines[1]["reason"] = "edited"
        tampered = tmp_path / "tampered.jsonl"
        tampered.write_text("".join(json.dumps(line) + "\n" for line in lines))
        result = runner.invoke(cli.app, ["ledger", "verify", "--file", str(tampered)])
        assert result.exit_code == 2 and "doesn't match" not in result.output
        assert "entry contents do not match its hash" in result.output


# ---------------------------------------------------------------------- records


def test_old_operational_records_go(settings: Settings) -> None:
    rt = Runtime(settings.with_overrides(data_retention_days=90))
    rt.init_db()
    now = ids.utcnow()
    old, recent = now - timedelta(days=120), now - timedelta(days=10)
    with rt.db.session() as s:
        for when, tag in ((old, "old"), (recent, "new")):
            day = when.strftime("%Y-%m-%d")
            s.add(AgentActivity(agent_id=f"agt_{tag}", day=day))
            s.add(ModelUsage(agent_id=f"agt_{tag}", day=day, provider="p", model="m"))
            s.add(RiskSignal(id=f"sig_{tag}", agent_id="agt_x", kind="denied", ts=when))
            s.add(ApprovalRequest(id=f"apr_{tag}", agent_id="agt_x", agent_name="x", action="a",
                                  resource="r", arguments_hash="h", status="approved",
                                  requested_at=when, expires_at=when))  # fmt: skip
            finding, _ = findings.raise_finding(
                s, type="test.thing", severity="low", subject=tag, title=tag
            )
            finding.status, finding.resolved_at = "resolved", when
            s.add(Notification(id=f"ntf_{tag}", finding_id=finding.id, level="team",
                               channel="email", recipient="a@example.com", status="sent",
                               created_at=when))  # fmt: skip
        s.add(ApprovalRequest(id="apr_waiting", agent_id="agt_x", agent_name="x", action="a",
                              resource="r", arguments_hash="h", status="pending",
                              requested_at=old, expires_at=now))  # fmt: skip
    with rt.db.session() as s:
        removed = retention.prune_records(s, rt.settings, now)
    assert removed == {
        "activity": 1,
        "model_usage": 1,
        "risk_signals": 1,
        "notifications": 1,
        "approvals": 1,
        "findings": 1,
    }
    with rt.db.session() as s:
        assert {a.agent_id for a in s.scalars(select(AgentActivity))} == {"agt_new"}
        assert {a.id for a in s.scalars(select(ApprovalRequest))} == {"apr_new", "apr_waiting"}
        assert [f.subject for f in s.scalars(select(Finding))] == ["new"]
        entry = s.scalar(select(LedgerEntry).where(LedgerEntry.type == "retention.pruned"))
        assert entry.details["findings"] == 1
    rt.db.dispose()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"ledger_retention_days": 30}, "at least 183"),
        ({"ledger_retention_days": 365}, "needs AGENTGOV_LEDGER_ARCHIVE_DIR"),
        ({"data_retention_days": 7}, "at least 30"),
        ({"ledger_tsa_url": "tsa.example"}, "http"),
        ({"ledger_checkpoint_hours": -1}, "LEDGER_CHECKPOINT_HOURS"),
    ],
)
def test_settings(settings: Settings, overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        settings.with_overrides(**overrides).validate()


# ---------------------------------------------------------------------- the API


def test_the_api(settings: Settings, tmp_path: Path) -> None:
    tsa = FakeTSA()
    rt = Runtime(
        settings.with_overrides(ledger_tsa_url="https://tsa.test/"),
        tsa_http=httpx.Client(transport=httpx.MockTransport(tsa)),
    )
    with TestClient(create_app(rt.settings, runtime=rt, background=False)) as client:
        assert client.post("/v1/ledger/checkpoints", headers=ADMIN).status_code == 409  # empty
        client.post("/v1/blueprints", json={"name": "support"}, headers=ADMIN).raise_for_status()
        made = client.post("/v1/ledger/checkpoints", headers=ADMIN)
        assert made.status_code == 201, made.text
        point = made.json()
        assert point["timestamped"] and point["statement"].startswith("agentgov ledger checkpoint")
        listed = client.get("/v1/ledger/checkpoints", headers=ADMIN).json()
        assert [c["seq"] for c in listed] == [point["seq"]]
        stamp = client.get(f"/v1/ledger/checkpoints/{point['seq']}/timestamp", headers=ADMIN)
        assert stamp.headers["content-type"] == tsp.REPLY
        digest = hashlib.sha256(point["statement"].encode()).digest()
        assert tsp.read_response(stamp.content, digest, None).time.year == 2026
        view = client.get("/v1/ledger/retention", headers=ADMIN).json()
        assert (view["chain_from"], view["tsa_url"]) == (0, "https://tsa.test/")
        assert view["latest_checkpoint"]["seq"] == point["seq"]
        ran = client.post("/v1/ledger/retention/run", headers=ADMIN).json()
        assert ran["archived"] is None and ran["pruned"] == {}
        assert client.get("/v1/ledger/verify", headers=ADMIN).json()["from"] == 0


# ------------------------------------------------------------------- compliance


def _key(client: TestClient, role: str) -> dict[str, str]:
    resp = client.post("/v1/apikeys", json={"name": f"{role}-key", "role": role}, headers=ADMIN)
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestCompliance:
    def test_reports_say_what_is_in_place_and_the_evidence(self, client: TestClient) -> None:
        seed(client)
        auditor = _key(client, "auditor")
        frameworks = client.get("/v1/evidence/frameworks", headers=auditor).json()
        assert [f["key"] for f in frameworks] == ["eu-ai-act", "iso-42001", "nist-ai-rmf"]
        assert "2 December 2027" in frameworks[0]["note"]
        report = client.get("/v1/evidence/report", params={"days": 30}, headers=auditor).json()
        controls = {c["id"]: c for c in report["controls"]}
        assert {"Art. 12", "Art. 14", "Art. 19, 26(6)", "Art. 73"} <= set(controls)
        assert controls["Art. 4"]["status"] == "outside"
        logging = controls["Art. 12"]
        # Without a time-stamping authority, the ledger only vouches for itself.
        assert logging["status"] == "partly" and "AGENTGOV_LEDGER_TSA_URL" in logging["gaps"][0]
        evidence = {e["label"]: e["value"] for e in logging["evidence"]}
        assert evidence["Ledger entries in the period"] > 0
        assert evidence["Chain"].startswith("verifies")
        assert controls["Art. 19, 26(6)"]["status"] == "in_place"
        assert report["ledger"]["valid"] and report["period"]["days"] == 30
        assert sum(report["summary"].values()) == len(report["controls"])
        for key in ("iso-42001", "nist-ai-rmf"):
            other = client.get("/v1/evidence/report", params={"framework": key}, headers=auditor)
            assert other.status_code == 200 and other.json()["controls"]
        assert (
            client.get(
                "/v1/evidence/report", params={"framework": "sox"}, headers=auditor
            ).status_code
            == 404
        )
        assert (
            client.get("/v1/evidence/report", params={"days": 0}, headers=auditor).status_code
            == 422
        )
        assert (
            client.get("/v1/evidence/report", headers=_key(client, "registrar")).status_code == 403
        )

    def test_statuses_follow_the_deployment(self, client: TestClient) -> None:
        seed(client)

        def control(cid: str, framework: str = "eu-ai-act") -> dict[str, Any]:
            report = client.get(
                "/v1/evidence/report", params={"framework": framework}, headers=ADMIN
            )
            return next(c for c in report.json()["controls"] if c["id"] == cid)

        assert control("Art. 14")["status"] == "in_place"
        client.put("/v1/features/approvals", json={"mode": "off"}, headers=ADMIN).raise_for_status()
        assert control("Art. 14")["status"] == "partly"
        client.put("/v1/features/least-privilege", json={"mode": "monitor"}, headers=ADMIN)
        security = control("MEASURE 2.7", "nist-ai-rmf")
        assert security["status"] == "partly" and "least-privilege" in security["gaps"][0]
        rt = client.app.state.rt  # type: ignore[attr-defined]
        with rt.db.session() as s:
            s.get(LedgerEntry, 1).reason = "edited"
        logging = control("A.6.2.8", "iso-42001")
        assert logging["status"] == "attention" and "broken" in logging["gaps"][0]

    def test_the_evidence_pack(self, client: TestClient, tmp_path: Path, monkeypatch) -> None:
        import zipfile

        from agentgov import cli
        from tests.test_cli import _Shared, runner

        seed(client)
        client.post("/v1/ledger/checkpoints", headers=ADMIN).raise_for_status()
        resp = client.get("/v1/evidence/pack", params={"days": 7}, headers=_key(client, "auditor"))
        assert resp.status_code == 200 and resp.headers["content-type"] == "application/zip"
        assert "agentgov-evidence-" in resp.headers["content-disposition"]
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            names = set(z.namelist())
            assert {"README.txt", "report.md", "ledger.jsonl", "checkpoints.json",
                    "inventory.json", "manifests.yaml", "features.json",
                    "reports/eu-ai-act.json", "reports/nist-ai-rmf.json"} <= names  # fmt: skip
            records = [json.loads(line) for line in z.read("ledger.jsonl").splitlines()]
            assert records and ledger.verify_records(records)["valid"]
            inventory = json.loads(z.read("inventory.json"))
            assert inventory[0]["name"] == "support-bot" and inventory[0]["owner"] == "cx"
            assert "kind: Blueprint" in z.read("manifests.yaml").decode()
            assert "doesn't say that the organisation complies" in z.read("report.md").decode()
        # From the CLI.
        bearer = ADMIN["Authorization"].removeprefix("Bearer ")
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, bearer))
        out = runner.invoke(cli.app, ["evidence", "report", "--framework", "nist-ai-rmf"])
        assert out.exit_code == 0, out.output
        assert "GOVERN 1.6" in out.output and "in place" in out.output
        target = tmp_path / "pack.zip"
        out = runner.invoke(cli.app, ["evidence", "pack", "--days", "7", "-o", str(target)])
        assert out.exit_code == 0, out.output
        assert zipfile.is_zipfile(target)
