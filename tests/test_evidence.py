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
from starlette.testclient import TestClient

from agentgov import compliance, ids, ledger, retention
from agentgov import timestamping as tsp
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.db.models import (
    AgentActivity,
    ApprovalRequest,
    Destination,
    Finding,
    LedgerCheckpoint,
    LedgerEntry,
    LedgerHead,
    ModelUsage,
    Notification,
    RiskSignal,
)
from agentgov.registry import features, findings
from agentgov.runtime import Runtime
from tests.conftest import ADMIN, seed
from tests.timestamps import Authority, FakeTSA, authority, query, unsigned_reply

# ------------------------------------------------------------------ time-stamps


class TestTimestamping:
    def test_a_granted_stamp(self) -> None:
        tsa = FakeTSA()
        got = tsp.stamp("https://tsa.test/", b"statement", http=tsa.client())
        assert got.time.isoformat() == "2026-10-11T12:00:00+00:00"
        # Checked against the certificate it carries only: no authority's were given.
        assert got.authority is False
        digest, _ = query(tsa.requests[0])
        assert digest == hashlib.sha256(b"statement").digest()

    def test_refusals_and_mismatches(self) -> None:
        tsa = FakeTSA()
        http = tsa.client()
        tsa.status = 2
        with pytest.raises(tsp.TimestampError, match=r"refused it \(rejection: unsupported"):
            tsp.stamp("https://tsa.test/", b"x", http=http)
        tsa.status, tsa.wrong_nonce = 0, True
        with pytest.raises(tsp.TimestampError, match="nonce"):
            tsp.stamp("https://tsa.test/", b"x", http=http)
        digest = hashlib.sha256(b"x").digest()
        signer = authority()
        with pytest.raises(tsp.TimestampError, match="another hash"):
            tsp.read_response(signer.reply(hashlib.sha256(b"y").digest(), 1), digest, 1)
        with pytest.raises(tsp.TimestampError, match="cut short"):
            tsp.read_response(signer.reply(digest, 1)[:40], digest, 1)
        down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
        with pytest.raises(tsp.TimestampError, match="HTTP 503"):
            tsp.stamp("https://tsa.test/", b"x", http=down)

    def test_the_authoritys_signature_is_checked(self, tmp_path: Path) -> None:
        """Anyone can write a time-stamp with the right hash: only the authority's
        signature shows that it gave it."""
        digest = hashlib.sha256(b"x").digest()
        signer = authority()
        with pytest.raises(tsp.TimestampError, match="isn't signed"):
            tsp.read_response(unsigned_reply(digest, 1), digest, 1)
        with pytest.raises(tsp.TimestampError, match="signature is on another time-stamp"):
            tsp.read_response(signer.reply(digest, 1, tamper=True), digest, 1)
        with pytest.raises(tsp.TimestampError, match="doesn't carry the certificate"):
            tsp.read_response(signer.reply(digest, 1, carry=False), digest, 1)
        # Against the authority's certificates: its own, or a root it leads to.
        assert tsp.read_response(signer.reply(digest, 1), digest, 1, roots=[signer.root]).authority
        chained = Authority("Chained TSA", chained=True)
        assert tsp.read_response(
            chained.reply(digest, 1), digest, 1, roots=[chained.root]
        ).authority
        other = Authority("Another TSA")
        with pytest.raises(tsp.TimestampError, match="doesn't lead to the authority's"):
            tsp.read_response(other.reply(digest, 1), digest, 1, roots=[signer.root])
        # Its certificate alone, without the token's: found among the authority's.
        alone = tsp.read_response(
            signer.reply(digest, 1, carry=False), digest, 1, roots=[signer.root]
        )
        assert alone.authority
        # Asked for one: a forged answer is an error, and nothing comes back to keep.
        tsa = FakeTSA()
        tsa.forge = True
        with pytest.raises(tsp.TimestampError, match="isn't signed"):
            tsp.stamp("https://tsa.test/", b"x", http=tsa.client())
        # The authority's certificates, from a file.
        pem = tmp_path / "tsa-ca.pem"
        pem.write_bytes(chained.pem)
        assert tsp.trust(str(pem)).roots == (chained.root,)
        assert "can't be read" in (tsp.trust(str(tmp_path / "missing.pem")).error or "")
        assert tsp.trust(None) == tsp.Trust()

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

        def openssl_authority(request: httpx.Request) -> httpx.Response:
            (tmp_path / "q.tsq").write_bytes(request.content)
            subprocess.run(
                ["openssl", "ts", "-reply", "-config", config, "-queryfile", tmp_path / "q.tsq",
                 "-out", tmp_path / "r.tsr"],
                check=True, capture_output=True,
            )  # fmt: skip
            return httpx.Response(200, content=(tmp_path / "r.tsr").read_bytes())

        statement = ledger.statement(42, "ab" * 32)
        http = httpx.Client(transport=httpx.MockTransport(openssl_authority))
        got = tsp.stamp("https://tsa.test/", statement, http=http, roots=tsp.load_roots(cert))
        assert abs((got.time - ids.utcnow()).total_seconds()) < 120
        # Its RSA signature checks out against its certificate, as OpenSSL's does below.
        assert got.authority is True
        with pytest.raises(tsp.TimestampError, match="doesn't lead to the authority's"):
            tsp.stamp("https://tsa.test/", statement, http=http, roots=[authority().root])
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
    with rt.db.transaction() as tx:
        for i in range(count):
            ledger.append(
                tx, type="test.old", actor="test", ts=ids.utcnow() - timedelta(days=days_ago - i)
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
        with rt.db.transaction() as tx:
            first = retention.checkpoint_if_due(tx, rt.settings, now)
            assert (first.seq, first.hash) == (3, LedgerEntry.objects.get(seq=3).hash)
        with rt.db.transaction() as tx:
            assert retention.checkpoint_if_due(tx, rt.settings, now + timedelta(hours=25)) is None
        _old_entries(rt, 1, 1)
        with rt.db.transaction() as tx:
            assert retention.checkpoint_if_due(tx, rt.settings, now + timedelta(hours=1)) is None
            assert retention.checkpoint_if_due(tx, rt.settings, now + timedelta(hours=25)).seq == 4

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
        with runtime.db.transaction() as tx:
            point = LedgerCheckpoint.objects.get(seq=2)
            assert point.timestamped_at.isoformat() == "2026-10-11T12:00:00+00:00"
            response = base64.b64decode(point.timestamp)
        digest, _ = query(tsa.requests[0])
        assert digest == hashlib.sha256(ledger.statement(2, point.hash)).digest()
        assert tsp.read_response(response, digest, None).time == point.timestamped_at
        # The chain records it: a time-stamp replaced later shows.
        with runtime.db.transaction() as tx:
            recorded = LedgerEntry.objects.get(seq=3)
            assert recorded.type == "ledger.timestamped"
            assert recorded.details == {
                "checkpoint": 2,
                "hash": point.hash,
                "token": hashlib.sha256(response).hexdigest(),
                "time": "2026-10-11T12:00:00Z",
                "tsa": "https://tsa.test/",
                "authority": False,
            }
        # A refusal is kept on the checkpoint, and tried again; so is an answer that isn't
        # the authority's (no signature): it isn't kept.
        for refuse in ("status", "forge"):
            setattr(tsa, refuse, 2 if refuse == "status" else True)
            _old_entries(runtime, 1, 1)
            with runtime.db.transaction() as tx:
                seq = ledger.checkpoint(tx).seq
            assert runtime.stamp_checkpoints() == 0
            with runtime.db.transaction() as tx:
                point = LedgerCheckpoint.objects.get(seq=seq)
                assert point.timestamp is None
                assert (
                    "refused" if refuse == "status" else "isn't signed"
                ) in point.timestamp_error
            setattr(tsa, refuse, 0 if refuse == "status" else False)
            assert runtime.stamp_checkpoints() == 1
        with runtime.db.transaction() as tx:
            assert ledger.verify(tx, settings=runtime.settings)["valid"] is True
        runtime.db.dispose()


class TestRewrites:
    """A chain rewritten with its hashes worked out again holds together: the checkpoints,
    time-stamped by an authority before the rewrite, don't match it."""

    def test_a_checkpoint_rewritten_too_fails_its_time_stamp(self, settings: Settings) -> None:
        from tests.test_ledger import _rewrite

        runtime = Runtime(
            settings.with_overrides(ledger_tsa_url="https://tsa.test/"),
            tsa_http=httpx.Client(transport=httpx.MockTransport(FakeTSA())),
        )
        runtime.init_db()
        _old_entries(runtime, 3, 1)
        assert runtime.run_retention()["timestamped"] == 1
        with runtime.db.transaction() as tx:
            _rewrite(tx, 2, "edited")
            LedgerCheckpoint.objects.filter(seq=3).update(hash=LedgerEntry.objects.get(seq=3).hash)
        with runtime.db.transaction() as tx:
            result = ledger.verify(tx)
        assert result["valid"] is False
        assert result["problem"].startswith(
            "checkpoint 3's time-stamp doesn't check out: the authority time-stamped another hash"
        )
        runtime.db.dispose()

    def _stamped(self, settings: Settings, tsa: FakeTSA, **overrides: Any) -> Runtime:
        runtime = Runtime(
            settings.with_overrides(ledger_tsa_url="https://tsa.test/", **overrides),
            tsa_http=tsa.client(),
        )
        runtime.init_db()
        _old_entries(runtime, 3, 1)
        assert runtime.run_retention()["timestamped"] == 1  # checkpoint 3, recorded at 4
        _old_entries(runtime, 2, 1)
        return runtime

    def test_a_time_stamp_made_up_or_replaced_shows(self, settings: Settings) -> None:
        """A rewritten chain's checkpoints need new time-stamps: one written by anyone but
        the authority doesn't verify, and one the authority gives again, for the rewritten
        statement, isn't the one the chain recorded."""
        from tests.test_ledger import _rewrite

        tsa = FakeTSA()
        runtime = self._stamped(settings, tsa)
        with runtime.db.transaction() as tx:
            _rewrite(tx, 2, "edited")
            point = LedgerCheckpoint.objects.get(seq=3)
            point.hash = LedgerEntry.objects.get(seq=3).hash
            digest = hashlib.sha256(ledger.statement(3, point.hash)).digest()
            point.timestamp = base64.b64encode(unsigned_reply(digest, None)).decode()
            point.save()
        with runtime.db.transaction() as tx:
            result = ledger.verify(tx)
        assert "checkpoint 3's time-stamp doesn't check out: the time-stamp isn't signed" in [
            p["problem"] for p in result["problems"]
        ]
        # Taken away, it is asked for again: the authority signs the rewritten statement.
        with runtime.db.transaction() as tx:
            LedgerCheckpoint.objects.filter(seq=3).update(timestamp=None)
        assert runtime.stamp_checkpoints() == 1
        with runtime.db.transaction() as tx:
            result = ledger.verify(tx)
        assert result["valid"] is False
        assert any(
            p["problem"].startswith("checkpoint 3 was time-stamped again at entry")
            for p in result["problems"]
        )
        runtime.db.dispose()

    def test_a_time_stamp_taken_away_or_swapped_shows(self, settings: Settings) -> None:
        tsa = FakeTSA()
        runtime = self._stamped(settings, tsa)
        with runtime.db.transaction() as tx:
            LedgerCheckpoint.objects.filter(seq=3).update(timestamp=None)
        with runtime.db.transaction() as tx:
            problem = ledger.verify(tx)["problem"]
        assert problem == "checkpoint 3's time-stamp, recorded at entry 4, is gone"
        # Another genuine one, from the same authority: not the one recorded.
        with runtime.db.transaction() as tx:
            point = LedgerCheckpoint.objects.get(seq=3)
            digest = hashlib.sha256(ledger.statement(3, point.hash)).digest()
            point.timestamp = base64.b64encode(tsa.signer.reply(digest, None)).decode()
            point.save()
        with runtime.db.transaction() as tx:
            problem = ledger.verify(tx)["problem"]
        assert problem.startswith("checkpoint 3's time-stamp isn't the one recorded at entry 4")
        with runtime.db.transaction() as tx:
            LedgerCheckpoint.objects.filter(seq=3).delete()
        with runtime.db.transaction() as tx:
            assert ledger.verify(tx)["problem"] == "checkpoint 3, time-stamped at entry 4, is gone"
        runtime.db.dispose()

    def test_a_late_time_stamp_vouches_only_from_its_time(self, settings: Settings) -> None:
        """A time-stamp proves the chain existed when the authority signed: given days after
        its entry, it says nothing about the days before."""
        tsa = FakeTSA()
        tsa.gen_time = (ids.utcnow() + timedelta(days=3)).strftime("%Y%m%d%H%M%SZ").encode()
        runtime = self._stamped(settings, tsa)
        with runtime.db.transaction() as tx:
            result = ledger.verify(tx, settings=runtime.settings)
        assert result["valid"] is True
        assert result["warnings"][0].startswith("checkpoint 3 vouches only from ")
        runtime.db.dispose()

    def test_the_authority_is_checked_against_its_certificates(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        tsa = FakeTSA()
        runtime = self._stamped(settings, tsa)
        with runtime.db.transaction() as tx:
            result = ledger.verify(tx, settings=runtime.settings)
        assert result["valid"] is True
        assert result["warnings"][-1].startswith(
            "the authority isn't checked: without AGENTGOV_LEDGER_TSA_CA_FILE"
        )
        runtime.db.dispose()
        # With the authority's certificates: no warning, and only its time-stamps are kept.
        ca = tmp_path / "tsa-ca.pem"
        ca.write_bytes(tsa.signer.pem)
        runtime = Runtime(
            runtime.settings.with_overrides(ledger_tsa_ca_file=str(ca)), tsa_http=tsa.client()
        )
        point = runtime.make_checkpoint()
        assert point is not None and point["timestamped"]
        with runtime.db.transaction() as tx:
            result = ledger.verify(tx, settings=runtime.settings)
            assert (result["valid"], result["warnings"]) == (True, [])
            recorded = (
                LedgerEntry.objects.filter(type="ledger.timestamped").order_by("-seq").first()
            )
            assert recorded.details["authority"] is True
        impostor = FakeTSA(Authority("Impostor TSA"))
        runtime._tsa_http = impostor.client()
        with runtime.db.transaction() as tx:
            seq = ledger.checkpoint(tx).seq
        assert runtime.stamp_checkpoints() == 0
        with runtime.db.transaction() as tx:
            point = LedgerCheckpoint.objects.get(seq=seq)
            assert "doesn't lead to the authority's" in point.timestamp_error
        runtime.db.dispose()

    def test_the_evidence_pack_is_checked_against_its_checkpoints(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        import zipfile

        from agentgov import cli
        from agentgov.api.app import create_app
        from tests.test_cli import runner

        stamped = settings.with_overrides(ledger_tsa_url="https://tsa.test/")
        runtime = Runtime(stamped, tsa_http=httpx.Client(transport=httpx.MockTransport(FakeTSA())))
        with TestClient(create_app(stamped, runtime=runtime, background=False)) as client:
            seed(client)
            assert runtime.run_retention()["timestamped"] == 1
            seed_more = {"name": "later", "description": "after the checkpoint"}
            client.post("/v1/teams", json=seed_more, headers=ADMIN)
            pack = client.get("/v1/evidence/pack", params={"days": 7}, headers=ADMIN).content
        good = tmp_path / "pack.zip"
        good.write_bytes(pack)
        out = runner.invoke(cli.app, ["ledger", "verify", "--pack", str(good)])
        assert out.exit_code == 0, out.output
        assert "1 checkpoint vouches for these entries" in out.output
        assert "1 of them time-stamped" in out.output
        assert "come after the last checkpoint" in out.output
        # Unzipped, too.
        folder = tmp_path / "unzipped"
        with zipfile.ZipFile(good) as z:
            z.extractall(folder)
        assert runner.invoke(cli.app, ["ledger", "verify", "--pack", str(folder)]).exit_code == 0
        # A decision rewritten, every later hash worked out again: the chain holds, the
        # checkpoint doesn't.
        records = [json.loads(line) for line in (folder / "ledger.jsonl").read_text().splitlines()]
        records[0]["reason"] = "rewritten"
        prev = records[0]["prev_hash"]
        for record in records:
            record["prev_hash"] = prev
            record["hash"] = prev = ledger.record_hash(prev, record)
        (folder / "ledger.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
        out = runner.invoke(cli.app, ["ledger", "verify", "--pack", str(folder)])
        assert out.exit_code == 2, out.output
        assert "valid, entries" in out.output  # the chain alone
        assert "doesn't match checkpoint" in out.output
        # An export checked alone says what it couldn't check.
        out = runner.invoke(cli.app, ["ledger", "verify", "--file", str(folder / "ledger.jsonl")])
        assert out.exit_code == 0 and "only the chain was checked" in out.output
        out = runner.invoke(
            cli.app,
            [
                "ledger", "verify", "--file", str(folder / "ledger.jsonl"),
                "--checkpoints", str(folder / "checkpoints"),
            ],
        )  # fmt: skip
        assert out.exit_code == 2 and "doesn't match checkpoint" in out.output
        runtime.db.dispose()

    def test_the_pack_verifier_checks_what_verify_does(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        """Offline, without AgentGov: the time-stamps' signatures, the authority's when its
        certificates are given; time-stamps the ledger recorded; where the pack's entries
        start; and checkpoints beyond them."""
        import zipfile

        from agentgov import cli
        from tests.test_cli import runner

        tsa = FakeTSA()
        runtime = self._stamped(settings, tsa)  # checkpoint 3, recorded at 4; entries to 6

        def pack(name: str) -> Path:
            with runtime.db.transaction() as tx:
                zipped = compliance.pack(tx.orm(), runtime.settings, 30)
            folder = tmp_path / name
            with zipfile.ZipFile(zipped) as z:
                z.extractall(folder)
            return folder

        def verify(folder: Path, *more: str) -> Any:
            return runner.invoke(cli.app, ["ledger", "verify", "--pack", str(folder), *more])

        good = pack("good")
        out = verify(good)
        assert out.exit_code == 0, out.output
        assert "1 checkpoint vouches for these entries, up to entry 3" in out.output
        assert "the authority isn't checked" in out.output
        ca = tmp_path / "tsa-ca.pem"
        ca.write_bytes(tsa.signer.pem)
        out = verify(good, "--tsa-ca", str(ca))
        assert out.exit_code == 0 and "the authority isn't checked" not in out.output
        assert "check out against the authority's certificates" in out.output
        out = verify(good, "--tsa-ca", str(tmp_path / "missing.pem"))
        assert out.exit_code != 0 and "can't be read" in out.output
        # A time-stamp anyone could write: no signature.
        forged = tmp_path / "forged"
        shutil.copytree(good, forged)
        statement = (forged / "checkpoints" / "3.txt").read_bytes()
        (forged / "checkpoints" / "3.tsr").write_bytes(
            unsigned_reply(hashlib.sha256(statement).digest(), None)
        )
        out = verify(forged)
        assert out.exit_code == 2 and "time-stamp isn't signed" in out.output
        # The authority's, for the same statement, but not the one the ledger recorded.
        (forged / "checkpoints" / "3.tsr").write_bytes(
            tsa.signer.reply(hashlib.sha256(statement).digest(), None, b"20261012120000Z")
        )
        out = verify(forged)
        assert out.exit_code == 2 and "isn't the one recorded at entry 4" in out.output
        # Cut back to before the checkpoint, the head with it: the checkpoint says it was
        # longer.
        with runtime.db.transaction():
            keep = LedgerEntry.objects.get(seq=2)
            LedgerEntry.objects.filter(seq__gt=2).delete()
            LedgerHead.objects.filter(id=1).update(last_seq=2, last_hash=keep.hash)
        out = verify(pack("cut"))
        assert out.exit_code == 2
        assert "checkpoint 3 is beyond the last entry here (2)" in out.output
        runtime.db.dispose()

    def test_the_pack_verifier_finds_entries_removed_behind_a_made_up_archive(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        import zipfile

        from agentgov import cli
        from tests.test_cli import runner

        tsa = FakeTSA()
        runtime = self._stamped(settings, tsa)
        with runtime.db.transaction() as tx:
            ledger.checkpoint(tx)  # 6
        _old_entries(runtime, 2, 1)
        # Marked as archived, and the entries before it removed.
        with runtime.db.transaction() as tx:
            LedgerCheckpoint.objects.filter(seq=6).update(pruned_at=ids.utcnow())
            LedgerEntry.objects.filter(seq__lte=6).delete()
        with runtime.db.transaction() as tx:
            zipped = compliance.pack(tx.orm(), runtime.settings, 30)
        folder = tmp_path / "pack"
        with zipfile.ZipFile(zipped) as z:
            z.extractall(folder)
        out = runner.invoke(cli.app, ["ledger", "verify", "--pack", str(folder)])
        assert out.exit_code == 2, out.output
        assert "no ledger.archived entry here says they were archived" in out.output
        # The time-stamped checkpoint of the entries that went: said, not skipped.
        assert "checkpoint 3 is for entries these files don't hold" in out.output
        runtime.db.dispose()

    def test_a_late_time_stamp_shows_offline_too(self, settings: Settings, tmp_path: Path) -> None:
        import zipfile

        from agentgov import cli
        from tests.test_cli import runner

        tsa = FakeTSA()
        tsa.gen_time = (ids.utcnow() + timedelta(days=3)).strftime("%Y%m%d%H%M%SZ").encode()
        runtime = self._stamped(settings, tsa)
        with runtime.db.transaction() as tx:
            zipped = compliance.pack(tx.orm(), runtime.settings, 30)
        folder = tmp_path / "pack"
        with zipfile.ZipFile(zipped) as z:
            z.extractall(folder)
        out = runner.invoke(cli.app, ["ledger", "verify", "--pack", str(folder)])
        assert out.exit_code == 0, out.output
        assert "checkpoint 3 vouches only from" in out.output
        runtime.db.dispose()


class TestArchives:
    def test_old_entries_are_archived_then_removed(self, archiving: Runtime) -> None:
        rt = archiving
        _old_entries(rt, 5, 300)
        _old_entries(rt, 2, 1)
        with rt.db.transaction() as tx:
            out = retention.archive(tx, rt.settings)
        assert (out["from"], out["to"], out["entries"]) == (1, 5, 5)
        path = Path(rt.settings.ledger_archive_dir) / out["archive"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == out["sha256"]
        records = list(retention.read_archive(path))
        assert [r["seq"] for r in records] == [1, 2, 3, 4, 5]
        assert ledger.verify_records(records, start=(0, ledger.GENESIS))["valid"]
        with rt.db.transaction() as tx:
            assert LedgerEntry.objects.order_by("seq").values_list("seq", flat=True).first() == 6
            point = LedgerCheckpoint.objects.get(seq=5)
            assert (point.archive, point.archived_from) == (out["archive"], 1)
            # The chain in the database goes on from the checkpoint, and still verifies.
            result = ledger.verify(tx)
            assert (result["valid"], result["from"], result["checked"]) == (True, 5, 8)
            archived = LedgerEntry.objects.filter(type="ledger.archived").first()
            assert archived.details["sha256"] == out["sha256"]
            # The chain says which entries left, up to which hash, going on from which.
            assert archived.details["follows"] == ledger.GENESIS
            assert (archived.details["from"], archived.details["to"]) == (1, 5)
            # The next archive goes on from this one.
            assert retention.archive(tx, rt.settings) is None
        # Nothing that left with it may still be in the database.
        records[2]["details"] = {}
        with rt.db.transaction() as tx:
            LedgerEntry.objects.create(**{**records[2], "ts": ids.utcnow()})
        with rt.db.transaction() as tx:
            assert ledger.verify(tx)["problem"] == (
                "entry 3 is still in the database, though the entries up to 5 left it with an "
                "archive"
            )

    def test_an_archive_already_there_is_left_as_it_is(self, archiving: Runtime) -> None:
        """Archives are evidence: one already there, with other entries in it, isn't
        written over; with the same ones (an earlier round that didn't finish), it is kept."""
        rt = archiving
        _old_entries(rt, 5, 300)
        directory = Path(rt.settings.ledger_archive_dir)
        directory.mkdir(parents=True, exist_ok=True)
        there = directory / "ledger-000000000001-000000000005.jsonl.gz"
        there.write_bytes(gzip.compress(b'{"seq": 1, "reason": "another history"}\n'))
        with rt.db.transaction() as tx:
            out = retention.archive(tx, rt.settings)
        assert "already there" in out["error"]
        assert gzip.decompress(there.read_bytes()) == b'{"seq": 1, "reason": "another history"}\n'
        with rt.db.transaction() as tx:
            assert LedgerEntry.objects.filter(seq=1).exists() and ledger.verify(tx)["from"] == 0
            failed = Finding.objects.filter(type=retention.ARCHIVE_FAILED).first()
            assert failed.status == "open" and "already there" in failed.description
        # The same entries, from a round whose transaction didn't commit: kept as they are.
        with rt.db.transaction() as tx:
            lines = [
                json.dumps(ledger.to_dict(e), sort_keys=True) + "\n"
                for e in ledger.iter_entries(tx, until=5)
            ]
        there.write_bytes(gzip.compress("".join(lines).encode(), mtime=0))
        kept = there.read_bytes()
        with rt.db.transaction() as tx:
            out = retention.archive(tx, rt.settings)
        assert out["to"] == 5 and there.read_bytes() == kept
        assert out["sha256"] == hashlib.sha256(kept).hexdigest()

    def test_what_a_destination_wasnt_sent_stays(self, archiving: Runtime) -> None:
        rt = archiving
        _old_entries(rt, 5, 300)
        with rt.db.transaction() as tx:
            features.set_mode(tx.orm(), rt.settings, "security-operations", "inform", actor="t")
            Destination.objects.create(
                id="dst_1", name="siem", kind="webhook", url="https://siem.test", cursor=3
            )
        with rt.db.transaction() as tx:
            assert retention.archive(tx, rt.settings)["to"] == 3
        with rt.db.transaction() as tx:
            # Not sent to while security operations are off: they don't hold anything back.
            features.set_mode(tx.orm(), rt.settings, "security-operations", "off", actor="t")
        with rt.db.transaction() as tx:
            # The rest of the old ones (6 on are recent: the features' changes, the archive).
            assert retention.archive(tx, rt.settings)["to"] == 5

    def test_a_broken_chain_isnt_archived(self, archiving: Runtime) -> None:
        rt = archiving
        _old_entries(rt, 4, 300)
        with rt.db.transaction() as tx:
            LedgerEntry.objects.filter(seq=2).update(reason="edited")
        with rt.db.transaction() as tx:
            assert "doesn't match its hash" in retention.archive(tx, rt.settings)["error"]
        with rt.db.transaction() as tx:
            assert LedgerEntry.objects.order_by("seq").values_list("seq", flat=True).first() == 1
            failed = Finding.objects.filter(type=retention.ARCHIVE_FAILED).first()
            assert failed.status == "open" and failed.severity == "high"

    def test_nowhere_to_write(self, archiving: Runtime, tmp_path: Path) -> None:
        blocked = tmp_path / "file"
        blocked.write_text("not a directory")
        rt = archiving
        rt.settings = rt.settings.with_overrides(ledger_archive_dir=str(blocked / "archive"))
        _old_entries(rt, 2, 300)
        with rt.db.transaction() as tx:
            assert retention.archive(tx, rt.settings)["error"]
        with rt.db.transaction() as tx:
            failed = Finding.objects.filter(type=retention.ARCHIVE_FAILED).first()
            assert failed.status == "open"
            # Nothing left the database.
            assert LedgerEntry.objects.filter(seq=1).exists() and ledger.verify(tx)["from"] == 0

    def test_archives_verify_offline(self, archiving: Runtime, monkeypatch, tmp_path: Path) -> None:
        from agentgov import cli
        from tests.test_cli import runner

        rt = archiving
        _old_entries(rt, 3, 300)
        with rt.db.transaction() as tx:
            first = retention.archive(tx, rt.settings)
        _old_entries(rt, 2, 250)
        with rt.db.transaction() as tx:
            # Entries 4 (ledger.archived) to 6, older than the period by now.
            second = retention.archive(tx, rt.settings, ids.utcnow() + timedelta(days=200))
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
    with rt.db.transaction() as tx:
        for when, tag in ((old, "old"), (recent, "new")):
            day = when.strftime("%Y-%m-%d")
            AgentActivity.objects.create(agent_id=f"agt_{tag}", day=day)
            ModelUsage.objects.create(agent_id=f"agt_{tag}", day=day, provider="p", model="m")
            RiskSignal.objects.create(id=f"sig_{tag}", agent_id="agt_x", kind="denied", ts=when)
            ApprovalRequest.objects.create(id=f"apr_{tag}", agent_id="agt_x", agent_name="x",
                                           action="a", resource="r", arguments_hash="h",
                                           status="approved", requested_at=when,
                                           expires_at=when)  # fmt: skip
            finding, _ = findings.raise_finding(
                tx, type="test.thing", severity="low", subject=tag, title=tag
            )
            finding.status, finding.resolved_at = "resolved", when
            finding.save()
            Notification.objects.create(id=f"ntf_{tag}", finding_id=finding.id, level="team",
                                        channel="email", recipient="a@example.com",
                                        status="sent", created_at=when)  # fmt: skip
        ApprovalRequest.objects.create(id="apr_waiting", agent_id="agt_x", agent_name="x",
                                       action="a", resource="r", arguments_hash="h",
                                       status="pending", requested_at=old,
                                       expires_at=now)  # fmt: skip
    with rt.db.transaction() as tx:
        removed = retention.prune_records(tx, rt.settings, now)
    assert removed == {
        "activity": 1,
        "model_usage": 1,
        "risk_signals": 1,
        "notifications": 1,
        "approvals": 1,
        "findings": 1,
    }
    with rt.db.transaction() as tx:
        assert set(AgentActivity.objects.values_list("agent_id", flat=True)) == {"agt_new"}
        assert set(ApprovalRequest.objects.values_list("id", flat=True)) == {
            "apr_new",
            "apr_waiting",
        }
        assert list(Finding.objects.values_list("subject", flat=True)) == ["new"]
        entry = LedgerEntry.objects.filter(type="retention.pruned").first()
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
        # Monitored, the calls that would wait go through: not in place either.
        body = {"mode": "monitor"}
        client.put("/v1/features/approvals", json=body, headers=ADMIN).raise_for_status()
        oversight = control("Art. 14")
        assert oversight["status"] == "partly"
        assert "monitor mode" in oversight["gaps"][0]
        client.put("/v1/features/least-privilege", json={"mode": "monitor"}, headers=ADMIN)
        security = control("MEASURE 2.7", "nist-ai-rmf")
        # Set, but no call went through AgentGov's checks yet: nothing shows them working.
        assert security["status"] == "configured"
        assert "least-privilege" in security["gaps"][0]
        assert "No call went through" in security["gaps"][-1]
        rt = client.app.state.rt  # type: ignore[attr-defined]
        with rt.db.transaction() as tx:
            for decision, reason in [
                ("deny", "crm/export_customers is not granted"),
                ("deny", "credentials in the arguments"),
                ("allow", "monitored: least-privilege: crm/export_customers is not granted"),
                ("allow", None),
            ]:
                ledger.append(
                    tx, type="decision.request", actor="agent:a", decision=decision, reason=reason
                )
        counts = {e["label"]: e["value"] for e in security["evidence"]}
        assert counts["Calls refused"] == 0 and counts["Let through in monitor mode"] == 0
        security = control("MEASURE 2.7", "nist-ai-rmf")
        assert security["status"] == "partly" and "least-privilege" in security["gaps"][0]
        counts = {e["label"]: e["value"] for e in security["evidence"]}
        assert counts["Calls refused"] == 2 and counts["Let through in monitor mode"] == 1
        with rt.db.transaction() as tx:
            LedgerEntry.objects.filter(seq=1).update(reason="edited")
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


def test_record_keeping_says_when_the_authority_isnt_checked(settings: Settings) -> None:
    with TestClient(
        create_app(settings.with_overrides(ledger_tsa_url="https://tsa.test/"), background=False)
    ) as client:
        report = client.get("/v1/evidence/report", params={"days": 7}, headers=ADMIN).json()
    art12 = next(c for c in report["controls"] if c["id"] == "Art. 12")
    assert art12["status"] == "partly" and "AGENTGOV_LEDGER_TSA_CA_FILE" in art12["gaps"][0]
