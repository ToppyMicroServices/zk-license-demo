"""Process-kill recovery after issuer SQL writes, not mid-COMMIT or power loss.

The fixture adds inert state padding and the child uses a small spilling cache
to require evidence of database-file writes before each uncommitted checkpoint.
Recovery explicitly opens both databases read/write with ATTACH. This does not
establish that a read-only application startup can recover a hot journal.
"""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import lifecycle as issuer
import split_wallet as wallet
from request_store import Rejected
from zk_license import backend

PADDING_BYTES = 256 * 1024
# SQLite's documented rollback-journal header, not a journal-content dump.
# https://www.sqlite.org/fileformat2.html#the_rollback_journal
JOURNAL_MAGIC = bytes.fromhex("d9d505f920a163d7")


def journal_metadata(path):
    journal = Path(str(path) + "-journal")
    if not journal.exists():
        return {"exists": False, "bytes": 0, "valid_header": False,
                "page_records": 0, "has_page_record": False}
    with journal.open("rb") as stream:
        header = stream.read(28)
    size = journal.stat().st_size
    sector = int.from_bytes(header[20:24], "big")
    page_size = int.from_bytes(header[24:28], "big")
    return {"exists": True, "bytes": size, "valid_header": header[:8] == JOURNAL_MAGIC,
            "page_records": int.from_bytes(header[8:12], "big"),
            "has_page_record": len(header) == 28 and sector >= 512
            and page_size >= 512 and size >= sector + page_size + 8}


def issuer_worker(private, registry, enrollment, checkpoint, baseline_hashes, connection):
    """Delegate real save/issuance operations, then block until the parent kills us."""
    paths = {"issuer": Path(private), "registry": Path(registry)}
    actual_save = issuer.save
    observed_close, completed_saves, settings = {}, [], {}

    class ObservedConnection(sqlite3.Connection):
        def close(self):
            observed_close["in_transaction"] = self.in_transaction
            super().close()
            observed_close["closed"] = True

    def controlled_connect(path, *, readonly=False):
        uri = Path(path).resolve().as_uri() + ("?mode=ro" if readonly else "?mode=rw")
        return sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None,
                               factory=ObservedConnection)

    def pause(stage, con=None, issued_index=None):
        connection.send({
            "checkpoint": stage, "pid": os.getpid(),
            "in_transaction": con.in_transaction if con is not None else observed_close["in_transaction"],
            "transaction_observed_at": "checkpoint" if con is not None else "connection_close",
            "connection_closed": con is None and observed_close.get("closed", False),
            "completed_saves": list(completed_saves), "settings": settings,
            "journals": {role: journal_metadata(path) for role, path in paths.items()},
            "database_files_changed": {
                role: hashlib.sha256(path.read_bytes()).hexdigest() != baseline_hashes[role]
                for role, path in paths.items()},
            "issued_index": issued_index,
        })
        connection.recv()
        raise RuntimeError("parent_released_kill_checkpoint")

    def saved(con, role, data, db="main"):
        # Test-only cache pressure. PRAGMA cache_spill allows dirty pages to be
        # written before COMMIT; the checkpoint verifies this actually happened.
        # https://www.sqlite.org/pragma.html#pragma_cache_spill
        con.execute("PRAGMA cache_spill=ON")
        con.execute(f"PRAGMA {db}.cache_size=1")
        con.execute(f"PRAGMA {db}.cache_spill=1")
        settings[role] = {
            "cache_size": con.execute(f"PRAGMA {db}.cache_size").fetchone()[0],
            "cache_spill": con.execute(f"PRAGMA {db}.cache_spill").fetchone()[0],
            "journal_mode": con.execute(f"PRAGMA {db}.journal_mode").fetchone()[0],
            "synchronous": con.execute(f"PRAGMA {db}.synchronous").fetchone()[0],
        }
        actual_save(con, role, data, db)
        completed_saves.append(role)
        stage = "after_issuer_save" if role == "issuer" else "after_registry_save"
        if checkpoint == stage:
            pause(stage, con)

    try:
        with patch.object(issuer, "connect", controlled_connect), patch.object(issuer, "save", saved):
            issued = issuer.issue(private, registry, enrollment)
        pause("after_commit", issued_index=backend().Credential.load(issued["credential"]).rev_reg_index)
    except Exception as exc:
        # A test failure must not print a credential or a private-state snapshot.
        connection.send({"checkpoint": "worker_error", "pid": os.getpid(),
                         "error_type": type(exc).__name__})
        raise SystemExit(1) from None
    finally:
        connection.close()


class IssuerCrashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            backend()
        except RuntimeError:
            if os.environ.get("REQUIRE_CRYPTO") == "1":
                raise
            raise unittest.SkipTest("anoncreds unavailable")
        fixture = tempfile.TemporaryDirectory()
        cls.addClassCleanup(fixture.cleanup)
        cls.source = Path(fixture.name) / "source"
        i, r, w, v = (cls.source / role / "state.sqlite3"
                      for role in ("issuer", "public", "wallet", "verifier"))
        cls.key = issuer.initialize(i, r)
        # Pad before any Wallet/verifier trust checkpoint is created. The field
        # is inert synthetic fixture data; it is never added to application code.
        for path, role in ((i, "issuer"), (r, "registry")):
            with issuer.store(path, role, write=True) as state:
                state["crash_fixture_padding"] = "x" * PADDING_BYTES
        pair = wallet.verifier_init(v, r, "synthetic-issuer-recovery.example")
        wallet.wallet_init(w, r, pair)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "case"
        shutil.copytree(self.source, self.root)
        self.i, self.r, self.w, self.v = (self.root / role / "state.sqlite3"
                                        for role in ("issuer", "public", "wallet", "verifier"))

    def recover_in_place(self):
        # Do not copy databases, remove journals, or use issuer_transaction to
        # observe recovery: it would write state and could hide an inconsistency.
        with closing(issuer.connect(self.i)) as con:
            con.execute("ATTACH DATABASE ? AS registry", (self.r.resolve().as_uri() + "?mode=rw",))
            con.execute("BEGIN")
            state = {"issuer": issuer.load(con, "issuer"),
                     "registry": issuer.load(con, "registry", "registry")}
            for db in ("main", "registry"):
                self.assertTrue(con.execute(f"PRAGMA {db}.integrity_check").fetchall() == [("ok",)],
                                f"{db} integrity_check failed")
            con.execute("COMMIT")
        return state

    def verify_fresh_proof(self):
        signed = wallet.request(self.v, self.r, self.key, "2030-06-01")
        shown = wallet.review(self.w, self.r, signed)
        proof = wallet.present(self.w, self.r, signed, shown["review_hash"], approve=True)
        result = wallet.verify(self.v, self.r, proof)
        self.assertIs(result["accepted"], True)
        self.assertIs(result["synthetic_revocation_checked"], True)
        self.assertIs(result["live_licence_status_checked"], False)
        with self.assertRaisesRegex(Rejected, "already_used"):
            wallet.verify(self.v, self.r, proof)

    def exercise_termination(self, checkpoint):
        offered = issuer.offer(self.i, self.r)
        enrollment = wallet.enroll(self.w, self.r, offered)
        baseline = self.recover_in_place()
        initial_index = baseline["registry"]["keys"][self.key]["next_index"]
        initial_revision = baseline["registry"]["revision"]
        paths = {"issuer": self.i, "registry": self.r}
        hashes = {role: hashlib.sha256(path.read_bytes()).hexdigest() for role, path in paths.items()}
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        process = context.Process(target=issuer_worker,
                                  args=(self.i, self.r, enrollment, checkpoint, hashes, child), daemon=True)
        try:
            process.start()
            child.close()
            self.assertTrue(parent.poll(60), "issuer child did not reach checkpoint")
            observed = parent.recv()
            self.assertEqual(observed["checkpoint"], checkpoint,
                             "issuer child reported an unexpected checkpoint")
            self.assertEqual(observed["pid"], process.pid)
            self.assertTrue(process.is_alive())
            committed = checkpoint == "after_commit"
            self.assertIs(observed["in_transaction"], not committed)
            expected_saves = ["issuer"] if checkpoint == "after_issuer_save" else ["issuer", "registry"]
            self.assertEqual(observed["completed_saves"], expected_saves)
            for role in expected_saves:
                settings = observed["settings"][role]
                self.assertEqual(settings["cache_size"], 1)
                self.assertGreater(settings["cache_spill"], 0)
                self.assertEqual(settings["journal_mode"], "delete")
                self.assertEqual(settings["synchronous"], 2)
                self.assertTrue(observed["database_files_changed"][role], "no database-file spill observed")
                if not committed:
                    journal = observed["journals"][role]
                    self.assertTrue(journal["valid_header"] and journal["has_page_record"],
                                    "no valid rollback-journal page record observed")
                    self.assertGreater(journal["page_records"], 0)
            if committed:
                self.assertIs(observed["connection_closed"], True)
                self.assertEqual(observed["issued_index"], initial_index)
            process.kill()
            process.join(10)
            self.assertFalse(process.is_alive(), "issuer child did not terminate")
            exitcode = process.exitcode
            self.assertIsNotNone(exitcode)
            self.assertNotEqual(exitcode, 0)
            if os.name == "posix":
                self.assertEqual(exitcode, -signal.SIGKILL)
        finally:
            if process.pid is not None:
                if process.is_alive():
                    process.kill()
                process.join(10)
                if not process.is_alive():
                    process.close()
            parent.close()
            child.close()

        after_kill_journals = {role: journal_metadata(path) for role, path in paths.items()}
        if not committed:
            for role in expected_saves:
                self.assertTrue(after_kill_journals[role]["valid_header"]
                                and after_kill_journals[role]["has_page_record"],
                                "rollback journal was not retained after kill")
        recovered = self.recover_in_place()
        self.assertTrue(all(not journal_metadata(path)["exists"] for path in paths.values()),
                        "rollback journals remain after read/write recovery")
        if not committed:
            self.assertTrue(recovered == baseline, "uncommitted issuer/registry state changed")
            retried = issuer.issue(self.i, self.r, enrollment)
            self.assertEqual(backend().Credential.load(retried["credential"]).rev_reg_index, initial_index)
            wallet.import_credential(self.w, self.r, retried)
            self.verify_fresh_proof()
            retry_result = "issued_original_index"
        else:
            expected_issuer = deepcopy(baseline["issuer"])
            del expected_issuer["offers"][enrollment["offer_id"]]
            self.assertTrue(recovered["issuer"] == expected_issuer, "committed issuer state mismatch")
            key = recovered["registry"]["keys"][self.key]
            self.assertEqual(recovered["registry"]["revision"], initial_revision + 1)
            self.assertEqual(key["next_index"], initial_index + 1)
            self.assertEqual(key["status"]["timestamp"], initial_revision + 1)
            with self.assertRaisesRegex(Rejected, "unknown_offer"):
                issuer.issue(self.i, self.r, enrollment)
            retry_result = "unknown_offer"

        fresh = issuer.issue(self.i, self.r, wallet.enroll(self.w, self.r, issuer.offer(self.i, self.r)))
        fresh_index = backend().Credential.load(fresh["credential"]).rev_reg_index
        self.assertEqual(fresh_index, initial_index + 1)
        wallet.import_credential(self.w, self.r, fresh)
        self.verify_fresh_proof()
        with issuer.store(self.r, "registry") as public:
            self.assertEqual(public["keys"][self.key]["next_index"], initial_index + 2)
        print(json.dumps({"check": "issuer_transaction_process_termination", "checkpoint": checkpoint,
                          "pid": observed["pid"], "exitcode": exitcode, "sqlite": sqlite3.sqlite_version,
                          "in_transaction": observed["in_transaction"],
                          "transaction_observed_at": observed["transaction_observed_at"],
                          "completed_saves": expected_saves, "settings": observed["settings"],
                          "padding_bytes_per_state": PADDING_BYTES,
                          "database_files_changed": observed["database_files_changed"],
                          "journals_after_kill": after_kill_journals, "integrity": "ok",
                          "uncommitted_state_matches_baseline": None if committed else True,
                          "original_enrollment_retry": retry_result, "fresh_index": fresh_index,
                          "fresh_proof_accepted": True, "proof_replay_rejected": True,
                          "recovery": "in_place_rw_attach", "power_loss_tested": False}), flush=True)

    def test_issuer_save_is_rolled_back_after_process_kill(self):
        self.exercise_termination("after_issuer_save")

    def test_both_saves_are_rolled_back_before_commit_after_process_kill(self):
        self.exercise_termination("after_registry_save")

    def test_committed_issuance_survives_process_kill_without_reusing_index(self):
        self.exercise_termination("after_commit")
