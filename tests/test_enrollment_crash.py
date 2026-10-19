"""OS-process termination with synthetic card/provider data, not power-loss QA."""
from contextlib import closing
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import unittest

from card_signature import CardSignatureVerifier
from enrollment_gate import EnrollmentGate, EnrollmentRejected
from test_enrollment_gate import FixtureIdentity, FixtureReader, synthetic_card_fixture


def enrollment_worker(path, request_id, key, capture, checkpoint, connection):
    """Signal only after reaching a real gate boundary, then await forced death."""
    def pause(stage):
        connection.send((stage, os.getpid()))
        # No timeout or ordinary exception: the parent must kill this process.
        connection.recv()
        raise AssertionError("parent released a process that should be killed")

    class Reader(FixtureReader):
        def read(self, context):
            if checkpoint == "reader":
                pause("reader")
            return super().read(context)

    class Identity(FixtureIdentity):
        def verify_and_match(self, context, card, signed_files):
            if checkpoint == "identity":
                pause("identity")
            return super().verify_and_match(context, card, signed_files)

    gate = EnrollmentGate.reopen(
        path, audience="issuer.test.example", reader=Reader(capture),
        signatures=CardSignatureVerifier((key,)), identity=Identity())
    gate.complete(request_id, account_id="synthetic-account",
                  wallet_request=b"wallet-A-request", consent=True, now=1001)
    pause("completed")


class EnrollmentCrashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.capture = synthetic_card_fixture()

    def exercise_termination(self, checkpoint, expected_state):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "enrollment.sqlite3"
            reader, identity = FixtureReader(self.capture), FixtureIdentity()
            config = dict(audience="issuer.test.example", reader=reader, identity=identity,
                          signatures=CardSignatureVerifier((self.key,)))
            gate = EnrollmentGate(path, **config)
            request = gate.begin(account_id="synthetic-account", wallet_request=b"wallet-A-request",
                                 purpose="synthetic-crash-test", now=1000)
            context = multiprocessing.get_context("spawn")
            parent, child = context.Pipe()
            process = context.Process(
                target=enrollment_worker,
                args=(path, request.request_id, self.key, self.capture, checkpoint, child),
                daemon=True)
            try:
                process.start()
                child.close()
                self.assertTrue(parent.poll(30), "child did not reach checkpoint")
                self.assertEqual(parent.recv(), (checkpoint, process.pid))
                self.assertTrue(process.is_alive())
                with closing(sqlite3.connect(path)) as con:
                    before = con.execute("SELECT state,card_digest FROM enrollments WHERE id=?",
                                         (request.request_id,)).fetchone()
                self.assertEqual(before[0], expected_state)
                process.kill()  # SIGKILL on POSIX, TerminateProcess on Windows.
                process.join(10)
                self.assertFalse(process.is_alive(), "child did not terminate")
                self.assertIsNotNone(process.exitcode)
                self.assertNotEqual(process.exitcode, 0)
                exitcode = process.exitcode
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

            reopened = EnrollmentGate.reopen(path, **config)
            with closing(sqlite3.connect(path)) as con:
                self.assertEqual(con.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
                after = con.execute("SELECT state,card_digest FROM enrollments WHERE id=?",
                                    (request.request_id,)).fetchone()
            self.assertEqual(after, before)
            if expected_state == "processing":
                self.assertIsNone(after[1])
            else:
                evidence = config["signatures"].verify(
                    profile=self.capture.profile, key_id=self.capture.key_id,
                    files=self.capture.files, signature=self.capture.signature)
                self.assertEqual(after[1], evidence.evidence_sha256)
            with self.assertRaisesRegex(EnrollmentRejected, "enrollment_unavailable_or_used"):
                reopened.complete(request.request_id, account_id="synthetic-account",
                                  wallet_request=b"wallet-A-request", consent=True, now=1002)
            self.assertEqual((reader.calls, identity.calls), (0, 0))

            fresh = reopened.begin(account_id="synthetic-account", wallet_request=b"new-request",
                                   purpose="synthetic-crash-test", now=1002)
            receipt = reopened.complete(fresh.request_id, account_id="synthetic-account",
                                        wallet_request=b"new-request", consent=True, now=1003)
            self.assertNotEqual(receipt.request_id, request.request_id)
            self.assertEqual(receipt.request_id, fresh.request_id)
            self.assertEqual((reader.calls, identity.calls), (1, 1))
            self.assertFalse(receipt.live_licence_status_checked)
            print(json.dumps(dict(check="enrollment_process_termination", checkpoint=checkpoint,
                                  exitcode=exitcode, retained_state=after[0], integrity="ok",
                                  replay_rejected=True, replay_adapter_calls=0,
                                  fresh_enrollment_completed=True)), flush=True)

    def test_killed_reader_claim_survives_restart(self):
        self.exercise_termination("reader", "processing")

    def test_killed_identity_claim_survives_restart(self):
        self.exercise_termination("identity", "processing")

    def test_completed_claim_survives_process_termination(self):
        self.exercise_termination("completed", "completed")
