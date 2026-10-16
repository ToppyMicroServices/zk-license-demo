"""Real cryptography and separate-process regressions for synthetic custody."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import lifecycle as issuer
import split_wallet as wallet
from request_store import Rejected
from zk_license import backend

ROOT = Path(__file__).resolve().parents[1]


class SplitWalletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            backend()
        except RuntimeError:
            if os.environ.get("REQUIRE_CRYPTO") == "1":
                raise
            raise unittest.SkipTest("anoncreds unavailable")
        cls.fixture = tempfile.TemporaryDirectory()
        cls.source = Path(cls.fixture.name)
        i, r, w, v = (cls.source / name / "state.sqlite3" for name in ("issuer", "public", "wallet", "verifier"))
        cls.key = issuer.initialize(i, r)
        pair = wallet.verifier_init(v, r, "synthetic-service.example")
        wallet.wallet_init(w, r, pair)
        wallet.import_credential(w, r, issuer.issue(i, r, wallet.enroll(w, r, issuer.offer(i, r))))

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "case"
        shutil.copytree(self.source, self.root)
        self.i, self.r, self.w, self.v = (self.root / name / "state.sqlite3" for name in ("issuer", "public", "wallet", "verifier"))

    def new_request(self, key=None, **kwargs):
        return wallet.request(self.v, self.r, key or self.key, "2030-06-01", **kwargs)

    def prove(self, request=None):
        request = request or self.new_request()
        reviewed = wallet.review(self.w, self.r, request)
        return wallet.present(self.w, self.r, request, reviewed["review_hash"], approve=True)

    def reissue(self):
        issued = issuer.issue(self.i, self.r, wallet.enroll(self.w, self.r, issuer.offer(self.i, self.r)))
        wallet.import_credential(self.w, self.r, issued)
        return backend().Credential.load(issued["credential"]).rev_reg_index

    def raw_proof(self, signed, *, weaker=False):
        """Bypass wallet consent/revoked guards to exercise verifier cryptography."""
        ac = backend()
        with issuer.store(self.w, "wallet") as local, issuer.store(self.r, "registry") as public:
            key = public["keys"][signed["payload"]["key_id"]]
            credential = ac.Credential.load(local["credentials"][signed["payload"]["key_id"]])
            tails = self.r.parent / "tails" / key["rev_reg_def"]["value"]["tailsHash"]
            state = ac.CredentialRevocationState.create(key["rev_reg_def"], key["status"], credential.rev_reg_index, str(tails))
            selected = ac.PresentCredentials()
            selected.add_predicates(credential, "ordinary", "expiry", timestamp=key["status"]["timestamp"], rev_state=state)
            policy = deepcopy(signed["payload"]["proof_request"])
            if weaker:
                policy["requested_predicates"]["ordinary"]["p_value"] = 0
            proof = ac.Presentation.create(policy, selected, {}, local["link_secret"],
                                           {key["schema_id"]: key["schema"]}, {key["cred_def_id"]: key["cred_def"]}).to_dict()
            return {"request_id": signed["payload"]["challenge"]["request_id"], "presentation": proof}

    def test_separate_cli_processes_and_private_state_absent_from_verifier(self):
        def cli(command, private, *, value=None, output=None, extra=()):
            args = [sys.executable, "-W", "error", str(ROOT / "split_demo.py"), command,
                    "--store", str(private), "--registry", str(self.r), *extra]
            if value is not None:
                args.extend(["--input", str(value)])
            if output is not None:
                args.extend(["--out", str(output)])
            result = subprocess.run(args, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return issuer.read_json(output) if output else json.loads(result.stdout)
        # The enrollment request, never the link secret, crosses to the issuer.
        offer, enrollment, credential = (self.root / n for n in ("offer.json", "enroll.json", "credential.json"))
        cli("issuer-offer", self.i, output=offer)
        cli("wallet-enroll", self.w, value=offer, output=enrollment)
        self.assertEqual(set(issuer.read_json(enrollment)), {"instance", "offer_id", "request"})
        cli("issuer-issue", self.i, value=enrollment, output=credential)
        cli("wallet-import", self.w, value=credential)
        request, review, proof = (self.root / n for n in ("request.json", "review.json", "proof.json"))
        cli("verifier-request", self.v, output=request, extra=("--key-id", self.key, "--service-day", "2030-06-01"))
        shown = cli("wallet-review", self.w, value=request, output=review)
        cli("wallet-decide", self.w, value=request, output=proof,
            extra=("--review-hash", shown["review_hash"], "--decision", "approve"))
        # Remove all private holder/issuer material before starting the verifier.
        shutil.rmtree(self.w.parent)
        shutil.rmtree(self.i.parent)
        for sensitive in (credential, enrollment, offer):
            sensitive.unlink()
        self.assertTrue(cli("verifier-verify", self.v, value=proof)["accepted"])
        with issuer.store(self.v, "verifier") as local, issuer.store(self.r, "registry") as public:
            encoded = issuer.canonical([local, public, issuer.read_json(proof)])
            for secret_field in ('"link_secret"', '"credential"', '"cred_def_private"', '"rev_reg_private"', '"metadata"'):
                self.assertNotIn(secret_field, encoded)
            self.assertNotIn("SAMPLE PERSON", encoded)
        self.assertEqual(issuer.read_json(proof)["presentation"]["requested_proof"]["revealed_attrs"], {})

    def test_consent_tampering_and_final_refusal(self):
        signed = self.new_request()
        with self.assertRaisesRegex(Rejected, "matching_wallet_review"):
            wallet.present(self.w, self.r, signed, issuer.digest(signed), approve=True)
        tampered = deepcopy(signed)
        tampered["payload"]["challenge"]["audience"] = "attacker.example"
        with self.assertRaisesRegex(Rejected, "unauthenticated"):
            wallet.review(self.w, self.r, tampered)
        reviewed = wallet.review(self.w, self.r, signed)
        with self.assertRaisesRegex(Rejected, "matching_wallet_review"):
            wallet.present(self.w, self.r, signed, "0" * 64, approve=True)
        denied = wallet.present(self.w, self.r, signed, reviewed["review_hash"], approve=False)
        self.assertEqual(denied["decision"], "denied")
        with self.assertRaisesRegex(Rejected, "request_changed_or_decided"):
            wallet.review(self.w, self.r, signed)
        with self.assertRaisesRegex(Rejected, "matching_wallet_review"):
            wallet.present(self.w, self.r, signed, reviewed["review_hash"], approve=True)

    def test_authentic_but_extra_disclosure_request_is_refused(self):
        signed = self.new_request()
        signed["payload"]["proof_request"]["requested_attributes"] = {"name": {"name": "full_name"}}
        with issuer.store(self.v, "verifier") as local:
            signed["mac"] = wallet.authenticate(signed["payload"], local["pairing"])
        with self.assertRaisesRegex(Rejected, "unsupported_disclosure_policy"):
            wallet.review(self.w, self.r, signed)

    def test_approval_is_single_use_and_expired_review_cannot_approve(self):
        signed = self.new_request()
        self.prove(signed)
        with self.assertRaisesRegex(Rejected, "matching_wallet_review"):
            wallet.present(self.w, self.r, signed, issuer.digest(signed), approve=True)
        expired = self.new_request(now=1000)
        shown = wallet.review(self.w, self.r, expired, now=1000)
        with self.assertRaisesRegex(Rejected, "request_expired"):
            wallet.present(self.w, self.r, expired, shown["review_hash"], approve=True, now=1300)

    def test_issuance_request_is_bound_to_wallet_link_secret(self):
        other = self.root / "other-wallet.sqlite3"
        with issuer.store(self.v, "verifier") as local:
            wallet.wallet_init(other, self.r, local["pairing"])
        offered = issuer.offer(self.i, self.r)
        enrollment = wallet.enroll(self.w, self.r, offered)
        wallet.enroll(other, self.r, offered)
        issued = issuer.issue(self.i, self.r, enrollment)
        with self.assertRaises(backend().AnoncredsError):
            wallet.import_credential(other, self.r, issued)
        wallet.import_credential(self.w, self.r, issued)
        self.assertTrue(wallet.verify(self.v, self.r, self.prove())["accepted"])
        with self.assertRaisesRegex(Rejected, "unknown_offer"):
            issuer.issue(self.i, self.r, enrollment)

    def test_concurrent_replay_and_restart(self):
        proof = self.prove()
        def submit():
            try:
                return wallet.verify(self.v, self.r, proof)["accepted"]
            except Rejected as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: submit(), range(2)))
        self.assertCountEqual(results, [True, "already_used"])
        self.assertEqual(submit(), "already_used")

    def test_device_reset_invalidates_requests_and_old_pairing(self):
        old = self.new_request()
        proof = self.prove(old)
        pair = wallet.verifier_reset(self.v, self.r)
        with self.assertRaisesRegex(Rejected, "unknown_request"):
            wallet.verify(self.v, self.r, proof)
        fresh = self.new_request()
        with self.assertRaisesRegex(Rejected, "unauthenticated"):
            wallet.review(self.w, self.r, fresh)
        wallet.wallet_pair(self.w, self.r, pair)
        with self.assertRaisesRegex(Rejected, "unauthenticated"):
            wallet.review(self.w, self.r, old)
        self.assertTrue(wallet.verify(self.v, self.r, self.prove(fresh))["accepted"])

    def test_rotation_overlap_rollback_retirement_and_reissue(self):
        new = issuer.rotate(self.i, self.r)
        self.reissue()
        for key in (self.key, new):
            self.assertTrue(wallet.verify(self.v, self.r, self.prove(self.new_request(key)))["accepted"])
        issuer.change_key(self.i, self.r, self.key, "rollback")
        self.assertEqual(issuer.offer(self.i, self.r)["key_id"], self.key)
        issuer.change_key(self.i, self.r, new, "retire")
        with self.assertRaisesRegex(Rejected, "untrusted_issuer_key"):
            issuer.change_key(self.i, self.r, new, "rollback")
        with self.assertRaisesRegex(Rejected, "untrusted_issuer_key"):
            self.new_request(new)

    def test_revocation_rejects_stale_and_fresh_native_proofs(self):
        old = self.prove()
        issuer.revoke_credential(self.i, self.r, self.key, 1)
        with self.assertRaisesRegex(Rejected, "stale_registry_request"):
            wallet.verify(self.v, self.r, old)
        signed = self.new_request()
        with self.assertRaisesRegex(Rejected, "credential_revoked"):
            self.prove(signed)
        # A malicious holder bypassing the wallet guard still fails at verifier.
        forged = self.raw_proof(signed)
        with self.assertRaisesRegex(Rejected, "invalid_proof"):
            wallet.verify(self.v, self.r, forged)
        # A different, newly issued credential under the same key remains valid.
        self.assertEqual(self.reissue(), 2)
        self.assertTrue(wallet.verify(self.v, self.r, self.prove())["accepted"])

    def test_backup_does_not_restore_revocations_or_reuse_indices(self):
        backup = self.root / "backup.json"
        issuer.backup(self.i, backup)
        self.assertEqual(self.reissue(), 2)
        issuer.revoke_credential(self.i, self.r, self.key, 2)
        self.i.unlink()  # Recovery from complete loss of the private store.
        issuer.restore(self.i, self.r, backup)
        with self.assertRaisesRegex(Rejected, "credential_revoked"):
            self.prove()
        self.assertEqual(self.reissue(), 3)
        self.assertTrue(wallet.verify(self.v, self.r, self.prove())["accepted"])

    def test_compromised_key_stays_revoked_after_restore(self):
        backup = self.root / "backup.json"
        issuer.backup(self.i, backup)
        old = self.prove()
        issuer.change_key(self.i, self.r, self.key, "revoke")
        issuer.restore(self.i, self.r, backup)
        with self.assertRaisesRegex(Rejected, "stale_registry_request"):
            wallet.verify(self.v, self.r, old)
        with self.assertRaisesRegex(Rejected, "untrusted_issuer_key"):
            issuer.change_key(self.i, self.r, self.key, "rollback")
        with self.assertRaisesRegex(Rejected, "active_private_key_unavailable"):
            issuer.offer(self.i, self.r)
        new = issuer.rotate(self.i, self.r)
        self.reissue()
        self.assertTrue(wallet.verify(self.v, self.r, self.prove(self.new_request(new)))["accepted"])

    def test_backup_missing_current_key_refuses_issuance_and_foreign_backup(self):
        backup = self.root / "backup.json"
        issuer.backup(self.i, backup)
        issuer.rotate(self.i, self.r)
        issuer.restore(self.i, self.r, backup)
        with self.assertRaisesRegex(Rejected, "active_private_key_unavailable"):
            issuer.offer(self.i, self.r)
        foreign = issuer.read_json(backup)
        foreign["instance"] = "other-registry"
        wrong = self.root / "foreign.json"
        issuer.write_json(wrong, foreign)
        with self.assertRaisesRegex(Rejected, "wrong_backup_registry"):
            issuer.restore(self.i, self.r, wrong)
        new = issuer.rotate(self.i, self.r)
        self.reissue()
        self.assertTrue(wallet.verify(self.v, self.r, self.prove(self.new_request(new)))["accepted"])

    def test_registry_rollback_detected_even_after_refusal(self):
        with issuer.store(self.r, "registry") as public:
            old = deepcopy(public)
        issuer.change_key(self.i, self.r, self.key, "revoke")
        with self.assertRaisesRegex(Rejected, "untrusted_issuer_key"):
            self.new_request()
        with issuer.store(self.r, "registry", write=True) as public:
            public.clear()
            public.update(old)
        with self.assertRaisesRegex(Rejected, "registry_rollback_or_equivocation"):
            self.new_request()

    def test_same_revision_equivocation_and_missing_registry_fail_closed(self):
        self.new_request()
        with issuer.store(self.r, "registry", write=True) as public:
            public["keys"][self.key]["state"] = "verify_only"
        with self.assertRaisesRegex(Rejected, "registry_rollback_or_equivocation"):
            self.new_request()
        self.r.unlink()
        import sqlite3
        with self.assertRaises(sqlite3.OperationalError):
            self.new_request()
        with self.assertRaises(sqlite3.OperationalError):
            issuer.offer(self.i, self.r)
        self.assertFalse(self.r.exists())

    def test_issuer_transaction_rolls_back_both_stores(self):
        with self.assertRaisesRegex(RuntimeError, "injected"):
            with issuer.issuer_transaction(self.i, self.r) as (private, public):
                private["offers"]["bad"] = {}
                public["revision"] = 999
                raise RuntimeError("injected failure")
        with issuer.store(self.i, "issuer") as private, issuer.store(self.r, "registry") as public:
            self.assertNotIn("bad", private["offers"])
            self.assertEqual(public["revision"], 2)

    def test_weaker_proof_tampering_and_expiry_do_not_consume(self):
        signed = self.new_request()
        weak = self.raw_proof(signed, weaker=True)
        with self.assertRaisesRegex(Rejected, "invalid_proof"):
            wallet.verify(self.v, self.r, weak)
        good = self.prove(signed)
        malformed = deepcopy(good)
        malformed["presentation"]["identifiers"] = [None]
        with self.assertRaisesRegex(Rejected, "invalid_proof"):
            wallet.verify(self.v, self.r, malformed)
        bad = deepcopy(good)
        bad["presentation"]["identifiers"][0]["timestamp"] += 1
        with self.assertRaisesRegex(Rejected, "invalid_proof"):
            wallet.verify(self.v, self.r, bad)
        deadline = signed["payload"]["challenge"]["expires_at"]
        with patch("split_wallet.time.time", side_effect=[deadline - 1, deadline]):
            with self.assertRaisesRegex(Rejected, "request_expired_during_verification"):
                wallet.verify(self.v, self.r, good)
        self.assertTrue(wallet.verify(self.v, self.r, good)["accepted"])


if __name__ == "__main__":
    unittest.main()
