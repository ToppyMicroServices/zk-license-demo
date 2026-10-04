"""REAL AnonCreds integration tests. No replacement/mock crypto backend is used.

Missing anoncreds skips this class for local policy-only work. CI and the release
script set REQUIRE_CRYPTO=1, turning a missing backend into a hard test failure.
"""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from request_store import Challenge
from zk_license import (DemoHolder, backend, issue_demo, make_issuer, make_presentation,
                        verify_presentation)


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if importlib.util.find_spec("anoncreds") is None:
            if os.getenv("REQUIRE_CRYPTO") == "1":
                raise RuntimeError("REQUIRE_CRYPTO=1 but anoncreds is unavailable")
            raise unittest.SkipTest("Real ZK backend unavailable; crypto is NOT verified")
        cls.ac = backend()
        cls.issuer = make_issuer()
        cls.holder = issue_demo(cls.issuer)
        cls.challenge = Challenge.new(audience="https://rental.example", session="test-session",
                                      service_day="2030-06-01")
        cls.proof = make_presentation(cls.holder, cls.challenge, cls.issuer.trust)

    def test_real_signature_and_hidden_predicates(self):
        self.assertTrue(verify_presentation(self.proof, self.challenge, self.issuer.trust))
        for key in ("revealed_attrs", "revealed_attr_groups", "unrevealed_attrs", "self_attested_attrs"):
            self.assertEqual(self.proof["requested_proof"].get(key, {}), {})

    def test_hidden_identity_strings_not_in_presentation(self):
        serialized = json.dumps(self.proof)
        for key in ("full_name", "address", "license_number"):
            self.assertNotIn(self.holder.synthetic_attributes[key], serialized)
        # A plaintext check is NOT a proof of zero-knowledge; this is an export regression check.

    def test_changed_nonce_rejected(self):
        changed = replace(self.challenge, nonce=str(int(self.challenge.nonce) + 1))
        self.assertFalse(verify_presentation(self.proof, changed, self.issuer.trust))

    def test_issuer_name_is_not_enough_key_is_pinned(self):
        # Adversary uses the SAME public identifiers with a DIFFERENT private key.
        attacker = make_issuer("trusted")
        holder = issue_demo(attacker)
        forged = make_presentation(holder, self.challenge, attacker.trust)
        self.assertFalse(verify_presentation(forged, self.challenge, self.issuer.trust))

    def test_untrusted_issuer_rejected(self):
        attacker = make_issuer("untrusted")
        forged = make_presentation(issue_demo(attacker), self.challenge, attacker.trust)
        self.assertFalse(verify_presentation(forged, self.challenge, self.issuer.trust))

    def test_expired_credential_with_weaker_request_rejected(self):
        holder = issue_demo(self.issuer, valid_until="2029-12-31")
        weaker = self.challenge.proof_request(self.issuer.trust.cred_def_id)
        weaker["requested_predicates"]["expiry"]["p_value"] = 20290101
        # Real proof of a weaker claim, not merely an honest prover refusing to run.
        proof = make_presentation(holder, self.challenge, self.issuer.trust, request_override=weaker)
        self.assertFalse(verify_presentation(proof, self.challenge, self.issuer.trust))

    def test_missing_entitlement_with_weaker_request_rejected(self):
        holder = issue_demo(self.issuer, can_drive=0)
        weaker = self.challenge.proof_request(self.issuer.trust.cred_def_id)
        weaker["requested_predicates"]["ordinary"]["p_value"] = 0
        proof = make_presentation(holder, self.challenge, self.issuer.trust, request_override=weaker)
        self.assertFalse(verify_presentation(proof, self.challenge, self.issuer.trust))

    def test_relabelled_weaker_entitlement_proof_rejected(self):
        holder = issue_demo(self.issuer, can_drive=0)
        weaker = self.challenge.proof_request(self.issuer.trust.cred_def_id)
        weaker["requested_predicates"]["ordinary"]["p_value"] = 0
        proof = make_presentation(holder, self.challenge, self.issuer.trust, request_override=weaker)
        for item in proof["proof"]["proofs"][0]["primary_proof"]["ge_proofs"]:
            if item["predicate"]["attr_name"] == "can_drive_ordinary":
                item["predicate"]["value"] = 1
        # Matching the wrapper's policy must not bypass cryptographic verification.
        self.assertFalse(verify_presentation(proof, self.challenge, self.issuer.trust))

    def test_relabelled_weaker_expiry_proof_rejected(self):
        holder = issue_demo(self.issuer, valid_until="2029-12-31")
        weaker = self.challenge.proof_request(self.issuer.trust.cred_def_id)
        weaker["requested_predicates"]["expiry"]["p_value"] = 20290101
        proof = make_presentation(holder, self.challenge, self.issuer.trust, request_override=weaker)
        for item in proof["proof"]["proofs"][0]["primary_proof"]["ge_proofs"]:
            if item["predicate"]["attr_name"] == "valid_until":
                item["predicate"]["value"] = 20300601
        self.assertFalse(verify_presentation(proof, self.challenge, self.issuer.trust))

    def test_different_predicate_attribute_rejected(self):
        changed = self.challenge.proof_request(self.issuer.trust.cred_def_id)
        changed["requested_predicates"]["ordinary"]["name"] = "birth_date"
        proof = make_presentation(self.holder, self.challenge, self.issuer.trust, request_override=changed)
        self.assertFalse(verify_presentation(proof, self.challenge, self.issuer.trust))

    def test_different_predicate_operator_rejected(self):
        changed = self.challenge.proof_request(self.issuer.trust.cred_def_id)
        changed["requested_predicates"]["ordinary"]["p_type"] = "<="
        proof = make_presentation(self.holder, self.challenge, self.issuer.trust, request_override=changed)
        self.assertFalse(verify_presentation(proof, self.challenge, self.issuer.trust))

    def test_signed_expiry_tampering_rejected(self):
        bad = self.holder.credential.to_dict()
        bad["values"]["valid_until"] = {"raw": "20991231", "encoded": "20991231"}
        try:
            holder = DemoHolder(self.ac.Credential.load(bad), self.holder.link_secret, {})
            proof = make_presentation(holder, self.challenge, self.issuer.trust)
        except self.ac.AnoncredsError:
            return  # Backend rejected tampering before a proof could be sent.
        self.assertFalse(verify_presentation(proof, self.challenge, self.issuer.trust))

    def test_modified_proof_rejected(self):
        bad = deepcopy(self.proof)
        bad["proof"]["aggregated_proof"]["c_hash"] = str(
            int(bad["proof"]["aggregated_proof"]["c_hash"]) + 1)
        self.assertFalse(verify_presentation(bad, self.challenge, self.issuer.trust))

    def test_removed_predicate_rejected(self):
        bad = deepcopy(self.proof)
        del bad["requested_proof"]["predicates"]["expiry"]
        self.assertFalse(verify_presentation(bad, self.challenge, self.issuer.trust))

    def test_new_proofs_are_not_identical(self):
        another = make_presentation(self.holder, self.challenge, self.issuer.trust)
        self.assertNotEqual(self.proof, another)
        self.assertTrue(verify_presentation(another, self.challenge, self.issuer.trust))
        # Difference alone does NOT establish unlinkability.

    def test_run_and_independent_verifier_process(self):
        root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            def invoke(*args):
                return subprocess.run([sys.executable, str(root / "demo.py"), *args],
                                      cwd=root, text=True, capture_output=True, timeout=180)
            result = invoke("run", "--out", str(out))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            first = invoke("verify", "--out", str(out))
            self.assertEqual(first.returncode, 0, first.stderr)
            second = invoke("verify", "--out", str(out))
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("already_used", second.stderr)
            report = json.loads((out / "report.json").read_text())
            self.assertTrue(report["measurements"]["accepted"])
            public = (out / "proof-envelope.json").read_text()
            self.assertNotIn("SAMPLE PERSON", public)
            self.assertNotIn("DEMO-NOT-A-LICENSE", public)
