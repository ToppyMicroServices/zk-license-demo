"""Real RSA with synthetic card bytes and explicit test-only provider adapters."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from card_signature import CardSignatureVerifier, TrustedCardKey
from enrollment_gate import (BoundIdentity, CardCapture, EnrollmentGate,
                             EnrollmentRejected, IntegrationUnavailable)


class FixtureReader:
    def __init__(self, capture):
        self.capture, self.calls = capture, 0

    def read(self, context):
        self.calls += 1
        return self.capture


class FixtureIdentity:
    provider_id = "test-only-identity.example"

    def __init__(self):
        self.modify = lambda person: person
        self.calls = 0

    def verify_and_match(self, context, card, signed_files):
        # NOT JPKI. Exercises the gate's binding checks, not real-person matching.
        self.calls += 1
        if hashlib.sha256(signed_files["WEF02"]).hexdigest() != card.signed_data_sha256:
            raise ValueError("test fixture received different signed data")
        try:
            signed_files["WEF02"] = b"changed"
        except TypeError:
            pass
        else:
            raise AssertionError("identity adapter received a mutable capture")
        return self.modify(BoundIdentity(
            self.provider_id, "synthetic-provider-subject", context.nonce,
            context.wallet_request_sha256, card.evidence_sha256, context.audience,
            context.created_at, context.expires_at))


class EnrollmentGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
        except ImportError:
            if os.environ.get("REQUIRE_CARD_CRYPTO") == "1":
                raise
            raise unittest.SkipTest("optional card cryptography unavailable")
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = private.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.key = TrustedCardKey("synthetic-test-key", "myna010", der,
                                "npa-rsa2048-pkcs1v15-raw-sha256-experimental")
        cls.files = {"WEF02": b"SYNTHETIC-NOT-A-REAL-CARD".ljust(5845, b"\0")}
        signature = private.sign(hashlib.sha256(cls.files["WEF02"]).digest(),
                                 padding.PKCS1v15(), utils.NoDigestInfo())
        cls.capture = CardCapture("myna010", cls.key.key_id, cls.files, signature)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "private-enrollment.sqlite3"
        self.reader, self.identity = FixtureReader(self.capture), FixtureIdentity()
        self.configuration = dict(audience="issuer.test.example", reader=self.reader,
                                  signatures=CardSignatureVerifier((self.key,)), identity=self.identity)
        self.gate = EnrollmentGate(self.path, **self.configuration)
        self.ctx = self.gate.begin(account_id="synthetic-account", wallet_request=b"wallet-A-request",
                                   purpose="test-only-enrollment", now=1000)

    def complete(self, **overrides):
        args = dict(account_id="synthetic-account", wallet_request=b"wallet-A-request", consent=True, now=1001)
        args.update(overrides)
        return self.gate.complete(self.ctx.request_id, **args)

    def test_crypto_backed_local_orchestration_and_restart_replay(self):
        receipt = self.complete()
        self.assertFalse(receipt.live_licence_status_checked)
        self.assertEqual(receipt.stage, "experimental_boundary_only")
        self.assertEqual(receipt.wallet_request_sha256, self.ctx.wallet_request_sha256)
        self.gate = EnrollmentGate.reopen(self.path, **self.configuration)
        with self.assertRaisesRegex(EnrollmentRejected, "unavailable_or_used"):
            self.complete()
        self.assertEqual(self.reader.calls, 1)

    def test_unconfigured_providers_fail_closed(self):
        for setting in ("reader", "signatures", "identity"):
            with self.subTest(setting=setting):
                self.gate = EnrollmentGate.reopen(self.path, **{**self.configuration, setting: None})
                with self.assertRaises(IntegrationUnavailable):
                    self.complete()
        self.assertEqual(self.reader.calls, 0)

    def test_owner_wallet_audience_and_expiry_before_provider(self):
        for changes in ({"account_id": "other-account"}, {"wallet_request": b"wallet-B-request"},
                        {"now": 1300}, {"now": 999}, {"consent": "true"}):
            with self.subTest(changes=changes), self.assertRaises(EnrollmentRejected):
                self.complete(**changes)
        other = EnrollmentGate.reopen(self.path, **{**self.configuration, "audience": "other-issuer"})
        with self.assertRaisesRegex(EnrollmentRejected, "binding_mismatch"):
            other.complete(self.ctx.request_id, account_id="synthetic-account",
                           wallet_request=b"wallet-A-request", consent=True, now=1001)
        self.assertEqual(self.reader.calls, 0)

    def test_denial_is_final_and_does_not_contact_adapters(self):
        with self.assertRaisesRegex(EnrollmentRejected, "consent_denied"):
            self.complete(consent=False)
        with self.assertRaisesRegex(EnrollmentRejected, "unavailable_or_used"):
            self.complete()
        self.assertEqual(self.reader.calls, 0)

    def test_identity_provider_card_and_wallet_substitutions(self):
        changes = ({"provider": "other-provider"}, {"subject": ""}, {"subject": True},
                   {"nonce": "other-nonce"}, {"audience": "other-audience"},
                   {"wallet_request_sha256": "0" * 64}, {"card_evidence_sha256": "0" * 64},
                   {"authenticated_at": 999}, {"authenticated_at": 1002},
                   {"authenticated_at": True}, {"expires_at": 1001}, {"expires_at": 1301})
        for change in changes:
            with self.subTest(change=change):
                self.identity.modify = lambda p, c=change: replace(p, **c)
                with self.assertRaisesRegex(EnrollmentRejected, "identity_binding_mismatch"):
                    self.complete()
        self.identity.modify = lambda p: {"verified": True}
        with self.assertRaisesRegex(EnrollmentRejected, "identity_binding_mismatch"):
            self.complete()
        self.identity.modify = lambda p: p
        self.assertEqual(self.complete().request_id, self.ctx.request_id)

    def test_expiry_rechecked_after_adapter_work(self):
        with patch("enrollment_gate.time.time", side_effect=[1001, 1300]):
            with self.assertRaisesRegex(EnrollmentRejected, "enrollment_expired"):
                self.complete(now=None)

    def test_tampered_card_never_reaches_identity_adapter(self):
        self.reader.capture = replace(self.capture, files={"WEF02": b"X" * 5845})
        with self.assertRaises(ValueError):
            self.complete()
        self.assertEqual(self.identity.calls, 0)

    def test_provider_error_does_not_create_receipt(self):
        def unavailable(_):
            raise IntegrationUnavailable("test-provider-outage")
        self.identity.modify = unavailable
        with self.assertRaises(IntegrationUnavailable):
            self.complete()
        self.identity.modify = lambda p: p
        self.complete()

    def test_concurrent_completion_is_single_use(self):
        def finish(_):
            try:
                return self.complete().request_id
            except EnrollmentRejected:
                return "rejected"
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(finish, range(2))), [self.ctx.request_id, "rejected"])

    def test_store_and_receipt_do_not_contain_raw_card_or_provider_subject(self):
        receipt = self.complete()
        self.assertNotIn(b"SYNTHETIC-NOT-A-REAL-CARD", self.path.read_bytes())
        self.assertNotIn(b"synthetic-provider-subject", self.path.read_bytes())
        self.assertNotIn("synthetic-provider-subject", repr(receipt))
        self.assertNotIn("synthetic-account", repr(self.ctx))
        if os.name != "nt":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_store_creation_does_not_overwrite_and_context_is_bounded(self):
        with self.assertRaises(FileExistsError):
            EnrollmentGate(self.path, audience="issuer.test.example")
        for changes in ({"ttl": 301}, {"ttl": True}, {"purpose": ""}, {"wallet_request": b""}):
            args = dict(account_id="synthetic-account", wallet_request=b"wallet-request", purpose="test")
            args.update(changes)
            with self.subTest(changes=changes), self.assertRaises(EnrollmentRejected):
                self.gate.begin(**args)

    def test_reopening_cannot_bypass_audience_validation(self):
        for audience in (None, "", True, "a" * 513):
            with self.subTest(audience=audience), self.assertRaisesRegex(
                    EnrollmentRejected, "invalid_audience"):
                EnrollmentGate.reopen(self.path, **{**self.configuration, "audience": audience})
