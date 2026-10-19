"""Synthetic RSA fixtures test the experimental byte-verification boundary only.

No official keys, real cards, personal data, SDK, or provider is exercised.
REQUIRE_CARD_CRYPTO=1 makes a missing backend a failure rather than a skip.
"""
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import importlib.util
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from card_signature import (CardSignatureError, CardSignatureVerifier,
                            EXPERIMENTAL_RAW_SHA256, TrustedCardKey)


SIZES = {
    "legacy-IC010": (("DF1/EF01", 880), ("DF1/EF02", 82), ("DF2/EF01", 2005)),
    "myna010": (("WEF02", 5845),),
}


def synthetic_files(profile="legacy-IC010"):
    return {name: bytes([65 + index]) * size
            for index, (name, size) in enumerate(SIZES[profile])}


class CardSignatureInputTests(unittest.TestCase):
    def configured(self):
        return TrustedCardKey("lab-key", "legacy-IC010", b"not-a-real-key",
                              EXPERIMENTAL_RAW_SHA256)

    def test_signature_mode_requires_explicit_operator_choice(self):
        with self.assertRaises(TypeError):
            TrustedCardKey("lab-key", "legacy-IC010", b"unused")
        with self.assertRaisesRegex(CardSignatureError, "unsupported_card_signature_mode"):
            replace(self.configured(), signature_mode="auto")

    def test_trust_records_and_allowlist_are_immutable(self):
        key = self.configured()
        entries = [key]
        verifier = CardSignatureVerifier(entries)
        entries.clear()
        self.assertEqual(verifier.keys, (key,))
        with self.assertRaises(FrozenInstanceError):
            key.key_id = "changed"
        with self.assertRaises(FrozenInstanceError):
            verifier.keys = ()

    def test_duplicate_trust_entries_are_rejected(self):
        with self.assertRaisesRegex(CardSignatureError, "duplicate_card_trust_entry"):
            CardSignatureVerifier((self.configured(), self.configured()))

    def test_invalid_trust_configuration_is_rejected(self):
        for value in (None, ({"verified": True},)):
            with self.subTest(value=value), self.assertRaises(CardSignatureError):
                CardSignatureVerifier(value)
        for change in ({"profile": "unknown"}, {"key_id": ""},
                       {"public_key_der": bytearray(b"mutable")},
                       {"public_key_der": b"x" * 16_385}):
            with self.subTest(change=change), self.assertRaises(CardSignatureError):
                replace(self.configured(), **change)

    def test_empty_allowlist_and_unknown_key_fail_closed(self):
        for verifier in (CardSignatureVerifier(()), CardSignatureVerifier((self.configured(),))):
            with self.subTest(verifier=verifier), self.assertRaisesRegex(
                    CardSignatureError, "untrusted_card_key"):
                verifier.verify(profile="legacy-IC010", key_id="unknown",
                                files=synthetic_files(), signature=b"x" * 256)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaisesRegex(CardSignatureError, "unsupported_card_profile"):
            CardSignatureVerifier(()).verify(profile="auto", key_id="key",
                                              files={}, signature=b"x" * 256)

    def test_missing_backend_is_hard_failure(self):
        with patch("card_signature.importlib.import_module", side_effect=ImportError):
            with self.assertRaisesRegex(RuntimeError, "backend unavailable"):
                CardSignatureVerifier((self.configured(),)).verify(
                    profile="legacy-IC010", key_id="lab-key",
                    files=synthetic_files(), signature=b"x" * 256)

    def test_module_import_does_not_import_crypto(self):
        code = """import builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith('cryptography'):
        raise ImportError('test excludes optional backend')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
import card_signature
assert card_signature.CardSignatureVerifier(()).keys == ()
"""
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exact_regions_and_byte_types_are_checked_before_backend(self):
        verifier = CardSignatureVerifier((self.configured(),))
        files = synthetic_files()
        wrong = [None, {}, {**files, "decoded_attributes": b"extra"},
                 {name: data for name, data in files.items() if name != "DF1/EF02"},
                 {**files, "DF1/EF01": b""},
                 {**files, "DF1/EF01": files["DF1/EF01"][:-1]},
                 {**files, "DF1/EF01": files["DF1/EF01"] + b"x"},
                 {**files, "DF1/EF01": bytearray(files["DF1/EF01"])}]
        with patch("card_signature._backend") as backend:
            for value in wrong:
                with self.subTest(value=value), self.assertRaises(CardSignatureError):
                    verifier.verify(profile="legacy-IC010", key_id="lab-key",
                                    files=value, signature=b"x" * 256)
            backend.assert_not_called()

    def test_signature_must_be_immutable_256_byte_value(self):
        verifier = CardSignatureVerifier((self.configured(),))
        with patch("card_signature._backend") as backend:
            for signature in (None, True, b"", b"x" * 255, b"x" * 257, bytearray(b"x" * 256)):
                with self.subTest(signature=signature), self.assertRaises(CardSignatureError):
                    verifier.verify(profile="legacy-IC010", key_id="lab-key",
                                    files=synthetic_files(), signature=signature)
            backend.assert_not_called()


class CardSignatureCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if importlib.util.find_spec("cryptography") is None:
            if os.getenv("REQUIRE_CARD_CRYPTO") == "1":
                raise RuntimeError("REQUIRE_CARD_CRYPTO=1 but cryptography is unavailable")
            raise unittest.SkipTest("Card crypto backend unavailable; RSA is NOT verified")
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
        cls.hashes, cls.serialization = hashes, serialization
        cls.ec, cls.padding, cls.rsa, cls.utils = ec, padding, rsa, utils
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.der = cls.private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def verifier(self, profile="legacy-IC010", der=None, key_id="lab-key"):
        return CardSignatureVerifier((TrustedCardKey(
            key_id, profile, self.der if der is None else der, EXPERIMENTAL_RAW_SHA256),))

    def signature(self, files, profile="legacy-IC010", private=None):
        data = b"".join(files[name] for name, _ in SIZES[profile])
        return (self.private if private is None else private).sign(
            hashlib.sha256(data).digest(), self.padding.PKCS1v15(), self.utils.NoDigestInfo())

    def verify(self, files=None, signature=None, verifier=None, profile="legacy-IC010"):
        files = synthetic_files(profile) if files is None else files
        signature = self.signature(files, profile) if signature is None else signature
        return (self.verifier(profile) if verifier is None else verifier).verify(
            profile=profile, key_id="lab-key", files=files, signature=signature)

    def test_both_profiles_verify_real_backend_signatures(self):
        for profile in SIZES:
            with self.subTest(profile=profile):
                files = synthetic_files(profile)
                result = self.verify(files=files, profile=profile)
                self.assertEqual(result.profile, profile)
                self.assertEqual(result.key_id, "lab-key")
                self.assertEqual(result.signature_mode, EXPERIMENTAL_RAW_SHA256)
                self.assertEqual(result.signed_data_sha256, hashlib.sha256(
                    b"".join(files[name] for name, _ in SIZES[profile])).hexdigest())

    def test_verified_record_has_only_immutable_digests_and_configuration(self):
        result = self.verify()
        self.assertEqual(set(asdict(result)), {"profile", "key_id", "key_fingerprint",
                                             "signature_mode", "signed_data_sha256",
                                             "evidence_sha256"})
        for value in (result.key_fingerprint, result.signed_data_sha256, result.evidence_sha256):
            self.assertRegex(value, r"^[0-9a-f]{64}$")
        with self.assertRaises(FrozenInstanceError):
            result.key_id = "changed"

    def test_input_mapping_order_does_not_change_signed_region_order(self):
        files = synthetic_files()
        self.assertEqual(self.verify(files), self.verify(dict(reversed(list(files.items())))))

    def test_every_signed_file_is_covered(self):
        files = synthetic_files()
        signature = self.signature(files)
        for name, data in files.items():
            changed = {**files, name: bytes([data[0] ^ 1]) + data[1:]}
            with self.subTest(name=name), self.assertRaisesRegex(CardSignatureError, "invalid_card_signature"):
                self.verify(changed, signature)

    def test_myna_signed_region_tampering_is_rejected(self):
        files = synthetic_files("myna010")
        signature = self.signature(files, "myna010")
        files["WEF02"] = b"x" + files["WEF02"][1:]
        with self.assertRaisesRegex(CardSignatureError, "invalid_card_signature"):
            self.verify(files, signature, profile="myna010")

    def test_signature_tampering_is_rejected(self):
        signature = self.signature(synthetic_files())
        changed = bytes([signature[0] ^ 1]) + signature[1:]
        with self.assertRaisesRegex(CardSignatureError, "invalid_card_signature"):
            self.verify(signature=changed)

    def test_other_signing_key_is_rejected(self):
        signature = self.signature(synthetic_files(), private=self.other)
        with self.assertRaisesRegex(CardSignatureError, "invalid_card_signature"):
            self.verify(signature=signature)

    def test_conventional_digestinfo_signature_has_no_fallback(self):
        files = synthetic_files()
        data = b"".join(files.values())
        signature = self.private.sign(data, self.padding.PKCS1v15(), self.hashes.SHA256())
        with self.assertRaisesRegex(CardSignatureError, "invalid_card_signature"):
            self.verify(files, signature)

    def test_wrong_hash_has_no_fallback(self):
        files = synthetic_files()
        signature = self.private.sign(hashlib.sha384(b"".join(files.values())).digest(),
                                      self.padding.PKCS1v15(), self.utils.NoDigestInfo())
        with self.assertRaisesRegex(CardSignatureError, "invalid_card_signature"):
            self.verify(files, signature)

    def test_wrong_rsa_size_and_non_rsa_key_are_rejected(self):
        wrong_keys = [self.rsa.generate_private_key(public_exponent=65537, key_size=1024),
                      self.ec.generate_private_key(self.ec.SECP256R1())]
        for private in wrong_keys:
            der = private.public_key().public_bytes(
                self.serialization.Encoding.DER, self.serialization.PublicFormat.SubjectPublicKeyInfo)
            with self.subTest(key=type(private).__name__), self.assertRaisesRegex(
                    CardSignatureError, "card_key_must_be_rsa2048"):
                self.verify(verifier=self.verifier(der=der))

    def test_invalid_provisioned_key_fails_closed(self):
        with self.assertRaisesRegex(CardSignatureError, "invalid_card_public_key"):
            self.verify(verifier=self.verifier(der=b"not-a-public-key"))

    def test_a_key_for_another_profile_is_not_trusted(self):
        with self.assertRaisesRegex(CardSignatureError, "untrusted_card_key"):
            self.verify(verifier=self.verifier(profile="myna010"))

    def test_evidence_digest_binds_the_operator_key_label(self):
        files = synthetic_files()
        signature = self.signature(files)
        first = self.verify(files, signature)
        other = self.verifier(key_id="other-label").verify(
            profile="legacy-IC010", key_id="other-label", files=files, signature=signature)
        self.assertEqual(first.signed_data_sha256, other.signed_data_sha256)
        self.assertNotEqual(first.evidence_sha256, other.evidence_sha256)

    def test_client_cannot_add_keys_algorithms_or_verified_flags(self):
        for extra in ({"public_key_der": self.der}, {"verified": True},
                      {"signature_mode": EXPERIMENTAL_RAW_SHA256}):
            with self.subTest(extra=tuple(extra)), self.assertRaises(TypeError):
                self.verifier().verify(profile="legacy-IC010", key_id="lab-key",
                                       files=synthetic_files(), signature=b"x" * 256, **extra)
