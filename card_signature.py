"""Experimental, issuer-side verification of a card's signed byte regions.

No reader, official trust bundle, attribute decoder, or identity provider is
included. The operator must supply each key and explicitly select the signature
mode. A result is a local record, not a portable attestation or proof of current
card possession, identity, driving entitlement, or live licence status.

The file order and sizes follow the diagrams in the NPA 2024-07-19 specification,
PDF pages 17 and 34. Its padding diagram shows a bare SHA-256 digest; compatibility
with real cards remains unverified. The only supported mode names that choice
explicitly. There is no fallback to another signature format.

Sources:
https://www.npa.go.jp/laws/notification/koutuu/menkyo/menkyo20240719_145.pdf
https://cryptography.io/en/49.0.0/hazmat/primitives/asymmetric/rsa/
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import importlib
import json


EXPERIMENTAL_RAW_SHA256 = "npa-rsa2048-pkcs1v15-raw-sha256-experimental"
# Full signed regions, not decoded/re-encoded TLVs or padded logical values.
# Exact lengths also prevent ambiguous boundaries in the signed concatenation.
_PROFILES = {
    "legacy-IC010": (("DF1/EF01", 880), ("DF1/EF02", 82), ("DF2/EF01", 2005)),
    "myna010": (("WEF02", 5845),),
}
MAX_PUBLIC_KEY_BYTES = 16_384


class CardSignatureError(ValueError):
    """Input, trust configuration, or cryptographic verification was rejected."""


def _profile(profile: str) -> tuple[tuple[str, int], ...]:
    if type(profile) is not str or profile not in _PROFILES:
        raise CardSignatureError("unsupported_card_profile")
    return _PROFILES[profile]


def _key_id(key_id: str) -> None:
    if type(key_id) is not str or not 1 <= len(key_id) <= 128:
        raise CardSignatureError("invalid_card_key_id")


@dataclass(frozen=True)
class TrustedCardKey:
    """Operator-owned configuration, never loaded from a card submission.

    This pins a public key directly; it does not validate an issuer certificate
    chain, acquire official keys, or establish their provenance for the operator.
    Removing an entry prevents its use by newly constructed verifiers.
    """

    key_id: str
    profile: str
    public_key_der: bytes
    signature_mode: str

    def __post_init__(self) -> None:
        _key_id(self.key_id)
        _profile(self.profile)
        if (type(self.public_key_der) is not bytes
                or not 1 <= len(self.public_key_der) <= MAX_PUBLIC_KEY_BYTES):
            raise CardSignatureError("invalid_card_public_key")
        if (type(self.signature_mode) is not str
                or self.signature_mode != EXPERIMENTAL_RAW_SHA256):
            raise CardSignatureError("unsupported_card_signature_mode")


@dataclass(frozen=True)
class VerifiedCardRecord:
    """Digests of verified bytes; no decoded personal attributes are returned.

    Only the trusted issuer's verifier call establishes this result. A serialized
    or client-created instance is not evidence and must not authorize issuance.
    """

    profile: str
    key_id: str
    key_fingerprint: str
    signature_mode: str
    signed_data_sha256: str
    evidence_sha256: str


def _backend():
    """Import only when verification is requested; missing crypto fails closed."""
    try:
        serialization = importlib.import_module("cryptography.hazmat.primitives.serialization")
        rsa = importlib.import_module("cryptography.hazmat.primitives.asymmetric.rsa")
        padding = importlib.import_module("cryptography.hazmat.primitives.asymmetric.padding")
        utils = importlib.import_module("cryptography.hazmat.primitives.asymmetric.utils")
        exceptions = importlib.import_module("cryptography.exceptions")
    except ImportError as exc:
        raise RuntimeError("Card signature backend unavailable; no verification performed") from exc
    if not hasattr(utils, "NoDigestInfo"):
        raise RuntimeError("Card signature backend requires cryptography 49 NoDigestInfo support")
    return serialization, rsa, padding, utils, exceptions


@dataclass(frozen=True)
class CardSignatureVerifier:
    """A snapshot of an operator-provisioned key allowlist."""

    keys: tuple[TrustedCardKey, ...]

    def __post_init__(self) -> None:
        try:
            entries = tuple(self.keys)
        except TypeError as exc:
            raise CardSignatureError("invalid_card_trust_configuration") from exc
        identities = set()
        for entry in entries:
            if type(entry) is not TrustedCardKey:
                raise CardSignatureError("invalid_card_trust_configuration")
            identity = (entry.profile, entry.key_id)
            if identity in identities:
                raise CardSignatureError("duplicate_card_trust_entry")
            identities.add(identity)
        object.__setattr__(self, "keys", entries)

    def verify(self, *, profile: str, key_id: str,
               files: Mapping[str, bytes], signature: bytes) -> VerifiedCardRecord:
        regions = _profile(profile)
        _key_id(key_id)
        trusted = next((entry for entry in self.keys
                        if entry.profile == profile and entry.key_id == key_id), None)
        if trusted is None:
            raise CardSignatureError("untrusted_card_key")
        if not isinstance(files, Mapping) or set(files) != {name for name, _ in regions}:
            raise CardSignatureError("unexpected_signed_files")
        snapshot = {name: files[name] for name, _ in regions}
        for name, size in regions:
            if type(snapshot[name]) is not bytes or len(snapshot[name]) != size:
                raise CardSignatureError("invalid_signed_file_length_or_type")
        if type(signature) is not bytes or len(signature) != 256:
            raise CardSignatureError("invalid_card_signature_length_or_type")

        serialization, rsa, padding, utils, exceptions = _backend()
        try:
            public_key = serialization.load_der_public_key(trusted.public_key_der)
        except (ValueError, TypeError, exceptions.UnsupportedAlgorithm) as exc:
            raise CardSignatureError("invalid_card_public_key") from exc
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 2048:
            raise CardSignatureError("card_key_must_be_rsa2048")
        canonical_key = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_fingerprint = hashlib.sha256(canonical_key).hexdigest()
        signed_data = b"".join(snapshot[name] for name, _ in regions)
        digest = hashlib.sha256(signed_data).digest()
        try:
            recovered = public_key.recover_data_from_signature(
                signature, padding.PKCS1v15(), utils.NoDigestInfo())
        except (exceptions.InvalidSignature, exceptions.UnsupportedAlgorithm,
                ValueError, TypeError) as exc:
            raise CardSignatureError("invalid_card_signature") from exc
        # The backend checks RSA and PKCS#1 padding. Accept only the chosen
        # bare-digest payload; conventional DigestInfo signatures do not pass.
        if not hmac.compare_digest(recovered, digest):
            raise CardSignatureError("invalid_card_signature")
        manifest = {
            "version": "toppy-card-signature-evidence-v1",
            "profile": profile,
            "key_id": key_id,
            "key_fingerprint": key_fingerprint,
            "signature_mode": trusted.signature_mode,
            "signed_data_sha256": digest.hex(),
            "files": [{"name": name, "length": size,
                       "sha256": hashlib.sha256(snapshot[name]).hexdigest()}
                      for name, size in regions],
            "signature_sha256": hashlib.sha256(signature).hexdigest(),
        }
        evidence = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
        return VerifiedCardRecord(profile, key_id, key_fingerprint, trusted.signature_mode,
                                  digest.hex(), hashlib.sha256(evidence).hexdigest())
