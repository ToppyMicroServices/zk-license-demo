"""Synthetic AnonCreds issuance and non-disclosing predicate presentation.

Uses the upstream anoncreds-rs Python API. Does not implement cryptographic
primitives, read real identity documents, perform OCR, or contact any service.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import importlib
import json
import secrets
from typing import Any

from request_store import Challenge, day_number

ATTRIBUTES = ["full_name", "address", "birth_date", "license_number",
              "can_drive_ordinary", "valid_until"]
MAX_PROOF_BYTES = 262_144


def backend():
    try:
        return importlib.import_module("anoncreds")
    except ImportError as exc:
        raise RuntimeError("Real ZK backend unavailable. Install the hash-pinned "
                           "requirements.txt. No simulated proof will be generated.") from exc


@dataclass(frozen=True)
class PublicTrust:
    schema_id: str
    cred_def_id: str
    schema: dict
    cred_def: dict

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> PublicTrust:
        if set(value) != {"schema_id", "cred_def_id", "schema", "cred_def"}:
            raise ValueError("Unexpected trust registry structure")
        return cls(**value)


@dataclass
class DemoIssuer:
    trust: PublicTrust
    public_key: Any
    private_key: Any
    correctness_proof: Any


@dataclass
class DemoHolder:
    credential: Any
    link_secret: str
    # For the educational full-copy comparison ONLY. Never added to a presentation.
    synthetic_attributes: dict[str, str]


def make_issuer(label: str = "trusted") -> DemoIssuer:
    ac = backend()
    issuer_id = f"https://{label}.issuer.example"
    schema_id = issuer_id + "/schemas/synthetic-license-v1"
    cred_def_id = issuer_id + "/credentials/synthetic-license-v1"
    schema = ac.Schema.create("synthetic-license", "1.0", issuer_id, ATTRIBUTES)
    public, private, correctness = ac.CredentialDefinition.create(
        schema_id, schema, issuer_id, "demo", "CL", support_revocation=False)
    trust = PublicTrust(schema_id, cred_def_id, schema.to_dict(), public.to_dict())
    return DemoIssuer(trust, public, private, correctness)


def issue_demo(issuer: DemoIssuer, *, can_drive: int = 1,
               valid_until: str = "2031-12-31") -> DemoHolder:
    """The synthetic issuer is responsible for attribute meaning and validation.

    The entitlement is binary. License categories are NOT treated as ordinal ranks.
    YYYYMMDD numbers stay within the 32-bit signed range required by predicates.
    """
    if type(can_drive) is not int or can_drive not in (0, 1):
        raise ValueError("Entitlement must be the integer 0 or 1")
    expiry = day_number(valid_until)
    ac = backend()
    raw = {
        "full_name": "SAMPLE PERSON -- NOT A REAL PERSON",
        "address": "SYNTHETIC ADDRESS -- NOT A REAL ADDRESS",
        "birth_date": "19900405",
        "license_number": "DEMO-NOT-A-LICENSE-0001",
        "can_drive_ordinary": str(can_drive),
        "valid_until": str(expiry),
    }
    secret = ac.create_link_secret()
    offer = ac.CredentialOffer.create(issuer.trust.schema_id, issuer.trust.cred_def_id,
                                     issuer.correctness_proof)
    request, metadata = ac.CredentialRequest.create(
        secrets.token_hex(32), None, issuer.public_key, secret, "demo-holder", offer)
    issued = ac.Credential.create(issuer.public_key, issuer.private_key, offer, request, raw)
    processed = issued.process(metadata, secret, issuer.public_key)
    return DemoHolder(processed, secret, raw)


def make_presentation(holder: DemoHolder, challenge: Challenge, trust: PublicTrust,
                      *, request_override: dict | None = None) -> dict:
    """request_override exists for adversarial tests; verifiers NEVER consume it."""
    ac = backend()
    request = request_override or challenge.proof_request(trust.cred_def_id)
    selected = ac.PresentCredentials()
    selected.add_predicates(holder.credential, *request["requested_predicates"])
    result = ac.Presentation.create(
        ac.PresentationRequest.load(request), selected, {}, holder.link_secret,
        {trust.schema_id: trust.schema}, {trust.cred_def_id: trust.cred_def})
    return result.to_dict()


def allowed_presentation_shape(value: dict, trust: PublicTrust) -> bool:
    """Enforce the narrow disclosure policy before passing data to the backend."""
    try:
        if set(value) != {"proof", "requested_proof", "identifiers"}:
            return False
        if len(json.dumps(value, allow_nan=False).encode()) > MAX_PROOF_BYTES:
            return False
        ids = value["identifiers"]
        if not isinstance(ids, list) or len(ids) != 1:
            return False
        identifier = ids[0]
        if set(identifier) - {"schema_id", "cred_def_id", "rev_reg_id", "timestamp"}:
            return False
        if identifier["schema_id"] != trust.schema_id or identifier["cred_def_id"] != trust.cred_def_id:
            return False
        if identifier.get("rev_reg_id") is not None or identifier.get("timestamp") is not None:
            return False  # Revocation is explicitly outside this demonstration.
        requested = value["requested_proof"]
        allowed = {"revealed_attrs", "revealed_attr_groups", "unrevealed_attrs",
                   "self_attested_attrs", "predicates"}
        if set(requested) - allowed:
            return False
        for name in allowed - {"predicates"}:
            if requested.get(name, {}) != {}:
                return False
        predicates = requested["predicates"]
        if set(predicates) != {"ordinary", "expiry"}:
            return False
        # Both predicates must come from one credential, not two unrelated ones.
        for item in predicates.values():
            if set(item) != {"sub_proof_index"} or type(item["sub_proof_index"]) is not int:
                return False
            if item["sub_proof_index"] != 0:
                return False
        return True
    except (TypeError, KeyError, ValueError, AttributeError):
        return False


def _matches_requested_predicates(value: dict, request: dict) -> bool:
    """Compare the embedded CL predicates with the verifier's stored policy.

    With the pinned backend, passing a stronger request to verify() alone did
    not reject a proof made for weaker bounds. Never trust those proof bounds
    as the policy. The backend still verifies their cryptographic integrity.
    """
    try:
        proofs = value["proof"]["proofs"]
        if not isinstance(proofs, list) or len(proofs) != 1:
            return False
        ge_proofs = proofs[0]["primary_proof"]["ge_proofs"]
        expected = {item["name"]: ("GE", item["p_value"])
                    for item in request["requested_predicates"].values()}
        if not isinstance(ge_proofs, list) or len(ge_proofs) != len(expected):
            return False
        actual = {}
        for item in ge_proofs:
            predicate = item["predicate"]
            if set(predicate) != {"attr_name", "p_type", "value"}:
                return False
            name = predicate["attr_name"]
            if type(name) is not str or type(predicate["p_type"]) is not str:
                return False
            if type(predicate["value"]) is not int or name in actual:
                return False
            actual[name] = (predicate["p_type"], predicate["value"])
        return actual == expected
    except (TypeError, KeyError, ValueError, AttributeError):
        return False


def verify_presentation(value: dict, challenge: Challenge, trust: PublicTrust) -> bool:
    if not allowed_presentation_shape(value, trust):
        return False
    request = challenge.proof_request(trust.cred_def_id)
    if not _matches_requested_predicates(value, request):
        return False
    ac = backend()  # Missing dependency is a hard failure, not successful verification.
    try:
        return bool(ac.Presentation.load(value).verify(
            request,
            {trust.schema_id: trust.schema}, {trust.cred_def_id: trust.cred_def}))
    except (ac.AnoncredsError, TypeError, ValueError, KeyError):
        return False
