"""File-exchange wallet/verifier prototype; synthetic accounts, real AnonCreds."""
from __future__ import annotations

from contextlib import contextmanager, closing
from copy import deepcopy
from dataclasses import asdict
import hashlib
import hmac
from pathlib import Path
import secrets
import time

from lifecycle import (canonical, checkpoint, connect, create_store, digest,
                       initial_checkpoint, load, save, store, trusted_key)
from request_store import Challenge, Rejected
from zk_license import (PublicTrust, _matches_requested_predicates,
                        allowed_presentation_shape, backend)


@contextmanager
def transaction(private, role, registry):
    # Always lock local state before the public registry. Hold the registry read
    # transaction through proof verification/consumption, serializing revocations.
    with closing(connect(private)) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            local = load(con, role)
            with store(registry, "registry") as public:
                checkpoint(local, public)
                observed = deepcopy(local)
                try:
                    yield local, public
                except BaseException:
                    # Persist a newly observed trust revision even on refusal, but
                    # roll back all request/credential changes from the failed step.
                    save(con, role, observed)
                    con.execute("COMMIT")
                    raise
                save(con, role, local)
                con.execute("COMMIT")
        except BaseException:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise


def pairing(public, audience):
    if not audience:
        raise Rejected("audience_required")
    return {"instance": public["instance"], "audience": audience,
            "binding": secrets.token_hex(16), "key": secrets.token_hex(32)}


def verifier_init(private, registry, audience):
    with store(registry, "registry") as public:
        pair = pairing(public, audience)
        create_store(private, "verifier", {**initial_checkpoint(public),
                                          "pairing": pair, "requests": {}})
        return pair


def verifier_reset(private, registry):
    with transaction(private, "verifier", registry) as (local, public):
        local["pairing"] = pairing(public, local["pairing"]["audience"])
        local["requests"].clear()
        return local["pairing"]


def validate_pair(pair, public):
    if set(pair) != {"instance", "audience", "binding", "key"} or pair["instance"] != public["instance"]:
        raise Rejected("invalid_pairing")
    if not all(type(v) is str and v for v in pair.values()) or len(bytes.fromhex(pair["key"])) != 32:
        raise Rejected("invalid_pairing")


def wallet_init(private, registry, pair):
    with store(registry, "registry") as public:
        validate_pair(pair, public)
        create_store(private, "wallet", {**initial_checkpoint(public), "pairing": pair,
                                        "link_secret": backend().create_link_secret(),
                                        "enrollments": {}, "credentials": {}, "reviews": {}})


def wallet_pair(private, registry, pair):
    with transaction(private, "wallet", registry) as (local, public):
        validate_pair(pair, public)
        local["pairing"] = pair
        local["reviews"].clear()


def enroll(private, registry, offered):
    ac = backend()
    with transaction(private, "wallet", registry) as (local, public):
        if set(offered) != {"instance", "offer_id", "key_id", "offer"} or offered["instance"] != public["instance"]:
            raise Rejected("invalid_offer")
        key = trusted_key(public, offered["key_id"])
        if key["state"] != "active" or offered["offer_id"] in local["enrollments"]:
            raise Rejected("offer_inactive_or_reused")
        if offered["offer"]["cred_def_id"] != key["cred_def_id"] or offered["offer"]["schema_id"] != key["schema_id"]:
            raise Rejected("offer_key_mismatch")
        request, metadata = ac.CredentialRequest.create(
            secrets.token_hex(32), None, key["cred_def"], local["link_secret"],
            "synthetic-wallet", offered["offer"])
        local["enrollments"][offered["offer_id"]] = {
            "key_id": offered["key_id"], "metadata": metadata.to_dict()}
        return {"instance": public["instance"], "offer_id": offered["offer_id"],
                "request": request.to_dict()}


def import_credential(private, registry, issued):
    ac = backend()
    with transaction(private, "wallet", registry) as (local, public):
        if set(issued) != {"instance", "offer_id", "key_id", "credential"} or issued["instance"] != public["instance"]:
            raise Rejected("invalid_credential_package")
        pending = local["enrollments"].get(issued["offer_id"])
        if pending is None or pending["key_id"] != issued["key_id"]:
            raise Rejected("unknown_enrollment")
        key = trusted_key(public, issued["key_id"])
        credential = ac.Credential.load(issued["credential"])
        if (credential.cred_def_id != key["cred_def_id"] or credential.schema_id != key["schema_id"]
                or credential.rev_reg_id != key["rev_reg_id"]):
            raise Rejected("credential_key_mismatch")
        processed = credential.process(pending["metadata"], local["link_secret"],
                                       key["cred_def"], key["rev_reg_def"])
        local["credentials"][issued["key_id"]] = processed.to_dict()
        del local["enrollments"][issued["offer_id"]]


def proof_request(challenge, key):
    request = challenge.proof_request(key["cred_def_id"])
    stamp = key["status"]["timestamp"]
    request["non_revoked"] = {"from": stamp, "to": stamp}
    return request


def authenticate(payload, pair):
    return hmac.new(bytes.fromhex(pair["key"]), canonical(payload).encode(), hashlib.sha256).hexdigest()


def request(private, registry, key_id, service_day, *, now=None):
    with transaction(private, "verifier", registry) as (local, public):
        key = trusted_key(public, key_id)
        pair = local["pairing"]
        challenge = Challenge.new(audience=pair["audience"], session=pair["binding"],
                                  service_day=service_day, now=now)
        payload = {"instance": public["instance"], "revision": public["revision"],
                   "registry_digest": digest(public), "key_id": key_id,
                   "challenge": asdict(challenge), "proof_request": proof_request(challenge, key)}
        signed = {"payload": payload, "mac": authenticate(payload, pair)}
        # The verifier, not the submitted envelope, owns the complete policy.
        local["requests"] = {i: r for i, r in local["requests"].items()
                             if r["signed"]["payload"]["challenge"]["expires_at"] > challenge.created_at}
        local["requests"][challenge.request_id] = {"signed": signed, "used": False}
        return signed


def validate_request(signed, local, public, now=None):
    if set(signed) != {"payload", "mac"} or type(signed["mac"]) is not str:
        raise Rejected("invalid_request")
    payload, pair = signed["payload"], local["pairing"]
    if not hmac.compare_digest(authenticate(payload, pair), signed["mac"]):
        raise Rejected("unauthenticated_request")
    if set(payload) != {"instance", "revision", "registry_digest", "key_id", "challenge", "proof_request"}:
        raise Rejected("invalid_request")
    if (payload["instance"] != public["instance"] or payload["revision"] != public["revision"]
            or payload["registry_digest"] != digest(public)):
        raise Rejected("stale_registry_request")
    challenge = Challenge(**payload["challenge"])
    now = int(time.time()) if now is None else now
    if not challenge.created_at <= now < challenge.expires_at or not 1 <= challenge.expires_at - challenge.created_at <= 600:
        raise Rejected("request_expired_or_clock_invalid")
    if challenge.audience != pair["audience"] or challenge.session != pair["binding"]:
        raise Rejected("wrong_audience_or_binding")
    key = trusted_key(public, payload["key_id"])
    if payload["proof_request"] != proof_request(challenge, key):
        raise Rejected("unsupported_disclosure_policy")
    return challenge, key


def review(private, registry, signed, *, now=None):
    with transaction(private, "wallet", registry) as (local, public):
        challenge, key = validate_request(signed, local, public, now)
        fingerprint = digest(signed)
        prior = local["reviews"].get(challenge.request_id)
        if prior is not None and (prior["digest"] != fingerprint or prior["decision"] != "reviewed"):
            raise Rejected("request_changed_or_decided")
        local["reviews"][challenge.request_id] = {"digest": fingerprint, "decision": "reviewed"}
        return {"request_id": challenge.request_id, "review_hash": fingerprint,
                "audience": challenge.audience, "device_binding": challenge.session,
                "service_day": challenge.service_day, "expires_at": challenge.expires_at,
                "issuer_key": signed["payload"]["key_id"], "key_state": key["state"],
                "claims": ["can_drive_ordinary >= 1", f"valid_until >= {challenge.service_day}"],
                "revealed_attributes": [], "synthetic_revocation_checked": True,
                "live_licence_status_checked": False}


def present(private, registry, signed, review_hash, *, approve, now=None, before_share=None):
    ac = backend()
    with transaction(private, "wallet", registry) as (local, public):
        challenge, key = validate_request(signed, local, public, now)
        consent = local["reviews"].get(challenge.request_id)
        if (consent is None or consent["decision"] != "reviewed" or consent["digest"] != review_hash
                or review_hash != digest(signed)):
            raise Rejected("matching_wallet_review_required")
        if not approve:
            if before_share is not None:
                before_share()
            consent["decision"] = "denied"
            return {"decision": "denied", "request_id": challenge.request_id}
        value = local["credentials"].get(signed["payload"]["key_id"])
        if value is None:
            raise Rejected("wallet_credential_unavailable")
        credential = ac.Credential.load(value)
        index = credential.rev_reg_index
        if key["status"]["revocationList"][index] != 0:
            raise Rejected("credential_revoked")
        # Only read tails from the provisioned directory, never from a request URL.
        tails_hash = key["rev_reg_def"]["value"]["tailsHash"]
        if not tails_hash or any(c not in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in tails_hash):
            raise Rejected("invalid_tails_hash")
        tails = Path(registry).resolve().parent / "tails" / tails_hash
        rev_state = ac.CredentialRevocationState.create(
            key["rev_reg_def"], key["status"], index, str(tails))
        selected = ac.PresentCredentials()
        selected.add_predicates(credential, "ordinary", "expiry",
                                timestamp=key["status"]["timestamp"], rev_state=rev_state)
        result = ac.Presentation.create(
            signed["payload"]["proof_request"], selected, {}, local["link_secret"],
            {key["schema_id"]: key["schema"]}, {key["cred_def_id"]: key["cred_def"]}).to_dict()
        if now is None and int(time.time()) >= challenge.expires_at:
            raise Rejected("request_expired_during_presentation")
        if before_share is not None:
            before_share()
        consent["decision"] = "approved"
        return {"request_id": challenge.request_id, "presentation": result}


def verify_crypto(value, challenge, key):
    try:
        identifier = value["identifiers"][0]
        if (identifier.get("rev_reg_id") != key["rev_reg_id"]
                or type(identifier.get("timestamp")) is not int
                or identifier["timestamp"] != key["status"]["timestamp"]):
            return False
        # The pinned backend can accept a predicate proof with only revocation
        # identifier metadata. Require the native non-revocation subproof too.
        non_revocation = value["proof"]["proofs"][0]["non_revoc_proof"]
        if (not isinstance(non_revocation, dict)
                or any(not isinstance(non_revocation.get(name), dict) or not non_revocation[name]
                       for name in ("c_list", "x_list"))):
            return False
        # Reuse the legacy narrow disclosure shape, then verify the ORIGINAL
        # revoking proof. Do not strip revocation from the cryptographic input.
        shape = deepcopy(value)
        shape["identifiers"][0].update(rev_reg_id=None, timestamp=None)
        trust = PublicTrust(key["schema_id"], key["cred_def_id"], key["schema"], key["cred_def"])
        policy = proof_request(challenge, key)
        if not allowed_presentation_shape(shape, trust) or not _matches_requested_predicates(value, policy):
            return False
        ac = backend()
        return bool(ac.Presentation.load(value).verify(
            policy, {key["schema_id"]: key["schema"]}, {key["cred_def_id"]: key["cred_def"]},
            {key["rev_reg_id"]: key["rev_reg_def"]}, [key["status"]]))
    except (KeyError, IndexError, TypeError, ValueError, AttributeError, backend().AnoncredsError):
        return False


def verify(private, registry, envelope, *, now=None, before_accept=None):
    with transaction(private, "verifier", registry) as (local, public):
        if set(envelope) != {"request_id", "presentation"}:
            raise Rejected("invalid_envelope")
        saved = local["requests"].get(envelope["request_id"])
        if saved is None:
            raise Rejected("unknown_request")
        if saved["used"]:
            raise Rejected("already_used")
        challenge, key = validate_request(saved["signed"], local, public, now)
        if not verify_crypto(envelope["presentation"], challenge, key):
            raise Rejected("invalid_proof")
        if now is None and int(time.time()) >= challenge.expires_at:
            raise Rejected("request_expired_during_verification")
        if before_accept is not None:
            before_accept()
        saved["used"] = True
        return {"accepted": True, "synthetic_revocation_checked": True,
                "live_licence_status_checked": False}
