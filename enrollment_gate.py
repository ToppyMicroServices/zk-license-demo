"""Issuer-side integration boundary. No reader, identity service or issuance UI.

Adapters are operator-installed server code, never data supplied by a browser.
This module does not turn a signed card record into an AnonCreds credential.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from types import MappingProxyType
from typing import Mapping, Protocol

from card_signature import CardSignatureVerifier, VerifiedCardRecord


class EnrollmentRejected(ValueError):
    pass


class IntegrationUnavailable(RuntimeError):
    pass


def validate_audience(audience: str) -> str:
    if type(audience) is not str or not 1 <= len(audience) <= 512:
        raise EnrollmentRejected("invalid_audience")
    return audience


def request_digest(request: bytes) -> str:
    """Bind the exact issuer-validated wallet credential request, not its label."""
    if type(request) is not bytes or not 1 <= len(request) <= 262_144:
        raise EnrollmentRejected("invalid_wallet_request")
    return hashlib.sha256(request).hexdigest()


@dataclass(frozen=True)
class EnrollmentContext:
    request_id: str
    nonce: str = field(repr=False)
    account_id: str = field(repr=False)
    wallet_request_sha256: str
    audience: str
    purpose: str
    created_at: int
    expires_at: int


@dataclass(frozen=True)
class CardCapture:
    profile: str
    key_id: str
    files: Mapping[str, bytes] = field(repr=False)
    signature: bytes = field(repr=False)


@dataclass(frozen=True)
class BoundIdentity:
    """Output of a trusted provider adapter, NOT a deserialized client claim.

The adapter must validate the provider protocol and establish that the person
matches the signed licence record. JPKI login alone does not establish that match.
It must use the context's nonce/state and bind the exact wallet request/card.
"""
    provider: str
    subject: str = field(repr=False)
    nonce: str = field(repr=False)
    wallet_request_sha256: str
    card_evidence_sha256: str
    audience: str
    authenticated_at: int
    expires_at: int


class CardReader(Protocol):
    def read(self, context: EnrollmentContext) -> CardCapture: ...


class IdentityAdapter(Protocol):
    provider_id: str

    def verify_and_match(self, context: EnrollmentContext, card: VerifiedCardRecord,
                         signed_files: Mapping[str, bytes]) -> BoundIdentity: ...


@dataclass(frozen=True)
class EnrollmentReceipt:
    """Local audit handle, not a credential, identity token or driving permit."""
    request_id: str
    card_evidence_sha256: str
    wallet_request_sha256: str
    completed_at: int
    stage: str = field(default="experimental_boundary_only", init=False)
    live_licence_status_checked: bool = field(default=False, init=False)


class EnrollmentGate:
    def __init__(self, path: Path, *, audience: str, reader: CardReader | None = None,
                 signatures: CardSignatureVerifier | None = None,
                 identity: IdentityAdapter | None = None):
        self.path, self.audience = Path(path), validate_audience(audience)
        self.reader, self.signatures, self.identity = reader, signatures, identity
        # Explicit private state; refuse an existing file rather than resetting it.
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(self._connect()) as con, con:
            con.execute("CREATE TABLE enrollments (id TEXT PRIMARY KEY, context TEXT NOT NULL, "
                        "state TEXT NOT NULL, card_digest TEXT)")

    @classmethod
    def reopen(cls, path: Path, **configuration) -> EnrollmentGate:
        if not Path(path).is_file():
            raise EnrollmentRejected("enrollment_store_missing")
        value = cls.__new__(cls)
        value.path = Path(path)
        value.audience = validate_audience(configuration.pop("audience"))
        value.reader = configuration.pop("reader", None)
        value.signatures = configuration.pop("signatures", None)
        value.identity = configuration.pop("identity", None)
        if configuration:
            raise TypeError("Unexpected enrollment configuration")
        return value

    def _connect(self):
        return sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True,
                               timeout=10, isolation_level=None)

    def begin(self, *, account_id: str, wallet_request: bytes, purpose: str,
              now: int | None = None, ttl: int = 300) -> EnrollmentContext:
        if (type(account_id) is not str or not 1 <= len(account_id) <= 256
                or type(purpose) is not str or not 1 <= len(purpose) <= 512
                or type(ttl) is not int or not 1 <= ttl <= 300):
            raise EnrollmentRejected("invalid_enrollment_context")
        now = self._now(now)
        ctx = EnrollmentContext(secrets.token_urlsafe(24), secrets.token_urlsafe(32),
                                account_id, request_digest(wallet_request), self.audience,
                                purpose, now, now + ttl)
        with closing(self._connect()) as con, con:
            con.execute("INSERT INTO enrollments VALUES (?,?,?,NULL)",
                        (ctx.request_id, json.dumps(ctx.__dict__), "pending"))
        return ctx

    @staticmethod
    def _now(now):
        value = int(time.time()) if now is None else now
        if type(value) is not int or value < 0:
            raise EnrollmentRejected("invalid_time")
        return value

    def complete(self, request_id: str, *, account_id: str, wallet_request: bytes,
                 consent: bool, now: int | None = None) -> EnrollmentReceipt:
        """Called by an authenticated issuer backend after displaying this context.

        External adapters must bound their own timeouts and never log card/PIN/token
        payloads. No HTTP endpoint is exposed by this experimental component.
        """
        started = self._now(now)
        if type(consent) is not bool:
            raise EnrollmentRejected("explicit_consent_required")
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT context,state FROM enrollments WHERE id=?",
                                  (request_id,)).fetchone()
                if row is None or row[1] != "pending":
                    raise EnrollmentRejected("enrollment_unavailable_or_used")
                ctx = EnrollmentContext(**json.loads(row[0]))
                if (ctx.account_id != account_id or ctx.audience != self.audience
                        or not hmac.compare_digest(ctx.wallet_request_sha256,
                                                   request_digest(wallet_request))):
                    raise EnrollmentRejected("enrollment_binding_mismatch")
                if not ctx.created_at <= started < ctx.expires_at:
                    raise EnrollmentRejected("enrollment_expired")
                if not consent:
                    con.execute("UPDATE enrollments SET state='denied' WHERE id=?", (request_id,))
                    con.commit()
                    raise EnrollmentRejected("consent_denied")
                if self.reader is None or self.signatures is None or self.identity is None:
                    raise IntegrationUnavailable("reader_trust_and_identity_adapters_required")
                capture = self.reader.read(ctx)
                if not isinstance(capture, CardCapture):
                    raise EnrollmentRejected("invalid_reader_result")
                # Identity matching must decode these exact verified bytes, not
                # a second mutable capture or client-supplied attribute object.
                signed_files = MappingProxyType(dict(capture.files))
                record = self.signatures.verify(profile=capture.profile, key_id=capture.key_id,
                                                 files=signed_files, signature=capture.signature)
                person = self.identity.verify_and_match(ctx, record, signed_files)
                finished = self._now(now)
                if not ctx.created_at <= finished < ctx.expires_at:
                    raise EnrollmentRejected("enrollment_expired")
                if (not isinstance(person, BoundIdentity)
                        or type(person.subject) is not str or not 1 <= len(person.subject) <= 512
                        or person.provider != self.identity.provider_id
                        or not person.provider
                        or person.audience != ctx.audience
                        or person.nonce != ctx.nonce
                        or person.wallet_request_sha256 != ctx.wallet_request_sha256
                        or person.card_evidence_sha256 != record.evidence_sha256
                        or type(person.authenticated_at) is not int
                        or type(person.expires_at) is not int
                        or not ctx.created_at <= person.authenticated_at <= finished < person.expires_at
                        or person.expires_at > ctx.expires_at):
                    raise EnrollmentRejected("identity_binding_mismatch")
                con.execute("UPDATE enrollments SET state='completed',card_digest=? WHERE id=?",
                            (record.evidence_sha256, request_id))
                con.commit()
                return EnrollmentReceipt(request_id, record.evidence_sha256,
                                         ctx.wallet_request_sha256, finished)
            except BaseException:
                if con.in_transaction:
                    con.rollback()
                raise
