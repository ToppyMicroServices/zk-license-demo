"""Server-owned requests and atomic replay rejection. No cryptography in this module."""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import date
import json
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Callable


class Rejected(ValueError):
    """An expected verification refusal, expressed as a stable reason code."""


def day_number(value: str) -> int:
    parsed = date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise ValueError("Use a canonical YYYY-MM-DD date")
    return int(parsed.strftime("%Y%m%d"))


@dataclass(frozen=True)
class Challenge:
    request_id: str
    nonce: str
    audience: str
    session: str
    service_day: str
    created_at: int
    expires_at: int

    @classmethod
    def new(cls, *, audience: str, session: str, service_day: str,
            now: int | None = None, ttl: int = 300) -> Challenge:
        day_number(service_day)
        if not audience or not session or not 1 <= ttl <= 600:
            raise ValueError("Audience, authenticated-session context and a 1..600s TTL are required")
        now = int(time.time()) if now is None else now
        return cls(secrets.token_hex(16), str(secrets.randbits(80)), audience,
                   session, service_day, now, now + ttl)

    def proof_request(self, cred_def_id: str) -> dict:
        # Both predicates refer to the same pinned issuer credential definition.
        # The verifier builds this from its own state, never from a submitted request.
        return {
            "nonce": self.nonce,
            "name": "toppy:zk-license-demo:v1",
            "version": "1.0",
            "requested_attributes": {},
            "requested_predicates": {
                "ordinary": {"name": "can_drive_ordinary", "p_type": ">=", "p_value": 1,
                             "restrictions": [{"cred_def_id": cred_def_id}]},
                "expiry": {"name": "valid_until", "p_type": ">=",
                           "p_value": day_number(self.service_day),
                           "restrictions": [{"cred_def_id": cred_def_id}]},
            },
        }


class RequestStore:
    """SQLite-backed demonstration store. Each successful request is consumed once.

    Audience and session arguments must come from a trusted verifier configuration
    and authenticated channel in a deployed system. CLI arguments do NOT authenticate
    a person. The in-process/SQLite boundary is an example, not an Internet service.
    """
    def __init__(self, path: str | Path):
        self.path = str(path)
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute("CREATE TABLE IF NOT EXISTS requests ("
                        "request_id TEXT PRIMARY KEY, payload TEXT NOT NULL, "
                        "used INTEGER NOT NULL DEFAULT 0)")

    def add(self, challenge: Challenge) -> None:
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute("INSERT INTO requests(request_id,payload) VALUES (?,?)",
                        (challenge.request_id, json.dumps(asdict(challenge))))

    def consume(self, request_id: str, *, audience: str, session: str,
                verify: Callable[[Challenge], bool], now: int | None = None) -> None:
        real_clock = now is None
        now = int(time.time()) if now is None else now
        con = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            # Hold the transaction through cryptographic verification, preventing
            # simultaneous successful submissions of the same request. Production
            # implementations also need workload limits and a scaling strategy.
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT payload,used FROM requests WHERE request_id=?",
                              (request_id,)).fetchone()
            if row is None:
                raise Rejected("unknown_request")
            challenge = Challenge(**json.loads(row[0]))
            if row[1]:
                raise Rejected("already_used")
            if now < challenge.created_at or now >= challenge.expires_at:
                raise Rejected("request_expired_or_clock_invalid")
            if audience != challenge.audience:
                raise Rejected("wrong_audience")
            if session != challenge.session:
                raise Rejected("wrong_session")
            if verify(challenge) is not True:
                raise Rejected("invalid_proof")
            if real_clock and int(time.time()) >= challenge.expires_at:
                raise Rejected("request_expired_during_verification")
            con.execute("UPDATE requests SET used=1 WHERE request_id=?", (request_id,))
            con.execute("COMMIT")
        except BaseException:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
        finally:
            con.close()
