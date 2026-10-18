#!/usr/bin/env python3
"""Two loopback-only Web roles over separate synthetic wallet/verifier stores."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import re
import secrets
import threading
import time

from lifecycle import store
from request_store import Rejected
from service import APIError, Handler, LocalServer, SESSION_TTL, Window, fields
import split_wallet


ASSETS = Path(__file__).with_name("split_web")
MAX_PENDING = 128


@dataclass
class WebSession:
    deadline: float = field(default_factory=lambda: time.monotonic() + SESSION_TTL)
    writes: Window = field(default_factory=lambda: Window(30))
    requests: dict[str, int] = field(default_factory=dict)
    used_requests: dict[str, int] = field(default_factory=dict)
    reviews: dict[str, dict] = field(default_factory=dict)
    decided_reviews: dict[str, int] = field(default_factory=dict)


class SplitApplication:
    """One role per process. No issuer private state or cross-role HTTP calls."""

    def __init__(self, role, store_path, registry, peer_origin, service_day="2030-06-01"):
        if role not in ("verifier", "wallet"):
            raise ValueError("role must be verifier or wallet")
        self.role = role
        self.private = Path(store_path)
        self.registry = Path(registry)
        if self.private.resolve() == self.registry.resolve():
            raise ValueError("private store must differ from registry")
        self.peer_origin = self.checked_origin(peer_origin)
        self.service_day = service_day
        self.login_code = secrets.token_urlsafe(24)
        self.sessions: dict[str, WebSession] = {}
        self.all_calls, self.logins = Window(120), Window(10)
        self.lock = threading.RLock()
        # A wrong-role store or mismatched registry must fail at startup.
        with store(self.private, role) as local, store(self.registry, "registry") as public:
            if local["instance"] != public["instance"]:
                raise Rejected("wrong_registry")

    @staticmethod
    def checked_origin(value):
        match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})", value) if isinstance(value, str) else None
        if match is None or not 1 <= int(match[1]) <= 65535:
            raise ValueError("peer origin must be a loopback HTTP origin with a port")
        return value

    def cleanup(self):
        now = time.monotonic()
        self.sessions = {token: session for token, session in self.sessions.items()
                         if session.deadline > now}
        wall_time = time.time()
        for session in self.sessions.values():
            session.requests = {key: expiry for key, expiry in session.requests.items()
                                if expiry > wall_time}
            session.used_requests = {key: expiry for key, expiry in session.used_requests.items()
                                     if expiry > wall_time}
            session.reviews = {key: review for key, review in session.reviews.items()
                               if review["expires_at"] > wall_time}
            session.decided_reviews = {key: expiry for key, expiry in session.decided_reviews.items()
                                       if expiry > wall_time}

    def require_live_session(self, token, session):
        if self.sessions.get(token) is not session or session.deadline <= time.monotonic():
            raise APIError(401, "authentication_required")

    def config(self):
        with store(self.registry, "registry") as public:
            keys = [{"key_id": key_id, "state": key["state"]}
                    for key_id, key in public["keys"].items()
                    if key["state"] in ("active", "verify_only")]
        return {"role": self.role, "peer_origin": self.peer_origin,
                "service_day": self.service_day, "keys": keys,
                "synthetic": True, "live_licence_status_checked": False}

    def dispatch(self, method, path, body, token, _csrf=""):
        # Serialize HTTP session changes with crypto, logout and expiry checks.
        with self.lock:
            self.cleanup()
            # Keep logout available even when a session or process quota is full.
            if method == "POST" and path == "/api/logout":
                session = self.sessions.get(token)
                if session is None:
                    raise APIError(401, "authentication_required")
                self.require_live_session(token, session)
                fields(body, set())
                del self.sessions[token]
                return {"logged_out": True}, None
            self.all_calls.take()
            if method == "GET" and path == "/api/config":
                return self.config(), None
            if method == "POST" and path == "/api/login":
                self.logins.take()
                fields(body, {"code"})
                code = body["code"]
                if not isinstance(code, str) or len(code) > 64 or not secrets.compare_digest(
                        code.encode(), self.login_code.encode()):
                    raise APIError(401, "invalid_login")
                if len(self.sessions) >= 32 and token not in self.sessions:
                    raise APIError(503, "session_capacity")
                self.sessions.pop(token, None)
                token = secrets.token_urlsafe(32)
                session = self.sessions[token] = WebSession()
                return {"token": token, **self.session_view(session)}, None

            session = self.sessions.get(token)
            if session is None:
                raise APIError(401, "authentication_required")
            self.require_live_session(token, session)
            if method == "GET" and path == "/api/session":
                return self.session_view(session), None
            if method == "POST":
                session.writes.take()
            try:
                if self.role == "verifier":
                    result = self.verifier_dispatch(method, path, body, token, session)
                else:
                    result = self.wallet_dispatch(method, path, body, token, session)
            except Rejected as exc:
                raise APIError(409, str(exc)) from None
            return result, None

    @staticmethod
    def session_view(session):
        return {"account": "サンプル利用者 01", "synthetic": True,
                "session_seconds_remaining": max(0, int(session.deadline - time.monotonic()))}

    def verifier_dispatch(self, method, path, body, token, session):
        if method == "POST" and path == "/api/requests":
            fields(body, {"key_id", "replaces_request_id"} if "replaces_request_id" in body else {"key_id"})
            if not isinstance(body["key_id"], str) or len(body["key_id"]) > 128:
                raise APIError(400, "invalid_key_id")
            replaced = body.get("replaces_request_id")
            if "replaces_request_id" in body and (
                    not isinstance(replaced, str) or not replaced or len(replaced) > 128):
                raise APIError(400, "invalid_request_id")
            # Only an ID owned by this session can release its pending slot.
            pending = len(session.requests) - int(replaced in session.requests)
            if pending >= MAX_PENDING:
                raise APIError(503, "request_capacity")
            signed = split_wallet.request(self.private, self.registry, body["key_id"], self.service_day)
            challenge = signed["payload"]["challenge"]
            request_id = challenge["request_id"]
            # Keep the old request usable if signing its successor fails.
            session.requests.pop(replaced, None)
            session.requests[request_id] = challenge["expires_at"]
            return {"signed_request": signed}
        if method == "POST" and path == "/api/verify":
            fields(body, {"request_id", "presentation"})
            request_id, presentation = body["request_id"], body["presentation"]
            if not isinstance(request_id, str) or not isinstance(presentation, dict):
                raise APIError(400, "invalid_envelope")
            if request_id in session.used_requests:
                raise APIError(409, "already_used")
            if request_id not in session.requests:
                raise APIError(404, "request_unavailable")
            result = split_wallet.verify(self.private, self.registry,
                                         {"request_id": request_id, "presentation": presentation},
                                         before_accept=lambda: self.require_live_session(token, session))
            session.used_requests[request_id] = session.requests.pop(request_id)
            return {"request_id": request_id, "verified": True, "synthetic": True, **result}
        raise APIError(404, "not_found")

    def wallet_dispatch(self, method, path, body, token, session):
        if method == "POST" and path == "/api/review":
            fields(body, {"signed_request"})
            signed = body["signed_request"]
            if not isinstance(signed, dict):
                raise APIError(400, "invalid_request")
            if len(session.reviews) >= MAX_PENDING:
                raise APIError(503, "request_capacity")
            try:
                shown = split_wallet.review(self.private, self.registry, signed)
            except Rejected:
                raise
            except (KeyError, TypeError, ValueError, AttributeError):
                raise APIError(400, "invalid_request") from None
            session.reviews[shown["request_id"]] = {"signed": signed,
                                                      "review_hash": shown["review_hash"],
                                                      "expires_at": shown["expires_at"]}
            return shown
        if method == "POST" and path == "/api/decision":
            fields(body, {"request_id", "review_hash", "decision"})
            request_id, review_hash, decision = (body["request_id"], body["review_hash"], body["decision"])
            if not isinstance(request_id, str) or not isinstance(review_hash, str):
                raise APIError(400, "invalid_review")
            if decision not in ("approve", "deny"):
                raise APIError(400, "invalid_decision")
            if request_id in session.decided_reviews:
                raise APIError(409, "decision_already_recorded")
            pending = session.reviews.get(request_id)
            if pending is None or not secrets.compare_digest(review_hash, pending["review_hash"]):
                raise APIError(404, "review_unavailable")
            result = split_wallet.present(self.private, self.registry, pending["signed"], review_hash,
                                          approve=decision == "approve",
                                          before_share=lambda: self.require_live_session(token, session))
            session.decided_reviews[request_id] = session.reviews.pop(request_id)["expires_at"]
            return result
        raise APIError(404, "not_found")


class SplitHandler(Handler):
    asset_root = ASSETS

    @property
    def asset_routes(self):
        page = "verifier.html" if self.server.app.role == "verifier" else "wallet.html"
        return {"/": (page, "text/html"), "/verifier.html": ("verifier.html", "text/html"),
                "/wallet.html": ("wallet.html", "text/html"),
                "/verifier.js": ("verifier.js", "text/javascript"),
                "/wallet.js": ("wallet.js", "text/javascript"),
                "/brand.css": ("../web/brand.css", "text/css"),
                "/toppy-logo.png": ("../web/toppy-logo.png", "image/png"),
                "/style.css": ("style.css", "text/css")}

    def credentials(self):
        values = self.headers.get_all("Authorization", [])
        if not values:
            return "", ""
        if len(values) != 1 or not re.fullmatch(r"Bearer [A-Za-z0-9_-]{43}", values[0]):
            raise APIError(401, "authentication_required")
        return values[0][7:], ""

    def reply(self, status, value, *, content_type="application/json; charset=utf-8", cookie=None):
        # Browser cookies are shared across loopback ports. This service never
        # sets them; each role's bearer token stays in its own page memory.
        return super().reply(status, value, content_type=content_type, cookie=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("verifier", "wallet"), required=True)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--peer-origin", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    app = SplitApplication(args.role, args.store, args.registry, args.peer_origin)
    with LocalServer(("127.0.0.1", args.port), app, handler=SplitHandler) as server:
        if server.origin == app.peer_origin:
            parser.error("peer origin must use a different port")
        print(f"Synthetic {args.role} Web demo: {server.origin}", flush=True)
        print(f"Demo login code: {app.login_code}", flush=True)
        print("No real identity or live licence-status verification. Ctrl-C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
