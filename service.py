#!/usr/bin/env python3
"""Loopback-only synthetic wallet/API. Real AnonCreds, no real identity service."""
from __future__ import annotations

import argparse
from collections import deque
from contextlib import closing
from dataclasses import dataclass, field
import hashlib
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import sqlite3
from tempfile import TemporaryDirectory
import threading
import time

from request_store import Challenge, Rejected, RequestStore
from zk_license import issue_demo, make_issuer, make_presentation, verify_presentation

ASSETS = Path(__file__).with_name("web")
COOKIE = "zk_demo_session"
SESSION_TTL = 1800
MAX_BODY = 300_000


class APIError(Exception):
    def __init__(self, status: int, code: str):
        self.status, self.code = status, code


def strict_json(raw: bytes) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    def bad_constant(_):
        raise ValueError("non-finite number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise APIError(400, "invalid_json") from None
    if not isinstance(value, dict):
        raise APIError(400, "object_required")
    return value


def fields(value: dict, expected: set[str]) -> None:
    if set(value) != expected:
        raise APIError(400, "unexpected_fields")


class Window:
    """Fixed-size rolling quota; caller holds the application's lock."""
    def __init__(self, limit: int, seconds: int = 60):
        self.limit, self.seconds = limit, seconds
        self.hits = deque()

    def take(self) -> None:
        now = time.monotonic()
        while self.hits and self.hits[0] <= now - self.seconds:
            self.hits.popleft()
        if len(self.hits) >= self.limit:
            raise APIError(429, "rate_limited")
        self.hits.append(now)


@dataclass
class Session:
    binding: str = field(default_factory=lambda: secrets.token_hex(16))
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    deadline: float = field(default_factory=lambda: time.monotonic() + SESSION_TTL)
    writes: Window = field(default_factory=lambda: Window(30))


@dataclass
class Pending:
    challenge: Challenge
    decision: str = "pending"


class DemoApplication:
    """Co-located issuer, holder and verifier. Secrets stay in this process."""
    def __init__(self, directory: Path, *, issuer=None, holder=None):
        self.issuer = issuer if issuer is not None else make_issuer()
        self.holder = holder if holder is not None else issue_demo(self.issuer)
        self.store = RequestStore(directory / "requests.sqlite3")
        self.login_code = secrets.token_urlsafe(24)
        self.sessions: dict[str, Session] = {}
        self.pending: dict[str, Pending] = {}
        self.lock = threading.RLock()
        self.all_calls, self.logins = Window(120), Window(10)
        self.audience = "https://rental.example"
        self.service_day = "2030-06-01"

    def cleanup(self) -> None:
        now = time.monotonic()
        self.sessions = {k: v for k, v in self.sessions.items() if v.deadline > now}
        active = {v.binding for v in self.sessions.values()}
        expired = [k for k, v in self.pending.items()
                   if v.challenge.expires_at <= time.time() or v.challenge.session not in active]
        if expired:
            with closing(sqlite3.connect(self.store.path)) as con, con:
                con.executemany("DELETE FROM requests WHERE request_id=?", [(k,) for k in expired])
            for key in expired:
                del self.pending[key]

    def describe(self, pending: Pending) -> dict:
        req = pending.challenge
        value = {"request_id": req.request_id, "audience": req.audience,
                 "verifier_name": "デモのカーシェア受付", "purpose": "利用予定日の運転資格と有効期限の確認",
                 "service_day": req.service_day, "expires_at": req.expires_at,
                 "proof_request": req.proof_request(self.issuer.trust.cred_def_id)}
        value["request_hash"] = hashlib.sha256(json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        value["decision"] = pending.decision
        return value

    def owned(self, request_id: str, session: Session) -> Pending:
        pending = self.pending.get(request_id)
        if pending is None or pending.challenge.session != session.binding:
            raise APIError(404, "request_unavailable")
        if pending.challenge.expires_at <= time.time():
            raise APIError(410, "request_expired")
        return pending

    def dispatch(self, method: str, path: str, body: dict, token: str,
                 csrf: str) -> tuple[dict, str | None]:
        # Serializing crypto bounds work and makes consent/logout transitions atomic.
        with self.lock:
            self.all_calls.take()
            self.cleanup()
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
                session = self.sessions[token] = Session()
                self.cleanup()
                return self.session_view(session), token

            session = self.sessions.get(token)
            if session is None:
                raise APIError(401, "authentication_required")
            if method == "GET" and path == "/api/session":
                return self.session_view(session), None
            if method == "POST":
                if not secrets.compare_digest(csrf.encode(), session.csrf.encode()):
                    raise APIError(403, "csrf_failed")
                session.writes.take()
            if method == "POST" and path == "/api/logout":
                fields(body, set())
                del self.sessions[token]
                self.cleanup()
                return {"logged_out": True}, ""
            if method == "POST" and path == "/api/requests":
                fields(body, set())  # Clients cannot weaken the policy or pick a session.
                if len(self.pending) >= 128:
                    raise APIError(503, "request_capacity")
                req = Challenge.new(audience=self.audience, session=session.binding,
                                    service_day=self.service_day)
                self.store.add(req)
                pending = self.pending[req.request_id] = Pending(req)
                return self.describe(pending), None

            match = re.fullmatch(r"/api/requests/([0-9a-f]{32})(?:/(consent|presentation))?", path)
            if match:
                pending = self.owned(match[1], session)
                if method == "GET" and match[2] is None:
                    return self.describe(pending), None
                if method == "POST" and match[2] == "consent":
                    fields(body, {"decision", "request_hash"})
                    if body["decision"] not in ("approve", "deny"):
                        raise APIError(400, "invalid_decision")
                    if body["request_hash"] != self.describe(pending)["request_hash"]:
                        raise APIError(409, "request_changed")
                    if pending.decision != "pending":
                        raise APIError(409, "consent_already_recorded")
                    pending.decision = "approved" if body["decision"] == "approve" else "denied"
                    return self.describe(pending), None
                if method == "POST" and match[2] == "presentation":
                    fields(body, set())
                    self.require_approval(pending)
                    proof = make_presentation(self.holder, pending.challenge, self.issuer.trust)
                    self.require_live_session(session)
                    self.owned(pending.challenge.request_id, session)
                    return {"request_id": pending.challenge.request_id, "presentation": proof}, None
            if method == "POST" and path == "/api/verify":
                fields(body, {"request_id", "presentation"})
                if not isinstance(body["request_id"], str) or not isinstance(body["presentation"], dict):
                    raise APIError(400, "invalid_envelope")
                pending = self.owned(body["request_id"], session)
                self.require_approval(pending)
                try:
                    self.store.consume(pending.challenge.request_id, audience=self.audience,
                                       session=session.binding, verify=lambda req: self.verify_for_session(
                                           body["presentation"], req, session))
                except Rejected as exc:
                    raise APIError(409, str(exc)) from None
                pending.decision = "consumed"
                return {"verified": True, "request_id": pending.challenge.request_id,
                        "synthetic": True, "live_licence_status_checked": False}, None
            raise APIError(404, "not_found")

    def verify_for_session(self, proof: dict, req: Challenge, session: Session) -> bool:
        valid = verify_presentation(proof, req, self.issuer.trust)
        self.require_live_session(session)  # Still inside the SQLite transaction.
        return valid

    @staticmethod
    def require_live_session(session: Session) -> None:
        if session.deadline <= time.monotonic():
            raise APIError(401, "authentication_required")

    @staticmethod
    def require_approval(pending: Pending) -> None:
        if pending.decision == "consumed":
            raise APIError(409, "already_used")
        if pending.decision != "approved":
            raise APIError(403, "consent_required")

    @staticmethod
    def session_view(session: Session) -> dict:
        return {"csrf": session.csrf, "account": "サンプル利用者 01", "synthetic": True,
                "session_seconds_remaining": max(0, int(session.deadline - time.monotonic()))}


class LocalServer(ThreadingHTTPServer):
    daemon_threads = False

    def __init__(self, address, app: DemoApplication, handler=None):
        if address[0] != "127.0.0.1":
            raise ValueError("This prototype only binds to 127.0.0.1")
        self.app = app
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, handler or Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.expected_host = f"127.0.0.1:{self.server_port}"

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        request.settimeout(5)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "SyntheticDemo"
    sys_version = ""
    asset_root = ASSETS
    asset_routes = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                    "/style.css": ("style.css", "text/css"),
                    "/brand.css": ("brand.css", "text/css"),
                    "/toppy-logo.png": ("toppy-logo.png", "image/png")}

    def log_message(self, *_):
        pass  # Do not log cookies, codes, proof bodies or request paths.

    def reply(self, status, value, *, content_type="application/json; charset=utf-8", cookie=None):
        raw = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; "
                         "style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                         "base-uri 'none'; form-action 'self'")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Connection", "close")
        if status == 429:
            self.send_header("Retry-After", "60")
        if cookie is not None:
            self.send_header("Set-Cookie", f"{COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict; "
                             f"Max-Age={SESSION_TTL if cookie else 0}")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def credentials(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            raise APIError(401, "authentication_required") from None
        token = cookies[COOKIE].value if COOKIE in cookies else ""
        return token, self.headers.get("X-CSRF-Token", "")

    def run_request(self):
        try:
            if self.headers.get_all("Host", []) != [self.server.expected_host]:
                raise APIError(403, "host_refused")
            origin = self.headers.get_all("Origin", [])
            if (self.command == "POST" and origin != [self.server.origin]) or (
                    origin and origin != [self.server.origin]):
                raise APIError(403, "origin_refused")
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                raise APIError(403, "origin_refused")
            if self.command == "GET" and self.path in self.asset_routes:
                name, mime = self.asset_routes[self.path]
                content_type = mime + "; charset=utf-8" if mime.startswith("text/") else mime
                self.reply(200, (self.asset_root / name).read_bytes(), content_type=content_type)
                return
            if not self.path.startswith("/api/"):
                raise APIError(404, "not_found")
            body = {}
            if self.command == "POST":
                if self.headers.get("Transfer-Encoding") is not None:
                    raise APIError(400, "transfer_encoding_refused")
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0]):
                    raise APIError(400, "length_required")
                size = int(lengths[0])
                if not 0 < size <= MAX_BODY:
                    raise APIError(413, "body_too_large")
                if self.headers.get_content_type() != "application/json":
                    raise APIError(415, "json_required")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise APIError(400, "incomplete_body")
                body = strict_json(raw)
            token, csrf = self.credentials()
            value, cookie = self.server.app.dispatch(self.command, self.path, body, token, csrf)
            self.reply(200, value, cookie=cookie)
        except APIError as exc:
            self.reply(exc.status, {"error": exc.code})
        except (ConnectionError, TimeoutError):
            self.close_connection = True
        except Exception:
            self.reply(500, {"error": "internal_error"})

    do_GET = run_request
    do_POST = run_request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("port must be 0..65535")
    with TemporaryDirectory(prefix="zk-synthetic-service-") as directory:
        app = DemoApplication(Path(directory))
        with LocalServer(("127.0.0.1", args.port), app) as server:
            print(f"Synthetic data only. Open {server.origin}", flush=True)
            print(f"Demo login code: {app.login_code}", flush=True)
            print("No real identity or live licence-status verification. Ctrl-C to stop.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    main()
