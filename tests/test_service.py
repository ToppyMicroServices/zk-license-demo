"""HTTP boundary tests with real synthetic credentials, never simulated crypto."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import http.client
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from service import COOKIE, DemoApplication, LocalServer, MAX_BODY
from zk_license import issue_demo, make_issuer, make_presentation, verify_presentation


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if importlib.util.find_spec("anoncreds") is None:
            if os.getenv("REQUIRE_CRYPTO") == "1":
                raise RuntimeError("REQUIRE_CRYPTO=1 but anoncreds is unavailable")
            raise unittest.SkipTest("Real ZK backend unavailable; HTTP crypto is NOT verified")
        cls.issuer = make_issuer()
        cls.holder = issue_demo(cls.issuer)

    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = DemoApplication(Path(self.directory.name), issuer=self.issuer, holder=self.holder)
        self.server = LocalServer(("127.0.0.1", 0), self.app)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=.01))
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.cookie, self.csrf = "", ""

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def call(self, method, path, body=None, *, headers=None, raw=None):
        values = {"Origin": self.server.origin, "Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        if body is not None:
            raw = json.dumps(body)
        if raw is not None:
            values["Content-Type"] = "application/json"
        values.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        try:
            connection.request(method, path, raw, values)
            response = connection.getresponse()
            data = response.read()
            parsed = json.loads(data) if response.getheader("Content-Type", "").startswith("application/json") else data
            return response.status, parsed, dict(response.getheaders())
        finally:
            connection.close()

    def login(self):
        status, data, headers = self.call("POST", "/api/login", {"code": self.app.login_code})
        self.assertEqual(status, 200, data)
        self.cookie = headers["Set-Cookie"].split(";")[0]
        self.csrf = data["csrf"]
        return headers

    def request(self):
        status, req, _ = self.call("POST", "/api/requests", {})
        self.assertEqual(status, 200, req)
        return req

    def consent(self, req, decision="approve"):
        return self.call("POST", f"/api/requests/{req['request_id']}/consent", {
            "decision": decision, "request_hash": req["request_hash"]})

    def presentation(self, req):
        status, envelope, _ = self.call("POST", f"/api/requests/{req['request_id']}/presentation", {})
        self.assertEqual(status, 200, envelope)
        return envelope

    def test_authentication_and_cookie_flags(self):
        self.assertEqual(self.call("POST", "/api/requests", {})[0], 401)
        self.assertEqual(self.call("POST", "/api/login", {"code": "wrong"})[0], 401)
        headers = self.login()
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        self.assertEqual(self.call("GET", "/api/session")[1]["synthetic"], True)

    def test_login_rotation_and_logout_invalidate_old_requests(self):
        self.login()
        req = self.request()
        old_cookie = self.cookie
        self.login()
        self.assertNotEqual(old_cookie, self.cookie)
        self.assertEqual(self.call("GET", "/api/session", headers={"Cookie": old_cookie})[0], 401)
        self.assertEqual(self.consent(req)[0], 404)
        self.assertEqual(self.call("POST", "/api/logout", {})[0], 200)
        self.assertEqual(self.call("GET", "/api/session")[0], 401)
        self.assertFalse(self.app.pending)

    def test_session_expiry(self):
        self.login()
        req = self.request()
        with self.app.lock:
            next(iter(self.app.sessions.values())).deadline = time.monotonic() - 1
        self.assertEqual(self.consent(req)[0], 401)

    def test_csrf_origin_and_host_rejection(self):
        self.login()
        for headers in ({"X-CSRF-Token": ""}, {"Origin": "https://attacker.example"},
                        {"Host": "attacker.example"}, {"Origin": ""},
                        {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.call("POST", "/api/requests", {}, headers=headers)[0], 403)
        self.assertFalse(self.app.pending)
        self.assertEqual(self.call("POST", "/api/login", {"code": self.app.login_code},
                                   headers={"Origin": "null"})[0], 403)

    def test_cross_session_request_and_proof_rejected(self):
        self.login()
        req = self.request()
        self.consent(req)
        envelope = self.presentation(req)
        self.cookie = ""
        self.login()  # Another session for the same synthetic account is still distinct.
        self.assertEqual(self.consent(req)[0], 404)
        self.assertEqual(self.call("GET", f"/api/requests/{req['request_id']}")[0], 404)
        self.assertEqual(self.call("POST", "/api/verify", envelope)[0], 404)

    def test_consent_required_even_for_externally_created_valid_proof(self):
        self.login()
        req = self.request()
        challenge = self.app.pending[req["request_id"]].challenge
        proof = make_presentation(self.holder, challenge, self.issuer.trust)
        envelope = {"request_id": req["request_id"], "presentation": proof}
        self.assertEqual(self.call("POST", f"/api/requests/{req['request_id']}/presentation", {})[0], 403)
        self.assertEqual(self.call("POST", "/api/verify", envelope)[0], 403)
        self.assertEqual(self.consent(req, "deny")[0], 200)
        self.assertEqual(self.consent(req)[0], 409)
        self.assertEqual(self.call("POST", "/api/verify", envelope)[0], 403)

    def test_consent_is_bound_to_exact_request(self):
        self.login()
        req = self.request()
        altered = dict(req, request_hash="0" * 64)
        self.assertEqual(self.consent(altered)[0], 409)
        self.assertEqual(self.app.pending[req["request_id"]].decision, "pending")
        self.assertEqual(self.consent(req)[0], 200)

    def test_valid_proof_no_identity_values_and_replay_rejection(self):
        self.login()
        req = self.request()
        self.consent(req)
        envelope = self.presentation(req)
        serialized = json.dumps(envelope)
        for name in ("full_name", "address", "license_number"):
            self.assertNotIn(self.holder.synthetic_attributes[name], serialized)
        status, result, _ = self.call("POST", "/api/verify", envelope)
        self.assertEqual(status, 200, result)
        self.assertTrue(result["verified"])
        self.assertFalse(result["live_licence_status_checked"])
        self.assertEqual(self.call("POST", "/api/verify", envelope)[1]["error"], "already_used")

    def test_tampered_proof_does_not_consume_request(self):
        self.login()
        req = self.request()
        self.consent(req)
        envelope = self.presentation(req)
        tampered = deepcopy(envelope)
        tampered["presentation"]["proof"]["aggregated_proof"]["c_hash"] = "0"
        self.assertEqual(self.call("POST", "/api/verify", tampered)[1]["error"], "invalid_proof")
        self.assertEqual(self.call("POST", "/api/verify", envelope)[0], 200)

    def test_concurrent_replay_has_exactly_one_success(self):
        self.login()
        req = self.request()
        self.consent(req)
        envelope = self.presentation(req)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.call, "POST", "/api/verify", envelope) for _ in range(2)]
            self.assertEqual(sorted(f.result()[0] for f in futures), [200, 409])

    def test_session_expiring_during_real_verification_rolls_back(self):
        self.login()
        req = self.request()
        self.consent(req)
        envelope = self.presentation(req)

        def verify_then_expire(*args):
            valid = verify_presentation(*args)
            next(iter(self.app.sessions.values())).deadline = time.monotonic() - 1
            return valid

        with patch("service.verify_presentation", side_effect=verify_then_expire):
            self.assertEqual(self.call("POST", "/api/verify", envelope)[0], 401)
        with sqlite3.connect(self.app.store.path) as con:
            self.assertEqual(con.execute("SELECT used FROM requests").fetchone()[0], 0)
        con.close()

    def test_proof_cannot_be_moved_to_another_approved_request(self):
        self.login()
        first, second = self.request(), self.request()
        self.consent(first)
        self.consent(second)
        envelope = self.presentation(first)
        envelope["request_id"] = second["request_id"]
        self.assertEqual(self.call("POST", "/api/verify", envelope)[1]["error"], "invalid_proof")

    def test_expired_request_is_removed_from_memory_and_database(self):
        self.login()
        req = self.request()
        pending = self.app.pending[req["request_id"]]
        with self.app.lock:
            pending.challenge = replace(pending.challenge, expires_at=int(time.time()) - 1)
        self.assertEqual(self.consent(req)[0], 404)
        with sqlite3.connect(self.app.store.path) as con:
            self.assertEqual(con.execute("SELECT count(*) FROM requests").fetchone()[0], 0)
        con.close()

    def test_client_cannot_override_policy_session_or_issuer(self):
        self.login()
        for key in ("session", "audience", "service_day", "proof_request", "trust"):
            with self.subTest(key=key):
                self.assertEqual(self.call("POST", "/api/requests", {key: "attacker"})[0], 400)

    def test_strict_json_size_and_content_type(self):
        self.login()
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '[]', '{'):
            with self.subTest(raw=raw):
                self.assertEqual(self.call("POST", "/api/requests", raw=raw)[0], 400)
        self.assertEqual(self.call("POST", "/api/requests", {},
                                   headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.call("POST", "/api/requests", {},
                                   headers={"Content-Length": str(MAX_BODY + 1)})[0], 413)
        self.assertEqual(self.call("POST", "/api/requests", {},
                                   headers={"Transfer-Encoding": "chunked"})[0], 400)

    def test_login_and_session_quotas(self):
        self.app.logins.limit = 1
        self.login()
        status, _, headers = self.call("POST", "/api/login", {"code": self.app.login_code})
        self.assertEqual(status, 429)
        self.assertEqual(headers["Retry-After"], "60")
        next(iter(self.app.sessions.values())).writes.limit = 1
        self.request()
        self.assertEqual(self.call("POST", "/api/requests", {})[0], 429)

    def test_static_routes_are_allowlisted_and_no_cache(self):
        for path in ("/", "/app.js", "/style.css", "/brand.css", "/toppy-logo.png"):
            status, data, headers = self.call("GET", path)
            self.assertEqual(status, 200)
            self.assertTrue(data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertIn("img-src 'self'", headers["Content-Security-Policy"])
            self.assertNotIn(self.app.login_code.encode(), data)
            if path == "/toppy-logo.png":
                self.assertEqual(headers["Content-Type"], "image/png")
                self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
        for path in ("/../service.py", "/.beads/issues.jsonl", "/error.log", "/../web/toppy-logo.png"):
            self.assertEqual(self.call("GET", path)[0], 404)

    def test_non_loopback_binding_refused(self):
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            LocalServer(("0.0.0.0", 0), self.app)


if __name__ == "__main__":
    unittest.main()
