"""HTTP tests for two local services holding separate synthetic state."""
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import lifecycle as issuer
from service import LocalServer
from split_service import SplitApplication, SplitHandler
import split_wallet as wallet
from zk_license import backend


class SplitServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            backend()
        except RuntimeError:
            if os.environ.get("REQUIRE_CRYPTO") == "1":
                raise
            raise unittest.SkipTest("anoncreds unavailable")
        fixture = tempfile.TemporaryDirectory()
        cls.addClassCleanup(fixture.cleanup)
        cls.source = Path(fixture.name) / "source"
        cls.i, cls.r, cls.w, cls.v = (
            cls.source / name / "state.sqlite3"
            for name in ("issuer", "public", "wallet", "verifier")
        )
        cls.key = issuer.initialize(cls.i, cls.r)
        pair = wallet.verifier_init(cls.v, cls.r, "synthetic-service.example")
        wallet.wallet_init(cls.w, cls.r, pair)
        issued = issuer.issue(cls.i, cls.r, wallet.enroll(cls.w, cls.r, issuer.offer(cls.i, cls.r)))
        wallet.import_credential(cls.w, cls.r, issued)

    def setUp(self):
        case = tempfile.TemporaryDirectory()
        self.addCleanup(case.cleanup)
        self.root = Path(case.name) / "case"
        shutil.copytree(self.source, self.root)
        self.issuer_store, self.registry, self.wallet_store, self.verifier_store = (
            self.root / name / "state.sqlite3"
            for name in ("issuer", "public", "wallet", "verifier")
        )
        self.verifier = SplitApplication(
            "verifier", self.verifier_store, self.registry, "http://127.0.0.1:1"
        )
        self.verifier_server = self.start_server(self.verifier)
        self.wallet = SplitApplication(
            "wallet", self.wallet_store, self.registry, self.verifier_server.origin
        )
        self.wallet_server = self.start_server(self.wallet)
        self.verifier.peer_origin = self.wallet_server.origin

    def start_server(self, app):
        server = LocalServer(("127.0.0.1", 0), app, handler=SplitHandler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)

        self.addCleanup(stop)
        return server

    def call(self, role, method, path, body=None, *, token="", headers=None, raw=None, port=None):
        if port is None:
            server = self.verifier_server if role == "verifier" else self.wallet_server
            port = server.server_port
        values = {"Origin": f"http://127.0.0.1:{port}"}
        if token:
            values["Authorization"] = "Bearer " + token
        if body is not None:
            raw = json.dumps(body, ensure_ascii=False)
        if raw is not None:
            values["Content-Type"] = "application/json"
        values.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        try:
            connection.request(method, path, raw, values)
            response = connection.getresponse()
            data = response.read()
            parsed = json.loads(data) if response.getheader("Content-Type", "").startswith("application/json") else data
            return response.status, parsed, dict(response.getheaders())
        finally:
            connection.close()

    def login(self, role):
        app = self.verifier if role == "verifier" else self.wallet
        status, value, headers = self.call(role, "POST", "/api/login", {"code": app.login_code})
        self.assertEqual(status, 200, value)
        self.assertIn("token", value)
        self.assertNotIn("Set-Cookie", headers)
        return value["token"]

    def request(self, token, key_id=None):
        status, value, _ = self.call(
            "verifier", "POST", "/api/requests", {"key_id": key_id or self.key}, token=token
        )
        self.assertEqual(status, 200, value)
        self.assertIn("signed_request", value)
        return value["signed_request"]

    def review(self, token, signed):
        status, value, _ = self.call(
            "wallet", "POST", "/api/review", {"signed_request": signed}, token=token
        )
        self.assertEqual(status, 200, value)
        return value

    def decide(self, token, shown, *, decision="approve"):
        return self.call("wallet", "POST", "/api/decision", {
            "request_id": shown["request_id"], "review_hash": shown["review_hash"],
            "decision": decision,
        }, token=token)

    def approve(self, verifier_token, wallet_token, *, key_id=None):
        signed = self.request(verifier_token, key_id)
        shown = self.review(wallet_token, signed)
        status, envelope, _ = self.decide(wallet_token, shown)
        self.assertEqual(status, 200, envelope)
        self.assertEqual(envelope["request_id"], shown["request_id"])
        return signed, shown, envelope

    def verify(self, token, envelope):
        return self.call("verifier", "POST", "/api/verify", envelope, token=token)

    def reissue(self):
        issued = issuer.issue(
            self.issuer_store, self.registry,
            wallet.enroll(self.wallet_store, self.registry,
                          issuer.offer(self.issuer_store, self.registry)),
        )
        wallet.import_credential(self.wallet_store, self.registry, issued)
        return backend().Credential.load(issued["credential"]).rev_reg_index

    def test_bearer_tokens_are_origin_local_and_request_boundary_is_strict(self):
        for role, app, peer in (
            ("verifier", self.verifier, self.wallet_server.origin),
            ("wallet", self.wallet, self.verifier_server.origin),
        ):
            status, config, _ = self.call(role, "GET", "/api/config")
            self.assertEqual(status, 200, config)
            self.assertEqual(config["role"], role)
            self.assertEqual(config["peer_origin"], peer)
            self.assertNotIn(app.login_code, json.dumps(config))
            self.assertEqual(self.call(role, "GET", "/api/session")[0], 401)
            self.assertEqual(self.call(role, "POST", "/api/login", {"code": "wrong"})[0], 401)

        verifier_token, wallet_token = self.login("verifier"), self.login("wallet")
        self.assertNotEqual(verifier_token, wallet_token)
        self.assertEqual(self.call("wallet", "GET", "/api/session", token=verifier_token)[0], 401)
        self.assertEqual(self.call("verifier", "GET", "/api/session", token=wallet_token)[0], 401)
        self.assertEqual(self.call("wallet", "GET", "/api/session", headers={"Cookie": verifier_token})[0], 401)
        self.assertEqual(self.call("verifier", "GET", "/api/session", token=verifier_token)[0], 200)

        for headers in (
            {"Origin": "http://attacker.example"},
            {"Origin": "null"},
            {"Host": "attacker.example"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.call("verifier", "POST", "/api/requests", {"key_id": self.key},
                                           token=verifier_token, headers=headers)[0], 403)
        self.assertEqual(self.call("verifier", "POST", "/api/requests",
                                   token=verifier_token, raw=b'{"key_id":"a","key_id":"b"}')[0], 400)

    def test_real_proof_needs_wallet_approval_and_verifier_needs_no_private_store(self):
        verifier_token, wallet_token = self.login("verifier"), self.login("wallet")
        signed, shown, envelope = self.approve(verifier_token, wallet_token)
        self.assertEqual(shown["revealed_attributes"], [])
        self.assertEqual(envelope["presentation"]["requested_proof"]["revealed_attrs"], {})

        with issuer.store(self.wallet_store, "wallet") as local:
            link_secret = local["link_secret"]
        exchanged = json.dumps([signed, shown, envelope], ensure_ascii=False)
        self.assertNotIn(link_secret, exchanged)
        for secret in ("link_secret", "cred_def_private", "rev_reg_private", "SAMPLE PERSON"):
            self.assertNotIn(secret, exchanged)

        shutil.rmtree(self.wallet_store.parent)
        shutil.rmtree(self.issuer_store.parent)
        status, result, _ = self.verify(verifier_token, envelope)
        self.assertEqual(status, 200, result)
        self.assertTrue(result["accepted"])
        self.assertTrue(result["synthetic_revocation_checked"])
        self.assertFalse(result["live_licence_status_checked"])
        self.assertEqual(self.verify(verifier_token, envelope)[0], 409)

    def test_denial_is_terminal_and_http_sessions_own_requests(self):
        verifier_token, wallet_token = self.login("verifier"), self.login("wallet")
        signed = self.request(verifier_token)
        shown = self.review(wallet_token, signed)
        status, value, _ = self.decide(wallet_token, shown, decision="deny")
        self.assertEqual(status, 200, value)
        self.assertEqual(value["decision"], "denied")
        self.assertEqual(self.decide(wallet_token, shown)[0], 409)

        signed = self.request(verifier_token)
        shown = self.review(wallet_token, signed)
        other_wallet_token = self.login("wallet")
        self.assertEqual(self.decide(other_wallet_token, shown)[0], 404)

        # A proof approved for one verifier browser session cannot be submitted
        # under another session, even when both know the same request ID.
        signed = self.request(verifier_token)
        shown = self.review(other_wallet_token, signed)
        status, envelope, _ = self.decide(other_wallet_token, shown)
        self.assertEqual(status, 200, envelope)
        other_verifier_token = self.login("verifier")
        self.assertEqual(self.verify(other_verifier_token, envelope)[0], 404)

    def test_revocation_stale_request_reissue_and_key_rotation(self):
        verifier_token, wallet_token = self.login("verifier"), self.login("wallet")
        _, _, old_proof = self.approve(verifier_token, wallet_token)
        issuer.revoke_credential(self.issuer_store, self.registry, self.key, 1)
        status, value, _ = self.verify(verifier_token, old_proof)
        self.assertEqual(status, 409, value)
        self.assertEqual(value["error"], "stale_registry_request")

        fresh = self.request(verifier_token)
        shown = self.review(wallet_token, fresh)
        status, value, _ = self.decide(wallet_token, shown)
        self.assertEqual(status, 409, value)
        self.assertEqual(value["error"], "credential_revoked")

        backup = self.root / "issuer-backup.json"
        issuer.backup(self.issuer_store, backup)
        self.issuer_store.unlink()
        issuer.restore(self.issuer_store, self.registry, backup)
        self.assertEqual(self.reissue(), 2)
        _, _, proof = self.approve(verifier_token, wallet_token)
        self.assertEqual(self.verify(verifier_token, proof)[0], 200)

        next_key = issuer.rotate(self.issuer_store, self.registry)
        self.assertEqual(self.reissue(), 1)
        _, _, proof = self.approve(verifier_token, wallet_token, key_id=next_key)
        self.assertEqual(self.verify(verifier_token, proof)[0], 200)
        issuer.change_key(self.issuer_store, self.registry, self.key, "revoke")
        status, value, _ = self.call("verifier", "POST", "/api/requests",
                                     {"key_id": self.key}, token=verifier_token)
        self.assertEqual(status, 409, value)
        self.assertEqual(value["error"], "untrusted_issuer_key")

    def test_running_services_require_wallet_repair_after_verifier_reset(self):
        verifier_token, wallet_token = self.login("verifier"), self.login("wallet")
        old_signed, _, old_proof = self.approve(verifier_token, wallet_token)
        pair = wallet.verifier_reset(self.verifier_store, self.registry)

        status, value, _ = self.verify(verifier_token, old_proof)
        self.assertEqual(status, 409, value)
        self.assertEqual(value["error"], "unknown_request")

        fresh = self.request(verifier_token)
        status, value, _ = self.call("wallet", "POST", "/api/review",
                                     {"signed_request": fresh}, token=wallet_token)
        self.assertEqual(status, 409, value)
        self.assertEqual(value["error"], "unauthenticated_request")
        wallet.wallet_pair(self.wallet_store, self.registry, pair)
        shown = self.review(wallet_token, fresh)
        status, proof, _ = self.decide(wallet_token, shown)
        self.assertEqual(status, 200, proof)
        self.assertEqual(self.verify(verifier_token, proof)[0], 200)

        # The old request remains invalid after both roles share the new pair.
        status, value, _ = self.call("wallet", "POST", "/api/review",
                                     {"signed_request": old_signed}, token=wallet_token)
        self.assertEqual(status, 409, value)
        self.assertEqual(value["error"], "unauthenticated_request")

    def test_two_cli_processes_verify_after_private_stores_are_removed(self):
        root = Path(__file__).resolve().parents[1]
        reservations = [socket.socket(), socket.socket()]
        try:
            for reservation in reservations:
                reservation.bind(("127.0.0.1", 0))
            ports = {
                "verifier": reservations[0].getsockname()[1],
                "wallet": reservations[1].getsockname()[1],
            }
        finally:
            for reservation in reservations:
                reservation.close()

        def start(role, private, peer):
            command = [sys.executable, "-u", str(root / "split_service.py"),
                       "--role", role, "--store", str(private),
                       "--registry", str(self.registry),
                       "--peer-origin", f"http://127.0.0.1:{ports[peer]}",
                       "--port", str(ports[role])]
            process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)

            def stop():
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)

            self.addCleanup(stop)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    self.fail(f"{role} process exited: {process.stderr.read()}")
                try:
                    status, _, _ = self.call(role, "GET", "/api/config", port=ports[role])
                    if status == 200:
                        break
                except OSError:
                    time.sleep(.05)
            else:
                self.fail(f"{role} process did not listen within 20 seconds")
            self.assertIn(f"Synthetic {role} Web demo:", process.stdout.readline())
            label, code = process.stdout.readline().strip().split(": ", 1)
            self.assertEqual(label, "Demo login code")
            return process, code

        verifier_process, verifier_code = start("verifier", self.verifier_store, "wallet")
        wallet_process, wallet_code = start("wallet", self.wallet_store, "verifier")
        self.assertNotEqual(verifier_process.pid, wallet_process.pid)
        self.assertIsNone(verifier_process.poll())
        self.assertIsNone(wallet_process.poll())

        def call(role, method, path, body=None, *, token=""):
            return self.call(role, method, path, body, token=token, port=ports[role])

        status, login, _ = call("verifier", "POST", "/api/login", {"code": verifier_code})
        self.assertEqual(status, 200, login)
        verifier_token = login["token"]
        status, login, _ = call("wallet", "POST", "/api/login", {"code": wallet_code})
        self.assertEqual(status, 200, login)
        wallet_token = login["token"]
        status, requested, _ = call("verifier", "POST", "/api/requests",
                                    {"key_id": self.key}, token=verifier_token)
        self.assertEqual(status, 200, requested)
        status, shown, _ = call("wallet", "POST", "/api/review",
                                {"signed_request": requested["signed_request"]}, token=wallet_token)
        self.assertEqual(status, 200, shown)
        status, proof, _ = call("wallet", "POST", "/api/decision", {
            "request_id": shown["request_id"], "review_hash": shown["review_hash"],
            "decision": "approve",
        }, token=wallet_token)
        self.assertEqual(status, 200, proof)

        shutil.rmtree(self.wallet_store.parent)
        shutil.rmtree(self.issuer_store.parent)
        self.assertIsNone(verifier_process.poll())
        status, result, _ = call("verifier", "POST", "/api/verify", proof,
                                 token=verifier_token)
        self.assertEqual(status, 200, result)
        self.assertTrue(result["accepted"])

    def test_completed_requests_and_reviews_free_session_capacity(self):
        verifier_token, wallet_token = self.login("verifier"), self.login("wallet")
        with patch("split_service.MAX_PENDING", 1):
            signed = self.request(verifier_token)
            status, value, _ = self.call("verifier", "POST", "/api/requests",
                                         {"key_id": self.key}, token=verifier_token)
            self.assertEqual((status, value["error"]), (503, "request_capacity"))

            shown = self.review(wallet_token, signed)
            status, value, _ = self.call("wallet", "POST", "/api/review",
                                         {"signed_request": signed}, token=wallet_token)
            self.assertEqual((status, value["error"]), (503, "request_capacity"))
            status, proof, _ = self.decide(wallet_token, shown)
            self.assertEqual(status, 200, proof)
            self.assertEqual(self.verify(verifier_token, proof)[0], 200)
            self.assertEqual(self.verify(verifier_token, proof)[0], 409)

            next_signed = self.request(verifier_token)
            next_shown = self.review(wallet_token, next_signed)
            self.assertNotEqual(next_shown["request_id"], shown["request_id"])

    def test_login_rate_limit_and_logout_invalidate_token(self):
        results = [self.call("wallet", "POST", "/api/login", {"code": "wrong"})[0]
                   for _ in range(12)]
        self.assertIn(429, results)
        verifier_token = self.login("verifier")
        self.request(verifier_token)
        self.assertEqual(self.call("verifier", "POST", "/api/logout", {}, token=verifier_token)[0], 200)
        self.assertEqual(self.call("verifier", "GET", "/api/session", token=verifier_token)[0], 401)

    def test_logout_succeeds_when_session_and_global_quotas_are_full(self):
        token = self.login("verifier")
        with self.verifier.lock:
            self.verifier.sessions[token].writes.limit = 0
            self.verifier.all_calls.limit = 0
        try:
            status, result, _ = self.call("verifier", "POST", "/api/logout", {}, token=token)
            self.assertEqual(status, 200, result)
            self.assertTrue(result["logged_out"])
        finally:
            with self.verifier.lock:
                self.verifier.all_calls.limit = 120
        self.assertEqual(self.call("verifier", "GET", "/api/session", token=token)[0], 401)

    def test_session_expiring_during_native_verification_does_not_consume_request(self):
        verifier_token, wallet_token = self.login("verifier"), self.login("wallet")
        _, _, proof = self.approve(verifier_token, wallet_token)
        real_verify = wallet.verify_crypto

        def verify_then_expire(*args):
            valid = real_verify(*args)
            self.verifier.sessions[verifier_token].deadline = time.monotonic() - 1
            return valid

        with patch("split_wallet.verify_crypto", side_effect=verify_then_expire):
            status, result, _ = self.verify(verifier_token, proof)
        self.assertEqual(status, 401, result)
        self.assertEqual(result["error"], "authentication_required")
        request_id = proof["request_id"]
        with issuer.store(self.verifier_store, "verifier") as local:
            self.assertFalse(local["requests"][request_id]["used"])


if __name__ == "__main__":
    unittest.main()
