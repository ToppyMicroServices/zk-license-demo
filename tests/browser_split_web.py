"""Remote Chromium checks for real split-service popup communication."""
import argparse
import hashlib
import http.client
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import expect, sync_playwright
import lifecycle as issuer
import split_wallet as wallet

ARTIFACTS = ROOT / "artifacts" / "browser"


class SplitBrowserTests(unittest.TestCase):
    evidence = []

    @classmethod
    def setUpClass(cls):
        fixture = tempfile.TemporaryDirectory()
        cls.addClassCleanup(fixture.cleanup)
        cls.source = Path(fixture.name) / "source"
        issuer_store, registry, wallet_store, verifier_store = (
            cls.source / role / "state.sqlite3"
            for role in ("issuer", "public", "wallet", "verifier")
        )
        issuer.initialize(issuer_store, registry)
        pair = wallet.verifier_init(verifier_store, registry, "synthetic-service.example")
        wallet.wallet_init(wallet_store, registry, pair)
        issued = issuer.issue(issuer_store, registry,
                              wallet.enroll(wallet_store, registry,
                                            issuer.offer(issuer_store, registry)))
        wallet.import_credential(wallet_store, registry, issued)
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        cls.browser = cls.playwright.chromium.launch()
        cls.addClassCleanup(cls.browser.close)
        cls.browser_version = cls.browser.version

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name) / "state"
        shutil.copytree(self.source, state)
        reservations = [socket.socket(), socket.socket()]
        try:
            for reservation in reservations:
                reservation.bind(("127.0.0.1", 0))
            ports = dict(zip(("verifier", "wallet"),
                             (item.getsockname()[1] for item in reservations)))
        finally:
            for reservation in reservations:
                reservation.close()
        self.origins = {role: f"http://127.0.0.1:{port}" for role, port in ports.items()}
        self.codes, self.processes = {}, {}
        for role, peer in (("verifier", "wallet"), ("wallet", "verifier")):
            process = subprocess.Popen([
                sys.executable, "-u", str(ROOT / "split_service.py"),
                "--role", role, "--store", str(state / role / "state.sqlite3"),
                "--registry", str(state / "public" / "state.sqlite3"),
                "--peer-origin", self.origins[peer], "--port", str(ports[role]),
            ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.processes[role] = process
            self.addCleanup(self.stop, process)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                self.assertIsNone(process.poll(), f"{role} stopped before listening")
                connection = http.client.HTTPConnection("127.0.0.1", ports[role], timeout=1)
                try:
                    connection.request("GET", "/api/config")
                    response = connection.getresponse()
                    response.read()
                    if response.status == 200:
                        break
                except OSError:
                    time.sleep(.05)
                finally:
                    connection.close()
            else:
                self.fail(f"{role} did not listen within 20 seconds")
            self.assertIn(f"Synthetic {role} Web demo:", process.stdout.readline())
            label, self.codes[role] = process.stdout.readline().strip().split(": ", 1)
            self.assertEqual(label, "Demo login code")
        self.assertNotEqual(self.processes["wallet"].pid, self.processes["verifier"].pid)
        self.context = self.browser.new_context(viewport={"width": 1100, "height": 1000})
        self.addCleanup(self.context.close)
        self.context.set_default_timeout(15000)
        self.calls, self.page_errors, self.replacements = [], [], []
        self.context.on("request", self.record_request)
        self.context.on("page", lambda page: page.on(
            "pageerror", lambda error: self.page_errors.append(str(error))))
        self.reception = self.context.new_page()
        self.reception.goto(self.origins["verifier"] + "/verifier.html")
        self.login(self.reception, "verifier")

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)

    def record_request(self, request):
        # Store only paths and counts, never bearer headers or response bodies.
        path = urlparse(request.url).path
        if request.method == "POST" and path in (
                "/api/requests", "/api/review", "/api/decision", "/api/verify"):
            self.calls.append(path)
            if path == "/api/requests":
                self.replacements.append(request.post_data_json.get("replaces_request_id"))

    def count(self, path):
        return self.calls.count(path)

    def login(self, page, role):
        page.locator("#login-code").fill(self.codes[role])
        page.locator("#login-form").get_by_role("button", name="ログイン", exact=True).click()
        expect(page.locator("#work-panel")).to_be_visible()
        expect(page.locator("#login-code")).to_have_value("")

    def open_wallet(self):
        with self.reception.expect_popup() as opened:
            self.reception.locator("#new-request").click()
        page = opened.value
        page.wait_for_url(self.origins["wallet"] + "/wallet.html")
        self.assertEqual(page.opener(), self.reception)
        self.login(page, "wallet")
        expect(page.locator("#review-panel")).to_be_visible()
        expect(self.reception.locator("#request-panel")).to_be_visible()
        return page

    def repeat(self, page):
        request_id = self.reception.locator("#request-id").inner_text()
        self.reception.locator("#new-request").click()
        expect(self.reception.locator("#request-id")).to_have_text(request_id)
        expect(page.locator("#review-panel")).to_be_visible()
        return request_id

    def decide(self, page, approved):
        if approved:
            with self.reception.expect_response(
                    lambda response: response.url == self.origins["verifier"] + "/api/verify"
            ) as verified:
                page.locator("#approve").click()
            result = verified.value.json()
            self.assertEqual(verified.value.status, 200)
            self.assertIs(result["verified"], True)
            self.assertIs(result["accepted"], True)
            self.assertIs(result["synthetic_revocation_checked"], True)
            self.assertIs(result["live_licence_status_checked"], False)
            expect(page.locator("#result-title")).to_have_text("証明を送信しました")
            expect(self.reception.locator("#result-title")).to_have_text("条件の確認が完了しました")
        else:
            verify_count = self.count("/api/verify")
            with page.expect_response(
                    lambda response: response.url == self.origins["wallet"] + "/api/decision"
            ) as denied:
                page.locator("#deny").click()
            result = denied.value.json()
            self.assertEqual(denied.value.status, 200)
            self.assertEqual(result["decision"], "denied")
            self.assertNotIn("presentation", result)
            expect(page.locator("#result-title")).to_have_text("今回は共有しませんでした")
            expect(self.reception.locator("#result-title")).to_have_text("今回は共有されませんでした")
            self.assertEqual(self.count("/api/verify"), verify_count)
        expect(page.locator("#review-panel")).to_be_hidden()
        expect(self.reception.locator("#request-panel")).to_be_hidden()
        outcome = "approved" if approved else "denied"
        for role, target in (("wallet", page), ("reception", self.reception)):
            target.screenshot(
                path=str(ARTIFACTS / f"{self._testMethodName}-{outcome}-{role}.png"),
                full_page=True)

    def test_approval_and_denial_preserve_request_on_repeat(self):
        page = self.open_wallet()
        first_id = self.repeat(page)
        self.assertEqual(self.count("/api/decision"), 0)
        self.assertEqual(self.count("/api/verify"), 0)
        self.decide(page, True)
        self.assertEqual(self.count("/api/requests"), 1)
        self.reception.locator("#new-request").click()
        expect(page.locator("#review-panel")).to_be_visible()
        second_id = self.repeat(page)
        self.assertNotEqual(first_id, second_id)
        expect(page.locator("#login-panel")).to_be_hidden()
        self.assertEqual(len(self.context.pages), 2)
        self.decide(page, False)
        self.assertEqual(self.count("/api/requests"), 2)
        self.assertEqual(self.count("/api/decision"), 2)
        self.assertEqual(self.count("/api/verify"), 1)
        self.assertEqual(self.replacements, [None, first_id])

    def test_reception_logout_reloads_pending_wallet(self):
        page = self.open_wallet()
        old_id = self.reception.locator("#request-id").inner_text()
        self.reception.locator("#logout").click()
        expect(self.reception.locator("#login-panel")).to_be_visible()
        self.login(self.reception, "verifier")
        self.reception.locator("#new-request").click()
        # This panel was hidden before the click; its visibility proves reload.
        expect(page.locator("#login-panel")).to_be_visible()
        self.login(page, "wallet")
        expect(page.locator("#review-panel")).to_be_visible()
        self.assertNotEqual(old_id, self.reception.locator("#request-id").inner_text())
        self.assertEqual(len(self.context.pages), 2)
        self.decide(page, False)
        self.assertEqual(self.count("/api/requests"), 2)
        self.assertEqual(self.count("/api/decision"), 1)
        self.assertEqual(self.count("/api/verify"), 0)
        self.assertEqual(self.replacements, [None, None])

    def test_closed_wallet_starts_new_request(self):
        page = self.open_wallet()
        old_id = self.reception.locator("#request-id").inner_text()
        page.close()
        replacement = self.open_wallet()
        self.assertNotEqual(old_id, self.reception.locator("#request-id").inner_text())
        self.decide(replacement, True)
        self.assertEqual(self.count("/api/requests"), 2)
        self.assertEqual(self.count("/api/decision"), 1)
        self.assertEqual(self.count("/api/verify"), 1)
        self.assertEqual(self.replacements, [None, old_id])

    def tearDown(self):
        for number, page in enumerate(self.context.pages):
            page.screenshot(
                path=str(ARTIFACTS / f"{self._testMethodName}-final-{number}.png"),
                full_page=True)
        self.evidence.append({
            "test": self._testMethodName,
            "requests": {path: self.count(path) for path in sorted(set(self.calls))},
            "process_ids": {role: process.pid for role, process in self.processes.items()},
            "page_errors": self.page_errors,
        })
        self.assertEqual(self.page_errors, [])
        for process in self.processes.values():
            self.assertIsNone(process.poll())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ARTIFACTS)
    args, remaining = parser.parse_known_args()
    ARTIFACTS = args.out
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    program = unittest.main(argv=[sys.argv[0], *remaining], verbosity=2, exit=False)
    report = {
        "checked_out_sha": os.environ.get("GITHUB_SHA"),
        "source_head_sha": os.environ.get("SOURCE_HEAD_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "playwright": version("playwright"),
        "anoncreds": version("anoncreds"),
        "browser": "Chromium",
        "browser_version": getattr(SplitBrowserTests, "browser_version", None),
        "tests_run": program.result.testsRun,
        "successful": program.result.wasSuccessful(),
        "failures": len(program.result.failures),
        "errors": len(program.result.errors),
        "evidence": SplitBrowserTests.evidence,
        "screenshots_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(ARTIFACTS.glob("*.png"))
        },
    }
    (ARTIFACTS / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    sys.exit(0 if program.result.wasSuccessful() else 1)
