#!/usr/bin/env python3
"""Bounded loopback HTTP measurements of the synthetic split Web demo.

Run on hosted CI. This measures one Wallet and one verifier, not production
capacity. Response bodies, credentials and bearer tokens never enter evidence.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import queue
import shutil
import socket
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time

from benchmark import summarize
import lifecycle as issuer
import split_wallet as wallet

ROOT = Path(__file__).resolve().parent
SOURCES = ("split_benchmark.py", "benchmark.py", "split_service.py", "service.py",
           "split_wallet.py", "lifecycle.py", "request_store.py", "zk_license.py",
           "requirements.txt", "requirements-ingestion.txt", ".github/workflows/test.yml")
ROLES = ("verifier", "wallet")
HTTP_TIMEOUT = 15
SCENARIO_SECONDS = 180


class MeasurementFailure(RuntimeError):
    """Only fixed, non-secret reason codes are used in evidence."""


def require(condition, code):
    if not condition:
        raise MeasurementFailure(code)


def source_state():
    result = {"sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                         for name in SOURCES}, "git_commit": None, "source_dirty": None}
    try:
        result["git_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
            stderr=subprocess.DEVNULL, timeout=10).strip()
        result["source_dirty"] = bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--", *SOURCES], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL, timeout=10).strip())
    except (OSError, subprocess.SubprocessError):
        pass  # Exact byte hashes still identify an extracted source archive.
    return result


class Client:
    def __init__(self, port, token=""):
        self.port, self.token = port, token

    def call(self, steps, name, path, body=None, *, status=200, error=None):
        started = time.perf_counter()
        metric = {"step": name, "http_status": None, "elapsed_ms": None}
        steps.append(metric)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=HTTP_TIMEOUT)
        try:
            headers = {"Origin": f"http://127.0.0.1:{self.port}"}
            if self.token:
                headers["Authorization"] = "Bearer " + self.token
            raw = None
            if body is not None:
                raw = json.dumps(body, ensure_ascii=False).encode()
                headers["Content-Type"] = "application/json"
            connection.request("POST" if body is not None else "GET", path, raw, headers)
            response = connection.getresponse()
            metric["http_status"] = response.status
            payload = response.read(1_000_001)
            require(len(payload) <= 1_000_000, "response_too_large")
            require(response.getheader("Content-Type", "").startswith("application/json"),
                    "non_json_response")
            value = json.loads(payload)
            require(isinstance(value, dict), "invalid_response_shape")
            require(response.status in (status if isinstance(status, tuple) else (status,)),
                    "unexpected_http_status")
            if error is not None and response.status != 200:
                require(value.get("error") == error, "unexpected_error_code")
                metric["expected_error"] = error
            if response.status == 429:
                require(response.getheader("Retry-After") == "60", "missing_retry_after")
                metric["retry_after_seconds"] = 60
            return value
        except (OSError, http.client.HTTPException, ValueError):
            # Never copy an exception message, HTTP body or token to output.
            raise MeasurementFailure("http_or_json_failure") from None
        finally:
            metric["elapsed_ms"] = (time.perf_counter() - started) * 1000
            connection.close()


def fixture(root):
    started = time.perf_counter()
    paths = {role: root / role / "state.sqlite3"
             for role in ("issuer", "public", "wallet", "verifier")}
    key = issuer.initialize(paths["issuer"], paths["public"])
    key_ready = time.perf_counter()
    pair = wallet.verifier_init(paths["verifier"], paths["public"], "synthetic-load.example")
    wallet.wallet_init(paths["wallet"], paths["public"], pair)
    issued = issuer.issue(paths["issuer"], paths["public"], wallet.enroll(
        paths["wallet"], paths["public"], issuer.offer(paths["issuer"], paths["public"])))
    wallet.import_credential(paths["wallet"], paths["public"], issued)
    return key, {"key_generation_and_registry_ms": (key_ready - started) * 1000,
                 "wallet_setup_enrollment_issuance_ms": (time.perf_counter() - key_ready) * 1000,
                 "total_ms": (time.perf_counter() - started) * 1000}


def copy_fixture(source, destination):
    shutil.copytree(source, destination)
    return {role: destination / role / "state.sqlite3"
            for role in ("issuer", "public", "wallet", "verifier")}


def startup_lines(stream, result):
    # Two lines only; the login code remains in this in-memory queue.
    result.put((stream.readline(), stream.readline()))


@contextmanager
def servers(paths, evidence):
    reservations, processes, readers = [], {}, []
    try:
        for _ in ROLES:
            reservation = socket.socket()
            reservations.append(reservation)
            reservation.bind(("127.0.0.1", 0))
        ports = dict(zip(ROLES, (item.getsockname()[1] for item in reservations)))
    finally:
        for reservation in reservations:
            reservation.close()
    codes = {}
    try:
        for role, peer in (("verifier", "wallet"), ("wallet", "verifier")):
            process = subprocess.Popen([
                sys.executable, "-u", str(ROOT / "split_service.py"),
                "--role", role, "--store", str(paths[role]),
                "--registry", str(paths["public"]), "--peer-origin",
                f"http://127.0.0.1:{ports[peer]}", "--port", str(ports[role]),
            ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            processes[role] = process
            result = queue.Queue(maxsize=1)
            reader = threading.Thread(target=startup_lines, args=(process.stdout, result), daemon=True)
            readers.append(reader)
            reader.start()
            try:
                banner, code = result.get(timeout=20)
            except queue.Empty:
                raise MeasurementFailure("service_startup_timeout") from None
            require(banner.startswith(f"Synthetic {role} Web demo:"), "invalid_startup_banner")
            require(code.startswith("Demo login code: "), "missing_login_code")
            codes[role] = code.strip().split(": ", 1)[1]
            config = Client(ports[role]).call(evidence.setdefault("startup_http", []),
                                             role + "_config", "/api/config")
            require(config.get("role") == role and config.get("synthetic") is True
                    and config.get("live_licence_status_checked") is False, "invalid_config")
        evidence["process_ids"] = {role: process.pid for role, process in processes.items()}
        require(processes["wallet"].pid != processes["verifier"].pid, "roles_share_process")
        yield ports, codes
        require(all(process.poll() is None for process in processes.values()), "service_stopped")
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=1)
        for process in processes.values():
            process.stdout.close()


def login(port, code, steps, role):
    client = Client(port)
    result = client.call(steps, role + "_login", "/api/login", {"code": code})
    token = result.get("token")
    require(isinstance(token, str) and len(token) == 43, "invalid_login_result")
    return Client(port, token)


def prepare_request(verifier, holder, key, steps):
    requested = verifier.call(steps, "request", "/api/requests", {"key_id": key})
    signed = requested["signed_request"]
    shown = holder.call(steps, "review", "/api/review", {"signed_request": signed})
    require(shown["request_id"] == signed["payload"]["challenge"]["request_id"],
            "review_request_mismatch")
    require(shown.get("revealed_attributes") == []
            and shown.get("live_licence_status_checked") is False, "invalid_review_scope")
    return {"request_id": shown["request_id"], "review_hash": shown["review_hash"]}


def approve(worker, clients, key, barrier):
    verifier, holder = clients
    sample = {"session": worker, "status": "FAILED", "steps": []}
    try:
        barrier.wait(timeout=10)
        started = time.perf_counter()
        decision = prepare_request(verifier, holder, key, sample["steps"])
        envelope = holder.call(sample["steps"], "approve", "/api/decision",
                               {**decision, "decision": "approve"})
        require(set(envelope) == {"request_id", "presentation"}
                and envelope["request_id"] == decision["request_id"], "invalid_proof_envelope")
        checked = verifier.call(sample["steps"], "verify", "/api/verify", envelope)
        require(checked.get("verified") is True and checked.get("accepted") is True
                and checked.get("synthetic") is True
                and checked.get("synthetic_revocation_checked") is True
                and checked.get("live_licence_status_checked") is False, "verification_not_accepted")
        sample.update(status="PASSED", flow_ms=(time.perf_counter() - started) * 1000,
                      accepted=True, synthetic_revocation_checked=True,
                      live_licence_status_checked=False)
        return sample, envelope
    except Exception as exc:
        sample["failure"] = str(exc) if isinstance(exc, MeasurementFailure) else "flow_exception"
        return sample, None


def concurrency_case(source, root, key, concurrency, warmups, flows, report):
    case = {"concurrency": concurrency, "status": "FAILED", "warmup_batches": [],
            "measured_batches": [], "denials": [], "login_http": []}
    report["scenarios"].append(case)
    scenario_started = time.perf_counter()
    deadline = time.monotonic() + SCENARIO_SECONDS
    started = time.perf_counter()
    paths = copy_fixture(source, root)
    case["fixture_copy_ms"] = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    with servers(paths, case) as (ports, codes):
        clients = [(login(ports["verifier"], codes["verifier"], case["login_http"], "verifier"),
                    login(ports["wallet"], codes["wallet"], case["login_http"], "wallet"))
                   for _ in range(4)]
        case["service_start_and_login_ms"] = (time.perf_counter() - started) * 1000
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            for offset in range(0, warmups + flows, concurrency):
                require(time.monotonic() < deadline, "scenario_deadline_elapsed")
                batch = {"batch": offset // concurrency + 1, "samples": [], "replay_http": []}
                destination = "warmup_batches" if offset < warmups else "measured_batches"
                case[destination].append(batch)
                barrier = threading.Barrier(concurrency + 1)
                selected = [((offset + worker) % 4, clients[(offset + worker) % 4])
                            for worker in range(concurrency)]
                futures = [pool.submit(approve, session + 1, pair, key, barrier)
                           for session, pair in selected]
                started = time.perf_counter()
                barrier.wait(timeout=10)
                results = [future.result(timeout=120) for future in futures]
                batch["completion_ms"] = (time.perf_counter() - started) * 1000
                batch["samples"] = [sample for sample, _ in results]
                require(all(sample["status"] == "PASSED" for sample, _ in results), "flow_failed")
                # Replay traffic starts only after every timed flow has finished.
                for (_, (verifier, _)), (_, envelope) in zip(selected, results):
                    verifier.call(batch["replay_http"], "replay", "/api/verify", envelope,
                                  status=409, error="already_used")
                batch["batch_completion_rate_per_second"] = concurrency * 1000 / batch["completion_ms"]
        for worker, (verifier, holder) in enumerate(clients, 1):
            require(time.monotonic() < deadline, "scenario_deadline_elapsed")
            denial = {"session": worker, "steps": []}
            case["denials"].append(denial)
            decision = prepare_request(verifier, holder, key, denial["steps"])
            result = holder.call(denial["steps"], "deny", "/api/decision",
                                 {**decision, "decision": "deny"})
            require(set(result) == {"decision", "request_id"} and result["decision"] == "denied"
                    and result["request_id"] == decision["request_id"], "denial_returned_proof")
            holder.call(denial["steps"], "approve_after_deny", "/api/decision",
                        {**decision, "decision": "approve"},
                        status=409, error="decision_already_recorded")
            denial.update(no_presentation=True, verifier_submissions=0)
        measured = case["measured_batches"]
        samples = [sample for batch in measured for sample in batch["samples"]]
        case["summary"] = {"flow_ms": summarize([sample["flow_ms"] for sample in samples]),
                           "batch_completion_ms": summarize([batch["completion_ms"] for batch in measured]),
                           "batch_completion_rate_per_second": summarize(
                               [batch["batch_completion_rate_per_second"] for batch in measured])}
        case["summary"]["steps_ms"] = {
            name: summarize([step["elapsed_ms"] for sample in samples for step in sample["steps"]
                             if step["step"] == name])
            for name in ("request", "review", "approve", "verify")}
    require(time.monotonic() < deadline, "scenario_deadline_elapsed")
    case["scenario_wall_ms"] = (time.perf_counter() - scenario_started) * 1000
    case["status"] = "PASSED"


def concurrent_rate_boundary(client, evidence):
    probes = [{"worker": worker, "status": "FAILED", "steps": []}
              for worker in range(1, 5)]
    evidence["concurrent_boundary"] = probes
    barrier = threading.Barrier(4)

    def boundary(probe):
        started = time.perf_counter()
        try:
            barrier.wait(timeout=10)
            client.call(probe["steps"], "process_limit_boundary", "/api/session",
                        status=(200, 429), error="rate_limited")
            probe["status"] = "PASSED"
        except Exception:
            # Keep the HTTP observations, but never export exception messages.
            probe["failure"] = "quota_probe_failed"
        finally:
            probe["elapsed_ms"] = (time.perf_counter() - started) * 1000

    failed_futures = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [(probe, pool.submit(boundary, probe)) for probe in probes]
        for probe, future in futures:
            try:
                future.result(timeout=HTTP_TIMEOUT + 15)
            except Exception:
                failed_futures.append(probe)
    for probe in failed_futures:
        probe.update(status="FAILED", failure="quota_probe_worker_failed")
    require(all(probe["status"] == "PASSED" for probe in probes), "concurrent_quota_probe_failed")
    statuses = sorted(probe["steps"][0]["http_status"] for probe in probes)
    require(statuses == [200, 200, 429, 429], "incorrect_concurrent_quota_boundary")


def rate_case(source, root, key, kind, report):
    case = {"kind": kind, "status": "FAILED", "roles": []}
    report["rate_limits"].append(case)
    paths = copy_fixture(source, root)
    with servers(paths, case) as (ports, codes):
        for role in (("verifier",) if kind == "session_writes" else ROLES):
            evidence = {"role": role, "steps": []}
            case["roles"].append(evidence)
            started = time.perf_counter()
            client = login(ports[role], codes[role], evidence["steps"], role)
            if kind == "session_writes":
                for _ in range(30):
                    client.call(evidence["steps"], "write", "/api/requests", {"key_id": key})
                client.call(evidence["steps"], "write_over_limit", "/api/requests", {"key_id": key},
                            status=429, error="rate_limited")
                evidence["accepted_writes"] = 30
            else:
                # One startup config and this login already consumed two calls.
                for _ in range(116):
                    client.call(evidence["steps"], "session_read", "/api/session")
                concurrent_rate_boundary(client, evidence)
                evidence["accepted_process_calls_including_config_and_login"] = 120
            require(time.perf_counter() - started < 60, "quota_window_elapsed")
            result = client.call(evidence["steps"], "logout_after_limit", "/api/logout", {})
            require(result.get("logged_out") is True, "logout_failed")
            client.call(evidence["steps"], "logout_again", "/api/logout", {},
                        status=401, error="authentication_required")
            evidence["elapsed_ms"] = (time.perf_counter() - started) * 1000
    case["status"] = "PASSED"


def measure(report, concurrency, warmups, flows):
    report["source"] = source_state()
    report["environment"] = {
        "python": platform.python_version(), "platform": platform.platform(),
        "machine": platform.machine(), "logical_cpus": os.cpu_count(),
        "sqlite": sqlite3.sqlite_version, "anoncreds": version("anoncreds"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "checked_out_sha": os.environ.get("GITHUB_SHA"),
        "source_head_sha": os.environ.get("SOURCE_HEAD_SHA"),
        "runner_os": os.environ.get("RUNNER_OS"),
    }
    with TemporaryDirectory(prefix="zk-split-http-benchmark-") as temporary:
        root = Path(temporary)
        source = root / "source"
        key, report["fixture_setup"] = fixture(source)
        for count in concurrency:
            concurrency_case(source, root / f"c{count}", key, count, warmups, flows, report)
        for kind in ("session_writes", "process_calls"):
            rate_case(source, root / kind, key, kind, report)
    require(source_state()["sha256"] == report["source"]["sha256"], "source_changed")


def run(out, *, concurrency=(1, 2, 4), warmups=4, flows=28):
    require(type(warmups) is int and 0 <= warmups <= 4
            and type(flows) is int and 1 <= flows <= 28, "invalid_flow_counts")
    require(isinstance(concurrency, (list, tuple)) and bool(concurrency)
            and all(type(count) is int and count in (1, 2, 4) for count in concurrency)
            and len(set(concurrency)) == len(concurrency), "invalid_concurrency")
    require(all(warmups % count == 0 and flows % count == 0 for count in concurrency),
            "flows_must_fill_batches")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # Reserve before starting any service; existing files/symlinks are never replaced.
    with out.open("x", encoding="utf-8") as stream:
        report = {
            "schema_version": 1, "status": "FAILED",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "protocol": {
                "concurrency": list(concurrency), "warmup_flows": warmups,
                "measured_flows": flows, "flows_per_batch": "one per concurrent worker",
                "sessions_per_role": 4, "session_assignment": "round-robin across all flows",
                "service_day": "2030-06-01", "credential_count_per_scenario": 1,
                "wallet_processes_per_scenario": 1, "verifier_processes_per_scenario": 1,
                "http_timeout_seconds": HTTP_TIMEOUT,
                "scenario_deadline_seconds": SCENARIO_SECONDS,
                "fixture": "One issuer/key/credential setup; pristine copy and fresh processes/sessions per scenario",
                "timing": "request/review/approve/verify including HTTP, JSON, lock wait and storage",
                "excluded_from_flow_timing": ["fixture and service setup", "login", "replay", "denial"],
                "batch_timing": "barrier release through all flow results; replay starts afterward",
                "batch_rate": "Measured active batches only; excludes replay and gaps, not a sustained rate",
                "p95_method": "nearest-rank: sorted[ceil(0.95 * n) - 1]",
                "scope": "Four sessions share one synthetic account/Wallet/credential; bounded loopback batches, not sustained load or production capacity",
                "rate_limits": "Existing 30 writes/session and 120 API calls/process per rolling 60s; no overrides",
                "limits": ["one synthetic credential", "small sample counts", "no TLS or remote network",
                           "no real identity or licence-status provider", "no rate-window recovery measurement"],
            }, "scenarios": [], "rate_limits": [],
        }
        try:
            measure(report, concurrency, warmups, flows)
            report["status"] = "PASSED"
        except Exception as exc:
            report["failure"] = str(exc) if isinstance(exc, MeasurementFailure) else "measurement_exception"
            report["exception_type"] = type(exc).__name__
        finally:
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--concurrency", nargs="+", type=int, default=[1, 2, 4])
    parser.add_argument("--warmup-flows", type=int, default=4)
    parser.add_argument("--flows", type=int, default=28)
    args = parser.parse_args()
    try:
        result = run(args.out, concurrency=args.concurrency,
                     warmups=args.warmup_flows, flows=args.flows)
    except (MeasurementFailure, OSError):
        print("FAILED: invalid configuration or unavailable output", file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "scenarios": [
        {"concurrency": case["concurrency"], "summary": case.get("summary")}
        for case in result["scenarios"]]}, indent=2))
    return 0 if result["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
