#!/usr/bin/env python3
"""Measure serial synthetic proofs with the real backend and fresh requests."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import math
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter

from request_store import Challenge, Rejected, RequestStore
from zk_license import issue_demo, make_issuer, make_presentation, verify_presentation

ROOT = Path(__file__).resolve().parent
SOURCE_FILES = ("benchmark.py", "demo.py", "request_store.py", "zk_license.py", "requirements.txt")


def summarize(values: list[float]) -> dict:
    if not values or any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("Measurements must be finite, nonnegative and nonempty")
    ordered = sorted(values)
    return {"count": len(values), "min": min(values), "median": statistics.median(values),
            "p95": ordered[math.ceil(0.95 * len(values)) - 1], "max": max(values),
            "mean": statistics.mean(values)}


def source_state() -> dict:
    state = {"sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                        for name in SOURCE_FILES}, "git_commit": None, "source_dirty": None}
    try:
        state["git_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        state["source_dirty"] = bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--", *SOURCE_FILES], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL).strip())
    except (OSError, subprocess.CalledProcessError):
        pass  # An extracted source archive still has exact source hashes.
    return state


def measure(runs: int, warmups: int, service_day: str) -> dict:
    provenance = source_state()
    started_at = datetime.now(timezone.utc).isoformat()
    start = perf_counter()
    issuer = make_issuer()
    setup_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    holder = issue_demo(issuer)
    issuance_ms = (perf_counter() - start) * 1000
    samples, warmup_samples = [], []
    with TemporaryDirectory(prefix="zk-license-benchmark-") as tmp:
        store = RequestStore(Path(tmp) / "requests.sqlite3")
        for index in range(warmups + runs):
            challenge = Challenge.new(audience="https://benchmark.example",
                                      session="synthetic-benchmark", service_day=service_day)
            store.add(challenge)
            start = perf_counter()
            proof = make_presentation(holder, challenge, issuer.trust)
            proof_ms = (perf_counter() - start) * 1000
            start = perf_counter()
            store.consume(challenge.request_id, audience=challenge.audience, session=challenge.session,
                          verify=lambda req: verify_presentation(proof, req, issuer.trust))
            verify_ms = (perf_counter() - start) * 1000
            try:
                store.consume(challenge.request_id, audience=challenge.audience, session=challenge.session,
                              verify=lambda req: verify_presentation(proof, req, issuer.trust))
            except Rejected as exc:
                if str(exc) != "already_used":
                    raise
            else:
                raise RuntimeError("Benchmark replay was accepted")
            sample = {"iteration": index + 1, "proof_ms": proof_ms,
                      "verify_with_state_ms": verify_ms,
                      "proof_json_bytes": len(json.dumps(proof, separators=(",", ":")).encode()),
                      "accepted": True, "replay": "already_used"}
            (warmup_samples if index < warmups else samples).append(sample)
    if source_state()["sha256"] != provenance["sha256"]:
        raise RuntimeError("Source files changed during measurement")
    return {
        "schema_version": 1, "status": "PASSED", "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "machine": platform.machine(), "processor": platform.processor(),
                        "logical_cpus": os.cpu_count(), "sqlite": sqlite3.sqlite_version,
                        "anoncreds": version("anoncreds")},
        "source": provenance,
        "protocol": {"runs": runs, "warmups": warmups, "service_day": service_day,
                     "concurrency": 1, "issuer_count": 1, "credential_count": 1,
                     "p95_method": "nearest-rank: sorted[ceil(0.95 * n) - 1]",
                     "verification": "RequestStore.consume including SQLite transaction and crypto",
                     "excluded_from_iteration_timing": ["issuer setup", "credential issuance",
                         "challenge creation and insertion", "JSON serialization", "replay check"],
                     "scope": "Serial local microbenchmark; not service load or production throughput"},
        "setup_ms": setup_ms, "issuance_ms": issuance_ms,
        "summary": {name: summarize([sample[name] for sample in samples])
                    for name in ("proof_ms", "verify_with_state_ms", "proof_json_bytes")},
        "warmup_samples": warmup_samples, "samples": samples,
    }


def run(out: Path, *, runs: int = 30, warmups: int = 3, service_day: str = "2030-06-01") -> dict:
    if type(runs) is not int or not 1 <= runs <= 1000:
        raise ValueError("runs must be an integer between 1 and 1000")
    if type(warmups) is not int or not 0 <= warmups <= 100:
        raise ValueError("warmups must be an integer between 0 and 100")
    # Refuse before key generation; never replace existing evidence.
    if out.exists() or out.is_symlink():
        raise FileExistsError(f"Output already exists: {out}")
    result = measure(runs, warmups, service_day)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--day", default="2030-06-01")
    args = parser.parse_args()
    try:
        result = run(args.out, runs=args.runs, warmups=args.warmups, service_day=args.day)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result["summary"], indent=2))
    print(f"Evidence: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
