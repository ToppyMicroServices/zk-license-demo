#!/usr/bin/env python3
"""Measure the compiled demo process; never include the Go compiler in RSS."""

import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if sys.platform not in ("darwin", "linux"):
        parser.error("RSS units are implemented only for macOS and Linux")
    binary = args.binary.resolve(strict=True)
    output = args.out.resolve()
    if output.exists():
        parser.error("output directory must be new")
    started = time.perf_counter()
    result = subprocess.run(
        [str(binary), "demo", "-out", str(output), "-runs", str(args.runs)],
        capture_output=True, text=True, check=False,
    )
    elapsed = time.perf_counter() - started
    if result.returncode != 0:
        print(json.dumps({"status": "failed", "exit_code": result.returncode}),
              file=sys.stderr)
        return 1
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    rss_bytes = usage.ru_maxrss * (1024 if sys.platform == "linux" else 1)
    module = Path(__file__).resolve().parents[1]
    sources = sorted(module.glob("*.go")) + sorted(module.glob("cmd/**/*.go"))
    sources += [module / "go.mod", module / "go.sum", Path(__file__).resolve()]
    measurements = {
        "status": "passed",
        "method": "resource.getrusage(RUSAGE_CHILDREN); one compiled child process",
        "platform": sys.platform,
        "elapsed_seconds": elapsed,
        "peak_rss_bytes": rss_bytes,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "source_sha256": {
            str(path.relative_to(module)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources
        },
    }
    with (output / "resources.json").open("x") as file:
        json.dump(measurements, file, indent=2)
        file.write("\n")
    print(json.dumps(measurements))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
