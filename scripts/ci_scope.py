#!/usr/bin/env python3
"""Select existing checks from changed paths; unknown inputs run all checks."""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ("js", "browser", "proof", "serial", "concurrent")
CORE = {"test_policy", "test_crypto", "test_service", "test_split_wallet",
        "test_issuer_crash", "test_split_service", "test_benchmark", "test_split_benchmark"}
SPLIT = {"test_split_wallet", "test_issuer_crash", "test_split_service", "test_split_benchmark"}
ENROLLMENT = {"test_enrollment_gate", "test_enrollment_crash"}

# Include subprocess entry points and shared fixtures, not only Python imports.
RULES = {
    "card_signature.py": (ENROLLMENT | {"test_card_signature"}, ()),
    "enrollment_gate.py": (ENROLLMENT, ()),
    "request_store.py": (CORE, ("browser", "proof", "serial", "concurrent")),
    "zk_license.py": (CORE, ("browser", "proof", "serial", "concurrent")),
    "demo.py": ({"test_policy", "test_crypto"}, ("proof", "serial")),
    "benchmark.py": ({"test_benchmark", "test_split_benchmark"}, ("serial", "concurrent")),
    "split_benchmark.py": ({"test_split_benchmark"}, ("concurrent",)),
    "lifecycle.py": (SPLIT, ("browser", "concurrent")),
    "split_wallet.py": (SPLIT, ("browser", "concurrent")),
    "split_demo.py": ({"test_split_wallet"}, ()),
    "service.py": ({"test_service", "test_split_service", "test_split_benchmark"},
                   ("browser", "concurrent")),
    "split_service.py": ({"test_split_service", "test_split_benchmark"},
                         ("browser", "concurrent")),
    "tests/browser_split_web.py": (set(), ("browser",)),
    "tests/test_split_web.mjs": (set(), ("js",)),
}


def test_modules(root):
    return {path.stem for path in (root / "tests").glob("test_*.py")
            if re.fullmatch(r"test_[A-Za-z0-9_]+", path.stem)}


def select_scope(paths, root=ROOT):
    available = test_modules(root)
    selected, flags = set(), set()
    if paths is None:
        selected, flags = available, set(FLAGS)
    else:
        for name in paths:
            path = Path(name)
            if (name.startswith(("docs/", ".beads/")) or name == ".gitignore"
                    or (len(path.parts) == 1 and path.suffix.lower() == ".md")):
                continue
            if name in RULES:
                tests, checks = RULES[name]
                selected.update(tests)
                flags.update(checks)
            elif (path.parent == Path("tests") and path.suffix == ".py"
                  and path.stem in available):
                selected.add(path.stem)
                if path.stem == "test_enrollment_gate":
                    selected.add("test_enrollment_crash")
            elif name.startswith("split_web/"):
                selected.add("test_split_service")
                flags.add("browser")
                if path.suffix == ".js":
                    flags.add("js")
            elif name in ("web/brand.css", "web/toppy-logo.png"):
                selected.update(("test_service", "test_split_service"))
                flags.add("browser")
            elif name.startswith("web/"):
                selected.add("test_service")
            else:
                # Includes dependencies, workflows, this selector, deleted tests,
                # new runtime files and unrecognised configuration.
                selected, flags = available, set(FLAGS)
                break
    output = {flag: str(flag in flags).lower() for flag in FLAGS}
    output["tests"] = " ".join(sorted(selected))
    output["python"] = str(bool(selected or flags & {"proof", "serial", "concurrent"})).lower()
    return output


def changed_paths(base, root=ROOT):
    if not base or not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", base) or not int(base, 16):
        return None
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--no-renames", "-z", base, "HEAD"],
            cwd=root, check=True, capture_output=True, timeout=30)
        return [name.decode("utf-8") for name in result.stdout.split(b"\0") if name]
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="Previous main commit or PR merge-base SHA")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args(argv)
    output = select_scope(None if args.full else changed_paths(args.base))
    lines = "".join(f"{key}={value}\n" for key, value in output.items())
    print(lines, end="")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(lines)


if __name__ == "__main__":
    main()
