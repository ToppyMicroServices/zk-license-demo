#!/usr/bin/env bash
# Explicitly creates a PUBLIC repository, only after all real-crypto tests pass.
# Run from this standalone directory. Does not change any existing repository.
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ -e .git ]]; then
  echo 'Refusing to publish from an existing Git repository. Use a fresh extracted copy.' >&2
  exit 1
fi
command -v gh >/dev/null || { echo 'GitHub CLI (gh) is required.' >&2; exit 1; }
gh auth status
export REQUIRE_CRYPTO=1
python -W error -m unittest discover -s tests -v
out="artifacts/prepublish-$(date +%Y%m%d%H%M%S)"
python demo.py run --out "$out"
python demo.py verify --out "$out"
if python demo.py verify --out "$out" 2>"$out/replay-error.txt"; then
  echo 'Refusing to publish: replay was accepted.' >&2
  exit 1
fi
grep -q already_used "$out/replay-error.txt"
git init -b main
git add -- .gitignore .github README.md LICENSE requirements.txt request_store.py zk_license.py demo.py tests docs publish.sh
git commit -m 'feat(demo): add synthetic license proofs and rejection tests'
gh repo create ToppyMicroServices/zk-license-demo --public --source=. --remote=origin --push
