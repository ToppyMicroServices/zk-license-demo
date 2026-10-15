# Demo validation and performance

Measured on 2026-10-15 at commit `78ba7d16f353cb7518edd74f71ce3f864512e699`.
All measurements use the real AnonCreds 0.2.3 backend and synthetic attributes.

## Validation

All 50 tests passed without skips on macOS 26.7.1 ARM64 / Python 3.14.6,
Ubuntu 24.04 x64 / Python 3.12.15, and Windows Server 2022 x64 / Python 3.12.10.
The 16 real-crypto tests are unchanged; four benchmark tests were added to the
30 existing policy/input/state tests.

[CI run 38671009097](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/38671009097)
also passed standalone proof generation, independent CLI verification and replay
rejection on both Ubuntu and Windows. Windows used Git Bash. Windows desktop,
Windows ARM and the PowerShell setup instructions were not separately tested.

Local checks passed: the 50-test suite with `REQUIRE_CRYPTO=1` and warnings as
errors, `pip check`, `bash -n publish.sh`, `actionlint` and `git diff --check`.

## Measurement method

```bash
python benchmark.py --runs 30 --warmups 3 --out artifacts/benchmark.json
```

One issuer key and one credential are created per run. Their setup times are
reported separately. Each iteration creates a fresh request and proof, verifies
it through `RequestStore.consume`, and checks that a second submission is rejected
with `already_used`. The first three iterations are warmups and excluded from
the summary. Their raw values are retained alongside the 30 measured iterations.

Proof timing covers `make_presentation`. Verification timing covers the SQLite
connection, transaction, stored-request checks, cryptographic verification and
commit. It excludes request insertion. JSON serialization and the replay check
are outside both timers. The same temporary database accumulates the requests;
it is deleted after the run. No credential, secret or proof body is exported by
the benchmark.

p95 uses the nearest-rank rule: sort the 30 observations and take the 29th.
The code and dependency hashes identify the measured sources. Windows checkout
uses CRLF; its recorded byte hashes were checked against CRLF versions of the
same source files. The other environments use LF.

## Results

Times are milliseconds. Each row is one serial run of 30 observations after warmup.

| Environment | Proof median | Proof p95 | Verification median | Verification p95 | Proof JSON median, bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| macOS ARM64, local | 93.05 | 96.42 | 91.55 | 95.96 | 31,756 |
| Ubuntu 24.04 x64, CI | 121.24 | 122.36 | 120.21 | 122.84 | 31,754.5 |
| Windows Server 2022 x64, CI | 107.45 | 108.06 | 129.75 | 299.68 | 31,749 |

Issuer setup took 816.87 ms, 3,040.25 ms and 3,323.20 ms respectively. Credential
issuance took 86.81 ms, 114.11 ms and 96.02 ms. These are single setup samples,
not estimates of typical setup latency.

Windows verification reached a maximum of 402.44 ms. This path includes SQLite
and filesystem work; the cause of the longer observations was not isolated.
Hardware, Python and SQLite versions differ across environments, so the table
does not measure an OS-only performance effect. Thirty observations from one
credential and one run do not establish stable tail latency or production
throughput. This is a serial microbenchmark, not a concurrent service load test.

## Retained evidence

- [macOS measurements](evidence/2026-10-15/benchmark-macos.json)
- [Ubuntu measurements](evidence/2026-10-15/benchmark-ubuntu.json)
- [Windows measurements](evidence/2026-10-15/benchmark-windows.json)
- [Checks and SHA-256 manifest](evidence/2026-10-15/qa-report.json)
- [CI job results](evidence/2026-10-15/ci-run.json)

The same directory contains test logs for all three environments, independent
verification and replay logs for CI, and the artifact metadata. The raw samples,
warmup exclusion, median/p95 calculations, source hashes and acceptance/replay
results were checked after downloading the CI artifacts. Those checks exited 0.
CI artifact retention is 14 days; the selected evidence is also retained in Git.

The workflow uses the standard [GitHub runner labels](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)
and [artifact uploads](https://github.com/actions/upload-artifact).
