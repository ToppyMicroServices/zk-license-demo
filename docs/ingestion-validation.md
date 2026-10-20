# Ingestion boundary validation

Date: 2026-10-17 (Asia/Tokyo).
Tested implementation: `247e0f6a2dfbc2834b17141fe34743d0183026f1`, [PR #5](https://github.com/ToppyMicroServices/zk-license-demo/pull/5).

| Environment | Tests | Result |
| --- | --- | --- |
| macOS arm64, Python 3.14.6 | 104 | Passed locally, 33.174 seconds |
| Ubuntu 24.04, Python 3.12 | 104 | Passed in CI, 15.186 seconds |
| Windows Server 2022, Python 3.12 | 104 | Passed in CI, 34.996 seconds |

Both `REQUIRE_CRYPTO=1` and `REQUIRE_CARD_CRYPTO=1` were set. Tests ran with
`python -W error -m unittest discover -s tests -v`. Dependencies were installed
with `--require-hashes`: anoncreds 0.2.3, cryptography 49.0.0, cffi 2.0.0 and pycparser 3.0.
The [CI run](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39038732414)
retains per-platform logs, environment and existing demo/proof artifacts for 14 days.
`git diff --check` also passed.

The added 36 tests cover RSA verification of synthetic signed regions, rejected
signature modes and untrusted keys, enrollment binding, consent, provider failure,
expiry, restart and concurrent replay. Internal review found that store reopen
skipped audience validation. The shared validation and a regression test were added
before this revision was tested. This was an internal review, not an external audit.

These results do not establish actual card-reader operation, real-card signature
compatibility, certificate provenance or rotation, identity-provider protocol
conformance, matching a real person to a licence, credential issuance, or current
suspension/cancellation status. No official keys, real personal data, licensed SDK,
provider sandbox or production endpoint was used. See the [implementation boundary](ingestion-boundary.md).

## Hosted follow-up, 2026-10-18

Implementation: `68002c12a95ea7c22956997e9a8e6cdb609ea8a7`, including merged PR #6.
[GitHub Actions run 39130582602](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39130582602)
tested merge preview `53deb967255427993f97bcd27ccbe18b0d4e6066` against main
`8c91852838e0a64cb38f8be486a9acbad83c5b15`.

| Hosted environment | Checks | Result |
| --- | --- | --- |
| Ubuntu 24.04, Python 3.12 | 136 Python tests; 5 JS state tests | Passed; Python 66.131 seconds |
| Windows Server 2022, Python 3.12 | 136 Python tests; 5 JS state tests | Passed; Python 68.510 seconds |
| Ubuntu 24.04, Chromium 156.0.8078.4 | 3 real browser scenarios | Passed; 11.276 seconds |

The matrix jobs required both cryptographic backends and treated Python warnings
as errors. Proof generation, independent verification, replay rejection and the
existing serial benchmark also completed successfully. Browser tests used
Playwright 1.64.0 and separate real Wallet/verifier HTTP processes and stores.
They covered approval/refusal after repeated clicks, closing/reopening the Wallet,
and reception logout/login, with no JavaScript page errors.

The review found that slow reader or identity adapters held a database-wide write
lock. A short persisted `processing` claim now precedes adapter I/O. Finalization
is conditional, ordinary failures permit retry, and interrupted claims remain
unavailable after reopening. New event-coordinated tests exercised both slow
adapters while another enrollment completed, plus same-request rejection.
The interruption test uses `KeyboardInterrupt` and store reopen; it is not an
OS-process crash test. Existing provider-error, binding and replay cases passed.

All tests for this follow-up ran on GitHub-hosted runners. No test, demo, build,
or browser verification ran on the user's PC. The real-card and provider limits
above remain unchanged. Logs and browser screenshots are retained by the run
for 14 days; this record preserves the tested revisions, counts and scope.

## Pre-merge review, 2026-10-19

Reviewed `8c91852838e0a64cb38f8be486a9acbad83c5b15..430efdd4104ec23e56ba406f71d8042f9f2ed5d6`.
No merge-blocking correctness issue remained. The previous write-lock finding was
fixed, and the source review covered both runtime modules, their tests, dependency
pins, CI integration and documented limits. This was an internal review.

The reviewed head passed [hosted run 39130827582](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39130827582):
136 Python and five JS tests on each platform, three Chromium scenarios, proof
and replay checks, and the serial benchmark. CodeQL checks also passed. The
subsequent access-research and Beads updates do not change executable code.
No local test was run for this review.

## OS-process termination, 2026-10-19

Implementation: `d55403f28a5a40a12e9bebf7469d3c7c5029d0c5`, [PR #7](https://github.com/ToppyMicroServices/zk-license-demo/pull/7).
[Hosted run 39252692698](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39252692698)
tested merge preview `9fc0440d08b93f91c6e0d8ceea92945411adbd98` against main
`6b79b2ac23d7753e791af590104983cbd4cab65f`.

| Hosted environment | Checks | Result |
| --- | --- | --- |
| Ubuntu 24.04, Python 3.12 | 139 Python tests; 5 JS state tests | Passed; Python 51.146 seconds |
| Windows Server 2022, Python 3.12 | 139 Python tests; 5 JS state tests | Passed; Python 65.755 seconds |
| Ubuntu 24.04, Chromium 156.0.8078.4 | 3 browser scenarios | Passed; 5.728 seconds |

The three new cases use a separate spawned process and a checkpoint before the
parent forcibly terminates it. Reader and identity-adapter checkpoints leave a
`processing` record; the checkpoint after `complete()` returns leaves a
`completed` record with its verified card digest. After termination, a new SQLite
connection reports a valid store. Reopening rejects the old request without
calling either adapter, and a fresh enrollment succeeds with fresh consent.

The observed process exit codes were -9 on Ubuntu and -15 on Windows. These are
the values reported by Python's multiprocessing API; the Windows value does not
mean a POSIX signal was delivered. Extracted checkpoint evidence and job IDs are
preserved in [enrollment-recovery-validation.json](enrollment-recovery-validation.json).
Proof generation, independent verification, replay rejection and the existing
serial benchmark also passed. No runtime code, dependency or UI was changed.

These are real OS-process termination checks with synthetic data. The checkpoints
are outside database transactions: they do not test power loss, a crash during
SQLite writes, real-provider reconciliation, issuance atomicity or production
recovery. All execution took place on GitHub-hosted runners; no test, build, demo
or browser execution used the user's PC. Beads `zkl-0wc` records this bounded
validation; `zkl-9w9` remains open.

## Dependency update, reviewed 2026-10-21

Implementation: `8f2a74caa4368e66298a6715b5fc589836dd6e63`, [PR #8](https://github.com/ToppyMicroServices/zk-license-demo/pull/8).
[Hosted run 39272174431](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39272174431)
tested merge preview `043dbd185a2fba9fd79331466c63d7d5949ec098` against main
`da32d08922f34f274398395e1755d7afcaa3adbb`.

| Hosted environment | Checks | Result |
| --- | --- | --- |
| Ubuntu 24.04, Python 3.12.15 | 139 Python tests; 5 JS state tests | Passed; Python 55.838 seconds |
| Windows Server 2022, Python 3.12.10 | 139 Python tests; 5 JS state tests | Passed; Python 76.132 seconds |
| Ubuntu 24.04, Chromium 156.0.8078.4 | 3 browser scenarios | Passed; 6.092 seconds |

Both matrix jobs installed cryptography 50.0.2, cffi 2.0.0, pycparser 3.0 and
anoncreds 0.2.3 with `--require-hashes`. Their environment records now include the
optional backend versions in both logs and artifacts. Both cryptographic backends
were required, and Python warnings remained errors. Proof generation, independent
verification, replay rejection and the serial benchmark also passed.

The browser job used Playwright 1.64.0 and the existing AnonCreds dependencies;
it checks UI regression, not the optional card-signature backend. These results
do not establish macOS compatibility for this update or real-card compatibility.
No test, dependency installation, build, demo or browser execution used the user's PC.
