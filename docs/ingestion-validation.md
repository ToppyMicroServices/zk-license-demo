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
