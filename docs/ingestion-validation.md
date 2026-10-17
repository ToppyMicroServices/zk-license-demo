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
