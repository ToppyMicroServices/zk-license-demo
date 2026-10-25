# Independent review handoff

Prepared 2026-10-25 for Beads `zkl-e86`. This document defines a proposed review;
no external reviewer has been commissioned and no independent audit result is
recorded. Internal reviews and passing tests do not satisfy that requirement.

## Baseline and evidence

Review the immutable source snapshot
[`109510dcf003d89f0b24daf0720e163a9aee830e`](https://github.com/ToppyMicroServices/zk-license-demo/tree/109510dcf003d89f0b24daf0720e163a9aee830e).
[Hosted run 40158040530](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/40158040530)
is the validation reference for that revision. Keep the source SHA with any
findings; later changes need their own review or an explicit comparison.

Start with the [threat model](threat-model.md) and the
[separate Wallet design](split-wallet.md). Existing evidence includes
[browser communication and consent](split-web-validation.md),
[ingestion and enrollment recovery](ingestion-validation.md),
[issuer transaction recovery](issuer-recovery-validation.md), and
[bounded concurrent HTTP measurements](split-service-performance.md).
Those records identify their own tested revisions and limits; older evidence
must not be relabelled as execution of this baseline.

Any new execution must use GitHub-hosted runners, not the user's PC. The existing
workflow is `.github/workflows/test.yml`; it covers Ubuntu and Windows Python
tests and separate Ubuntu Chromium scenarios. Use synthetic inputs only. Retain
the reviewed SHA, runner details, commands, results and sanitized reproduction
evidence. Do not publish credentials, private stores, tokens or real personal data.

## Proposed scope

Review whether the implementation enforces its stated boundaries under malformed
input, changed requests, concurrent calls and interrupted operations. Check both
acceptance and rejection paths; do not infer a security property from a test name.

| Area | Source and existing regression coverage | Review question |
| --- | --- | --- |
| Proof and request binding | `zk_license.py`, `request_store.py`; `tests/test_crypto.py`, `tests/test_policy.py` | Are the issuer, exact predicates, audience, session and deadline checked against stored policy, with single-use acceptance? |
| HTTP and browser consent | `service.py`, `split_service.py`, `web/app.js`, `split_web/verifier.js`, `split_web/wallet.js`; `tests/test_service.py`, `tests/test_split_service.py`, `tests/test_split_web.mjs`, `tests/browser_split_web.py` | Do ownership, origin, session and request checks preserve approval or refusal through repeated clicks, replacement and reconnection? Distinguish mocked JS tests from browser execution. |
| Wallet and issuer lifecycle | `split_wallet.py`, `lifecycle.py`; `tests/test_split_wallet.py`, `tests/test_issuer_crash.py` | Can private holder material reach the verifier, or stale state undo revocation, reuse an issued index or bypass the stored review? Check restore assumptions and the actual process-kill checkpoints. |
| Experimental ingestion | `card_signature.py`, `enrollment_gate.py`; `tests/test_card_signature.py`, `tests/test_enrollment_gate.py`, `tests/test_enrollment_crash.py` | Are trusted keys and exact signed bytes bound to the account, Wallet request, consent and identity-adapter result? Do missing providers and interrupted claims fail closed? |

## Limits and requested result

The target is the synthetic demo and experimental adapter boundary. Real-card
compatibility, official key provenance, real identity matching and administrative
driving-entitlement status remain unresolved in the
[integration record](real-license-integration.md). Synthetic revocation is not a
live licence-status check.

This scope does not commission a new proof of the underlying cryptography or
approve production deployment. Plaintext storage, trusted local registry
provisioning, lack of OS isolation and production authentication are documented
limits. Process-kill evidence does not establish power-loss, disk-loss or
COMMIT-internal recovery. Review whether claims stay within these limits; report
additional reachable defects separately from already disclosed exclusions.

The requested report should identify the reviewer and their independence from
the implementation, the exact revision and scope, and any unexamined areas.
For each finding, include the affected location, preconditions, reproduction
evidence, impact and severity rationale. Record remediation and retest revisions
separately. A no-findings result must still state its coverage and limits.

Keep `zkl-e86` open until an independent result is recorded or the owner explicitly
decides to defer it. Preparing this handoff does not close the task or the
production-readiness task `zkl-9w9`.
