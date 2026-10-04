# Validation record

Updated: 2026-10-04. The current result is a local macOS run, not a CI result or a production audit.

## Current execution

- macOS 26.7.1, ARM64, Python 3.14.6, AnonCreds 0.2.3.
- The official macOS universal2 wheel was downloaded and installed with `--require-hashes`.
  Its SHA-256 is `9bc5d6f4404f611e8ad74801fcf1aa05bf4307831edf18bfd9438d811df053fc`, matching [PyPI](https://pypi.org/project/anoncreds/0.2.3/).
- All 46 tests passed: 30 policy/input/state tests and 16 real-crypto integration tests. None were skipped.
  `REQUIRE_CRYPTO=1` was set, and warnings were treated as errors.
- Real credential issuance, proof generation and verification succeeded.
- A separate CLI process accepted the presentation. Its next invocation refused it with `already_used`.
- `pip check` and `bash -n publish.sh` passed.

The first real-crypto run exposed two failures in the prepared sample: proofs of weaker entitlement and expiry
thresholds were accepted against the intended request. The verifier now compares the embedded predicate names,
operators and thresholds with its stored policy before calling the backend. The original rejection tests pass,
as do added tests for altered attributes/operators and for relabelling weaker proofs to the expected thresholds.
Relabelling still fails cryptographic verification.

The version-pinned [upstream verifier](https://github.com/anoncreds/anoncreds-rs/blob/v0.2.3/src/services/verifier.rs)
builds its CL sub-proof request from `sub_proof.predicates()`. The local rejection tests establish why this
sample needs the explicit policy comparison; this is not a claim about all AnonCreds implementations or versions.

## Evidence

- [Full test log](test-release.log)
- [Local release gate log](release-gate-current.log)
- [QA report and artifact hashes](qa-report.json)
- [Machine-readable status](validation.json)
- [Source hashes](source-sha256.json)

The final demonstration is in `artifacts/final-run/`. These ignored local files include the HTML/JSON report,
public presentation and synthetic verifier provisioning. Their request has already been consumed;
run the demo in a new output directory for another independent verification.

One illustrative run measured proof generation at 95.513 ms, verification including state handling at 92.504 ms,
and a compact presentation JSON size of 31,736 bytes. These are one local sample, not a benchmark.
Issuer key generation took 8,654.065 ms and is recorded separately.

## Publication and limits

GitHub authentication and active admin membership in `ToppyMicroServices` were confirmed in the current environment.
The proposed repository lookup did not resolve. No public repository or CI run has been created in this session.
LinkedIn and the article remain drafts pending a public URL and the owner's wording review.

Windows and Linux real-crypto execution remain unverified. Python 3.12 on Ubuntu is configured for CI but has not run.
An independent security audit, production deployment, Japanese driving-licence signature integration,
revocation checking and real-person authentication are not established.

## Preparation history

The original isolated Linux preparation environment ran 30 non-crypto tests on Python 3.13.5.
The original 12-test crypto class was skipped because the backend could not be downloaded.
Release mode and the demo failed closed. Those historical logs remain in `test-policy.log` and `release-gate.log`;
the original status is retained under `preparation_record` in `validation.json`.

A preparation-time GitHub write attempt against an existing site repository returned
`403: Resource not accessible by integration`. It created no branch, commit, PR, deployment or LinkedIn post.
That earlier connection failure is separate from the current authenticated local environment.
