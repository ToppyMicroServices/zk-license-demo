# Issuer transaction recovery validation

Beads `zkl-1i3` tracks a bounded part of `zkl-9w9`: terminating a process during
synthetic credential issuance and checking the surviving issuer and public
SQLite stores. The existing exception test raises before either SQL update;
the new cases reach the real database writes.

## Protocol

A spawned child calls the existing issuance function with a real AnonCreds
credential request. Test-only instrumentation pauses it after the private-store
UPDATE, after the public-store UPDATE but before COMMIT, or after issuance has
committed. The parent verifies the checkpoint and child PID, then forcibly
terminates the child. It does not release an ordinary exception path.

Each fixture state includes 256 KiB of inert padding, added before Wallet trust
checkpoints are created. Before each real UPDATE the child changes that test-only
padding from `x` to `y` and sets a one-page cache target with spilling enabled.
The test requires changed database-file bytes
and a rollback journal with a valid header and page record at each uncommitted
save checkpoint. These are test-only conditions for observing writes before
COMMIT, not the application's default cache or data-size configuration.

The uncommitted cases must recover both stores to their full pre-issuance state.
The committed case must retain the consumed offer and exactly one increment of
the credential index and registry revision. Retrying that offer must fail.
Subsequent issuance, proof verification and replay rejection must work without
reusing an index that was committed before termination.

Recovery uses a fresh writable SQLite connection and attaches the public store.
Both stores must pass `PRAGMA integrity_check`. This is an explicit recovery
step: opening a database read-only can fail when a hot journal needs recovery.
It does not establish that a Wallet or verifier can repair the stores on startup.
SQLite documents [cache spill and multi-file commits](https://www.sqlite.org/atomiccommit.html)
and the [read-only recovery error](https://www.sqlite.org/rescode.html#readonly_rollback).

## Evidence and limits

[Hosted run 39584906748](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39584906748)
passed source `a25dc3c986b1630b4c5da642ab0070653b08df10`, checked out as merge
preview `d83b70f83a277147fd18bb6a9a3a867fc880902b` against main
`d88d4313f90f2532c83d8422ccd1f99a5c13cc9e` in [PR #10](https://github.com/ToppyMicroServices/zk-license-demo/pull/10).

| Hosted environment | Checks | Result |
| --- | --- | --- |
| Ubuntu 24.04, Python 3.12.15, SQLite 3.45.1 | 146 Python tests; 5 JS tests | Passed; Python 69.383 seconds |
| Windows Server 2022, Python 3.12.10, SQLite 3.49.1 | 146 Python tests; 5 JS tests | Passed; Python 97.327 seconds |
| Ubuntu, Chromium | 3 browser scenarios | Passed; 9.046 seconds |

Both OS jobs completed all three termination cases. The first-save case retained
an issuer journal; the second-save case retained journals for both databases.
The saved stores returned to their full baseline state in both uncommitted
cases. The committed case had no remaining rollback journals and rejected the
old enrollment. Fresh issuance used index 2, with proof acceptance and replay
rejection in every case. Both databases passed their integrity checks. Process
exit codes were -9 on Ubuntu and -15 on Windows; the latter is Python's reported
Windows termination code, not a POSIX signal.

The same run passed the existing proof/replay checks and serial/concurrent
measurements. CodeQL also passed. Raw [Ubuntu test logs](evidence/2026-10-21-issuer-recovery/ubuntu-tests.log),
[Windows test logs](evidence/2026-10-21-issuer-recovery/windows-tests.log), environments,
[artifact metadata](evidence/2026-10-21-issuer-recovery/artifacts.json) and an
[extracted evidence manifest](evidence/2026-10-21-issuer-recovery/manifest.json)
are retained in the repository. The downloaded archive hashes matched GitHub's
artifact digests. The manifest records the retained files' SHA-256 hashes.
No test, installation, demo, build or browser execution used the user's PC.
Runtime code, dependencies and default cache settings are unchanged.

The initial [hosted attempt](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39584401882)
at `c8ab08fb618ed0310d73290d6d661c6d1e2ecfa3` failed the file-change assertion in
the second-save case on both systems. Fixed padding and a small cache did not
establish writes to both database files before COMMIT. The other two cases
passed. The fixture now changes the padding during each save, retains the write
assertions, and emits sanitized checkpoint observations before assertions so a
failure preserves its evidence. This initial run does not establish recovery
success at the second-save checkpoint.

The retained evidence identifies each checkpoint, process exit code, journal
observations and recovered state. Private database snapshots, keys, credentials
and proofs must not enter the evidence or repository. Changed file bytes and
journal records show writes visible to this process; they do not prove that a
device's volatile write cache was flushed.

These cases use one local filesystem and synthetic credentials. They do not
cover a kill inside SQLite's COMMIT, power loss, device write-cache behavior,
filesystem corruption, network storage, loss of the public registry, or
reconciliation with a real provider. In the committed case the credential result
can be lost with the process; the consumed offer cannot be retried, so a fresh
offer is required. This is regression evidence, not production recovery approval.

## Merge review, 2026-10-25

Reviewed `d88d4313f90f2532c83d8422ccd1f99a5c13cc9e..4e64930b9d468f078794aa4aa9104fc8f6e19c7f`.
No blocking correctness finding remained. Source review covered the real issuance
path, child termination and cleanup, in-place recovery, index/offer checks and
the documented limits. Retained log hashes, checkpoint records and test counts
matched the evidence manifest. This was internal review, not an external audit.

The final PR head passed [hosted run 39585644108](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39585644108):
146 Python tests on Ubuntu (48.357 seconds) and Windows (77.209 seconds), five
JS tests on each, and three Chromium scenarios (12.239 seconds). Proof/replay
checks, serial/concurrent measurements and CodeQL passed. No local test,
installation, build, demo or browser execution was performed for this review.

[PR #10](https://github.com/ToppyMicroServices/zk-license-demo/pull/10) merged as
`7691cebe6841550d5ab14d6fb3323618dadc7752`. The production and real-provider limits
above remain unchanged.
