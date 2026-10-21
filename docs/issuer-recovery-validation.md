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
checkpoints are created. The child sets a one-page cache target with spilling
enabled before each real UPDATE. The test requires changed database-file bytes
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

Hosted execution is pending. No test, installation, demo, build or browser
execution for this work has used the user's PC. Ubuntu and Windows run the new
cases through the existing CI test discovery; runtime code and dependencies
are unchanged.

The retained evidence will identify each checkpoint, process exit code, journal
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
