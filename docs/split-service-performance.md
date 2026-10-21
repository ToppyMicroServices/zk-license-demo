# Concurrent split Web validation

This checks the existing synthetic demo over loopback HTTP. It does not establish
production capacity, availability, independent-user isolation or real-provider
performance. Beads `zkl-tyl` tracks this bounded part of `zkl-9w9`.

## Protocol

The GitHub-hosted Ubuntu and Windows jobs run:

```bash
python -W error split_benchmark.py --out artifacts/validation/split-benchmark.json
```

Each concurrency condition (1, 2 and 4) starts separate Wallet and verifier
processes with fresh state copied from the same synthetic fixture. Four session
pairs share one Wallet, one credential and one verifier. They are not four
independent people or Wallet stores. Issuer setup, issuance, service startup and
login are outside flow timing.

Four warmup flows precede 28 measured flows per condition. Batches start together
at the selected concurrency; each session handles eight approvals across warmup
and measurement. Each flow creates a request, reviews it in the Wallet, approves
sharing and verifies the resulting real AnonCreds proof through HTTP. Timing
includes HTTP connections, JSON transfer, application locks, SQLite and crypto.
Every proof is then resubmitted and must fail with `409 already_used`. Replay is
outside the flow latency and finishes before the next batch starts.

After the approval measurements, each session declines a fresh request. The
response must contain no presentation, and a later approval of that request must
be rejected. Separate fresh-service scenarios check the existing session/process
quotas, `429 rate_limited`, `Retry-After: 60`, and logout while the quota is full.
For the process quota, four concurrent calls compete for two remaining slots;
exactly two must succeed and two must be rate limited. A second logout must
report that the session is no longer authenticated.
The native limits are not raised or mocked. Recovery after the 60-second window
is not measured.

The report retains raw timings, expected HTTP results, setup costs, source hashes,
runner versions, process IDs and the exact revision. It excludes login codes,
Bearer tokens, proofs, request bodies and databases. An unexpected result fails
the run; a failed report is not a successful performance measurement. Existing
output files are not overwritten.

## Interpretation

The application holds a lock for each role while processing an API call,
including cryptographic work. More concurrent clients can therefore increase
queueing; this experiment does not measure parallel crypto within either role.
The eight-connection acceptance limit is not saturated by these four clients.
All processes and the load driver share one runner and its loopback network.

With 28 observations, nearest-rank p95 is the 27th sorted value. These short,
synchronized batches do not establish sustained throughput or stable tail
latency. Batch completion rates exclude replay traffic and gaps between batches;
the report also retains the full scenario duration. The existing 120 API
calls/minute and 30 session writes/minute remain part of the demo. Different
runner hardware and software prevent attributing
Windows/Ubuntu differences solely to the OS.

## Hosted results, 2026-10-21

[Run 39522559331](https://github.com/ToppyMicroServices/zk-license-demo/actions/runs/39522559331)
tested source head `c5633efec62f576156af5a10f92c2d7c4da95340` as merge preview
`bd4be4263d7b3a316fa9e5da43965fcfed713529` against main
`19fe0c9aa0593d2d244d06858e957d7004982669` in [PR #9](https://github.com/ToppyMicroServices/zk-license-demo/pull/9).

Each row contains 28 measured flows after four warmups. Times are milliseconds
from request creation through the first successful verification.

| Hosted environment | Concurrency | Median | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Ubuntu 24.04, Python 3.12.15 | 1 | 292.05 | 295.23 | 296.81 |
| Ubuntu 24.04, Python 3.12.15 | 2 | 367.18 | 442.06 | 443.68 |
| Ubuntu 24.04, Python 3.12.15 | 4 | 529.72 | 743.07 | 752.56 |
| Windows Server 2022, Python 3.12.10 | 1 | 324.01 | 351.74 | 364.89 |
| Windows Server 2022, Python 3.12.10 | 2 | 471.17 | 563.05 | 590.20 |
| Windows Server 2022, Python 3.12.10 | 4 | 655.34 | 944.66 | 963.65 |

Both jobs used four logical CPUs and AnonCreds 0.2.3. SQLite was 3.45.1 on Ubuntu
and 3.49.1 on Windows. All measured and warmup approvals passed, every replay
was rejected, and all 12 denials per OS produced no presentation. The write
quota rejected request 31 after 30 accepted writes. Both roles enforced the
two-remaining-slot concurrent boundary and allowed logout, then rejected a
second logout. No timing threshold was used to label these results successful.

The same run passed 143 Python tests on Ubuntu (56.304 seconds) and Windows
(38.426 seconds), five JS state tests on each, and three Chromium scenarios
(7.621 seconds). Proof/replay checks, the serial benchmark and CodeQL also passed.
An internal review found missing evidence when a concurrent quota probe failed;
the helper now preserves all four observations before reporting failure, with a
regression test. This is internal review and regression evidence, not an audit.

The unmodified [Ubuntu report](evidence/2026-10-21-split-load/ubuntu.json) and
[Windows report](evidence/2026-10-21-split-load/windows.json) retain raw samples,
warmups, setup costs, per-step times, process IDs and source byte hashes.
[Artifact metadata](evidence/2026-10-21-split-load/artifacts.json) and the
[evidence manifest](evidence/2026-10-21-split-load/manifest.json) retain provenance
after the hosted artifacts expire. The downloaded ZIP hashes matched the hashes
returned by GitHub. Windows source hashes reflect its checkout line endings.
No test, package installation, demo, build or browser execution for this task
used the user's PC.
