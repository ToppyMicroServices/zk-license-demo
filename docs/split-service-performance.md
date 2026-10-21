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
latency. The existing 120 API calls/minute and 30 session writes/minute remain
part of the demo. Different runner hardware and software prevent attributing
Windows/Ubuntu differences solely to the OS.

Hosted results will be recorded here after execution. No test, package install,
demo, build or browser execution for this task uses the user's PC.
