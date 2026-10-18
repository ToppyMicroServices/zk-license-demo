# Local synthetic wallet and API

Run `python service.py` after installing the existing pinned requirements. Open
the printed `http://127.0.0.1:8765` URL and enter the random code printed in that
terminal. `--port 0` selects an unused port. No additional dependency is needed.

The Japanese screen supports login, request review, explicit approval or refusal,
and real AnonCreds proof generation and verification. The account and credential
are synthetic. The service date is fixed at 2030-06-01 and the credential expiry
at 2031-12-31, as in the CLI. They are explanatory dates.

## API contract

All POSTs require `Origin` equal to the printed origin, `Content-Type:
application/json`, and a JSON object. Except login, they also require the session
cookie and the `X-CSRF-Token` returned by login or `/api/session`. GET API routes
require the cookie. The exact `Host` must match the printed address, including
the port. API clients must send these headers too; there is no CORS allowance.

| Method and path | Body | Result |
| --- | --- | --- |
| POST `/api/login` | `{"code":"<terminal code>"}` | New cookie, CSRF token, synthetic account |
| GET `/api/session` | — | Account, CSRF token, remaining session lifetime |
| POST `/api/requests` | `{}` | Server-owned request and its SHA-256 hash |
| GET `/api/requests/<id>` | — | Owned request and current consent state |
| POST `/api/requests/<id>/consent` | `{"decision":"approve","request_hash":"<displayed hash>"}` or decision `deny` | Recorded decision |
| POST `/api/requests/<id>/presentation` | `{}` | `{request_id, presentation}` with real proof |
| POST `/api/verify` | The returned proof envelope | Verified synthetic result; live status is explicitly false |
| POST `/api/logout` | `{}` | Session and its requests invalidated |

Only `pending → approved → consumed` and `pending → denied` are accepted.
Refusal is final for that request. A new request requires a new decision.
Approval binds to the exact request description and proof policy. The hash is
a consistency check, not a user signature or legal consent receipt. Both proof
generation and verification enforce approval and ownership on the server.
The caller cannot choose an audience, session, policy or issuer trust key.

Verification uses the existing pinned trust and predicate checks. Successful
verification atomically consumes the stored request. Invalid proofs do not
consume it. Two concurrent submissions cannot both succeed. The authenticated
session must remain live after cryptographic work; requests also expire after
300 seconds, including during verification.

## Bounds and storage

- Sessions last 30 minutes without sliding renewal. Login replaces the presented
  session; logout invalidates it. Cookies are HttpOnly and SameSite=Strict. They
  lack Secure because this demo uses loopback HTTP; do not deploy it remotely.
- Each process permits 120 API calls/minute, including 10 login attempts/minute.
  Each session permits 30 POSTs/minute. A quota rejection returns 429 with
  Retry-After: 60. Quotas are monotonic-clock sliding windows, not shared across
  processes. Static resources and parser rejections are outside these quotas.
- There are at most 32 sessions, 128 active request records, and 8 connection
  handlers. Connections have a 5-second socket timeout. Excess connections are
  closed; capacity errors return 503. Crypto operations run serially under a
  process lock. These bounds are not a service availability guarantee.
- POST bodies are capped at 300,000 bytes; proof shape has the existing 262,144-byte
  cap. Duplicate keys, NaN/Infinity literals, unexpected fields and transfer encoding
  are refused. Only three named static resources are served; no directory is exposed.
- The issuer key, credential, link secret, login code, sessions and consent state
  live in memory. Request state lives in a private temporary directory and is
  removed on normal shutdown. Expired/logout request records are deleted during
  API cleanup. Abrupt termination can leave the temporary request database.
  No access log or proof archive is written. The browser temporarily holds the
  proof it submits, but receives no credential or link secret.

## Boundaries and follow-up

The issuer, wallet emulator and verifier share one process. This demonstrates a
flow, not isolation between those parties. A code proves access to this local
synthetic account, not a person's identity. This is neither passkey nor JPKI
authentication. The prototype has no card adapter, live licence-status source,
revocation registry, durable key rotation or recovery. AnonCreds revocation is
still disabled. A restart creates new keys and invalidates existing sessions.
The separate [CLI prototype](split-wallet.md) implements wallet custody, rotation,
revocation and recovery with durable stores. Those features are not wired into this HTTP service.

Python explicitly describes `http.server` as unsuitable for production in its
[3.12 documentation](https://docs.python.org/3.12/library/http.server.html).
The application refuses non-loopback binding. A production deployment needs a
separate server, actual identity enrollment, holder-side custody, protected key
lifecycle and operational validation; see Beads `zkl-69f`, `zkl-e14`, `zkl-88t`,
and `zkl-9w9`. Licence-source research is in [real-license-integration.md](real-license-integration.md).

`tests/test_service.py` exercises the HTTP boundary with actual synthetic
credentials, including session isolation, CSRF/origin checks, explicit consent,
proof tampering and replay. It requires local socket access. The existing CI
discovers these tests on Ubuntu and Windows with `REQUIRE_CRYPTO=1`.
