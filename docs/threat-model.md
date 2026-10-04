# Threat model and acceptance boundary

## Statement

The accepted presentation demonstrates, relative to a verifier-pinned AnonCreds credential definition,
that one holder knows a valid credential and its link secret with:
`can_drive_ordinary >= 1` and `valid_until >= requested YYYYMMDD`.
The synthetic issuer only issues entitlement values 0 or 1. It also validates calendar dates.
Predicates must refer to sub-proof index 0 in exactly one credential.
No attribute values are requested for disclosure, and the wrapper refuses additional disclosures/self-attestations.

This is not a proof of physical-card possession, current legal entitlement, identity of the human at the keyboard,
a non-compromised wallet, or up-to-date revocation status.
The credential holder can transfer a credential together with the secret if the environment permits it.

## Roles

**Issuer:** Knows and checks source attributes, signs the synthetic credential. Production source verification is not implemented.
A compromised/malicious trusted issuer can certify false facts; a valid proof cannot fix that.

**Holder:** Generates the link secret and presentation locally. The test fixture is in memory; no real document import exists.
All three roles run on the same machine for reproducibility, with no OS-level isolation claim.

**Verifier:** Pins a public credential definition and schema in its own configuration; creates and stores the exact request;
uses its configured audience and an authenticated-session context; checks a presentation against the stored request;
atomically marks successful requests as consumed.

The CLI reads verifier provisioning from local files. These files must not be supplied or editable by an adversary.
The CLI session value is an illustration of channel binding, NOT an authentication implementation.

## Why a nonce is not enough

Each random 80-bit presentation nonce belongs to a server-owned record containing the audience, session, policy and deadline.
Different requests have independent nonces. The proof is verified against the exact stored request.
The caller cannot choose a weaker request for verification. No assumption is made that the descriptive `name` field
alone cryptographically binds all application context.

Before cryptographic verification, the wrapper compares each embedded CL predicate's attribute name,
operator and threshold with the stored request and requires exactly one sub-proof. In local tests with
AnonCreds 0.2.3, passing the stored request to the backend alone accepted proofs of weaker thresholds.
The explicit comparison rejects those proofs; changing their embedded thresholds also fails cryptographic verification.

Replay protection is stateful. `BEGIN IMMEDIATE` serializes acceptance so two simultaneous submissions cannot both succeed.
An invalid proof does not consume the request. With the real clock, expiry is checked again after cryptographic verification.
A copied/stale verifier database, attacker-controlled request state, or separate uncoordinated stores defeats a global one-use guarantee.
The demonstration does not solve relay/phishing attacks, cross-device authentication or transaction authorization.

## Storage and visibility

The public presentation contains cryptographic values and shared schema/credential-definition identifiers.
The verifier also knows the requested predicates, service date, session, audience, nonce, time window and decision.
Accepted presentations do not contain names, addresses, birth dates or licence numbers as disclosed values.
The schema still contains attribute **names**. Identifier metadata can expose an issuer or cohort.
Proof inequality in a regression test does not prove unlinkability. Network/account/timing correlation remains possible.
Repeated, adaptively chosen threshold queries can narrow a hidden value: a production wallet needs request review,
reasonable policy limits and consent. ZK hides witnesses; it does not hide what the statement logically implies.

The HTML/JSON report deliberately shows synthetic holder values for teaching. It is NOT the verifier's record,
and must not be described as what would remain after a verifier breach.
The sample does not reconstruct a breached company's actual data model or retention policy.

## Tests and limits

State/input tests have no cryptography and use explicit test callbacks. Real-crypto tests use anoncreds and never
substitute a locally fabricated successful verifier. Missing crypto must fail in CI/release mode.
Some malformed signed credential inputs may be rejected while generating a proof; that is distinguished in test comments
from a verifier rejecting an actually generated proof. Weaker-policy tests deliberately generate a genuine proof of a weaker
claim and submit it to the stricter verifier.

A passing suite provides regression evidence, not a cryptographic audit or proof of end-to-end production security.
No service endpoint, rate limiting, user authentication, device attestation, issuer key rotation, recovery, deployment hardening,
Japanese licence RSA adapter, or revocation subsystem is included.
