# Career ZK prototype

Prove whether signed career evidence supports **at least N days of Python
production-operations experience within a requested period**, without sending
the underlying records to the verifier.

This local Go module uses real Groth16 proofs on BN254. EdDSA signature checks,
holder-secret possession, interval union, and the answer calculation are inside
the circuit. It is separate from the existing AnonCreds license demo.

## Run

Requires Go 1.26.8 or later. Download dependencies once; subsequent issuance,
proving, and verification run locally without API keys.

```sh
cd research/career-zk
go mod download
go test -count=1 ./...
go vet ./...
mkdir -p artifacts
go build -o artifacts/career-zk ./cmd/career-zk
./artifacts/career-zk demo -out artifacts/demo-1 -runs 3

./artifacts/career-zk prove \
  -setup artifacts/demo-1/setup \
  -credential artifacts/demo-1/fixtures/undetermined.credential.private.json \
  -holder artifacts/demo-1/fixtures/holder.private.json \
  -request artifacts/demo-1/fixtures/undetermined.request.json \
  -out artifacts/another.response.json

./artifacts/career-zk verify \
  -vk artifacts/demo-1/setup/verifying.key \
  -request artifacts/demo-1/fixtures/undetermined.request.json \
  -proof artifacts/another.response.json
```

Use a fresh output path. Existing files are never overwritten.
The verifier needs only its trusted verification key, its own expected request,
and the response. Do not adopt a request or verification key supplied by the prover.

## Meaning of the answers

There are one to three signed records. Each states a date interval, whether
Python was used, and whether production duties were present, absent, or unknown.
The circuit enumerates all eight role-bit assignments; known roles and unused
slots only duplicate an interpretation. The prover cannot supply a subset.

| Answer | Meaning |
|---|---|
| YES | Every interpretation reaches N days. |
| NO | Every interpretation falls short, and the issuer attests complete coverage of the queried period. |
| UNDETERMINED | Interpretations disagree, or the completeness needed for NO is missing. |

Dates use UTC half-open intervals, with overlapping days counted once.
Empty evidence, invalid dates, unsupported policies, invalid signatures, and
failed proofs are errors, not successful negative or uncertain answers.
The fixtures cover all three answers and incomplete evidence.

## Scope and trust

One synthetic issuer signs the entire manifest, including its count, validity,
subject, coverage, and completeness assertion. The circuit checks the signature;
it does not establish the truth of the issuer's claims. It proves knowledge of a
holder secret, not physical identity or non-transferability.

The verifier learns the answer and request parameters, issuer key, setup
identifier, audience, nonce, a randomized commitment, and the proof.
Records, holder identifier, signature, record count, and completeness flag are
private witnesses. Repeated questions can still reveal information.

Setup uses genuine randomness, but is performed by one trusted local process.
There is no production setup ceremony or independent audit. Verification is
stateless: checking the same proof against the same request succeeds again.
Nonce substitution is rejected; a used-nonce ledger is not implemented.

Demo secrets are saved in files ending in `.private.json` with mode 0600 inside
directories created with mode 0700. They are not encrypted. Share response files,
not the whole demo folder. All generated artifacts are ignored by Git.
Revocation, live identity services, multiple issuers, consent UI, real resumes,
and natural-language interpretation are outside this implementation.

See [Japanese design and usage](README.md), [measured validation](validation.md),
and [prior work](research.md). The prototype's finite interpretations are a
specific policy model; the implementation does not establish research novelty.
