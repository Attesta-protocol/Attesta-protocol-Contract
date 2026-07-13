# Issue backlog

> **Filed:** these are live on the tracker as
> [issues #1–#10](https://github.com/Attesta-protocol/Attesta-protocol-Contract/issues)
> (numbering matches). The tracker is the source of truth for status;
> this file preserves the full specifications.

Ten scoped, ready-to-file issues derived from the current state of the
repo and the [roadmap](./README.md#roadmap). Each follows the
[issue taxonomy](./CONTRIBUTING.md): a layer label, a difficulty label,
concrete tasks, and acceptance criteria. Issues touching circuits,
verifying keys, or the no-secrets-server invariant carry
`security-critical` and require dual review.

Standing invariant for every issue here: **no change may create a code
path where a plaintext amount, spending key, or raw credential reaches
the backend.**

---

## 1. Testnet deployment pipeline + published addresses

**Labels:** `contract` · `medium` · `M1/M2`

### Description

M1 is code complete but nothing is deployed. We need a repeatable,
scripted deployment of the full topology to Stellar testnet —
verifiers (pinned to the dev verifying keys), `issuer_registry`,
`attestation_registry`, and a `shielded_pool` instance wrapping testnet
USDC — plus a committed record of the resulting addresses so
integrators and the prover docs can point at something real.

Deploy order (from `contracts/README.md`): verifiers →
`issuer_registry` → `attestation_registry` → `shielded_pool` per token.
The verifier constructor takes the host-encoded verifying key from
`circuits/artifacts/<circuit>/verifying_key.hex`.

### Tasks

- [ ] `scripts/deploy-testnet.sh` (or a small Rust xtask): builds wasm
      (`stellar contract build`), deploys both `zk_verifier` instances
      with the transfer/withdraw dev VKs, then the registries, then the
      pool bound to the testnet USDC SAC address.
- [ ] Parse `verifying_key.hex` into constructor arguments inside the
      script — no hand-copied hex.
- [ ] `DEPLOYMENTS.md` at the repo root: network, contract addresses,
      wasm hashes, the artifact `SHA256SUMS` the keys came from, and the
      git commit deployed.
- [ ] A smoke-test script that runs `deposit` → `transfer` → `withdraw`
      against the live deployment using `attesta-prover` bundles.
- [ ] Prominent dev-key warning in `DEPLOYMENTS.md` (these keys are
      forgeable by design; testnet only).

### Acceptance criteria

- Running the script from a clean checkout against a funded testnet
  account produces a working deployment with no manual steps.
- The smoke test completes a full shielded cycle on testnet and prints
  the transaction hashes.
- `DEPLOYMENTS.md` is committed and every address in it responds
  correctly to `root()` / `verifier()` queries.
- Re-running the script is idempotent-safe (fails loudly rather than
  silently redeploying over a recorded address).

---

## 2. Commitment-log indexer service

**Labels:** `backend` · `medium` · `M2`

### Description

Provers need the pool's full commitment log in leaf order (see
[`circuits/docs/prover.md`](./circuits/docs/prover.md)). Today they
must scrape `Deposit` / `ShieldedTransfer` events by hand. Build the
first backend component: an untrusted indexer that follows pool events
over Soroban RPC and serves the log. Per the trust rule, the indexer
holds no keys and sees only public state — a compromised indexer can
serve a stale log (which provers detect: the root won't verify) but
can never learn an amount.

### Tasks

- [ ] Service (language free; Rust or TypeScript preferred) that
      ingests `Deposit` and `ShieldedTransfer` events from a configured
      pool contract, ordered by ledger and `leaf_index`.
- [ ] Persist to a simple store (SQLite is fine) with resume-from-last-
      ledger on restart; handle RPC retention limits by supporting
      backfill from a checkpoint file.
- [ ] HTTP API: `GET /commitments` (the full log, `attesta-prover
      --commitments` text format), `GET /commitments?from=<n>`
      (incremental), `GET /root` (indexer's computed root for
      cross-checking against on-chain `root()`).
- [ ] Serve `ShieldedTransfer.encrypted_notes` alongside their
      commitments (`GET /notes?from=<n>`) so wallets can scan.
- [ ] Continuous self-check: recompute the Merkle root and compare with
      the on-chain root; alarm on divergence.
- [ ] `backend/README.md` documenting the API and the trust model.

### Acceptance criteria

- Against a testnet deployment (issue 1), the indexer serves a log from
  which `attesta-prover` produces a bundle the live pool accepts.
- Restarting the indexer mid-stream loses no leaves and duplicates
  none (verified by an integration test using a local RPC).
- The self-check endpoint reports root equality with the chain.
- No endpoint accepts or returns key material of any kind.

---

## 3. `attesta-prover sync` — fetch the commitment log from RPC

**Labels:** `circuits` · `good-first-issue`/`medium` · `M2`

### Description

The CLI prover should not *require* the indexer (issue 2): a user with
only a Soroban RPC endpoint should be able to reconstruct the log
themselves. Add a `sync` subcommand that pulls pool events and writes
the standard commitments file. This keeps the prover self-sovereign —
the indexer becomes a convenience, not a dependency.

### Tasks

- [ ] `attesta-prover sync --rpc <url> --pool <contract-id> --out
      log.txt [--from-ledger <n>]` using the `getEvents` RPC method.
- [ ] Order events by ledger and `leaf_index`; verify contiguity
      (leaf indices 0..n with no gaps) and fail loudly otherwise.
- [ ] After sync, recompute the local Merkle root and compare against
      the pool's `root()` (simulated read); print both.
- [ ] Incremental mode: appending to an existing log file resumes from
      its last leaf.
- [ ] Extend `circuits/docs/prover.md` with the sync workflow.
- [ ] Decide and document the HTTP client dependency (the circuits
      crate is currently network-free; consider a feature flag so
      library consumers don't inherit it).

### Acceptance criteria

- On a testnet deployment, `sync` produces a log byte-identical to one
  assembled manually from explorer events.
- The recomputed root matches on-chain `root()`, and the command exits
  nonzero when it does not.
- RPC retention gaps produce a clear error naming the missing ledger
  range, not a silently truncated log.
- `cargo build` without the new feature flag pulls in no HTTP
  dependencies.

---

## 4. Encrypted note format + viewing keys (design + reference implementation)

**Labels:** `core` · `hard` · `security-critical` · `M3/M4`

### Description

`shielded_pool::transfer` already carries `encrypted_notes: Vec<Bytes>`
and the docs promise viewing keys, but no ciphertext format exists.
This is the spec that unlocks both the wallet (M3: recipients
discovering their notes) and selective disclosure (M4: scoped viewing
keys for auditors). It must be designed once, carefully — the standing
rule from `circuits/CONTRIBUTING.md` applies: standard constructions
only, with a written design document and dual review.

### Tasks

- [ ] Design doc (`docs/notes-encryption.md`): key hierarchy (spending
      key → viewing key → per-note keys), the encryption scheme (an
      established ECIES-style construction, e.g. X25519 +
      XChaCha20-Poly1305, mirroring Zcash's approach), what a viewing
      key holder can and cannot see, and forward-secrecy/revocation
      semantics for auditors.
- [ ] Define the plaintext layout: `(value, owner_pk, blinding)` plus a
      version byte; define the ciphertext envelope committed in
      `encrypted_notes`.
- [ ] Reference implementation in the circuits crate (or a new
      `attesta-notes` crate) with test vectors, used by
      `attesta-prover prove-transfer` to actually populate the
      ciphertexts.
- [ ] Note-scanning reference: given a viewing key and the indexer's
      `/notes` stream, recover owned notes (this defines the wallet's
      scanning cost — document it).
- [ ] Threat analysis section: what a malicious relayer/indexer holding
      all ciphertexts learns (must be: nothing beyond timing/count).

### Acceptance criteria

- The design doc is reviewed by two maintainers and merged before any
  implementation PR.
- Test vectors round-trip: encrypt with recipient pk, scan+decrypt with
  the viewing key, and the recovered note's commitment matches the one
  on-chain.
- A wrong viewing key rejects ciphertexts (AEAD failure), never
  mis-decrypts.
- `attesta-prover prove-transfer` emits real ciphertexts sized within
  the envelope limit the contract test suite enforces.
- No plaintext note data appears in any relay/indexer API in the
  accompanying changes.

---

## 5. Note relay service (transaction submission for shielded transfers)

**Labels:** `backend` · `hard` · `M2`

### Description

If the sender submits their own `transfer` transaction, their Stellar
account signs it — linking them to the shielded action and weakening
the model. The relay is the untrusted backend component that accepts a
finished proof bundle and submits it from the relay's own account.
Withdraw bundles are already relayer-safe (the proof binds the
recipient); transfers carry no funds to steal, so the relay can censor
but not redirect or learn amounts.

### Tasks

- [ ] HTTP service: `POST /relay/transfer` and `POST /relay/withdraw`
      accepting the `attesta-prover` bundle format plus
      `encrypted_notes` (transfer) or `to` (withdraw).
- [ ] Pre-submission validation: verify the proof locally against the
      published VK (reject garbage before paying fees), check the root
      is known and nullifiers unspent via simulation.
- [ ] Submission with retry/fee-bump handling; return the tx hash.
- [ ] Rate limiting and an explicit, documented censorship model
      (the relay is a convenience; users can always self-submit).
- [ ] Decide the fee story for v1 and document it: relay eats testnet
      fees now; note the M6-era design space (fee notes in-circuit vs.
      out-of-band payment) without building it.
- [ ] `backend/README.md` section covering the trust model.

### Acceptance criteria

- A bundle produced by `attesta-prover` and POSTed to the relay lands
  on testnet and the pool state updates (integration test against
  issue 1's deployment).
- Invalid proofs, unknown roots, and spent nullifiers are rejected
  with distinct 4xx errors *without* a chain submission.
- The relay's logs and storage contain no fields that could hold
  amounts, keys, or plaintext notes (reviewed against the invariant).
- Self-submission path remains documented and working (the relay is
  optional).

---

## 6. WASM prover — browser proving for M3

**Labels:** `circuits` / `frontend` · `hard` · `help-wanted` · `M3`

### Description

`circuits/src/prover.rs` was written to be the library behind both the
CLI and a WASM prover. Make that real: compile the proving pipeline to
WebAssembly with a JS-friendly API, so the M3 wallet can prove in the
browser with keys and notes that never leave the page.

### Tasks

- [ ] `circuits/wasm/` crate (`cdylib`) exposing `wasm-bindgen`
      functions: `keygen`, `derive_pk`, `note_commitment`,
      `prove_transfer`, `prove_withdraw` — bytes/JSON in, bundle out,
      mirroring the CLI's semantics.
- [ ] Solve the RNG story: `getrandom`'s `js` feature for browser
      entropy; document why `OsRng` is safe there.
- [ ] Proving-key delivery: fetch `proving_key.bin` (4MB transfer /
      1.8MB withdraw) with SHA-256 verification against the published
      `SHA256SUMS` before use; cache in IndexedDB.
- [ ] Benchmark page (no framework needed): time to load keys, prove a
      transfer, and prove a withdraw on a mid-range laptop and phone;
      record numbers in the README.
- [ ] Investigate `wasm-bindgen-rayon` for multi-threaded proving
      behind a flag (native proving uses ~1.5 cores today); ship
      single-threaded if it complicates the build.
- [ ] CI job building the wasm crate and running its tests under
      `wasm-pack test --node`.

### Acceptance criteria

- A browser demo proves a transfer against a fixture log and the
  resulting bundle verifies with `attesta-prover verify` and against
  the contract test suite's verifier.
- Proof generation completes in under 60s on a 2020-era laptop
  (document the measured number; native is ~10s).
- Key download is integrity-checked; a corrupted key is rejected
  before proving.
- No API in the wasm surface accepts a URL or callback that could
  exfiltrate `sk`/blindings; secrets exist only in wasm memory.

---

## 7. First attestation circuit: `attest_kyc_level`

**Labels:** `circuits` · `core` · `hard` · `security-critical` · `M5`

### Description

The attestation layer's contracts exist (`attestation_registry.present`
already verifies against a per-claim-kind verifier slot), but no
`attest_*` circuit does. Build the first one end to end for the
simplest claim: *"I hold a valid, unexpired KYC-level-n credential
signed by this issuer key"* — with public inputs
`[issuer_key, credential_ref, claim_binding, subject_binding,
expires_at]` as laid out in `circuits/src/lib.rs`
(`ATTESTATION_PUBLIC_INPUTS = 5`).

This issue includes defining the credential format the issuer signs —
the choice of in-circuit signature scheme (e.g. Poseidon-based EdDSA
over a SNARK-friendly curve vs. hash-based commitments) is the core
design decision and must follow the standard-constructions rule.

### Tasks

- [ ] Credential format spec (`docs/credential-format.md`): fields,
      canonical serialization, issuer signature scheme, revocation hook
      (`credential_ref`), expiry semantics.
- [ ] Soundness document (`circuits/docs/attest_kyc_level.md`) *before*
      the implementation PR, per `circuits/CONTRIBUTING.md`.
- [ ] The circuit: signature verification over the credential, claim
      extraction (`level >= n`), binding to the presenting subject and
      the verifying context, expiry as a public input the contract
      range-checks against ledger time.
- [ ] Wire into the artifact pipeline (`build_artifacts.rs`), layouts
      (`layout::ATTESTATION_PUBLIC_INPUTS`), and a `zk_verifier`
      instance in the contract e2e tests.
- [ ] `attesta-prover prove-attest` subcommand consuming a credential
      file.
- [ ] End-to-end contract test: issuer registered → credential issued
      (test fixture) → `present()` with a real proof → `check()`
      returns true; plus revocation and expiry negative tests.

### Acceptance criteria

- Soundness doc merged with two approving reviews before circuit code.
- The e2e test proves and verifies through the real
  `attestation_registry` → `zk_verifier` path with nothing mocked.
- Negative tests: wrong issuer key, expired credential, revoked
  `credential_ref`, and a proof bound to a different subject are all
  rejected.
- No personal data beyond the claim's boolean outcome is derivable
  from the public inputs (argued in the soundness doc).

---

## 8. Ceremony phase-2 tooling: contribution CLI + transcript verifier

**Labels:** `circuits` · `core` · `hard` · `security-critical` · `M7-prep`

### Description

`circuits/ceremony/README.md` commits to a public multi-party setup
with a verifiable transcript: hash-chained contributions, open
participation, and a beacon finalization. The tooling that makes that
real doesn't exist yet, and it must be exercised well before M7 — a
dry-run ceremony on the dev circuits is the deliverable here.

### Tasks

- [ ] `attesta-ceremony contribute`: takes the previous phase-2 state,
      applies a participant's randomness (OS entropy + optional user
      input), outputs the new state plus a contribution receipt
      (previous-state hash, new-state hash, attestation public key).
- [ ] `attesta-ceremony verify-transcript`: re-verifies the full hash
      chain and each contribution's pairing checks from the published
      transcript — runnable by anyone, no coordinator trust.
- [ ] Beacon finalization step applying a committed-in-advance public
      randomness value (design for drand; accept a hex value in v1).
- [ ] Deterministic key extraction: transcript → `proving_key.bin` /
      `verifying_key.hex` byte-identical for all verifiers.
- [ ] Dry run over the frozen dev transfer/withdraw circuits with ≥3
      contributors; publish the practice transcript under
      `circuits/ceremony/dry-run/`.
- [ ] Document the contributor guide (what participants run, what they
      must destroy, what they publish).

### Acceptance criteria

- `verify-transcript` accepts the dry-run transcript and rejects a
  tampered one (flipped byte anywhere in the chain).
- Keys extracted from the dry-run transcript verify proofs generated
  by `attesta-prover` (swap them into the e2e tests).
- A contribution can be produced on an air-gapped machine from a file
  handoff (no network requirement in `contribute`).
- Two maintainers review; the ceremony README's status table is
  updated to point at the tooling.

---

## 9. Fuzz and property tests for parsers and encodings

**Labels:** `circuits` · `good-first-issue`/`medium` · `quality`

### Description

Several hand-written parsers now sit on trust boundaries: `parse_vk_hex`
(consumes published artifacts), the prover CLI's bundle parser and
`--spend`/`--output` descriptors (consume user input), and the host
encodings in `encoding.rs` (bridge to the chain; a mis-encoding is a
soundness-adjacent bug). They have example-based tests; they deserve
adversarial ones.

### Tasks

- [ ] `cargo-fuzz` targets: `parse_vk_hex`, the bundle reader,
      `Spend`/`Output` descriptor parsing, and `g1/g2/fr_from_bytes`
      (must never panic on arbitrary input — return errors or, for the
      documented-unchecked point decoders, be exercised via the
      CLI's checked wrappers).
- [ ] Property tests (`proptest`): `fr/g1/g2` encode→decode roundtrip
      on random valid points; `parse_vk_hex ∘ render` is identity on
      random VKs; bundle write→read is identity.
- [ ] Property test pinning native Poseidon vs. the R1CS gadget vs.
      the generated on-chain constants on random inputs (extends the
      existing fixed-vector lockstep test).
- [ ] A CI job running each fuzz target for a bounded time (e.g. 60s)
      on PRs touching the parsers, and the property suite always.
- [ ] Fix whatever falls out (panics on malformed hex lengths,
      duplicate keys, integer overflow in indices are the likely
      candidates) — each fix with a regression test.

### Acceptance criteria

- All fuzz targets run clean for an extended local session (≥1h each,
  documented in the PR).
- No code path panics on malformed input reachable from CLI arguments
  or artifact files; all return typed errors.
- The Poseidon three-way equivalence property runs in the standard
  test suite.
- CI enforces the bounded fuzz pass and the property tests.

---

## 10. Prover key loading: integrity-checked fast path + benchmarks

**Labels:** `circuits` · `medium` · `performance`

### Description

`ProvingKey::deserialize_compressed` validates every curve point, which
is cryptographically redundant when the file's SHA-256 already matches
the published `SHA256SUMS` — and it dominates prover startup (the 4MB
transfer key). Add an integrity-checked fast path and real benchmarks,
so both the CLI and the future WASM prover (issue 6) start fast without
ever loading an unverified key.

### Tasks

- [ ] Extend `artifacts::load_proving_key` (and the CLI) to accept an
      expected SHA-256; when it matches, use
      `deserialize_compressed_unchecked`, otherwise fall back to the
      validating path. Never use the unchecked path without a hash.
- [ ] Teach the CLI to find the hash automatically from the sibling
      `SHA256SUMS` file, with `--no-verify-key` explicitly *not*
      offered (no unchecked-without-hash escape hatch).
- [ ] `criterion` benchmarks: key load (checked vs. hash+unchecked),
      tree rebuild at 1k/10k/100k leaves, transfer proof, withdraw
      proof. Commit the harness, record numbers in `circuits/README`
      or the prover doc.
- [ ] Profile `rebuild_tree` — the current prover rebuilds the full
      tree per invocation; document the cost curve and file a follow-up
      if a persisted-tree cache is warranted for large logs.
- [ ] Uncompressed-key variant assessment: arkworks uncompressed keys
      trade file size for load time; measure and decide, documenting
      the choice.

### Acceptance criteria

- Prover startup with a matching hash is measurably faster (record the
  before/after numbers; expect several × on the transfer key).
- A key whose hash does not match `SHA256SUMS` is either fully
  validated point-by-point or rejected — never trusted unchecked.
- Benchmarks run via `cargo bench` and their numbers are committed to
  docs with the machine spec noted.
- The e2e smoke flow (`prove-transfer` → `verify`) still passes, and
  CI stays green.
