# attesta-protocol

A confidential payments layer with built-in compliance for the Stellar ecosystem — shielded transfer amounts with selective disclosure for auditors, plus reusable ZK compliance attestations (prove KYC status, income thresholds, or jurisdiction without revealing the underlying data). Built on Stellar Protocol 25's zero-knowledge primitives.

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Soroban](https://img.shields.io/badge/Soroban-Protocol%2025-brightgreen)
![Status](https://img.shields.io/badge/status-M1%20in%20progress-orange)

---

## The Problem

Stellar has become a serious settlement network — institutional stablecoins (USDC, EURC, PYUSD, MGUSD), $2B+ in tokenized RWAs, real payroll and remittance volume. But every payment amount on Stellar is public forever. That single fact blocks entire categories of adoption:

- **On-chain payroll is unusable.** Paying a team in stablecoins publishes every employee's salary to the world, permanently.
- **B2B settlement leaks strategy.** Supplier payment sizes, invoice amounts, and treasury movements are competitive intelligence handed to anyone with an explorer.
- **Compliance is all-or-nothing.** Today the only two options are full transparency (everything public) or off-chain rails (nothing verifiable). Regulated entities need the middle: private to the public, provable to the auditor.

And a second, related gap: every Stellar app that needs compliance (anchors, RWA platforms, lending protocols) re-verifies the same user data — full KYC documents, income statements, residency proofs — over and over, each integration a new honeypot of personal data.

**Protocol 25 (January 2026) changed what's possible.** Stellar's ZK upgrade brought BLS12-381 operations to Soroban, making on-chain verification of zero-knowledge proofs practical for the first time. The primitives exist. Almost nothing has been built on them. attesta-protocol is the payments-and-compliance layer those primitives were shipped for.

## What It Does

Two products, one cryptographic foundation:

### 1. Confidential payments (shielded amounts, visible participants)

- Deposit stablecoins into the shielded pool → amounts become cryptographic commitments.
- Transfer confidentially: the chain records that a valid transfer happened (no double-spend, no inflation — enforced by ZK proofs verified on-chain), but amounts are hidden.
- Selective disclosure is first-class, not an afterthought: every account has viewing keys. An employer can hand a scoped viewing key to their auditor or tax authority, revealing exactly their own payment history — nothing about anyone else, and revocable going forward.
- Deliberate scope choice: **amounts are shielded; the sender/receiver graph is not** (v1). This is the compliance-compatible point on the privacy spectrum — regulators can see who transacts with whom, businesses keep the numbers private. Full graph privacy is explicitly out of scope until the regulatory picture for it matures.

### 2. ZK compliance attestations (the reusable primitive)

- Trusted issuers (anchors, KYC providers) issue signed credentials to users off-chain: "KYC level 2 passed," "resident of jurisdiction X," "monthly inflows above Y."
- Users generate ZK proofs client-side over those credentials and present them on-chain: "I hold a valid, unexpired KYC credential from an approved issuer" — without revealing name, document data, or even which issuer, beyond what the verifying app requires.
- Any Soroban contract can consume these attestations through one registry call. An anchor checks jurisdiction, a lending pool checks income threshold, an RWA platform checks accreditation — no app ever touches the underlying personal data.
- The two products compose: the shielded pool itself can require a valid compliance attestation to enter — making it a **compliant-by-construction privacy pool** rather than a mixer.

## Why Stellar Specifically

- Protocol 25's BLS12-381 host functions make on-chain ZK proof verification feasible — this project is only ~6 months possible, which is exactly why the niche is empty.
- The demand side already lives here: institutional stablecoins, anchors with existing KYC obligations, RWA issuers with accredited-investor requirements, and real payroll/remittance flows — all currently forced to choose between transparency and going off-chain.
- Anchors are natural attestation issuers. They already KYC users under SEP-12; Attesta lets that verification become portable and privacy-preserving instead of being repeated per-app.
- Sub-cent fees and fast finality make per-payment proof verification economically sane in a way it is not on Ethereum L1.

## Repository Structure

```
contracts/                    Soroban workspace (Rust, soroban-sdk 27)
├── zk_verifier/              Groth16 verification over BLS12-381; one instance
│                             per circuit, verifying key immutable per instance
├── shielded_pool/            Per-token confidential value: commitments,
│                             nullifiers, incremental Poseidon Merkle tree,
│                             optional attestation gate on entry
├── attestation_registry/     present() proofs over issuer credentials;
│                             check() one-call integration; revocation
├── issuer_registry/          Governance-curated issuers with timelocked,
│                             evented add/remove/rotate-key
└── interfaces/               Shared types + cross-contract clients —
                              what integrators depend on
circuits/                     Groth16 circuits (arkworks): transfer + withdraw
├── src/                      implemented, with per-circuit soundness docs
├── docs/                     under docs/; attest_* circuits are M5
├── artifacts/                Reproducible dev keys + host-encoded VKs
└── ceremony/                 The published trusted-setup plan
COMPLIANCE.md                 The selective-disclosure model, for legal teams
SECURITY.md                   Disclosure policy + protocol invariants
CONTRIBUTING.md               Dev setup, PR checklist, issue taxonomy
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  CLIENT LAYER (browser / CLI)                 │
│   WASM prover · note scanning · viewing keys · credentials    │
│        — private data never leaves the user's device —        │
└───────────────────────────┬──────────────────────────────────┘
                            │ ciphertext + proofs only
┌───────────────────────────▼──────────────────────────────────┐
│                BACKEND (relay + indexer, untrusted)           │
│     encrypted-note relay · public-state indexer · no keys     │
└───────────────────────────┬──────────────────────────────────┘
                            │ Soroban RPC
┌───────────────────────────▼──────────────────────────────────┐
│                CONTRACT LAYER (Soroban / Rust)                │
│  ShieldedPool · ZkVerifier (BLS12-381) · AttestationRegistry  │
│  IssuerRegistry — commitments, nullifiers, proofs, revocation │
└──────────────────────────────────────────────────────────────┘
```

**The trust rule that defines this project:** proofs are generated client-side, in the browser or CLI. Private amounts, credentials, and viewing keys never leave the user's device. The backend relays ciphertext and indexes public state; a fully compromised backend can censor convenience, but can never learn an amount or forge a proof. If a proposed feature violates this rule, the feature is wrong.

---

## Part 1 — Contract Layer

**Directory:** [`/contracts`](./contracts)
**Stack:** Rust, `soroban-sdk` 27, Protocol 25 BLS12-381 host functions

All four contracts below are implemented and tested (wasm builds clean);
see [`contracts/README.md`](./contracts/README.md) for the deployment
topology. The transfer and withdraw circuits they verify against are
implemented under [`circuits/`](./circuits) with written soundness
arguments, and the two layers are tested against each other for real:
the full deposit → shielded transfer → withdraw flow runs in the
contract test suite with nothing mocked — real Groth16 proofs verified
through the BLS12-381 host functions, over the Poseidon Merkle hash now
pinned identically in-circuit and on-chain. Verifying keys remain
development keys until the [public setup ceremony](./circuits/ceremony)
runs; the attestation circuits are M5.

### 1. `shielded_pool` — confidential value

| Function | Purpose |
| --- | --- |
| `deposit(from, token, amount, commitment)` | Public → shielded: locks tokens, inserts note commitment into the Merkle tree (checks the attestation gate if the pool is gated) |
| `transfer(proof, nullifiers, new_commitments, encrypted_notes, root)` | Shielded transfer: verifies the ZK proof (balance preserved, notes owned, no double-spend) against a recent root, spends nullifiers, inserts new commitments, emits encrypted notes for the recipient |
| `withdraw(proof, nullifier, to, amount, root)` | Shielded → public: exits the pool with a validity proof bound to the recipient, so a relayer cannot redirect funds |
| `root()` / `is_known_root(root)` / `is_spent(nullifier)` / `size()` | Public state queries for provers and indexers |

**Design:** Pedersen commitments over note values; incremental Merkle tree of commitments; nullifier set prevents double-spends; per-token pools (USDC pool, EURC pool) so value can never cross assets invisibly. Total pool balance is always publicly auditable — the contract's token balance must equal the sum of shielded notes, so insolvency or inflation bugs are externally detectable even though individual amounts are hidden.

### 2. `zk_verifier` — proof verification

- On-chain Groth16 verification over BLS12-381 using Protocol 25 host functions.
- One verifier contract per circuit (transfer, withdraw, attestation), each pinned to a published verifying key.
- Circuit upgrades deploy new verifier instances behind a timelocked governance switch — verifying keys are immutable per instance, never mutated in place.
- Circuits, proving keys, and the trusted-setup ceremony transcript are all published in this repo; the ceremony is run as a public multi-party contribution.

### 3. `attestation_registry` — the compliance primitive

| Function | Purpose |
| --- | --- |
| `present(user, proof, claim_type, context, issuer_key, credential_ref, expires_at)` | User presents a ZK proof over an issuer credential; on success, records a scoped, time-boxed attestation for their address |
| `check(address, claim_type)` | The one-call integration for every other Stellar app: returns whether a valid attestation of this type is active |
| `revoke_credential(issuer, credential_ref)` | Issuer-driven revocation (compromised or invalidated credentials), propagated into proof validity |

Integrating from any Soroban contract is one dependency and one call:

```rust
use attesta_interfaces::{AttestationClient, ClaimType};

let ok = AttestationClient::new(&env, &attesta_registry)
    .check(&user, &ClaimType::KycLevel(2));
```

Claim types are an extensible enum: `KycLevel(n)`, `Jurisdiction(allowed_set)`, `IncomeAbove(threshold)`, `Accredited`, with a registry process for adding new types.

### 4. `issuer_registry` — who may attest

- Governance-curated list of credential issuers (anchors, KYC providers) with published signing keys.
- Issuer keys are rotatable; rotation and removal are timelocked and evented.
- Multi-issuer by design: no single KYC provider becomes a chokepoint for the whole ecosystem.

**Cross-cutting:** every contract passes through the Soroban Audit Bank plus a dedicated cryptography review before mainnet (standard contract audits do not cover circuit soundness); all state transitions emit events; admin functions sit behind a timelocked multi-sig.

## Roadmap

| Milestone | Scope | Status |
| --- | --- | --- |
| **M1 — Circuits + verifier on testnet** | Transfer/withdraw circuits, Groth16 verification via BLS12-381 host functions, published trusted-setup plan | 🟢 Code complete — circuits, on-chain verification, e2e tests, and the [setup plan](./circuits/ceremony) landed; testnet deployment remains |
| **M2 — Shielded pool MVP** | Deposit/transfer/withdraw on testnet (USDC), indexer + note relay, CLI prover | 🟡 In progress — pool contract and the [CLI prover](./circuits/docs/prover.md) landed; indexer, note relay, and testnet deployment remain |
| **M3 — WASM prover + wallet UI** | Browser proving, pay/receive surfaces, viewing keys + local history | Planned |
| **M4 — Selective disclosure** | Scoped viewing keys, auditor portal, disclosure CLI | Planned |
| **M5 — Attestation layer** | Credential format, issuer gateway + SDK, attestation circuits, registry contracts, first pilot issuer | Planned |
| **M6 — Payroll console** | Batch runs, CSV import, recurring payments | Planned |
| **M7 — Audits + mainnet** | Soroban Audit Bank + independent cryptography review, public setup ceremony, capped mainnet launch | Planned |

## Contributing

Three decoupled layers — plus a fourth contribution surface (circuits) for cryptography-inclined contributors.

### Where to start

- 🟢 **Good first issues** — `contract/good-first-issue`, `backend/good-first-issue`, `frontend/good-first-issue`
- 🟡 **Help wanted** — WASM prover performance, note-scanning efficiency, issuer SDK examples, i18n
- 🔴 **Core** — circuit design and review, nullifier/commitment scheme invariants, trusted-setup ceremony tooling
- 🧮 **`circuits/`** — every circuit change requires a written soundness argument and two reviews; this directory has its own [CONTRIBUTING addendum](./circuits/CONTRIBUTING.md)

### Issue taxonomy

Every issue carries a layer label, difficulty label, and acceptance criteria. Anything touching circuits, verifying keys, or the no-secrets-server invariant carries a `security-critical` label with mandatory dual review. The standing invariant: **no change may create a code path where a plaintext amount, spending key, or raw credential reaches the backend.**

### Development setup

Prerequisites: Rust (stable) with the `wasm32v1-none` target, and the
[Stellar CLI](https://developers.stellar.org/docs/tools/cli):

```bash
rustup target add wasm32v1-none
cargo install --locked stellar-cli
```

```bash
# Contracts
cd contracts && cargo test && stellar contract build

# Circuits (arkworks toolchain)
cd circuits && cargo test && ./scripts/build-artifacts.sh
```

> **Note:** build with the committed `contracts/Cargo.lock`. It pins
> `ed25519-dalek` to 2.x — `soroban-env-host 27.0.0` declares `>= 2.0.0`
> but does not compile against 3.0.0.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for testnet setup, local proving, and the PR checklist.

## Maintenance Commitment

- **Cryptography is treated as a liability, not a flex:** audited standard constructions (Groth16, Pedersen, established Merkle/nullifier patterns) over novel schemes; a public multi-party setup ceremony; circuits and keys versioned and published; a [SECURITY.md](./SECURITY.md) with a disclosure policy from day one.
- **Compliance posture is documented, not implied:** a living [COMPLIANCE.md](./COMPLIANCE.md) explains the selective-disclosure model, the deliberate amounts-only privacy scope, and how the attestation-gated pool differs from a mixer — written for integrators' legal teams as much as for developers.
- **Protocol tracking:** Protocol 25's ZK host functions are new; this project commits to tracking protocol-level changes and re-benchmarking verification costs each network upgrade.
- **Issuer neutrality:** the issuer registry's governance path from multi-sig to community curation is documented with milestones.
- **Docs as a deliverable:** every milestone ships integrator docs — the attestation layer succeeds only if other Stellar projects can adopt it in an afternoon.

## Ecosystem Alignment

- Builds directly on Protocol 25's ZK primitives (Jan 2026) — early-mover territory where the ecosystem has shipped primitives but almost no applications
- Solves adoption blockers for constituencies already on Stellar: payroll/remittance users, anchors, RWA issuers, institutional stablecoin holders
- The attestation registry is a public-good primitive: one integration call gives any Soroban app privacy-preserving compliance, replacing N redundant KYC honeypots
- Complements SEPs rather than competing: issuer flow aligns with SEP-12 KYC practice; shielded pool wraps existing Stellar assets (USDC/EURC) rather than introducing new ones
- Deep, long-lived maintenance surface across four contribution areas — structured for sustained community contribution rather than a one-off grant build

## License

[Apache-2.0](./LICENSE)

---

*Attesta: private to the public, provable to the auditor.*
