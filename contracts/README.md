# Attesta — Contract Layer

Soroban contracts (Rust, `soroban-sdk`, Protocol 25 BLS12-381 host
functions). See the [top-level README](../README.md) for the protocol
design and [CONTRIBUTING.md](../CONTRIBUTING.md) for the PR checklist.

## Crates

| Crate | Contract | Role |
| --- | --- | --- |
| [`shielded_pool`](./shielded_pool) | `ShieldedPool` | Confidential value: deposits → commitments, ZK-verified transfers, withdrawals. One instance per token. |
| [`zk_verifier`](./zk_verifier) | `ZkVerifier` | Groth16 verification over BLS12-381. One instance per circuit, verifying key immutable per instance. |
| [`attestation_registry`](./attestation_registry) | `AttestationRegistry` | Present ZK proofs over issuer credentials; `check(address, claim_type)` is the one-call integration for any Soroban app. |
| [`issuer_registry`](./issuer_registry) | `IssuerRegistry` | Governance-curated issuers with timelocked, evented add/remove/rotate. |
| [`interfaces`](./interfaces) | — | Shared types (`ClaimType`, `Groth16Proof`, `VerificationKey`) and cross-contract clients. Integrators depend on this crate. |

## Deployment topology

```
issuer_registry ◄── attestation_registry ◄── shielded_pool (optional gate)
                          │                        │
                          ▼                        ▼
                   zk_verifier(attest_*)   zk_verifier(transfer)
                                           zk_verifier(withdraw)
```

Deploy order: verifiers (with their published verifying keys) →
`issuer_registry` → `attestation_registry` → `shielded_pool` per token.

## The pinned protocol hash

The pool's Merkle tree hashes with the protocol Poseidon instance over
the BLS12-381 scalar field, computed via the Fr host functions — the
same function the transfer/withdraw circuits evaluate in-circuit. Its
constants (`shielded_pool/src/poseidon_params.rs`) are **generated**
from [`circuits/`](../circuits) by `circuits/scripts/build-artifacts.sh`;
never edit them here. The lockstep is enforced by a committed test
vector plus an end-to-end test (`shielded_pool/src/test_e2e.rs`) that
runs deposit → shielded transfer → withdraw against real `ZkVerifier`
instances with real Groth16 proofs and asserts the on-chain root equals
the prover-side tree root after every insertion.

## Measured costs

From the e2e benchmark (`shielded_pool/src/test_e2e.rs`, real proofs,
real verifiers; run with `--nocapture` for current numbers). The
benchmark asserts every operation stays inside the network transaction
limits (100M instructions / 40MB memory), so a cost regression fails
the suite:

| Operation | Instructions | Memory |
| --- | --- | --- |
| `deposit` (20-level Poseidon insert) | ~0.5M | ~78KB |
| `transfer` (2-in/2-out: pairing check + 2 inserts) | ~53M | ~510KB |
| `withdraw` (pairing check + payout) | ~51M | ~490KB |

Transfers and withdrawals are dominated by the Groth16 pairing check,
which is where the cost should live. Numbers are host-metered from
native tests; the in-wasm Poseidon arithmetic adds a few million wasm
instructions on-network on top of the figures above (still far inside
the limit). Re-benchmark on every protocol upgrade per the
[maintenance commitment](../README.md#maintenance-commitment).

## Commands

```bash
cargo test               # native unit + integration tests (the e2e
                         # tests generate real proofs; first run is slow)
cargo fmt --all          # format
cargo clippy --all-targets
stellar contract build   # wasm for deployment (target/wasm32v1-none/release)
```

## Integrating with Attesta from your contract

Depend on `attesta-interfaces` and call the registry:

```rust
use attesta_interfaces::{AttestationClient, ClaimType};

let ok = AttestationClient::new(&env, &attesta_registry)
    .check(&user, &ClaimType::KycLevel(2));
```

That's the whole integration — no personal data ever reaches your contract.
