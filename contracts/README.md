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

## Commands

```bash
cargo test               # native unit + integration tests
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
