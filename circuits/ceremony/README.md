# Trusted setup — the Attesta ceremony plan

Groth16 requires a circuit-specific trusted setup: whoever knows the
setup randomness ("toxic waste") can forge proofs — for this protocol,
that means minting shielded value invisibly. Attesta treats the setup
as a public, multi-party, verifiable process. This document is the M1
deliverable describing that process; the tooling and transcript land
here before any key gates real value.

## Status

| Phase | Status |
| --- | --- |
| Development keys (public seed, forgeable by design) | ✅ in use — see [`../artifacts/`](../artifacts) |
| Phase 1: Powers of Tau | Planned — will reuse an existing widely-attested BLS12-381 perpetual ceremony rather than running our own |
| Phase 2: circuit-specific MPC (per circuit) | Planned — runs after the transfer/withdraw circuits freeze for audit |
| Transcript publication + independent verification | Planned — transcript, contribution attestations, and a verifier tool in this directory |

## Ground rules

1. **1-of-N honesty.** The MPC is secure if *any single* contributor
   discards their randomness. The contributor set must therefore be
   open: anyone may join during the public contribution window, and the
   organizers contribute first (so a malicious organizer is neutralized
   by any later honest participant).
2. **Everything is reproducible.** Each contribution publishes a hash
   chain entry (previous state hash, contribution hash, public key of
   the contributor's attestation). Anyone can re-verify the full chain
   from the published transcript with the verifier tool in this
   directory — no trust in the coordinator.
3. **The beacon finalizes.** The final contribution applies a public
   randomness beacon (e.g. a drand round committed to in advance) so
   the last human contributor cannot grind the result.
4. **Circuits freeze first.** The ceremony runs only over audited,
   frozen circuit sources, identified by commit hash in the transcript.
   Any later constraint change — even one gate — requires a new phase 2.
5. **Keys are published as artifacts** under `../artifacts/<circuit>/`,
   with checksums, the transcript commit, and the verifying key that
   on-chain `zk_verifier` instances pin. The dev-key warning in that
   directory is removed only by the ceremony PR itself.

## Why dev keys are safe to use now — and where the line is

The committed development keys are generated from a *fixed public
seed* (`circuits/src/bin/build_artifacts.rs`): everyone can reproduce
them, which also means everyone knows the toxic waste. They exist so
testnet deployments, integration tests, and integrators' CI are
reproducible. The line: **no contract holding real value may be
constructed with a dev verifying key.** The M7 mainnet checklist
includes verifying on-chain that every pinned key hash matches a
ceremony artifact.
