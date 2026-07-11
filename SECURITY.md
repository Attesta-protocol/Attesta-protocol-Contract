# Security Policy

Attesta is a cryptographic payments protocol. We treat cryptography as a
liability to be minimized, not a feature to be flexed: audited standard
constructions (Groth16, Pedersen commitments, established Merkle/nullifier
patterns) over novel schemes.

## Reporting a vulnerability

**Do not open a public issue for security bugs.**

- Email: **favoursejiro@gmail.com** with subject `[SECURITY] attesta-protocol`
- Or use GitHub's private vulnerability reporting on this repository.

Include: affected contract/circuit, reproduction steps or a proof-of-concept,
and the impact you believe it has. You will receive an acknowledgement within
72 hours and a triage verdict within 7 days.

## Scope

In scope:

- Soroban contracts under `contracts/` (soundness of nullifier/commitment
  handling, Merkle tree invariants, verifier integration, access control,
  timelock bypasses)
- Circuits under `circuits/` (under-constrained circuits, soundness or
  zero-knowledge failures, trusted-setup issues)
- The no-secrets-server invariant: any path by which a plaintext amount,
  spending key, or raw credential could reach infrastructure

Out of scope:

- Issues requiring a compromised user device
- Denial of service against public testnet deployments
- Findings in dependencies already publicly reported upstream

## Severity guidance

| Severity | Example |
| --- | --- |
| Critical | Inflation/double-spend, forged attestation, verifying-key substitution |
| High | Nullifier replay across roots, timelock bypass, issuer impersonation |
| Medium | Griefing of deposits/withdrawals, event/state divergence |
| Low | Missing events, gas/footprint inefficiencies with no safety impact |

## Disclosure

We follow coordinated disclosure: fixes land and are deployed before details
are published. Reporters are credited (or kept anonymous, your choice) in the
release notes. Pre-mainnet, all contracts pass through the Soroban Audit Bank
plus an independent cryptography review; audit reports will be published in
this repository.

## Key invariants (what "broken" means here)

1. The pool's token balance always equals the sum of shielded note values
   (no inflation, externally auditable).
2. A nullifier can be spent at most once, ever.
3. No attestation is recorded without a valid proof over a credential from an
   active, unrevoked issuer key.
4. Verifying keys are immutable per verifier instance; upgrades only via new
   instances behind the timelocked governance switch.
5. Secrets never leave the client. Ever.
