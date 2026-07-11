# Compliance Posture

*A living document, written for integrators' legal teams as much as for
developers. Last updated: 2026-07.*

## Summary

Attesta is **not a mixer**. It is a confidential payments layer designed around
three deliberate, compliance-compatible choices:

1. **Amounts are shielded; participants are not (v1).** The sender/receiver
   graph stays public. Regulators and analytics providers can see who
   transacts with whom; businesses keep the numbers private. Full graph
   privacy is explicitly out of scope until the regulatory picture for it
   matures.
2. **Selective disclosure is first-class.** Every shielded account has viewing
   keys. An account holder can hand a scoped viewing key to an auditor, tax
   authority, or counterparty, revealing exactly their own payment history —
   nothing about anyone else — and revoke it going forward.
3. **The pool can be attestation-gated.** A shielded pool may require a valid
   compliance attestation (e.g. `KycLevel(2)` from an approved issuer) to
   enter. This makes it a compliant-by-construction privacy pool: every
   participant has been verified by a regulated issuer, without any app or
   the pool itself ever touching the underlying personal data.

## How this differs from a mixer

| Property | Mixer | Attesta shielded pool |
| --- | --- | --- |
| Participant graph | Hidden | **Public** |
| Amounts | Hidden | Hidden, with per-account auditor disclosure |
| Entry requirements | None | Optional issuer-verified attestation gate |
| Aggregate solvency | Often opaque | Contract token balance publicly equals sum of notes |
| Regulator access | None | Scoped viewing keys, revocable, per-account |

## The attestation model

- **Issuers** are governance-curated regulated entities (anchors already
  performing SEP-12 KYC, licensed KYC providers). Their signing keys are
  published on-chain in the `issuer_registry`; additions, removals, and key
  rotations are timelocked and evented.
- **Credentials** are issued off-chain and stay on the user's device. What
  goes on-chain is a zero-knowledge proof of a *predicate* over the credential
  ("KYC level ≥ 2", "resident of an allowed jurisdiction", "monthly inflows
  above Y") — never the credential itself.
- **Attestations are scoped and time-boxed.** Each recorded attestation
  expires and can be invalidated by issuer-driven credential revocation.
- **Consuming apps** call `attestation_registry.check(address, claim_type)`
  and receive a boolean. No personal data flows to the app; there is no
  honeypot to breach.

## Data handling

- Names, documents, addresses, and income data: **never on-chain, never on
  Attesta servers.** They exist only between the user and their issuer.
- On-chain state: commitments, nullifiers, proofs, issuer public keys,
  attestation validity windows, revocation flags.
- Backend infrastructure relays ciphertext and indexes public state. A fully
  compromised backend can censor convenience; it cannot learn an amount,
  identity attribute, or forge a proof.

## Governance path

The issuer registry launches under a timelocked multi-sig and migrates toward
community curation on a published milestone schedule (see README roadmap,
M5–M7). No single KYC provider can become a chokepoint: the registry is
multi-issuer by design.

## Questions integrators should ask us

- Which jurisdictions' disclosure obligations does the scoped viewing key
  model satisfy for your use case? (We maintain integration notes per
  deployment; ask.)
- What is the revocation latency between an issuer invalidating a credential
  and attestations failing `check()`? (One ledger — revocation is on-chain.)
- Can law enforcement compel disclosure? (Viewing keys are held by account
  owners; Attesta infrastructure holds no keys to compel.)
