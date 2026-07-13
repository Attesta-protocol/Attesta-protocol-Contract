# Soundness argument — `withdraw` circuit

Per [CONTRIBUTING](../CONTRIBUTING.md): what the circuit proves, its
exact public-input layout, and why the constraint system admits no
witness outside the intended relation. Updated in the same PR as any
constraint change.

## Statement

For a pool tree of depth `d`, the prover knows a spending key,
blinding, and authentication path such that a note of **exactly** the
public `amount`, owned by that key, is a leaf of the commitment tree
under the public `root`, and the public `nullifier` is that note's.
The public `recipient_binding` is part of the proven statement, fixing
who receives the exit.

## Public-input layout

Field elements, in the order `shielded_pool::withdraw` builds them:

| Index | Input |
| --- | --- |
| 0 | `root` |
| 1 | `nullifier` |
| 2 | `recipient_binding` — `address_binding(to)`: SHA-256 of the recipient's address XDR, top byte cleared |
| 3 | `amount` — the i128 token amount, big-endian in a field element |

Total: 4 (see `lib.rs::layout::WITHDRAW_PUBLIC_INPUTS`). The protocol
instance is `d = 20`.

## Why the relation is sound

`H` is the protocol Poseidon 2-to-1 hash, assumed collision-resistant.

**The amount is the note's value, not a claim.** The commitment is
recomputed in-circuit as `H(H(amount, H(1, sk)), blinding)` with the
*public* `amount` in the value slot. A proof for any amount other than
the committed value would need an `H` collision. No range check is
needed: honest notes are created with 64-bit values, so an
out-of-range `amount` matches no real leaf, and the contract
independently rejects `amount ≤ 0`.

**Ownership is forced.** As in the transfer circuit, the owner key is
derived from the witness `sk` in-circuit; a prover without the key has
no satisfying assignment.

**Membership and nullifier are bound to one leaf.** The Merkle path and
the nullifier `H(H(2, sk), leaf_index)` consume the same boolean
index-bit witnesses, so the published nullifier is exactly the proven
leaf's — one note, one nullifier.

**The recipient cannot be swapped by a relayer.** `recipient_binding`
is a public input of the verified statement, so the proof is valid only
for the exact input vector the contract assembles from its `to`
argument — a relayer substituting a different recipient changes input
3 and the proof no longer verifies. The binding appears in one
multiplication constraint (`rb·rb = rb²`) purely so its column in the
constraint matrices is non-zero: a Groth16 public input appearing in no
constraint has a zero QAP column and would verify for *any* value (the
classic unconstrained-input malleability bug). The binding value itself
(`SHA-256(address XDR)` with the top byte cleared for field
canonicity) is computed by the contract, not proven in-circuit; the
circuit only needs it fixed, not preimage-checked.

**Every public input is constrained.** `root` and `nullifier` via
enforced equalities, `amount` inside the commitment hash,
`recipient_binding` via the pinning constraint.

## What the circuit deliberately does not prove

- **Nullifier freshness / root recency** — on-chain state, checked by
  the contract before verification.
- **`amount > 0` and token movement** — enforced by the contract.
