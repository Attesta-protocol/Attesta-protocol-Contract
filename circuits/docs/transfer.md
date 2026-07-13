# Soundness argument — `transfer` circuit

Per [CONTRIBUTING](../CONTRIBUTING.md), this document states what the
circuit proves, its exact public-input layout, and why the constraint
system admits no witness outside the intended relation. It must be
updated in the same PR as any constraint change.

## Statement

For a pool tree of depth `d` and a fixed arity of `n_in` spent /
`n_out` created notes, the prover knows notes and keys such that:

1. every spent note's commitment is a leaf of the commitment tree under
   the public `root` (or the note is an explicit zero-value dummy),
2. the prover holds the spending key of every spent note,
3. each public nullifier is correctly derived from that key and the
   note's leaf index,
4. every created note's public commitment is well-formed over a
   64-bit value, and
5. total spent value equals total created value.

## Public-input layout

Field elements, in the order `shielded_pool::transfer` builds them:

| Index | Input |
| --- | --- |
| 0 | `root` |
| 1 ‥ n_in | `nullifier_i` |
| n_in+1 ‥ n_in+n_out | `new_commitment_j` |

Total: `1 + n_in + n_out` (see `lib.rs::layout::transfer_public_inputs`).
The protocol instance is `d = 20`, `n_in = n_out = 2`.

## Why the relation is sound

Notation: `H` is the protocol Poseidon 2-to-1 hash (see
`src/poseidon.rs`), assumed collision-resistant on field pairs.

**Values cannot leave 64 bits.** Every note value (spent and created)
enters the circuit only as the recomposition `Σ b_i·2^i` of 64 boolean
witnesses, so it is an integer in `[0, 2^64)` by construction. With
`n_in, n_out ≤ 4` the sums stay below `2^66 ≪ p`, so the field equation
`Σ in = Σ out` is integer equality: **no inflation** (5).

**Ownership is forced, not claimed.** The spent-note commitment is
recomputed in-circuit as `H(H(v, H(1, sk)), blinding)` from the witness
`sk`. A prover who does not know a preimage `sk` for the note's owner
key cannot produce any witness assignment matching a real leaf, except
by finding an `H` collision (2).

**Membership binds to the public root.** The recomputed commitment is
hashed up the tree through witness siblings steered by witness index
bits, and the result is constrained equal to the public `root`. Any
fabricated leaf or path requires an `H` collision (1).

**Nullifiers are bound to the same leaf as the path.** The nullifier is
constrained as `H(H(2, sk), Σ bit_i·2^i)` over the *same* boolean index
bits that steer the Merkle path. A prover therefore cannot prove
membership at leaf `i` while publishing the nullifier of leaf `j ≠ i`;
double-spending one note under two nullifiers would require an `H`
collision (3). Domain tag 2 separates nullifier derivation from key
derivation (tag 1), so publishing nullifiers reveals nothing about
`pk`.

**Dummy inputs are value-free.** The membership constraint is relaxed
(conditionally enforced) exactly when the spent value is zero — the
`is_real` flag is `value ≠ 0`, computed in-circuit from the range-checked
value, not a free witness. A dummy therefore contributes 0 to the input
sum and cannot mint value. Its nullifier is still a public input and
still constrained to `H(H(2, sk), index)`; clients use a fresh random
`sk` per dummy so these are unique. (This is the standard
Sapling-style dummy-note pattern.)

**Created notes are well-formed.** Each public `new_commitment` is
constrained equal to `H(H(v, pk), blinding)` over a range-checked `v`
(4). The recipient `pk` and `blinding` are private, so amounts and
recipients' keys never appear on-chain.

**Every public input is constrained.** `root`, each nullifier, and each
commitment all appear in enforced equalities above; there are no
unconstrained public inputs (the classic Groth16 malleability bug).

## What the circuit deliberately does not prove

- **Nullifier freshness** — the spent set is on-chain state; the
  contract rejects known nullifiers and intra-call duplicates.
- **Root recency** — the contract checks `root` against its known-root
  set.
- **Ciphertext correctness** — encrypted notes are relay payload, not
  consensus data; a sender who garbles them harms only their recipient
  (funds remain spendable by the committed `pk`).
