# `attesta-prover` — the CLI proving guide

The CLI prover turns your notes and the pool's public commitment log
into the proof bundles that `shielded_pool::transfer` and
`shielded_pool::withdraw` accept. Everything runs on your machine:
spending keys, note values, and blindings never leave the process. The
bundle files it writes contain only public data (the proof and the
public inputs), so they are safe to hand to a relayer.

```sh
cd circuits
cargo build --release --bin attesta-prover
./target/release/attesta-prover keygen
```

Proving keys are not committed (they are large); regenerate the
development artifacts with `scripts/build-artifacts.sh`.

> **Development keys only.** The committed artifacts come from a fixed
> public seed — anyone can forge proofs against them. They exercise the
> pipeline on testnet; production keys come from the multi-party
> ceremony (`../ceremony/`).

## Keys and notes

```sh
attesta-prover keygen                     # fresh sk/pk pair
attesta-prover pk --sk <hex>              # re-derive pk from sk
attesta-prover note --value 500 --owner-pk <hex>   # [--blinding <hex>]
```

`note` prints the commitment to deposit with
(`shielded_pool::deposit(from, token, amount, commitment)`) and the
blinding that spending it later requires. **Keep `sk` and each note's
`blinding` — losing either loses the funds; leaking `sk` loses them to
someone else.**

All hex field arguments are 32-byte big-endian scalars and must be
canonical (< the BLS12-381 scalar field order); values and leaf
indices are decimal.

## The commitment log

`--commitments` is a text file with one 32-byte hex leaf per line, in
leaf order (blank lines and `#` comments allowed). Reconstruct it from
the pool's events: each `Deposit` appends its `commitment` at
`leaf_index`, and each `ShieldedTransfer` appends its
`new_commitments` in order. The prover rebuilds the Merkle tree from
this log, so it must be complete and in order — a wrong log produces a
root the contract does not know.

## Proving a transfer

```sh
attesta-prover prove-transfer \
  --proving-key artifacts/transfer/proving_key.bin \
  --commitments log.txt \
  --spend  <sk>:<value>:<blinding>:<leaf_index> \
  --spend  <sk>:0:<any 32-byte hex>:0 \
  --output <owner_pk>:<value>:<blinding> \
  --output <owner_pk>:0:<blinding> \
  --out transfer.bundle
```

The circuit is fixed at 2-in/2-out, so `--spend` and `--output` appear
exactly twice each and input values must sum to output values. Pad
with dummies:

- **Dummy spend** — value `0` with a **fresh random `sk`** (use
  `keygen`; a dummy still publishes a nullifier, and reusing a real key
  at the same leaf index would collide with a real spend). The blinding
  and leaf index are ignored in-circuit.
- **Dummy output** — value `0` to any key you control, with a fresh
  blinding.

Spends of real notes are checked against the log before proving, so a
wrong key, value, blinding, or index fails immediately with a
diagnosable error instead of an unsatisfiable circuit.

## Proving a withdrawal

```sh
attesta-prover prove-withdraw \
  --proving-key artifacts/withdraw/proving_key.bin \
  --commitments log.txt \
  --spend <sk>:<value>:<blinding>:<leaf_index> \
  --recipient-binding <hex> \
  --out withdraw.bundle
```

A withdrawal exits one note's exact value. `--recipient-binding` must
equal the contract's binding of the payout address: the SHA-256 of the
address XDR with the top byte zeroed (`address_binding` in
`shielded_pool`). The proof commits to it, so a relayer submitting the
bundle cannot redirect the funds.

## Verifying a bundle

```sh
attesta-prover verify --vk artifacts/transfer/verifying_key.hex --bundle transfer.bundle
attesta-prover verify --vk artifacts/withdraw/verifying_key.hex --bundle withdraw.bundle
```

Runs the same Groth16 check the chain will, offline — useful before
paying fees, and for relayers screening bundles. Proof points are
rejected if off-curve or in the wrong subgroup.

## Bundle format and the contract call

Bundles are `key=value` lines (hex fields, decimal `amount`), starting
with `circuit=transfer` or `circuit=withdraw`. Fields map directly
onto the contract arguments:

| Bundle field | Contract argument |
| --- | --- |
| `proof.a` / `proof.b` / `proof.c` | `proof: Groth16Proof` (G1, G2, G1 — host encoding) |
| `root` | `root` — must still be a known root when the call lands |
| `nullifier.0`, `nullifier.1` | `nullifiers` (transfer) |
| `new_commitment.0`, `new_commitment.1` | `new_commitments` (transfer) |
| `nullifier` | `nullifier` (withdraw) |
| `recipient_binding` | must equal `address_binding(to)` (withdraw) |
| `amount` | `amount` (withdraw) |

`transfer` additionally takes `encrypted_notes` — the recipient-keyed
note ciphertexts. Encryption is a wallet-layer concern (M3); the
prover does not produce them.

The pool remembers every historical root, so a bundle stays valid
across deposits and transfers that land after proving — the
nullifier, not the root, is what prevents replay. Nullifiers spend on
submission: if a transfer bundle is submitted twice, the second call
fails with `AlreadySpent`.
