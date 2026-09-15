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

`note` prints the `owner_pk` and `blinding` to deposit with
(`shielded_pool::deposit(from, token, amount, owner_pk, blinding)` —
the contract derives the commitment itself from these plus the amount
transferred, so a note's shielded value can never diverge from what was
actually paid in) and the blinding that spending it later requires.
**Keep `sk` and each note's `blinding` — losing either loses the funds;
leaking `sk` loses them to someone else.**

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

## Key loading: integrity-checked fast path

`--proving-key` loads through `attesta_circuits::artifacts::load_proving_key`,
which looks for a `SHA256SUMS` file next to the key (the format
`scripts/build-artifacts.sh` emits — `<hex>  <filename>` per line). If
the key's own SHA-256 matches the recorded entry, loading uses
arkworks' unchecked deserializer: `deserialize_compressed` validates
every curve point on the way in, which is redundant once the file's
hash is already pinned, and that validation dominates startup for the
4MB transfer key. A missing or mismatched `SHA256SUMS` entry always
falls back to the fully validating path — there is no flag to skip
validation without a matching hash.

Measured with `cargo bench` (`circuits/benches/prover_bench.rs`),
single-threaded, on a 2-core Intel Xeon Platinum 8370C @ 2.80GHz
(rustc 1.98.1, release profile — a shared CI-class VM, not dedicated
hardware, so treat these as ballpark, not a regression gate):

| Benchmark | Time |
| --- | --- |
| `proving_key.bin` (transfer, 3,998,544 bytes) load — checked | 7.33 s |
| — hash mismatch (falls back to checked) | 7.34 s |
| — hash match (unchecked fast path) | **2.58 s (≈2.8×)** |
| Merkle tree rebuild, 1,000 leaves | 0.69 s |
| Merkle tree rebuild, 10,000 leaves | 6.92 s |
| Merkle tree rebuild, 100,000 leaves | 72.96 s |
| Transfer proof (2-in/2-out) | 2.54 s |
| Withdraw proof | 1.46 s |

The tree-rebuild numbers scale roughly linearly with leaf count — the
prover currently rebuilds the full tree from the commitment log on
every invocation (no persisted-tree cache), so a wallet with a large
history pays this cost on every `prove-transfer`/`prove-withdraw` call.
Fine today; worth a follow-up (a cached, incrementally-updated local
tree) if provers start seeing six-figure leaf counts in practice.

Run `cargo bench` from `circuits/` to reproduce on your machine.

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
