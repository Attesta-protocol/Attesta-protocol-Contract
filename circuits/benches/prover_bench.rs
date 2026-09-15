//! Prover-side performance benchmarks: proving-key load (checked vs.
//! hash-verified unchecked), Merkle tree rebuild at increasing commitment
//! log sizes, and end-to-end transfer/withdraw proving.
//!
//! `cargo bench` runs these against the real protocol shape (tree depth
//! [`POOL_TREE_DEPTH`], 2-in/2-out transfer) using freshly generated dev
//! keys (never committed — see `circuits/artifacts/README.md`), so numbers
//! reflect what `attesta-prover` actually does. Proving is CPU-heavy
//! (~10s/transfer, ~5s/withdraw on the reference machine noted in
//! `circuits/docs/prover.md`), so those two groups pin `sample_size` to
//! criterion's minimum (10) — expect this file to take several minutes.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use attesta_circuits::artifacts::{load_proving_key_bytes, sha256_hex};
use attesta_circuits::merkle::POOL_TREE_DEPTH;
use attesta_circuits::note::{derive_pk, Note};
use attesta_circuits::prover::{prove_transfer, prove_withdraw, rebuild_tree, Output, Spend};
use attesta_circuits::transfer::TransferCircuit;
use attesta_circuits::withdraw::WithdrawCircuit;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn key_load_benches(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(0xbe4c4);
    let (transfer_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
        TransferCircuit::blank(POOL_TREE_DEPTH, 2, 2),
        &mut rng,
    )
    .unwrap();
    let mut bytes = Vec::new();
    transfer_pk.serialize_compressed(&mut bytes).unwrap();
    let hash = sha256_hex(&bytes);
    let wrong_hash = "0".repeat(64);

    let mut group = c.benchmark_group("proving_key_load_transfer");
    group.sample_size(20);
    group.bench_function("checked (no hash)", |b| {
        b.iter(|| load_proving_key_bytes(&bytes, None).unwrap())
    });
    group.bench_function("hash mismatch (falls back to checked)", |b| {
        b.iter(|| load_proving_key_bytes(&bytes, Some(&wrong_hash)).unwrap())
    });
    group.bench_function("hash match (unchecked fast path)", |b| {
        b.iter(|| load_proving_key_bytes(&bytes, Some(&hash)).unwrap())
    });
    group.finish();

    println!("proving_key.bin (transfer, dev key): {} bytes", bytes.len());
}

fn tree_rebuild_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree_rebuild");
    group.sample_size(10);
    for size in [1_000usize, 10_000, 100_000] {
        let leaves: Vec<Fr> = (0..size as u64).map(Fr::from).collect();
        group.bench_with_input(BenchmarkId::from_parameter(size), &leaves, |b, leaves| {
            b.iter(|| rebuild_tree(leaves))
        });
    }
    group.finish();
}

fn proving_benches(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(0xf00d);
    let (transfer_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
        TransferCircuit::blank(POOL_TREE_DEPTH, 2, 2),
        &mut rng,
    )
    .unwrap();
    let (withdraw_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
        WithdrawCircuit::blank(POOL_TREE_DEPTH),
        &mut rng,
    )
    .unwrap();

    let sk = Fr::from(11u64);
    let note = Note {
        value: 500,
        owner_pk: derive_pk(sk),
        blinding: Fr::from(101u64),
    };
    let log = vec![note.commitment()];

    let spends = [
        Spend {
            sk,
            value: 500,
            blinding: Fr::from(101u64),
            leaf_index: 0,
        },
        Spend {
            sk: Fr::rand(&mut rng),
            value: 0,
            blinding: Fr::from(0u64),
            leaf_index: 0,
        },
    ];
    let outputs = [
        Output {
            owner_pk: derive_pk(Fr::from(33u64)),
            value: 500,
            blinding: Fr::from(201u64),
        },
        Output {
            owner_pk: derive_pk(sk),
            value: 0,
            blinding: Fr::from(202u64),
        },
    ];

    let mut group = c.benchmark_group("proving");
    group.sample_size(10); // criterion's minimum; each iteration is ~seconds
    group.bench_function("transfer (2-in/2-out)", |b| {
        b.iter(|| prove_transfer(&transfer_pk, &log, &spends, &outputs, &mut rng).unwrap())
    });
    group.bench_function("withdraw", |b| {
        b.iter(|| {
            prove_withdraw(
                &withdraw_pk,
                &log,
                &Spend {
                    sk,
                    value: 500,
                    blinding: Fr::from(101u64),
                    leaf_index: 0,
                },
                Fr::from(4242u64),
                &mut rng,
            )
            .unwrap()
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    key_load_benches,
    tree_rebuild_benches,
    proving_benches
);
criterion_main!(benches);
