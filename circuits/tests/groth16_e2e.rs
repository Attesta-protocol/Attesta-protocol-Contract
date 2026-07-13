//! End-to-end Groth16 tests: generate keys from the blank circuit
//! shapes, prove with real witnesses, verify — and reject tampered
//! statements. This is the native counterpart of what the on-chain
//! `zk_verifier` does with the same keys and proofs.

use ark_bls12_381::Fr;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use attesta_circuits::merkle::MerkleTree;
use attesta_circuits::note::{derive_nullifier, derive_pk, Note};
use attesta_circuits::transfer::{NewNote, SpentNote, TransferCircuit};
use attesta_circuits::withdraw::WithdrawCircuit;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const DEPTH: usize = 8;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0xa77e57a)
}

#[test]
fn transfer_proof_verifies_and_tampering_fails() {
    let mut rng = rng();
    let (pk, vk) =
        Groth16::<ark_bls12_381::Bls12_381>::circuit_specific_setup(
            TransferCircuit::blank(DEPTH, 2, 2),
            &mut rng,
        )
        .unwrap();

    // 600 + 400 in, 750 + 250 out.
    let sk1 = Fr::from(11u64);
    let sk2 = Fr::from(22u64);
    let n1 = Note {
        value: 600,
        owner_pk: derive_pk(sk1),
        blinding: Fr::from(101u64),
    };
    let n2 = Note {
        value: 400,
        owner_pk: derive_pk(sk2),
        blinding: Fr::from(102u64),
    };
    let mut tree = MerkleTree::new(DEPTH);
    let i1 = tree.insert(n1.commitment());
    let i2 = tree.insert(n2.commitment());
    let out1 = NewNote {
        value: 750,
        owner_pk: derive_pk(Fr::from(33u64)),
        blinding: Fr::from(201u64),
    };
    let out2 = NewNote {
        value: 250,
        owner_pk: derive_pk(sk1),
        blinding: Fr::from(202u64),
    };

    let public_inputs = vec![
        tree.root(),
        derive_nullifier(sk1, i1),
        derive_nullifier(sk2, i2),
        out1.commitment(),
        out2.commitment(),
    ];
    let circuit = TransferCircuit {
        depth: DEPTH,
        root: Some(public_inputs[0]),
        nullifiers: vec![Some(public_inputs[1]), Some(public_inputs[2])],
        new_commitments: vec![Some(public_inputs[3]), Some(public_inputs[4])],
        spent: vec![
            Some(SpentNote {
                value: n1.value,
                sk: sk1,
                blinding: n1.blinding,
                path: tree.path(i1),
            }),
            Some(SpentNote {
                value: n2.value,
                sk: sk2,
                blinding: n2.blinding,
                path: tree.path(i2),
            }),
        ],
        created: vec![Some(out1), Some(out2)],
    };

    let proof = Groth16::<ark_bls12_381::Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(
        Groth16::<ark_bls12_381::Bls12_381>::verify(&vk, &public_inputs, &proof).unwrap()
    );

    // Any tampered statement must fail: try swapping a nullifier.
    let mut tampered = public_inputs.clone();
    tampered[1] = Fr::from(31337u64);
    assert!(
        !Groth16::<ark_bls12_381::Bls12_381>::verify(&vk, &tampered, &proof).unwrap()
    );
}

#[test]
fn withdraw_proof_verifies_and_recipient_swap_fails() {
    let mut rng = rng();
    let (pk, vk) = Groth16::<ark_bls12_381::Bls12_381>::circuit_specific_setup(
        WithdrawCircuit::blank(DEPTH),
        &mut rng,
    )
    .unwrap();

    let sk = Fr::from(11u64);
    let note = Note {
        value: 900,
        owner_pk: derive_pk(sk),
        blinding: Fr::from(101u64),
    };
    let mut tree = MerkleTree::new(DEPTH);
    let idx = tree.insert(note.commitment());
    let recipient_binding = Fr::from(4242u64);

    let public_inputs = vec![
        tree.root(),
        derive_nullifier(sk, idx),
        recipient_binding,
        Fr::from(note.value),
    ];
    let circuit = WithdrawCircuit {
        depth: DEPTH,
        root: Some(public_inputs[0]),
        nullifier: Some(public_inputs[1]),
        recipient_binding: Some(recipient_binding),
        amount: Some(public_inputs[3]),
        sk: Some(sk),
        blinding: Some(note.blinding),
        path: Some(tree.path(idx)),
    };

    let proof = Groth16::<ark_bls12_381::Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(
        Groth16::<ark_bls12_381::Bls12_381>::verify(&vk, &public_inputs, &proof).unwrap()
    );

    // A relayer redirecting the exit changes public input 2 → invalid.
    let mut redirected = public_inputs.clone();
    redirected[2] = Fr::from(6666u64);
    assert!(
        !Groth16::<ark_bls12_381::Bls12_381>::verify(&vk, &redirected, &proof).unwrap()
    );
}
