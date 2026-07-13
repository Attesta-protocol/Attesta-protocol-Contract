#![cfg(test)]
//! On-chain verification of *real* Groth16 proofs: witnesses proven with
//! `attesta-circuits` at the protocol shape (depth-20 tree, 2-in/2-out),
//! verified by this contract through the Protocol 25 host functions.
//! This is the cross-layer test that pins the circuits' encodings and
//! public-input layouts to the contract's.

extern crate std;

use super::*;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use attesta_circuits::encoding::{fr_to_bytes, proof_to_bytes, vk_to_bytes};
use attesta_circuits::merkle::{MerkleTree, POOL_TREE_DEPTH};
use attesta_circuits::note::{derive_nullifier, derive_pk, Note};
use attesta_circuits::transfer::{NewNote, SpentNote, TransferCircuit};
use attesta_interfaces::VerificationKey;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use soroban_sdk::{symbol_short, vec, Env, Vec};

fn to_soroban_vk(env: &Env, vk: &ark_groth16::VerifyingKey<Bls12_381>) -> VerificationKey {
    let b = vk_to_bytes(vk);
    let mut ic = vec![env];
    for p in &b.ic {
        ic.push_back(BytesN::from_array(env, p));
    }
    VerificationKey {
        alpha: BytesN::from_array(env, &b.alpha),
        beta: BytesN::from_array(env, &b.beta),
        gamma: BytesN::from_array(env, &b.gamma),
        delta: BytesN::from_array(env, &b.delta),
        ic,
    }
}

fn to_soroban_proof(env: &Env, proof: &ark_groth16::Proof<Bls12_381>) -> Groth16Proof {
    let b = proof_to_bytes(proof);
    Groth16Proof {
        a: BytesN::from_array(env, &b.a),
        b: BytesN::from_array(env, &b.b),
        c: BytesN::from_array(env, &b.c),
    }
}

#[test]
fn real_transfer_proof_verifies_on_chain() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x0e2e);
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        TransferCircuit::blank(POOL_TREE_DEPTH, 2, 2),
        &mut rng,
    )
    .unwrap();

    // A real spend: 600 + 400 in, 750 + 250 out.
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
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
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

    let public_inputs = [
        tree.root(),
        derive_nullifier(sk1, i1),
        derive_nullifier(sk2, i2),
        out1.commitment(),
        out2.commitment(),
    ];
    let circuit = TransferCircuit {
        depth: POOL_TREE_DEPTH,
        root: Some(public_inputs[0]),
        nullifiers: std::vec![Some(public_inputs[1]), Some(public_inputs[2])],
        new_commitments: std::vec![Some(public_inputs[3]), Some(public_inputs[4])],
        spent: std::vec![
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
        created: std::vec![Some(out1), Some(out2)],
    };
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();

    // On-chain: pin the VK into a verifier instance and verify for real.
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let id = env.register(
        ZkVerifier,
        (symbol_short!("transfer"), to_soroban_vk(&env, &vk)),
    );
    let client = ZkVerifierClient::new(&env, &id);

    let mut inputs: Vec<BytesN<32>> = vec![&env];
    for x in &public_inputs {
        inputs.push_back(BytesN::from_array(&env, &fr_to_bytes(*x)));
    }
    let soroban_proof = to_soroban_proof(&env, &proof);
    assert!(client.verify(&soroban_proof, &inputs));

    // The same proof for a tampered statement must fail: claim a
    // different nullifier.
    let mut tampered = inputs.clone();
    tampered.set(
        1,
        BytesN::from_array(&env, &fr_to_bytes(Fr::from(31337u64))),
    );
    assert!(!client.verify(&soroban_proof, &tampered));
}

#[test]
fn real_withdraw_proof_verifies_on_chain() {
    use attesta_circuits::withdraw::WithdrawCircuit;

    let mut rng = ChaCha20Rng::seed_from_u64(0x0e2f);
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        WithdrawCircuit::blank(POOL_TREE_DEPTH),
        &mut rng,
    )
    .unwrap();

    let sk = Fr::from(11u64);
    let note = Note {
        value: 900,
        owner_pk: derive_pk(sk),
        blinding: Fr::from(101u64),
    };
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
    let idx = tree.insert(note.commitment());
    let binding = Fr::from(4242u64);

    let public_inputs = [
        tree.root(),
        derive_nullifier(sk, idx),
        binding,
        Fr::from(note.value),
    ];
    let circuit = WithdrawCircuit {
        depth: POOL_TREE_DEPTH,
        root: Some(public_inputs[0]),
        nullifier: Some(public_inputs[1]),
        recipient_binding: Some(binding),
        amount: Some(public_inputs[3]),
        sk: Some(sk),
        blinding: Some(note.blinding),
        path: Some(tree.path(idx)),
    };
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let id = env.register(
        ZkVerifier,
        (symbol_short!("withdraw"), to_soroban_vk(&env, &vk)),
    );
    let client = ZkVerifierClient::new(&env, &id);

    let mut inputs: Vec<BytesN<32>> = vec![&env];
    for x in &public_inputs {
        inputs.push_back(BytesN::from_array(&env, &fr_to_bytes(*x)));
    }
    let soroban_proof = to_soroban_proof(&env, &proof);
    assert!(client.verify(&soroban_proof, &inputs));

    // The recipient binding is part of the statement: redirecting the
    // exit must invalidate the proof on-chain, exactly as it does
    // natively — this is what stops a relayer stealing a withdrawal.
    let mut redirected = inputs.clone();
    redirected.set(2, BytesN::from_array(&env, &fr_to_bytes(Fr::from(6666u64))));
    assert!(!client.verify(&soroban_proof, &redirected));

    // And a different claimed amount is a different statement.
    let mut inflated = inputs.clone();
    inflated.set(3, BytesN::from_array(&env, &fr_to_bytes(Fr::from(901u64))));
    assert!(!client.verify(&soroban_proof, &inflated));
}
