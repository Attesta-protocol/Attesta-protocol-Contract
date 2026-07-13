#![cfg(test)]

use super::*;
use attesta_interfaces::{Groth16Proof, VerificationKey};
use soroban_sdk::{symbol_short, vec, Bytes, Env};

/// Fabricate structurally valid (on-curve, in-subgroup) points via
/// hash-to-curve. They satisfy the encoding checks of the host functions but
/// are not a real proof/key pair, so verification must return false.
fn arbitrary_g1(env: &Env, seed: &[u8]) -> BytesN<96> {
    let dst = Bytes::from_slice(env, b"ATTESTA_TEST_G1");
    let msg = Bytes::from_slice(env, seed);
    env.crypto().bls12_381().hash_to_g1(&msg, &dst).to_bytes()
}

fn arbitrary_g2(env: &Env, seed: &[u8]) -> BytesN<192> {
    let dst = Bytes::from_slice(env, b"ATTESTA_TEST_G2");
    let msg = Bytes::from_slice(env, seed);
    env.crypto().bls12_381().hash_to_g2(&msg, &dst).to_bytes()
}

fn test_vk(env: &Env, num_inputs: u32) -> VerificationKey {
    let mut ic = vec![env];
    for i in 0..=num_inputs {
        ic.push_back(arbitrary_g1(env, &[b'i', b'c', i as u8]));
    }
    VerificationKey {
        alpha: arbitrary_g1(env, b"alpha"),
        beta: arbitrary_g2(env, b"beta"),
        gamma: arbitrary_g2(env, b"gamma"),
        delta: arbitrary_g2(env, b"delta"),
        ic,
    }
}

fn test_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: arbitrary_g1(env, b"proof-a"),
        b: arbitrary_g2(env, b"proof-b"),
        c: arbitrary_g1(env, b"proof-c"),
    }
}

#[test]
fn vk_is_pinned_at_construction() {
    let env = Env::default();
    let vk = test_vk(&env, 2);
    let id = env.register(ZkVerifier, (symbol_short!("transfer"), vk.clone()));
    let client = ZkVerifierClient::new(&env, &id);

    assert_eq!(client.circuit_id(), symbol_short!("transfer"));
    assert_eq!(client.vk(), vk);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn rejects_empty_verifying_key() {
    let env = Env::default();
    let vk = VerificationKey {
        alpha: arbitrary_g1(&env, b"alpha"),
        beta: arbitrary_g2(&env, b"beta"),
        gamma: arbitrary_g2(&env, b"gamma"),
        delta: arbitrary_g2(&env, b"delta"),
        ic: vec![&env],
    };
    env.register(ZkVerifier, (symbol_short!("transfer"), vk));
}

#[test]
fn invalid_proof_is_rejected() {
    let env = Env::default();
    let vk = test_vk(&env, 1);
    let id = env.register(ZkVerifier, (symbol_short!("transfer"), vk));
    let client = ZkVerifierClient::new(&env, &id);

    let inputs = vec![&env, BytesN::from_array(&env, &[7u8; 32])];
    // Arbitrary points cannot satisfy the pairing equation.
    assert!(!client.verify(&test_proof(&env), &inputs));
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn input_length_mismatch_panics() {
    let env = Env::default();
    let vk = test_vk(&env, 2);
    let id = env.register(ZkVerifier, (symbol_short!("withdraw"), vk));
    let client = ZkVerifierClient::new(&env, &id);

    // vk expects 2 public inputs; supply 1.
    let inputs = vec![&env, BytesN::from_array(&env, &[1u8; 32])];
    client.verify(&test_proof(&env), &inputs);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn non_canonical_input_is_rejected() {
    let env = Env::default();
    let vk = test_vk(&env, 1);
    let id = env.register(ZkVerifier, (symbol_short!("transfer"), vk));
    let client = ZkVerifierClient::new(&env, &id);

    // The group order r itself: one more than the largest canonical
    // scalar. The host would reduce it to 0, so a proof for input 0
    // would verify under both encodings — reject it instead.
    let mut r = super::FR_MINUS_ONE;
    r[31] = 0x01;
    let inputs = vec![&env, BytesN::from_array(&env, &r)];
    client.verify(&test_proof(&env), &inputs);
}

#[test]
fn largest_canonical_input_is_accepted() {
    let env = Env::default();
    let vk = test_vk(&env, 1);
    let id = env.register(ZkVerifier, (symbol_short!("transfer"), vk));
    let client = ZkVerifierClient::new(&env, &id);

    // r - 1 is canonical: must reach the pairing check (and fail it,
    // since the key/proof are arbitrary points) instead of panicking.
    let inputs = vec![&env, BytesN::from_array(&env, &super::FR_MINUS_ONE)];
    assert!(!client.verify(&test_proof(&env), &inputs));
}
