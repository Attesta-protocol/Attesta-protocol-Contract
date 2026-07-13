//! # zk_verifier
//!
//! On-chain Groth16 verification over BLS12-381 using Stellar Protocol 25
//! host functions.
//!
//! One verifier instance is deployed **per circuit** (transfer, withdraw,
//! attestation), each pinned to a published verifying key at construction.
//! The key is immutable for the life of the instance — there is no admin,
//! no upgrade hook, and no way to mutate it. Circuit upgrades deploy a new
//! verifier instance and switch consumers over behind the timelocked
//! governance path (see `issuer_registry` for the timelock pattern).
//!
//! Verifying keys, circuits, and the trusted-setup ceremony transcript are
//! published in this repository under `circuits/` (M1).
//!
//! ## Storage
//! - `DataKey::CircuitId` (instance): `Symbol` naming the pinned circuit.
//! - `DataKey::Vk` (instance): the immutable [`VerificationKey`].

#![no_std]

use attesta_interfaces::{Groth16Proof, VerificationKey, Verifier};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bls12_381::{Bls12381Fr, Bls12381G1Affine, Bls12381G2Affine},
    panic_with_error, vec, BytesN, Env, Symbol, Vec, U256,
};

/// The BLS12-381 scalar field order minus one, big-endian. Multiplying a G1
/// point by this scalar negates it, which is how we fold `-A` into the
/// single multi-pairing check below.
const FR_MINUS_ONE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
];

#[contracttype]
enum DataKey {
    CircuitId,
    Vk,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VerifierError {
    /// The verifying key must have exactly one more IC point than the
    /// circuit has public inputs; a mismatched call is a caller bug.
    InputLengthMismatch = 1,
    /// The verifying key is malformed (empty IC).
    MalformedKey = 2,
    /// A public input is not a canonical field element (≥ the group
    /// order). The host reduces scalars mod r silently, so `x` and
    /// `x + r` are distinct byte strings naming the same field element —
    /// accepting both would let callers replay one proof under two
    /// encodings (e.g. spending one nullifier twice). Canonical bytes
    /// are required so each statement has exactly one encoding.
    NonCanonicalInput = 3,
}

#[contract]
pub struct ZkVerifier;

#[contractimpl]
impl ZkVerifier {
    /// Deploy-time initialization. `vk` is pinned forever; `circuit_id`
    /// names the circuit (e.g. `transfer`, `withdraw`, `attest_kyc`) so
    /// indexers and integrators can identify instances on-chain.
    pub fn __constructor(env: Env, circuit_id: Symbol, vk: VerificationKey) {
        if vk.ic.is_empty() {
            panic_with_error!(&env, VerifierError::MalformedKey);
        }
        env.storage()
            .instance()
            .set(&DataKey::CircuitId, &circuit_id);
        env.storage().instance().set(&DataKey::Vk, &vk);
    }

    /// The circuit this instance is pinned to.
    pub fn circuit_id(env: Env) -> Symbol {
        env.storage().instance().get(&DataKey::CircuitId).unwrap()
    }

    /// The pinned verifying key, for provers and auditors.
    pub fn vk(env: Env) -> VerificationKey {
        env.storage().instance().get(&DataKey::Vk).unwrap()
    }
}

#[contractimpl]
impl Verifier for ZkVerifier {
    /// Groth16 verification: checks
    /// `e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1`
    /// where `vk_x = IC[0] + Σ input_i · IC[i+1]`, as a single host-function
    /// multi-pairing.
    ///
    /// Public inputs are big-endian 32-byte scalars and must be canonical
    /// field elements (< the group order); non-canonical encodings panic
    /// with [`VerifierError::NonCanonicalInput`] rather than being
    /// silently reduced — see that variant for why accepting them would
    /// be unsound for consumers keyed on input bytes (nullifier sets).
    fn verify(env: Env, proof: Groth16Proof, public_inputs: Vec<BytesN<32>>) -> bool {
        let vk: VerificationKey = env.storage().instance().get(&DataKey::Vk).unwrap();
        if public_inputs.len() + 1 != vk.ic.len() {
            panic_with_error!(&env, VerifierError::InputLengthMismatch);
        }
        for input in public_inputs.iter() {
            // Canonical ⇔ input ≤ r − 1, compared big-endian.
            if input.to_array() > FR_MINUS_ONE {
                panic_with_error!(&env, VerifierError::NonCanonicalInput);
            }
        }

        let bls = env.crypto().bls12_381();

        // vk_x = IC[0] + Σ input_i · IC[i+1], via one multi-scalar mul.
        let mut points: Vec<Bls12381G1Affine> = vec![&env];
        let mut scalars: Vec<Bls12381Fr> = vec![&env];
        points.push_back(Bls12381G1Affine::from_bytes(vk.ic.get_unchecked(0)));
        scalars.push_back(Bls12381Fr::from_u256(U256::from_u32(&env, 1)));
        for (i, input) in public_inputs.iter().enumerate() {
            points.push_back(Bls12381G1Affine::from_bytes(
                vk.ic.get_unchecked(i as u32 + 1),
            ));
            scalars.push_back(Bls12381Fr::from_bytes(input));
        }
        let vk_x = bls.g1_msm(points, scalars);

        // -A = A · (r - 1)
        let a = Bls12381G1Affine::from_bytes(proof.a);
        let neg_a = bls.g1_mul(
            &a,
            &Bls12381Fr::from_bytes(BytesN::from_array(&env, &FR_MINUS_ONE)),
        );

        let vp1: Vec<Bls12381G1Affine> = vec![
            &env,
            neg_a,
            Bls12381G1Affine::from_bytes(vk.alpha),
            vk_x,
            Bls12381G1Affine::from_bytes(proof.c),
        ];
        let vp2: Vec<Bls12381G2Affine> = vec![
            &env,
            Bls12381G2Affine::from_bytes(proof.b),
            Bls12381G2Affine::from_bytes(vk.beta),
            Bls12381G2Affine::from_bytes(vk.gamma),
            Bls12381G2Affine::from_bytes(vk.delta),
        ];
        bls.pairing_check(vp1, vp2)
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_real_proof;
