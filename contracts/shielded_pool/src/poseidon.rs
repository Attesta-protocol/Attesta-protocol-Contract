//! Poseidon 2-to-1 hash over the BLS12-381 scalar field, computed with
//! the Protocol 25 Fr host functions.
//!
//! This is the protocol hash pinned by M1: it must be constant-for-
//! constant identical to `circuits/src/poseidon.rs`, which the transfer
//! and withdraw circuits evaluate in-circuit over the same tree. The
//! round constants and MDS matrix in [`crate::poseidon_params`] are
//! generated from the circuits crate by
//! `circuits/scripts/build-artifacts.sh`; regenerating them there is
//! the only sanctioned way to change this function.
//!
//! [`Hasher`] loads the round constants as host objects once and reuses
//! them across evaluations — a Merkle insert hashes `TREE_DEPTH` times,
//! and per-hash constant loading dominates the invocation's memory
//! budget otherwise. A further known optimization (the sparse-matrix
//! partial-round evaluation from the Poseidon paper) is deliberately
//! deferred: it changes evaluation strategy, not the function, and
//! belongs with M2 cost tuning.

use crate::poseidon_params::{ARK, FULL_ROUNDS, MDS, PARTIAL_ROUNDS, WIDTH};
use soroban_sdk::crypto::bls12_381::{Bls12_381, Bls12381Fr};
use soroban_sdk::{BytesN, Env, U256};

const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

/// The Poseidon permutation with its constants resident as host objects.
pub struct Hasher {
    bls: Bls12_381,
    zero: Bls12381Fr,
    ark: [[Bls12381Fr; WIDTH]; TOTAL_ROUNDS],
    mds: [[Bls12381Fr; WIDTH]; WIDTH],
}

impl Hasher {
    /// Loads the generated constants. Do this once per invocation and
    /// reuse the hasher for every hash it needs.
    pub fn new(env: &Env) -> Self {
        let fr = |bytes: &[u8; 32]| Bls12381Fr::from_bytes(BytesN::from_array(env, bytes));
        Hasher {
            bls: env.crypto().bls12_381(),
            zero: Bls12381Fr::from_u256(U256::from_u32(env, 0)),
            ark: core::array::from_fn(|r| core::array::from_fn(|i| fr(&ARK[r][i]))),
            mds: core::array::from_fn(|r| core::array::from_fn(|i| fr(&MDS[r][i]))),
        }
    }

    /// S-box `x^5`.
    fn sbox(&self, x: &Bls12381Fr) -> Bls12381Fr {
        self.bls.fr_pow(x, 5)
    }

    /// The Poseidon permutation on a width-3 state.
    fn permute(&self, mut state: [Bls12381Fr; WIDTH]) -> [Bls12381Fr; WIDTH] {
        let half_full = FULL_ROUNDS / 2;
        for round in 0..TOTAL_ROUNDS {
            // Add round constants.
            for (lane, c) in state.iter_mut().zip(self.ark[round].iter()) {
                *lane = self.bls.fr_add(lane, c);
            }
            // S-box: every lane in full rounds, lane 0 in partial rounds.
            let full = round < half_full || round >= half_full + PARTIAL_ROUNDS;
            if full {
                for lane in state.iter_mut() {
                    *lane = self.sbox(lane);
                }
            } else {
                state[0] = self.sbox(&state[0]);
            }
            // MDS mix.
            let mixed: [Bls12381Fr; WIDTH] = core::array::from_fn(|i| {
                let row = &self.mds[i];
                let mut acc = self.bls.fr_mul(&state[0], &row[0]);
                for (lane, m) in state.iter().zip(row.iter()).skip(1) {
                    acc = self.bls.fr_add(&acc, &self.bls.fr_mul(lane, m));
                }
                acc
            });
            state = mixed;
        }
        state
    }

    /// 2-to-1 compression: `permute([0, l, r])[0]`, identical to
    /// `attesta_circuits::poseidon::hash2`. Inputs must be canonical
    /// big-endian field elements (< the group order), which note
    /// commitments and Merkle nodes are by construction.
    pub fn hash2(&self, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
        let state = self.permute([
            self.zero.clone(),
            Bls12381Fr::from_bytes(left.clone()),
            Bls12381Fr::from_bytes(right.clone()),
        ]);
        state[0].to_bytes()
    }
}

/// One-shot convenience for single hashes; loads the constants each
/// call, so batched callers should hold a [`Hasher`] instead.
#[cfg(test)]
pub fn hash2(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    Hasher::new(env).hash2(left, right)
}
