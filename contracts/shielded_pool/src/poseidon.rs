//! Poseidon 2-to-1 hash over the BLS12-381 scalar field, computed
//! in-wasm with `ark-ff`.
//!
//! This is the protocol hash pinned by M1: it must be constant-for-
//! constant identical to `circuits/src/poseidon.rs`, which the transfer
//! and withdraw circuits evaluate in-circuit over the same tree. The
//! round constants and MDS matrix in [`crate::poseidon_params`] are
//! generated from the circuits crate by
//! `circuits/scripts/build-artifacts.sh`; regenerating them there is
//! the only sanctioned way to change this function.
//!
//! ## Why in-wasm rather than the Fr host functions
//!
//! A permutation is ~850 field operations; through the host functions
//! each is a metered host call (~8k instructions of dispatch and
//! metering), putting a 20-level Merkle insert far above the network's
//! per-transaction CPU limit. The identical arithmetic compiled into
//! the contract wasm is metered as plain wasm instructions and is
//! roughly 25× cheaper. The cost is binary size (the `ark-ff` Fr
//! backend), which the release profile's `opt-level = "z"` + LTO keeps
//! modest. The e2e cost benchmark in `test_e2e.rs` guards the limits.

use crate::poseidon_params::{ARK, FULL_ROUNDS, MDS, PARTIAL_ROUNDS, WIDTH};
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use soroban_sdk::{BytesN, Env};

fn fr(bytes: &[u8; 32]) -> Fr {
    // Constants and inputs are canonical big-endian encodings (< r);
    // callers enforce canonicity at the contract boundary.
    Fr::from_be_bytes_mod_order(bytes)
}

/// The Poseidon permutation on a width-3 state; constant-for-constant
/// identical to `attesta_circuits::poseidon::permute`.
fn permute(mut state: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let half_full = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;
    for round in 0..total {
        // Add round constants.
        for (lane, c) in state.iter_mut().zip(ARK[round].iter()) {
            *lane += fr(c);
        }
        // S-box x^5: every lane in full rounds, lane 0 in partial rounds.
        let full = round < half_full || round >= half_full + PARTIAL_ROUNDS;
        if full {
            for lane in state.iter_mut() {
                *lane = lane.pow([5u64]);
            }
        } else {
            state[0] = state[0].pow([5u64]);
        }
        // MDS mix.
        let mut mixed = [Fr::zero(); WIDTH];
        for (i, row) in MDS.iter().enumerate() {
            for (lane, m) in state.iter().zip(row.iter()) {
                mixed[i] += *lane * fr(m);
            }
        }
        state = mixed;
    }
    state
}

/// 2-to-1 compression: `permute([0, l, r])[0]`, identical to
/// `attesta_circuits::poseidon::hash2`. Inputs must be canonical
/// big-endian field elements (< the group order), which note
/// commitments and Merkle nodes are by construction.
pub fn hash2(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let state = permute([Fr::zero(), fr(&left.to_array()), fr(&right.to_array())]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&state[0].into_bigint().to_bytes_be());
    BytesN::from_array(env, &out)
}
