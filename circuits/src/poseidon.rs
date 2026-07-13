//! Poseidon over the BLS12-381 scalar field.
//!
//! This is the protocol hash: Merkle nodes, note commitments, and
//! nullifiers are all Poseidon evaluations, so the same function is
//! computed natively (prover, tests), in-circuit (R1CS gadget), and
//! on-chain (`shielded_pool::hash_pair` via the Protocol 25 Fr host
//! functions). All three implement the identical permutation below;
//! the round constants are generated deterministically by the standard
//! Grain LFSR procedure via arkworks and are the single source of truth
//! for the constants exported to the contract layer.
//!
//! ## Instance
//!
//! Standard HADES construction, standard parameters for a ~255-bit field
//! at 128-bit security:
//!
//! - width `t = 3` (2-to-1 compression: capacity 1, rate 2)
//! - S-box `x^5`
//! - 8 full rounds, 57 partial rounds
//!
//! ## 2-to-1 hash
//!
//! `hash2(l, r) = permute([0, l, r])[0]` — the fixed zero capacity
//! element domain-separates the compression function; this is the same
//! shape circomlib's Poseidon uses.

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_ff::Field;
use std::sync::OnceLock;

/// Permutation width: capacity 1 + rate 2.
pub const WIDTH: usize = 3;
/// Full (all-lane S-box) rounds; half run before the partial rounds and
/// half after.
pub const FULL_ROUNDS: usize = 8;
/// Partial (single-lane S-box) rounds.
pub const PARTIAL_ROUNDS: usize = 57;
/// S-box exponent.
pub const ALPHA: u64 = 5;

/// Poseidon round constants and MDS matrix for this instance.
pub struct Parameters {
    /// Additive round constants, one row of `WIDTH` per round.
    pub ark: Vec<[Fr; WIDTH]>,
    /// The `WIDTH × WIDTH` MDS matrix.
    pub mds: [[Fr; WIDTH]; WIDTH],
}

/// The parameters for the protocol's Poseidon instance, generated once by
/// the standard Grain LFSR procedure (arkworks implementation) from the
/// instance description above.
pub fn parameters() -> &'static Parameters {
    static PARAMS: OnceLock<Parameters> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            255, // modulus bits of the BLS12-381 scalar field
            WIDTH - 1,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0, // skip_matrices: first candidate MDS
        );
        let ark = ark
            .into_iter()
            .map(|row| {
                let mut out = [Fr::from(0u64); WIDTH];
                out.copy_from_slice(&row);
                out
            })
            .collect();
        let mut mds_out = [[Fr::from(0u64); WIDTH]; WIDTH];
        for (i, row) in mds.into_iter().enumerate() {
            mds_out[i].copy_from_slice(&row);
        }
        Parameters { ark, mds: mds_out }
    })
}

/// The Poseidon permutation on a width-3 state.
pub fn permute(mut state: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let params = parameters();
    let half_full = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;
    for round in 0..total {
        // Add round constants.
        for (lane, c) in state.iter_mut().zip(params.ark[round].iter()) {
            *lane += c;
        }
        // S-box: every lane in full rounds, lane 0 in partial rounds.
        let full = round < half_full || round >= half_full + PARTIAL_ROUNDS;
        if full {
            for lane in state.iter_mut() {
                *lane = lane.pow([ALPHA]);
            }
        } else {
            state[0] = state[0].pow([ALPHA]);
        }
        // MDS mix.
        let mut mixed = [Fr::from(0u64); WIDTH];
        for (i, row) in params.mds.iter().enumerate() {
            for (lane, m) in state.iter().zip(row.iter()) {
                mixed[i] += *lane * m;
            }
        }
        state = mixed;
    }
    state
}

/// 2-to-1 compression: `permute([0, l, r])[0]`. This is the Merkle node
/// hash and the building block for note commitments and nullifiers.
pub fn hash2(left: Fr, right: Fr) -> Fr {
    permute([Fr::from(0u64), left, right])[0]
}

/// R1CS gadget computing the identical permutation over `FpVar`s.
pub mod gadget {
    use super::{parameters, ALPHA, FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};
    use ark_bls12_381::Fr;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::fields::FieldVar;
    use ark_relations::r1cs::SynthesisError;

    fn sbox(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        debug_assert_eq!(ALPHA, 5);
        let x2 = x.square()?;
        let x4 = x2.square()?;
        Ok(x4 * x)
    }

    /// The Poseidon permutation over R1CS variables; constant-for-constant
    /// identical to the native [`super::permute`].
    pub fn permute(mut state: [FpVar<Fr>; WIDTH]) -> Result<[FpVar<Fr>; WIDTH], SynthesisError> {
        let params = parameters();
        let half_full = FULL_ROUNDS / 2;
        let total = FULL_ROUNDS + PARTIAL_ROUNDS;
        for round in 0..total {
            for (lane, c) in state.iter_mut().zip(params.ark[round].iter()) {
                *lane += FpVar::constant(*c);
            }
            let full = round < half_full || round >= half_full + PARTIAL_ROUNDS;
            if full {
                for lane in state.iter_mut() {
                    *lane = sbox(lane)?;
                }
            } else {
                state[0] = sbox(&state[0])?;
            }
            let mut mixed: [FpVar<Fr>; WIDTH] =
                [FpVar::zero(), FpVar::zero(), FpVar::zero()];
            for (i, row) in params.mds.iter().enumerate() {
                for (lane, m) in state.iter().zip(row.iter()) {
                    mixed[i] += lane * FpVar::constant(*m);
                }
            }
            state = mixed;
        }
        Ok(state)
    }

    /// In-circuit 2-to-1 hash, identical to the native [`super::hash2`].
    pub fn hash2(left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        let state = permute([FpVar::zero(), left.clone(), right.clone()])?;
        Ok(state[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn parameters_have_expected_shape() {
        let p = parameters();
        assert_eq!(p.ark.len(), FULL_ROUNDS + PARTIAL_ROUNDS);
    }

    #[test]
    fn hash2_is_deterministic_and_asymmetric() {
        let a = Fr::from(7u64);
        let b = Fr::from(11u64);
        assert_eq!(hash2(a, b), hash2(a, b));
        assert_ne!(hash2(a, b), hash2(b, a));
        assert_ne!(hash2(a, b), hash2(a, a));
    }

    #[test]
    fn gadget_matches_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let l = Fr::from(123456789u64);
        let r = Fr::from(987654321u64);
        let lv = FpVar::new_witness(cs.clone(), || Ok(l)).unwrap();
        let rv = FpVar::new_witness(cs.clone(), || Ok(r)).unwrap();
        let hv = gadget::hash2(&lv, &rv).unwrap();
        assert_eq!(hv.value().unwrap(), hash2(l, r));
        assert!(cs.is_satisfied().unwrap());
    }
}
