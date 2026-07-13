//! Small shared R1CS helpers.

use ark_bls12_381::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Allocates a 64-bit unsigned value as its little-endian bit witnesses
/// and returns the recomposed field element. The decomposition *is* the
/// range check: the recomposition `Σ bit_i · 2^i` over 64 booleans cannot
/// represent anything ≥ 2^64, so sums of a bounded number of such values
/// can never wrap the ~255-bit field.
pub fn alloc_u64(
    cs: ConstraintSystemRef<Fr>,
    value: Option<u64>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let bits = alloc_index_bits(cs, value, 64)?;
    Boolean::le_bits_to_fp(&bits)
}

/// Allocates the low `n` bits of `value` as boolean witnesses,
/// little-endian.
pub fn alloc_index_bits(
    cs: ConstraintSystemRef<Fr>,
    value: Option<u64>,
    n: usize,
) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    (0..n)
        .map(|i| {
            Boolean::new_witness(cs.clone(), || {
                value
                    .map(|v| (v >> i) & 1 == 1)
                    .ok_or(SynthesisError::AssignmentMissing)
            })
        })
        .collect()
}
