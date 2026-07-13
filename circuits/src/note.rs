//! Note commitments, spending keys, and nullifiers.
//!
//! A shielded note is `(value, owner, blinding)`:
//!
//! - `value` — the token amount, range-checked to 64 bits in-circuit so
//!   sums of a transfer's notes can never wrap the field.
//! - `owner` — the public key `pk = H(DOMAIN_PK, sk)` of a spending key
//!   `sk` that never leaves the client.
//! - `blinding` — fresh randomness making the commitment hiding.
//!
//! The commitment inserted into the pool's Merkle tree is
//! `cm = H(H(value, pk), blinding)` and reveals nothing about the note.
//!
//! The nullifier is `nf = H(H(DOMAIN_NF, sk), leaf_index)` — the
//! established Tornado/Semaphore pattern: only the spending key holder
//! can derive it, and because the pool assigns each commitment a unique
//! leaf index, each note has exactly one nullifier. Publishing it spends
//! the note without linking back to the commitment.
//!
//! `H` is the protocol Poseidon 2-to-1 hash ([`crate::poseidon::hash2`]);
//! `DOMAIN_PK = 1` and `DOMAIN_NF = 2` separate key derivation from
//! nullifier derivation.

use crate::poseidon::hash2;
use ark_bls12_381::Fr;

/// Domain tag for spending-key → public-key derivation.
pub const DOMAIN_PK: u64 = 1;
/// Domain tag for nullifier derivation.
pub const DOMAIN_NF: u64 = 2;

/// A shielded note as the client knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    /// Token amount (stroops); must fit in 64 bits.
    pub value: u64,
    /// The owner's public key `H(DOMAIN_PK, sk)`.
    pub owner_pk: Fr,
    /// Commitment randomness.
    pub blinding: Fr,
}

impl Note {
    /// The note commitment inserted into the pool's Merkle tree:
    /// `H(H(value, pk), blinding)`.
    pub fn commitment(&self) -> Fr {
        hash2(hash2(Fr::from(self.value), self.owner_pk), self.blinding)
    }
}

/// Derives the public key for a spending key: `H(DOMAIN_PK, sk)`.
pub fn derive_pk(sk: Fr) -> Fr {
    hash2(Fr::from(DOMAIN_PK), sk)
}

/// Derives the nullifier for the note at `leaf_index` owned by `sk`:
/// `H(H(DOMAIN_NF, sk), leaf_index)`.
pub fn derive_nullifier(sk: Fr, leaf_index: u64) -> Fr {
    hash2(hash2(Fr::from(DOMAIN_NF), sk), Fr::from(leaf_index))
}

/// R1CS gadgets computing the identical derivations in-circuit.
pub mod gadget {
    use super::{DOMAIN_NF, DOMAIN_PK};
    use crate::poseidon::gadget::hash2;
    use ark_bls12_381::Fr;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::SynthesisError;

    /// `pk = H(DOMAIN_PK, sk)`.
    pub fn derive_pk(sk: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        hash2(&FpVar::Constant(Fr::from(DOMAIN_PK)), sk)
    }

    /// `cm = H(H(value, pk), blinding)`.
    pub fn commitment(
        value: &FpVar<Fr>,
        owner_pk: &FpVar<Fr>,
        blinding: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        hash2(&hash2(value, owner_pk)?, blinding)
    }

    /// `nf = H(H(DOMAIN_NF, sk), leaf_index)`.
    pub fn nullifier(
        sk: &FpVar<Fr>,
        leaf_index: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        hash2(&hash2(&FpVar::Constant(Fr::from(DOMAIN_NF)), sk)?, leaf_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    fn sample_note(sk: Fr) -> Note {
        Note {
            value: 1_000_000,
            owner_pk: derive_pk(sk),
            blinding: Fr::from(42u64),
        }
    }

    #[test]
    fn commitment_hides_nothing_leaks_nothing_trivially() {
        let sk = Fr::from(1234u64);
        let note = sample_note(sk);
        let mut other = note;
        other.blinding = Fr::from(43u64);
        // Same value+owner, different blinding → different commitment.
        assert_ne!(note.commitment(), other.commitment());
    }

    #[test]
    fn nullifiers_are_unique_per_leaf_and_key() {
        let sk = Fr::from(1234u64);
        assert_ne!(derive_nullifier(sk, 0), derive_nullifier(sk, 1));
        assert_ne!(
            derive_nullifier(sk, 0),
            derive_nullifier(Fr::from(5678u64), 0)
        );
    }

    #[test]
    fn pk_and_nf_domains_are_separated() {
        let sk = Fr::from(1234u64);
        // pk derivation and the inner nullifier hash differ on the domain
        // tag, so knowing pk reveals nothing about nullifiers.
        assert_ne!(derive_pk(sk), hash2(Fr::from(DOMAIN_NF), sk));
    }

    #[test]
    fn gadgets_match_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let sk = Fr::from(99u64);
        let note = sample_note(sk);
        let leaf_index = 7u64;

        let sk_v = FpVar::new_witness(cs.clone(), || Ok(sk)).unwrap();
        let value_v = FpVar::new_witness(cs.clone(), || Ok(Fr::from(note.value))).unwrap();
        let blind_v = FpVar::new_witness(cs.clone(), || Ok(note.blinding)).unwrap();
        let idx_v = FpVar::new_witness(cs.clone(), || Ok(Fr::from(leaf_index))).unwrap();

        let pk_v = gadget::derive_pk(&sk_v).unwrap();
        assert_eq!(pk_v.value().unwrap(), note.owner_pk);

        let cm_v = gadget::commitment(&value_v, &pk_v, &blind_v).unwrap();
        assert_eq!(cm_v.value().unwrap(), note.commitment());

        let nf_v = gadget::nullifier(&sk_v, &idx_v).unwrap();
        assert_eq!(nf_v.value().unwrap(), derive_nullifier(sk, leaf_index));

        assert!(cs.is_satisfied().unwrap());
    }
}
