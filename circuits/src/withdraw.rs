//! The withdraw circuit.
//!
//! Proves ownership of an unspent note of exactly the public `amount`
//! under the public `root`, with the correctly derived nullifier, bound
//! to the public recipient so a relayer submitting the transaction
//! cannot redirect the exit.
//!
//! Public inputs, in the order `shielded_pool::withdraw` builds them:
//! `[root, nullifier, recipient_binding, amount]`.
//!
//! The soundness argument required by `circuits/CONTRIBUTING.md` lives in
//! `docs/withdraw.md`; constraint changes must update it in the same PR.

use crate::merkle::{self, MerklePath};
use crate::note;
use crate::util::alloc_index_bits;
use ark_bls12_381::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// The withdraw relation, fixed at setup time to a tree depth. The
/// protocol instance uses [`merkle::POOL_TREE_DEPTH`].
#[derive(Clone)]
pub struct WithdrawCircuit {
    /// Merkle tree depth this instance was set up for.
    pub depth: usize,
    /// Public: a known root of the commitment tree.
    pub root: Option<Fr>,
    /// Public: the spent note's nullifier.
    pub nullifier: Option<Fr>,
    /// Public: the recipient binding (`shielded_pool::address_binding`).
    pub recipient_binding: Option<Fr>,
    /// Public: the exact note value being withdrawn.
    pub amount: Option<Fr>,
    /// Witness: the note owner's spending key.
    pub sk: Option<Fr>,
    /// Witness: the note's commitment randomness.
    pub blinding: Option<Fr>,
    /// Witness: authentication path for the note's leaf.
    pub path: Option<MerklePath>,
}

impl WithdrawCircuit {
    /// An unassigned circuit of the given shape, for key generation.
    pub fn blank(depth: usize) -> Self {
        WithdrawCircuit {
            depth,
            root: None,
            nullifier: None,
            recipient_binding: None,
            amount: None,
            sk: None,
            blinding: None,
            path: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs, in the contract's order ──────────────────────
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let recipient_binding = FpVar::new_input(cs.clone(), || {
            self.recipient_binding
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let amount = FpVar::new_input(cs.clone(), || {
            self.amount.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── Witnesses ───────────────────────────────────────────────────
        let sk = FpVar::new_witness(cs.clone(), || {
            self.sk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let blinding = FpVar::new_witness(cs.clone(), || {
            self.blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let index_bits = alloc_index_bits(
            cs.clone(),
            self.path.as_ref().map(|p| p.leaf_index),
            self.depth,
        )?;
        let siblings = (0..self.depth)
            .map(|level| {
                FpVar::new_witness(cs.clone(), || {
                    self.path
                        .as_ref()
                        .map(|p| p.siblings[level])
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Ownership: the commitment is over the prover's own pk and the
        // public amount — a note of any other value cannot satisfy this.
        let pk = note::gadget::derive_pk(&sk)?;
        let cm = note::gadget::commitment(&amount, &pk, &blinding)?;

        // Membership under the public root.
        let computed_root = merkle::gadget::compute_root(&cm, &siblings, &index_bits)?;
        computed_root.enforce_equal(&root)?;

        // Nullifier bound to the same leaf index as the membership path.
        let leaf_index = Boolean::le_bits_to_fp(&index_bits)?;
        let nf = note::gadget::nullifier(&sk, &leaf_index)?;
        nf.enforce_equal(&nullifier)?;

        // The recipient binding exists to be part of the proven statement
        // rather than to constrain the witness — but a Groth16 public
        // input that appears in no constraint is malleable, so pin it
        // with one multiplication (allocates rb² with constraint
        // rb·rb = rb², putting rb in the constraint matrices).
        let _pinned = &recipient_binding * &recipient_binding;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::note::{derive_nullifier, derive_pk, Note};
    use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal};

    const DEPTH: usize = 8;

    fn fixture() -> WithdrawCircuit {
        let sk = Fr::from(11u64);
        let note = Note {
            value: 900,
            owner_pk: derive_pk(sk),
            blinding: Fr::from(101u64),
        };
        let mut tree = MerkleTree::new(DEPTH);
        let idx = tree.insert(note.commitment());
        WithdrawCircuit {
            depth: DEPTH,
            root: Some(tree.root()),
            nullifier: Some(derive_nullifier(sk, idx)),
            recipient_binding: Some(Fr::from(4242u64)),
            amount: Some(Fr::from(note.value)),
            sk: Some(sk),
            blinding: Some(note.blinding),
            path: Some(tree.path(idx)),
        }
    }

    fn is_satisfied(circuit: WithdrawCircuit) -> bool {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn honest_withdraw_satisfies() {
        assert!(is_satisfied(fixture()));
    }

    #[test]
    fn wrong_amount_is_rejected() {
        let mut c = fixture();
        c.amount = Some(Fr::from(901u64));
        assert!(!is_satisfied(c));
    }

    #[test]
    fn foreign_key_is_rejected() {
        let mut c = fixture();
        let thief = Fr::from(666u64);
        c.sk = Some(thief);
        c.nullifier = Some(derive_nullifier(thief, 0));
        assert!(!is_satisfied(c));
    }

    #[test]
    fn wrong_nullifier_is_rejected() {
        let mut c = fixture();
        c.nullifier = Some(Fr::from(12345u64));
        assert!(!is_satisfied(c));
    }

    #[test]
    fn wrong_leaf_index_is_rejected() {
        // Publishing the nullifier of a different leaf than the path
        // proves membership for must fail: the bits are shared.
        let mut c = fixture();
        let sk = Fr::from(11u64);
        c.nullifier = Some(derive_nullifier(sk, 3));
        assert!(!is_satisfied(c));
    }
}
