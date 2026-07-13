//! The shielded transfer circuit.
//!
//! Proves, without revealing any amount: the spent notes are members of
//! the commitment tree under the public root (or are explicit zero-value
//! dummies), the prover holds their spending keys, the published
//! nullifiers are correctly derived from those keys and leaf positions,
//! and total input value equals total output value with every value
//! range-checked to 64 bits.
//!
//! Public inputs, in the order `shielded_pool::transfer` builds them:
//! `[root, nullifiers.., new_commitments..]`.
//!
//! The soundness argument required by `circuits/CONTRIBUTING.md` lives in
//! `docs/transfer.md`; constraint changes must update it in the same PR.

use crate::merkle::{self, MerklePath};
use crate::note::{self, Note};
use crate::util::{alloc_index_bits, alloc_u64};
use ark_bls12_381::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Witness data for one spent note.
#[derive(Clone, Debug)]
pub struct SpentNote {
    /// Note value; a zero value marks a dummy input whose membership
    /// check is disabled (its nullifier is still published and must be
    /// derived from a fresh random `sk` to stay unique).
    pub value: u64,
    /// The owner's spending key.
    pub sk: Fr,
    /// Commitment randomness.
    pub blinding: Fr,
    /// Authentication path to the public root (arbitrary for dummies).
    pub path: MerklePath,
}

/// Witness data for one created note.
#[derive(Clone, Debug)]
pub struct NewNote {
    /// Note value.
    pub value: u64,
    /// Recipient public key.
    pub owner_pk: Fr,
    /// Commitment randomness.
    pub blinding: Fr,
}

impl NewNote {
    /// The commitment this note produces (a public input).
    pub fn commitment(&self) -> Fr {
        Note {
            value: self.value,
            owner_pk: self.owner_pk,
            blinding: self.blinding,
        }
        .commitment()
    }
}

/// The transfer relation, fixed at setup time to a tree depth and a note
/// arity (`n_in` spent, `n_out` created). The protocol instance is
/// 2-in/2-out at [`merkle::POOL_TREE_DEPTH`].
#[derive(Clone)]
pub struct TransferCircuit {
    /// Merkle tree depth this instance was set up for.
    pub depth: usize,
    /// Public: a known root of the commitment tree.
    pub root: Option<Fr>,
    /// Public: one nullifier per spent note.
    pub nullifiers: Vec<Option<Fr>>,
    /// Public: one commitment per created note.
    pub new_commitments: Vec<Option<Fr>>,
    /// Witness: the spent notes.
    pub spent: Vec<Option<SpentNote>>,
    /// Witness: the created notes.
    pub created: Vec<Option<NewNote>>,
}

impl TransferCircuit {
    /// An unassigned circuit of the given shape, for key generation.
    pub fn blank(depth: usize, n_in: usize, n_out: usize) -> Self {
        TransferCircuit {
            depth,
            root: None,
            nullifiers: vec![None; n_in],
            new_commitments: vec![None; n_out],
            spent: vec![None; n_in],
            created: vec![None; n_out],
        }
    }
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs, in the contract's order ──────────────────────
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|nf| {
                FpVar::new_input(cs.clone(), || nf.ok_or(SynthesisError::AssignmentMissing))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let new_commitments = self
            .new_commitments
            .iter()
            .map(|c| FpVar::new_input(cs.clone(), || c.ok_or(SynthesisError::AssignmentMissing)))
            .collect::<Result<Vec<_>, _>>()?;

        // ── Spent notes ─────────────────────────────────────────────────
        let mut input_sum = FpVar::<Fr>::zero();
        for (spent, nf_public) in self.spent.iter().zip(&nullifiers) {
            let value = alloc_u64(cs.clone(), spent.as_ref().map(|s| s.value))?;
            let sk = FpVar::new_witness(cs.clone(), || {
                spent
                    .as_ref()
                    .map(|s| s.sk)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let blinding = FpVar::new_witness(cs.clone(), || {
                spent
                    .as_ref()
                    .map(|s| s.blinding)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let index_bits = alloc_index_bits(
                cs.clone(),
                spent.as_ref().map(|s| s.path.leaf_index),
                self.depth,
            )?;
            let siblings = (0..self.depth)
                .map(|level| {
                    FpVar::new_witness(cs.clone(), || {
                        spent
                            .as_ref()
                            .map(|s| s.path.siblings[level])
                            .ok_or(SynthesisError::AssignmentMissing)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Ownership: the commitment is over the prover's own pk.
            let pk = note::gadget::derive_pk(&sk)?;
            let cm = note::gadget::commitment(&value, &pk, &blinding)?;

            // Membership under the public root — skipped only for
            // explicit zero-value dummies.
            let is_real = value.is_neq(&FpVar::zero())?;
            let computed_root = merkle::gadget::compute_root(&cm, &siblings, &index_bits)?;
            computed_root.conditional_enforce_equal(&root, &is_real)?;

            // Nullifier: bound to the same leaf index as the membership
            // path via the shared bits.
            let leaf_index = Boolean::le_bits_to_fp(&index_bits)?;
            let nf = note::gadget::nullifier(&sk, &leaf_index)?;
            nf.enforce_equal(nf_public)?;

            input_sum += value;
        }

        // ── Created notes ───────────────────────────────────────────────
        let mut output_sum = FpVar::<Fr>::zero();
        for (created, cm_public) in self.created.iter().zip(&new_commitments) {
            let value = alloc_u64(cs.clone(), created.as_ref().map(|c| c.value))?;
            let owner_pk = FpVar::new_witness(cs.clone(), || {
                created
                    .as_ref()
                    .map(|c| c.owner_pk)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let blinding = FpVar::new_witness(cs.clone(), || {
                created
                    .as_ref()
                    .map(|c| c.blinding)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            let cm = note::gadget::commitment(&value, &owner_pk, &blinding)?;
            cm.enforce_equal(cm_public)?;

            output_sum += value;
        }

        // ── No inflation ────────────────────────────────────────────────
        // Values are 64-bit by decomposition and note arity is small, so
        // the field sums cannot wrap: this is integer equality.
        input_sum.enforce_equal(&output_sum)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::note::{derive_nullifier, derive_pk};
    use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal};

    const DEPTH: usize = 8;

    struct Fixture {
        circuit: TransferCircuit,
    }

    /// Two real notes in (600 + 400), two notes out (750 + 250).
    fn fixture() -> Fixture {
        let sk1 = Fr::from(11u64);
        let sk2 = Fr::from(22u64);
        let recipient_pk = derive_pk(Fr::from(33u64));

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
            owner_pk: recipient_pk,
            blinding: Fr::from(201u64),
        };
        let out2 = NewNote {
            value: 250,
            owner_pk: derive_pk(sk1), // change back to self
            blinding: Fr::from(202u64),
        };

        let circuit = TransferCircuit {
            depth: DEPTH,
            root: Some(tree.root()),
            nullifiers: vec![
                Some(derive_nullifier(sk1, i1)),
                Some(derive_nullifier(sk2, i2)),
            ],
            new_commitments: vec![Some(out1.commitment()), Some(out2.commitment())],
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
        Fixture { circuit }
    }

    fn is_satisfied(circuit: TransferCircuit) -> bool {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn honest_transfer_satisfies() {
        assert!(is_satisfied(fixture().circuit));
    }

    #[test]
    fn inflation_is_rejected() {
        let mut f = fixture();
        // Claim more output value than input.
        if let Some(out) = f.circuit.created[0].as_mut() {
            out.value = 751;
            f.circuit.new_commitments[0] = Some(out.commitment());
        }
        assert!(!is_satisfied(f.circuit));
    }

    #[test]
    fn wrong_nullifier_is_rejected() {
        let mut f = fixture();
        f.circuit.nullifiers[0] = Some(Fr::from(12345u64));
        assert!(!is_satisfied(f.circuit));
    }

    #[test]
    fn foreign_note_is_rejected() {
        let mut f = fixture();
        // Claim a note that is not in the tree: break the path.
        if let Some(s) = f.circuit.spent[0].as_mut() {
            s.path.siblings[0] = Fr::from(999u64);
        }
        assert!(!is_satisfied(f.circuit));
    }

    #[test]
    fn stolen_note_is_rejected() {
        let mut f = fixture();
        // Present note 1 with a key that does not own it.
        let thief_sk = Fr::from(666u64);
        let idx = f.circuit.spent[0].as_ref().unwrap().path.leaf_index;
        f.circuit.spent[0].as_mut().unwrap().sk = thief_sk;
        f.circuit.nullifiers[0] = Some(derive_nullifier(thief_sk, idx));
        assert!(!is_satisfied(f.circuit));
    }

    #[test]
    fn dummy_input_skips_membership_but_adds_no_value() {
        let sk = Fr::from(11u64);
        let dummy_sk = Fr::from(77u64);
        let note = Note {
            value: 500,
            owner_pk: derive_pk(sk),
            blinding: Fr::from(101u64),
        };
        let mut tree = MerkleTree::new(DEPTH);
        let idx = tree.insert(note.commitment());

        let out = NewNote {
            value: 500,
            owner_pk: derive_pk(Fr::from(33u64)),
            blinding: Fr::from(201u64),
        };
        // Dummy occupies slot 2: zero value, fabricated path.
        let dummy_path = tree.path(idx); // arbitrary siblings
        let circuit = TransferCircuit {
            depth: DEPTH,
            root: Some(tree.root()),
            nullifiers: vec![
                Some(derive_nullifier(sk, idx)),
                Some(derive_nullifier(dummy_sk, 0)),
            ],
            new_commitments: vec![Some(out.commitment()), Some(out.commitment())],
            spent: vec![
                Some(SpentNote {
                    value: 500,
                    sk,
                    blinding: note.blinding,
                    path: tree.path(idx),
                }),
                Some(SpentNote {
                    value: 0,
                    sk: dummy_sk,
                    blinding: Fr::from(0u64),
                    path: MerklePath {
                        siblings: dummy_path.siblings,
                        leaf_index: 0,
                    },
                }),
            ],
            created: vec![
                Some(out.clone()),
                Some(NewNote {
                    value: 0,
                    owner_pk: out.owner_pk,
                    blinding: out.blinding,
                }),
            ],
        };
        // Fix second output commitment for the zero-value note.
        let mut circuit = circuit;
        circuit.new_commitments[1] =
            Some(circuit.created[1].as_ref().unwrap().commitment());
        assert!(is_satisfied(circuit));
    }
}
