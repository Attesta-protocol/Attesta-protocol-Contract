//! The client-side proving pipeline: from a spend description and the
//! public commitment log to the exact byte bundle a `shielded_pool`
//! call takes.
//!
//! This is the library behind the `attesta-prover` CLI and the M3 WASM
//! prover. Everything here runs on the user's device: spending keys,
//! values, and blindings never leave the process, and the outputs
//! (proof bytes, nullifiers, commitments) are precisely the public
//! arguments of `transfer` / `withdraw`.

use crate::encoding::{fr_to_bytes, proof_to_bytes, ProofBytes};
use crate::merkle::{MerkleTree, POOL_TREE_DEPTH};
use crate::note::{derive_nullifier, derive_pk, Note};
use crate::transfer::{NewNote, SpentNote, TransferCircuit};
use crate::withdraw::WithdrawCircuit;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use rand::{CryptoRng, RngCore};

/// A note the prover intends to spend, located in the pool's tree.
#[derive(Clone, Debug)]
pub struct Spend {
    /// The owner's spending key.
    pub sk: Fr,
    /// Note value.
    pub value: u64,
    /// Commitment randomness.
    pub blinding: Fr,
    /// The note's leaf index in the pool (from the deposit / transfer
    /// event that created it).
    pub leaf_index: u64,
}

/// A note the transfer creates.
#[derive(Clone, Debug)]
pub struct Output {
    /// Recipient public key (`derive_pk` of their spending key).
    pub owner_pk: Fr,
    /// Note value.
    pub value: u64,
    /// Fresh commitment randomness.
    pub blinding: Fr,
}

/// Everything `shielded_pool::transfer` takes, in host encoding.
#[derive(Debug)]
pub struct TransferBundle {
    /// The Groth16 proof.
    pub proof: ProofBytes,
    /// The root the proof was generated against.
    pub root: [u8; 32],
    /// Nullifiers of the spent notes (dummies included).
    pub nullifiers: Vec<[u8; 32]>,
    /// Commitments of the created notes.
    pub new_commitments: Vec<[u8; 32]>,
}

/// Everything `shielded_pool::withdraw` takes, in host encoding.
#[derive(Debug)]
pub struct WithdrawBundle {
    /// The Groth16 proof.
    pub proof: ProofBytes,
    /// The root the proof was generated against.
    pub root: [u8; 32],
    /// The exited note's nullifier.
    pub nullifier: [u8; 32],
    /// The recipient binding the proof commits to.
    pub recipient_binding: [u8; 32],
    /// The exact note value being withdrawn.
    pub amount: u64,
}

/// Rebuilds the pool tree from the indexed commitment log (deposit and
/// transfer events, in leaf order).
pub fn rebuild_tree(commitments: &[Fr]) -> MerkleTree {
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
    for c in commitments {
        tree.insert(*c);
    }
    tree
}

fn check_spend(tree: &MerkleTree, spend: &Spend) -> Result<Note, String> {
    let note = Note {
        value: spend.value,
        owner_pk: derive_pk(spend.sk),
        blinding: spend.blinding,
    };
    if spend.leaf_index as usize >= tree.size() {
        return Err(format!(
            "leaf index {} out of range (tree has {} leaves)",
            spend.leaf_index,
            tree.size()
        ));
    }
    // Fail here, with a diagnosable error, rather than producing an
    // unsatisfiable witness: the commitment at the claimed leaf must be
    // exactly this note's.
    let expected = crate::merkle::compute_root(note.commitment(), &tree.path(spend.leaf_index));
    if expected != tree.root() {
        return Err(format!(
            "note does not match the commitment at leaf {} — wrong sk, value, blinding, or index",
            spend.leaf_index
        ));
    }
    Ok(note)
}

/// Proves a 2-in/2-out shielded transfer. `commitments` is the full
/// pool commitment log; spends with fewer than two real notes should
/// pass a zero-value dummy with a fresh random `sk`.
pub fn prove_transfer(
    proving_key: &ProvingKey<Bls12_381>,
    commitments: &[Fr],
    spends: &[Spend; 2],
    outputs: &[Output; 2],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<TransferBundle, String> {
    let in_total: u128 = spends.iter().map(|s| s.value as u128).sum();
    let out_total: u128 = outputs.iter().map(|o| o.value as u128).sum();
    if in_total != out_total {
        return Err(format!(
            "value mismatch: spending {in_total} but creating {out_total}"
        ));
    }

    let tree = rebuild_tree(commitments);
    let mut spent = Vec::new();
    let mut nullifiers = Vec::new();
    for spend in spends {
        if spend.value > 0 {
            check_spend(&tree, spend)?;
        }
        nullifiers.push(derive_nullifier(spend.sk, spend.leaf_index));
        spent.push(Some(SpentNote {
            value: spend.value,
            sk: spend.sk,
            blinding: spend.blinding,
            path: if spend.value > 0 {
                tree.path(spend.leaf_index)
            } else {
                // Dummy input: membership is disabled in-circuit; any
                // well-formed path works.
                crate::merkle::MerklePath {
                    siblings: vec![Fr::from(0u64); POOL_TREE_DEPTH],
                    leaf_index: 0,
                }
            },
        }));
    }

    let created: Vec<NewNote> = outputs
        .iter()
        .map(|o| NewNote {
            value: o.value,
            owner_pk: o.owner_pk,
            blinding: o.blinding,
        })
        .collect();
    let new_commitments: Vec<Fr> = created.iter().map(|n| n.commitment()).collect();

    let circuit = TransferCircuit {
        depth: POOL_TREE_DEPTH,
        root: Some(tree.root()),
        nullifiers: nullifiers.iter().map(|nf| Some(*nf)).collect(),
        new_commitments: new_commitments.iter().map(|c| Some(*c)).collect(),
        spent,
        created: created.into_iter().map(Some).collect(),
    };
    let proof =
        Groth16::<Bls12_381>::prove(proving_key, circuit, rng).map_err(|e| format!("{e}"))?;

    Ok(TransferBundle {
        proof: proof_to_bytes(&proof),
        root: fr_to_bytes(tree.root()),
        nullifiers: nullifiers.iter().map(|nf| fr_to_bytes(*nf)).collect(),
        new_commitments: new_commitments.iter().map(|c| fr_to_bytes(*c)).collect(),
    })
}

/// Proves a withdrawal of the exact value of one note, bound to the
/// recipient. `recipient_binding` is the contract's `address_binding`
/// of the payout address (SHA-256 of the address XDR, top byte zero).
pub fn prove_withdraw(
    proving_key: &ProvingKey<Bls12_381>,
    commitments: &[Fr],
    spend: &Spend,
    recipient_binding: Fr,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<WithdrawBundle, String> {
    let tree = rebuild_tree(commitments);
    check_spend(&tree, spend)?;
    let nullifier = derive_nullifier(spend.sk, spend.leaf_index);

    let circuit = WithdrawCircuit {
        depth: POOL_TREE_DEPTH,
        root: Some(tree.root()),
        nullifier: Some(nullifier),
        recipient_binding: Some(recipient_binding),
        amount: Some(Fr::from(spend.value)),
        sk: Some(spend.sk),
        blinding: Some(spend.blinding),
        path: Some(tree.path(spend.leaf_index)),
    };
    let proof =
        Groth16::<Bls12_381>::prove(proving_key, circuit, rng).map_err(|e| format!("{e}"))?;

    Ok(WithdrawBundle {
        proof: proof_to_bytes(&proof),
        root: fr_to_bytes(tree.root()),
        nullifier: fr_to_bytes(nullifier),
        recipient_binding: fr_to_bytes(recipient_binding),
        amount: spend.value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn pipeline_proves_and_verifies_transfer_and_withdraw() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x9c0de);
        let (t_pk, t_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            TransferCircuit::blank(POOL_TREE_DEPTH, 2, 2),
            &mut rng,
        )
        .unwrap();
        let (w_pk, w_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            WithdrawCircuit::blank(POOL_TREE_DEPTH),
            &mut rng,
        )
        .unwrap();

        // Deposit one 500 note; spend it with a dummy second input.
        let sk = Fr::from(11u64);
        let note = Note {
            value: 500,
            owner_pk: derive_pk(sk),
            blinding: Fr::from(101u64),
        };
        let log = vec![note.commitment()];

        let spends = [
            Spend {
                sk,
                value: 500,
                blinding: Fr::from(101u64),
                leaf_index: 0,
            },
            Spend {
                sk: Fr::from(777u64), // fresh dummy key
                value: 0,
                blinding: Fr::from(0u64),
                leaf_index: 0,
            },
        ];
        let recipient_sk = Fr::from(33u64);
        let outputs = [
            Output {
                owner_pk: derive_pk(recipient_sk),
                value: 500,
                blinding: Fr::from(201u64),
            },
            Output {
                owner_pk: derive_pk(sk),
                value: 0,
                blinding: Fr::from(202u64),
            },
        ];

        let bundle = prove_transfer(&t_pk, &log, &spends, &outputs, &mut rng).unwrap();
        let mut inputs = vec![crate::encoding::fr_from_bytes(&bundle.root)];
        for nf in &bundle.nullifiers {
            inputs.push(crate::encoding::fr_from_bytes(nf));
        }
        for c in &bundle.new_commitments {
            inputs.push(crate::encoding::fr_from_bytes(c));
        }
        let proof = ark_groth16::Proof {
            a: crate::encoding::g1_from_bytes(&bundle.proof.a),
            b: crate::encoding::g2_from_bytes(&bundle.proof.b),
            c: crate::encoding::g1_from_bytes(&bundle.proof.c),
        };
        assert!(Groth16::<Bls12_381>::verify(&t_vk, &inputs, &proof).unwrap());

        // Now withdraw the recipient's new note (leaf 1 in the grown log).
        let log = vec![
            note.commitment(),
            crate::encoding::fr_from_bytes(&bundle.new_commitments[0]),
            crate::encoding::fr_from_bytes(&bundle.new_commitments[1]),
        ];
        let w = prove_withdraw(
            &w_pk,
            &log,
            &Spend {
                sk: recipient_sk,
                value: 500,
                blinding: Fr::from(201u64),
                leaf_index: 1,
            },
            Fr::from(4242u64),
            &mut rng,
        )
        .unwrap();
        let inputs = vec![
            crate::encoding::fr_from_bytes(&w.root),
            crate::encoding::fr_from_bytes(&w.nullifier),
            crate::encoding::fr_from_bytes(&w.recipient_binding),
            Fr::from(w.amount),
        ];
        let proof = ark_groth16::Proof {
            a: crate::encoding::g1_from_bytes(&w.proof.a),
            b: crate::encoding::g2_from_bytes(&w.proof.b),
            c: crate::encoding::g1_from_bytes(&w.proof.c),
        };
        assert!(Groth16::<Bls12_381>::verify(&w_vk, &inputs, &proof).unwrap());
    }

    #[test]
    fn mismatched_note_fails_before_proving() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (t_pk, _) = Groth16::<Bls12_381>::circuit_specific_setup(
            TransferCircuit::blank(POOL_TREE_DEPTH, 2, 2),
            &mut rng,
        )
        .unwrap();

        let sk = Fr::from(11u64);
        let note = Note {
            value: 500,
            owner_pk: derive_pk(sk),
            blinding: Fr::from(101u64),
        };
        let log = vec![note.commitment()];
        let bad_spends = [
            Spend {
                sk,
                value: 501, // wrong value for this commitment
                blinding: Fr::from(101u64),
                leaf_index: 0,
            },
            Spend {
                sk: Fr::from(777u64),
                value: 0,
                blinding: Fr::from(0u64),
                leaf_index: 0,
            },
        ];
        let outputs = [
            Output {
                owner_pk: derive_pk(Fr::from(33u64)),
                value: 501,
                blinding: Fr::from(201u64),
            },
            Output {
                owner_pk: derive_pk(sk),
                value: 0,
                blinding: Fr::from(202u64),
            },
        ];
        let err = prove_transfer(&t_pk, &log, &bad_spends, &outputs, &mut rng).unwrap_err();
        assert!(err.contains("does not match"), "got: {err}");
    }
}
