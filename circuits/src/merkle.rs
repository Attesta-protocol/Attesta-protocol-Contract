//! The commitment Merkle tree, prover-side, plus the in-circuit
//! membership gadget.
//!
//! Semantics mirror `shielded_pool` exactly: an append-only binary tree
//! of fixed depth, zero-valued empty leaves, node hash
//! [`crate::poseidon::hash2`]. The native tree here is what a prover (or
//! test) uses to reconstruct authentication paths from the public
//! commitment log; the contract maintains the same tree incrementally
//! on-chain and the roots must agree bit-for-bit.

use crate::poseidon::hash2;
use ark_bls12_381::Fr;

/// The pool's tree depth (`shielded_pool::TREE_DEPTH`).
pub const POOL_TREE_DEPTH: usize = 20;

/// An authentication path: the sibling at each level, leaf to root, plus
/// the leaf index whose bits steer left/right.
#[derive(Clone, Debug)]
pub struct MerklePath {
    /// Sibling nodes, level 0 (leaf's sibling) upward.
    pub siblings: Vec<Fr>,
    /// The leaf's index in the tree.
    pub leaf_index: u64,
}

/// A full in-memory Merkle tree over note commitments.
///
/// O(2^depth) storage — fine for provers and tests, which rebuild from
/// the indexed commitment log; the contract uses the incremental
/// filled-subtrees form instead.
pub struct MerkleTree {
    depth: usize,
    /// Zero hash per level: `zeros[0] = 0`, `zeros[i+1] = H(z_i, z_i)`.
    zeros: Vec<Fr>,
    /// `nodes[level]` holds the non-default nodes of that level, dense
    /// from index 0. `nodes[0]` are the leaves.
    nodes: Vec<Vec<Fr>>,
}

impl MerkleTree {
    /// An empty tree of the given depth.
    pub fn new(depth: usize) -> Self {
        let mut zeros = vec![Fr::from(0u64)];
        for i in 0..depth {
            zeros.push(hash2(zeros[i], zeros[i]));
        }
        MerkleTree {
            depth,
            zeros,
            nodes: vec![Vec::new(); depth + 1],
        }
    }

    /// Number of leaves inserted.
    pub fn size(&self) -> usize {
        self.nodes[0].len()
    }

    /// Appends a leaf, returning its index.
    pub fn insert(&mut self, leaf: Fr) -> u64 {
        let index = self.nodes[0].len();
        assert!(index < 1 << self.depth, "tree full");
        self.nodes[0].push(leaf);
        // Recompute the touched node per level.
        let mut idx = index;
        for level in 0..self.depth {
            let parent = idx / 2;
            let left = self.node(level, parent * 2);
            let right = self.node(level, parent * 2 + 1);
            let h = hash2(left, right);
            if parent < self.nodes[level + 1].len() {
                self.nodes[level + 1][parent] = h;
            } else {
                self.nodes[level + 1].push(h);
            }
            idx = parent;
        }
        index as u64
    }

    fn node(&self, level: usize, index: usize) -> Fr {
        self.nodes[level]
            .get(index)
            .copied()
            .unwrap_or(self.zeros[level])
    }

    /// The current root.
    pub fn root(&self) -> Fr {
        self.node(self.depth, 0)
    }

    /// The authentication path for the leaf at `index`.
    pub fn path(&self, index: u64) -> MerklePath {
        assert!((index as usize) < self.nodes[0].len(), "no such leaf");
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index as usize;
        for level in 0..self.depth {
            siblings.push(self.node(level, idx ^ 1));
            idx /= 2;
        }
        MerklePath {
            siblings,
            leaf_index: index,
        }
    }
}

/// Recomputes the root from a leaf and its path (native check).
pub fn compute_root(leaf: Fr, path: &MerklePath) -> Fr {
    let mut node = leaf;
    let mut idx = path.leaf_index;
    for sibling in &path.siblings {
        node = if idx & 1 == 0 {
            hash2(node, *sibling)
        } else {
            hash2(*sibling, node)
        };
        idx >>= 1;
    }
    node
}

/// R1CS membership gadget.
pub mod gadget {
    use crate::poseidon::gadget::hash2;
    use ark_bls12_381::Fr;
    use ark_r1cs_std::boolean::Boolean;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::select::CondSelectGadget;
    use ark_relations::r1cs::SynthesisError;

    /// Computes the root implied by `leaf`, sibling witnesses, and the
    /// leaf-index bits (little-endian, one per level; bit set = leaf is
    /// the right child at that level). The caller constrains the result
    /// against the public root and derives `index_bits` from the same
    /// index used for the nullifier, binding both to one leaf.
    pub fn compute_root(
        leaf: &FpVar<Fr>,
        siblings: &[FpVar<Fr>],
        index_bits: &[Boolean<Fr>],
    ) -> Result<FpVar<Fr>, SynthesisError> {
        assert_eq!(siblings.len(), index_bits.len());
        let mut node = leaf.clone();
        for (sibling, bit) in siblings.iter().zip(index_bits) {
            let left = FpVar::conditionally_select(bit, sibling, &node)?;
            let right = FpVar::conditionally_select(bit, &node, sibling)?;
            node = hash2(&left, &right)?;
        }
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::boolean::Boolean;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn empty_root_matches_zero_chain() {
        let tree = MerkleTree::new(4);
        let mut z = Fr::from(0u64);
        for _ in 0..4 {
            z = hash2(z, z);
        }
        assert_eq!(tree.root(), z);
    }

    #[test]
    fn paths_verify_and_roots_evolve() {
        let mut tree = MerkleTree::new(4);
        let mut roots = Vec::new();
        for i in 0..5u64 {
            tree.insert(Fr::from(100 + i));
            roots.push(tree.root());
        }
        // All roots distinct.
        for i in 0..roots.len() {
            for j in 0..i {
                assert_ne!(roots[i], roots[j]);
            }
        }
        // Every inserted leaf's path verifies against the final root.
        for i in 0..5u64 {
            let path = tree.path(i);
            assert_eq!(compute_root(Fr::from(100 + i), &path), tree.root());
        }
        // A wrong leaf does not.
        let path = tree.path(2);
        assert_ne!(compute_root(Fr::from(999u64), &path), tree.root());
    }

    #[test]
    fn gadget_matches_native() {
        let mut tree = MerkleTree::new(4);
        for i in 0..3u64 {
            tree.insert(Fr::from(7 * (i + 1)));
        }
        let index = 1u64;
        let leaf = Fr::from(14u64);
        let path = tree.path(index);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let leaf_v = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let siblings: Vec<FpVar<Fr>> = path
            .siblings
            .iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)).unwrap())
            .collect();
        let bits: Vec<Boolean<Fr>> = (0..4)
            .map(|i| Boolean::new_witness(cs.clone(), || Ok((index >> i) & 1 == 1)).unwrap())
            .collect();
        let root_v = gadget::compute_root(&leaf_v, &siblings, &bits).unwrap();
        assert_eq!(root_v.value().unwrap(), tree.root());
        assert!(cs.is_satisfied().unwrap());
    }
}
