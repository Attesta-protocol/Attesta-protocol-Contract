//! # attesta-circuits
//!
//! Groth16 circuits over BLS12-381 for the Attesta protocol (M1, in
//! progress). Every circuit here has a matching on-chain `zk_verifier`
//! instance pinned to its verifying key.
//!
//! ## Planned circuits
//!
//! - **`transfer`** — proves, for a shielded transfer: the spent notes are
//!   members of the commitment tree under the public root; the prover
//!   holds their spending keys; the published nullifiers are correctly
//!   derived; and total input value equals total output value (no
//!   inflation), with all values range-checked.
//!   Public inputs: `[root, nullifiers.., new_commitments..]`.
//!
//! - **`withdraw`** — proves ownership of an unspent note of exactly the
//!   public amount, bound to the public recipient so a relayer cannot
//!   redirect the exit.
//!   Public inputs: `[root, nullifier, recipient_binding, amount]`.
//!
//! - **`attest_*`** (M5) — one circuit per claim kind, proving possession
//!   of a valid, unexpired credential signed by an issuer key that is a
//!   public input (registry membership is checked on-chain).
//!   Public inputs: `[issuer_key, credential_ref, claim_binding,
//!   subject_binding, expires_at]`.
//!
//! ## Ground rules (see ../CONTRIBUTING.md)
//!
//! - Standard constructions only: Groth16, Pedersen commitments,
//!   established Merkle/nullifier patterns. Novel cryptography is a bug.
//! - Every circuit change ships with a written soundness argument and two
//!   reviews.
//! - Proving happens client-side only. Proving keys are published;
//!   the trusted setup is a public multi-party ceremony whose transcript
//!   lives in this directory.

#![deny(missing_docs)]

pub mod note;
pub mod poseidon;

/// Circuit public-input layouts shared with the contract layer. Kept in
/// sync by hand until M1 lands code generation from one definition.
pub mod layout {
    /// Public input count for the transfer circuit with `n_in` spent notes
    /// and `n_out` created notes: root + nullifiers + commitments.
    pub const fn transfer_public_inputs(n_in: usize, n_out: usize) -> usize {
        1 + n_in + n_out
    }

    /// Public input count for the withdraw circuit:
    /// root, nullifier, recipient binding, amount.
    pub const WITHDRAW_PUBLIC_INPUTS: usize = 4;

    /// Public input count for attestation circuits: issuer key,
    /// credential ref, claim binding, subject binding, expiry.
    pub const ATTESTATION_PUBLIC_INPUTS: usize = 5;
}

#[cfg(test)]
mod tests {
    use super::layout;

    #[test]
    fn layouts_match_contract_expectations() {
        // shielded_pool::transfer builds 1 + n_in + n_out inputs.
        assert_eq!(layout::transfer_public_inputs(2, 2), 5);
        assert_eq!(layout::WITHDRAW_PUBLIC_INPUTS, 4);
        assert_eq!(layout::ATTESTATION_PUBLIC_INPUTS, 5);
    }
}
