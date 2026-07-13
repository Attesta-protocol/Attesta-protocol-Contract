//! # attesta-interfaces
//!
//! Shared types and cross-contract client interfaces for the Attesta
//! protocol. Every Attesta contract — and any third-party Soroban contract
//! integrating with Attesta — depends on this crate instead of importing
//! other contracts' wasm.
//!
//! The clients generated here (`VerifierClient`, `AttestationClient`,
//! `IssuerClient`) are the integration surface described in the README:
//! one `check` call gives any Soroban app privacy-preserving compliance.

#![no_std]

use soroban_sdk::{contractclient, contracttype, Address, BytesN, Env, Symbol, Vec};

/// Compliance claim types.
///
/// Extensible by governance: adding a variant requires a new attestation
/// circuit, a deployed verifier instance pinned to that circuit's verifying
/// key, and a registry entry mapping the claim kind to the verifier.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimType {
    /// KYC verification at or above the given level (e.g. SEP-12 tiers).
    KycLevel(u32),
    /// Residency in one of an allowed set of jurisdictions, identified by a
    /// hash over the sorted ISO 3166-1 alpha-2 set the verifying app accepts.
    Jurisdiction(BytesN<32>),
    /// Monthly inflows above the given threshold (stroops of the reference
    /// asset), proven over an issuer-signed income credential.
    IncomeAbove(i128),
    /// Accredited-investor status.
    Accredited,
}

impl ClaimType {
    /// The claim *kind*, used to route to the verifier for the matching
    /// circuit. Distinct parameters of one kind (e.g. `KycLevel(1)` vs
    /// `KycLevel(2)`) share a circuit; the parameter is a public input.
    pub fn kind(&self, env: &Env) -> Symbol {
        match self {
            ClaimType::KycLevel(_) => Symbol::new(env, "kyc_level"),
            ClaimType::Jurisdiction(_) => Symbol::new(env, "jurisdiction"),
            ClaimType::IncomeAbove(_) => Symbol::new(env, "income_above"),
            ClaimType::Accredited => Symbol::new(env, "accredited"),
        }
    }
}

/// Canonicity of BLS12-381 scalar encodings.
///
/// The host functions reduce scalar bytes mod the group order silently,
/// so `x` and `x + r` are distinct byte strings naming the same field
/// element. Contracts that key state on scalar bytes (nullifier sets,
/// commitment trees) must accept only the canonical encoding; these
/// helpers are the shared definition of "canonical".
pub mod fr {
    /// The BLS12-381 scalar field order minus one, big-endian — the
    /// largest canonical scalar encoding.
    pub const FR_MINUS_ONE: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];

    /// Whether `bytes` is a canonical big-endian field element (< r).
    pub fn is_canonical(bytes: &[u8; 32]) -> bool {
        *bytes <= FR_MINUS_ONE
    }
}

/// A Groth16 proof over BLS12-381, in the uncompressed affine encoding
/// expected by the Protocol 25 host functions (G1: 96 bytes, G2: 192 bytes).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Groth16Proof {
    pub a: BytesN<96>,
    pub b: BytesN<192>,
    pub c: BytesN<96>,
}

/// A Groth16 verifying key. Immutable per verifier instance: circuit
/// upgrades deploy a new verifier rather than mutating a key in place.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationKey {
    pub alpha: BytesN<96>,
    pub beta: BytesN<192>,
    pub gamma: BytesN<192>,
    pub delta: BytesN<192>,
    /// IC / gamma_abc: one G1 point per public input, plus one.
    pub ic: Vec<BytesN<96>>,
}

/// Client interface for `zk_verifier` instances (one per circuit).
#[contractclient(name = "VerifierClient")]
pub trait Verifier {
    /// Verify `proof` against the instance's pinned verifying key with the
    /// given public inputs (big-endian scalars < the BLS12-381 group order).
    fn verify(env: Env, proof: Groth16Proof, public_inputs: Vec<BytesN<32>>) -> bool;
}

/// Client interface for the `attestation_registry` — the one-call
/// integration for every other Stellar app.
#[contractclient(name = "AttestationClient")]
pub trait Attestations {
    /// Returns whether `address` currently holds a valid, unexpired,
    /// unrevoked attestation of `claim_type`.
    fn check(env: Env, address: Address, claim_type: ClaimType) -> bool;
}

/// Client interface for the `issuer_registry`.
#[contractclient(name = "IssuerClient")]
pub trait Issuers {
    /// Whether `issuer` is a registered, active credential issuer.
    fn is_issuer(env: Env, issuer: Address) -> bool;
    /// Whether `signing_key` is an active signing key of an active issuer.
    /// Attestation proofs are verified against issuer keys, so rotation or
    /// removal immediately invalidates presentations under the old key.
    fn is_key_active(env: Env, signing_key: BytesN<32>) -> bool;
}
