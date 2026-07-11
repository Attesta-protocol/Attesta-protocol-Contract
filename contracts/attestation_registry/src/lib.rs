//! # attestation_registry
//!
//! The compliance primitive. Users present ZK proofs over issuer-signed
//! credentials ("I hold a valid, unexpired KYC credential from an approved
//! issuer") without revealing the credential; on success the registry
//! records a scoped, time-boxed attestation for their address.
//!
//! Any Soroban contract consumes attestations through one call:
//! [`AttestationsImpl::check`] — no app ever touches the underlying
//! personal data. Credentials themselves never go on-chain; what is stored
//! is `(address, claim_type, expiry, credential_ref)` where
//! `credential_ref` is an opaque revocation handle that does not identify
//! the issuer or the credential contents to observers.
//!
//! ## Verifier routing
//! Each claim *kind* (`kyc_level`, `jurisdiction`, `income_above`,
//! `accredited`) has its own circuit and thus its own pinned `zk_verifier`
//! instance. Mapping a kind to a verifier is an admin action; the admin is
//! the protocol's timelocked multi-sig (the same governance that curates
//! the issuer registry), and every change is evented.
//!
//! ## Storage
//! - Instance: `Admin`, `IssuerRegistry`, `Verifier(kind)`.
//! - Persistent: `Attestation(address, claim_type)` records,
//!   `Revoked(credential_ref)` flags.

#![no_std]
// `present` takes 8 flat arguments deliberately: contract entry points are
// invoked from CLIs and SDKs where flat, self-describing parameters beat a
// wrapper struct. The allow is crate-wide because the lint also fires inside
// the macro-generated client for the same function.
#![allow(clippy::too_many_arguments)]

use attesta_interfaces::{Attestations, ClaimType, Groth16Proof, IssuerClient, VerifierClient};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, vec,
    Address, Bytes, BytesN, Env, Symbol, Vec,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationRecord {
    /// Ledger timestamp after which the attestation is invalid.
    pub expires_at: u64,
    /// Opaque revocation handle: issuer-driven revocation of the underlying
    /// credential invalidates this attestation via `Revoked(credential_ref)`.
    pub credential_ref: BytesN<32>,
    pub presented_at: u64,
}

#[contracttype]
enum DataKey {
    Admin,
    IssuerRegistry,
    Verifier(Symbol),
    Attestation(Address, ClaimType),
    Revoked(BytesN<32>),
}

/// A claim kind was routed to a verifier instance.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierSet {
    #[topic]
    pub claim_kind: Symbol,
    pub verifier: Address,
}

/// An attestation was recorded. Note what is *not* here: nothing about the
/// credential contents or which issuer verified the user.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Presented {
    #[topic]
    pub user: Address,
    pub claim_type: ClaimType,
    pub expires_at: u64,
}

/// An issuer revoked a credential; attestations carrying this ref are
/// invalid from this ledger on.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRevoked {
    #[topic]
    pub issuer: Address,
    pub credential_ref: BytesN<32>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttestationError {
    NoVerifierForClaim = 1,
    InactiveIssuerKey = 2,
    CredentialRevoked = 3,
    InvalidProof = 4,
    InvalidExpiry = 5,
    NotAnIssuer = 6,
}

#[contract]
pub struct AttestationRegistry;

#[contractimpl]
impl AttestationRegistry {
    pub fn __constructor(env: Env, admin: Address, issuer_registry: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::IssuerRegistry, &issuer_registry);
    }

    /// Route a claim kind to the `zk_verifier` instance pinned to its
    /// circuit. Admin = timelocked multi-sig; evented.
    pub fn set_verifier(env: Env, claim_kind: Symbol, verifier: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::Verifier(claim_kind.clone()), &verifier);
        VerifierSet {
            claim_kind,
            verifier,
        }
        .publish(&env);
    }

    /// Present a ZK proof over an issuer credential.
    ///
    /// * `user` — the address the attestation is recorded for (must auth,
    ///   so attestations cannot be replayed onto someone else).
    /// * `claim_type` — the claim being proven, parameters included.
    /// * `context` — verifying-app-specific binding data (e.g. a domain
    ///   separator), hashed into the public inputs.
    /// * `issuer_key` — the issuer signing key the credential verifies
    ///   against; must be active in the issuer registry. Which real-world
    ///   issuer this is need not be revealed beyond registry membership.
    /// * `credential_ref` — revocation handle derived in-circuit from the
    ///   credential (not linkable to its contents).
    /// * `expires_at` — attestation expiry, constrained in-circuit to not
    ///   outlive the credential.
    pub fn present(
        env: Env,
        user: Address,
        proof: Groth16Proof,
        claim_type: ClaimType,
        context: Bytes,
        issuer_key: BytesN<32>,
        credential_ref: BytesN<32>,
        expires_at: u64,
    ) {
        user.require_auth();
        if expires_at <= env.ledger().timestamp() {
            panic_with_error!(&env, AttestationError::InvalidExpiry);
        }

        let issuer_registry: Address = env
            .storage()
            .instance()
            .get(&DataKey::IssuerRegistry)
            .unwrap();
        if !IssuerClient::new(&env, &issuer_registry).is_key_active(&issuer_key) {
            panic_with_error!(&env, AttestationError::InactiveIssuerKey);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::Revoked(credential_ref.clone()))
        {
            panic_with_error!(&env, AttestationError::CredentialRevoked);
        }

        let kind = claim_type.kind(&env);
        let verifier: Address = env
            .storage()
            .instance()
            .get(&DataKey::Verifier(kind))
            .unwrap_or_else(|| panic_with_error!(&env, AttestationError::NoVerifierForClaim));

        // Public inputs, in circuit order: issuer key, credential ref,
        // claim+context binding, subject binding, expiry.
        let public_inputs: Vec<BytesN<32>> = vec![
            &env,
            issuer_key,
            credential_ref.clone(),
            claim_binding(&env, &claim_type, &context),
            address_binding(&env, &user),
            u64_to_field(&env, expires_at),
        ];
        if !VerifierClient::new(&env, &verifier).verify(&proof, &public_inputs) {
            panic_with_error!(&env, AttestationError::InvalidProof);
        }

        let record = AttestationRecord {
            expires_at,
            credential_ref,
            presented_at: env.ledger().timestamp(),
        };
        env.storage().persistent().set(
            &DataKey::Attestation(user.clone(), claim_type.clone()),
            &record,
        );

        Presented {
            user,
            claim_type,
            expires_at,
        }
        .publish(&env);
    }

    /// Issuer-driven revocation of a credential (compromised or
    /// invalidated). Every attestation carrying this `credential_ref` fails
    /// `check` from the next ledger on.
    pub fn revoke_credential(env: Env, issuer: Address, credential_ref: BytesN<32>) {
        issuer.require_auth();
        let issuer_registry: Address = env
            .storage()
            .instance()
            .get(&DataKey::IssuerRegistry)
            .unwrap();
        if !IssuerClient::new(&env, &issuer_registry).is_issuer(&issuer) {
            panic_with_error!(&env, AttestationError::NotAnIssuer);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Revoked(credential_ref.clone()), &true);
        CredentialRevoked {
            issuer,
            credential_ref,
        }
        .publish(&env);
    }

    /// The attestation record, for indexers and disclosure tooling.
    pub fn get_attestation(
        env: Env,
        address: Address,
        claim_type: ClaimType,
    ) -> Option<AttestationRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Attestation(address, claim_type))
    }
}

#[contractimpl]
impl Attestations for AttestationRegistry {
    /// The one-call integration for every other Stellar app.
    fn check(env: Env, address: Address, claim_type: ClaimType) -> bool {
        let Some(record) = env
            .storage()
            .persistent()
            .get::<_, AttestationRecord>(&DataKey::Attestation(address, claim_type))
        else {
            return false;
        };
        if env.ledger().timestamp() > record.expires_at {
            return false;
        }
        !env.storage()
            .persistent()
            .has(&DataKey::Revoked(record.credential_ref))
    }
}

/// Hash the claim (parameters included) and app context into one field
/// element, top byte cleared for canonicity in the BLS12-381 scalar field.
/// The attestation circuits compute the same binding.
fn claim_binding(env: &Env, claim_type: &ClaimType, context: &Bytes) -> BytesN<32> {
    use soroban_sdk::xdr::ToXdr;
    let mut data = claim_type.clone().to_xdr(env);
    data.append(context);
    truncate_to_field(env, env.crypto().sha256(&data).to_array())
}

fn address_binding(env: &Env, address: &Address) -> BytesN<32> {
    use soroban_sdk::xdr::ToXdr;
    truncate_to_field(
        env,
        env.crypto().sha256(&address.clone().to_xdr(env)).to_array(),
    )
}

fn u64_to_field(env: &Env, value: u64) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

fn truncate_to_field(env: &Env, mut bytes: [u8; 32]) -> BytesN<32> {
    bytes[0] = 0;
    BytesN::from_array(env, &bytes)
}

#[cfg(test)]
mod test;
