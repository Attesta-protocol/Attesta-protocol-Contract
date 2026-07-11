#![cfg(test)]

use super::*;
use attesta_interfaces::{ClaimType, Groth16Proof};
use attesta_issuer_registry::{Action, IssuerRegistry, IssuerRegistryClient};
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger},
    Address, Bytes, BytesN, Env, String, Symbol, Vec,
};

/// Stand-in verifier with a fixed verdict; real Groth16 plumbing is tested
/// in `zk_verifier`.
#[contract]
struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn __constructor(env: Env, accept: bool) {
        env.storage().instance().set(&0u32, &accept);
    }
    pub fn verify(env: Env, _proof: Groth16Proof, _public_inputs: Vec<BytesN<32>>) -> bool {
        env.storage().instance().get(&0u32).unwrap()
    }
}

const DELAY: u64 = 3600;

struct Setup {
    env: Env,
    registry: AttestationRegistryClient<'static>,
    issuer: Address,
    issuer_key: BytesN<32>,
    user: Address,
}

fn setup(verifier_accepts: bool) -> Setup {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let user = Address::generate(&env);
    let issuer_key = BytesN::from_array(&env, &[42u8; 32]);

    // Real issuer registry: register an issuer through the timelock.
    let issuer_registry_id = env.register(IssuerRegistry, (admin.clone(), DELAY));
    let issuer_registry = IssuerRegistryClient::new(&env, &issuer_registry_id);
    let action_id = issuer_registry.queue(&Action::AddIssuer(
        issuer.clone(),
        issuer_key.clone(),
        String::from_str(&env, "Anchor One"),
    ));
    env.ledger().with_mut(|l| l.timestamp += DELAY);
    issuer_registry.execute(&action_id);

    let registry_id = env.register(AttestationRegistry, (admin, issuer_registry_id));
    let registry = AttestationRegistryClient::new(&env, &registry_id);
    let verifier = env.register(MockVerifier, (verifier_accepts,));
    registry.set_verifier(&Symbol::new(&env, "kyc_level"), &verifier);

    Setup {
        env,
        registry,
        issuer,
        issuer_key,
        user,
    }
}

fn dummy_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: BytesN::from_array(env, &[0u8; 96]),
        b: BytesN::from_array(env, &[0u8; 192]),
        c: BytesN::from_array(env, &[0u8; 96]),
    }
}

fn present_kyc(s: &Setup, credential_ref: &BytesN<32>, expires_at: u64) {
    s.registry.present(
        &s.user,
        &dummy_proof(&s.env),
        &ClaimType::KycLevel(2),
        &Bytes::from_slice(&s.env, b"pool-entry"),
        &s.issuer_key,
        credential_ref,
        &expires_at,
    );
}

#[test]
fn present_then_check() {
    let s = setup(true);
    let claim = ClaimType::KycLevel(2);
    assert!(!s.registry.check(&s.user, &claim));

    let cred = BytesN::from_array(&s.env, &[7u8; 32]);
    present_kyc(&s, &cred, s.env.ledger().timestamp() + 1000);

    assert!(s.registry.check(&s.user, &claim));
    // Scoped to the exact claim: a different level is a different claim.
    assert!(!s.registry.check(&s.user, &ClaimType::KycLevel(3)));
    // Scoped to the address.
    assert!(!s.registry.check(&Address::generate(&s.env), &claim));

    let record = s.registry.get_attestation(&s.user, &claim).unwrap();
    assert_eq!(record.credential_ref, cred);
}

#[test]
fn attestation_expires() {
    let s = setup(true);
    let cred = BytesN::from_array(&s.env, &[7u8; 32]);
    present_kyc(&s, &cred, s.env.ledger().timestamp() + 1000);

    assert!(s.registry.check(&s.user, &ClaimType::KycLevel(2)));
    s.env.ledger().with_mut(|l| l.timestamp += 1001);
    assert!(!s.registry.check(&s.user, &ClaimType::KycLevel(2)));
}

#[test]
fn revocation_invalidates_attestation() {
    let s = setup(true);
    let cred = BytesN::from_array(&s.env, &[7u8; 32]);
    present_kyc(&s, &cred, s.env.ledger().timestamp() + 1000);
    assert!(s.registry.check(&s.user, &ClaimType::KycLevel(2)));

    s.registry.revoke_credential(&s.issuer, &cred);
    assert!(!s.registry.check(&s.user, &ClaimType::KycLevel(2)));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn revoked_credential_cannot_be_presented() {
    let s = setup(true);
    let cred = BytesN::from_array(&s.env, &[7u8; 32]);
    s.registry.revoke_credential(&s.issuer, &cred);
    present_kyc(&s, &cred, s.env.ledger().timestamp() + 1000);
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn only_registered_issuers_can_revoke() {
    let s = setup(true);
    let outsider = Address::generate(&s.env);
    s.registry
        .revoke_credential(&outsider, &BytesN::from_array(&s.env, &[7u8; 32]));
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn invalid_proof_rejected() {
    let s = setup(false);
    present_kyc(
        &s,
        &BytesN::from_array(&s.env, &[7u8; 32]),
        s.env.ledger().timestamp() + 1000,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn unknown_issuer_key_rejected() {
    let s = setup(true);
    s.registry.present(
        &s.user,
        &dummy_proof(&s.env),
        &ClaimType::KycLevel(2),
        &Bytes::from_slice(&s.env, b"ctx"),
        &BytesN::from_array(&s.env, &[99u8; 32]),
        &BytesN::from_array(&s.env, &[7u8; 32]),
        &(s.env.ledger().timestamp() + 1000),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn claim_kind_without_verifier_rejected() {
    let s = setup(true);
    s.registry.present(
        &s.user,
        &dummy_proof(&s.env),
        &ClaimType::Accredited,
        &Bytes::from_slice(&s.env, b"ctx"),
        &s.issuer_key,
        &BytesN::from_array(&s.env, &[7u8; 32]),
        &(s.env.ledger().timestamp() + 1000),
    );
}
