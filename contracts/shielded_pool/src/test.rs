#![cfg(test)]

use super::*;
use attesta_interfaces::{ClaimType, Groth16Proof};
use soroban_sdk::{
    contract, contractimpl,
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    vec, Address, Bytes, BytesN, Env, Vec,
};

/// Stand-in verifier: accepts or rejects everything, per construction.
/// Real proof plumbing is exercised in `zk_verifier`'s own tests; here we
/// test the pool's state machine around the verifier's verdict.
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

/// Stand-in attestation registry with a fixed verdict.
#[contract]
struct MockAttestations;

#[contractimpl]
impl MockAttestations {
    pub fn __constructor(env: Env, verdict: bool) {
        env.storage().instance().set(&0u32, &verdict);
    }
    pub fn check(env: Env, _address: Address, _claim_type: ClaimType) -> bool {
        env.storage().instance().get(&0u32).unwrap()
    }
}

struct Setup {
    env: Env,
    pool: ShieldedPoolClient<'static>,
    token: TokenClient<'static>,
    user: Address,
}

fn setup(verifier_accepts: bool, gate: Option<GateConfig>) -> Setup {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    let token = TokenClient::new(&env, &asset.address());
    StellarAssetClient::new(&env, &asset.address()).mint(&user, &1_000_000);

    let transfer_verifier = env.register(MockVerifier, (verifier_accepts,));
    let withdraw_verifier = env.register(MockVerifier, (verifier_accepts,));
    let pool_id = env.register(
        ShieldedPool,
        (
            admin,
            asset.address(),
            transfer_verifier,
            withdraw_verifier,
            gate,
        ),
    );
    let pool = ShieldedPoolClient::new(&env, &pool_id);
    Setup {
        env,
        pool,
        token,
        user,
    }
}

fn commitment(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

fn dummy_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: BytesN::from_array(env, &[0u8; 96]),
        b: BytesN::from_array(env, &[0u8; 192]),
        c: BytesN::from_array(env, &[0u8; 96]),
    }
}

#[test]
fn deposit_locks_tokens_and_grows_tree() {
    let s = setup(true, None);
    let root_before = s.pool.root();

    s.pool
        .deposit(&s.user, &s.token.address, &500, &commitment(&s.env, 1));

    assert_eq!(s.token.balance(&s.user), 999_500);
    assert_eq!(s.token.balance(&s.pool.address), 500);
    assert_eq!(s.pool.size(), 1);
    let root_after = s.pool.root();
    assert_ne!(root_before, root_after);
    // Historical roots stay valid for in-flight proofs.
    assert!(s.pool.is_known_root(&root_before));
    assert!(s.pool.is_known_root(&root_after));
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn deposit_rejects_foreign_token() {
    let s = setup(true, None);
    let other_admin = Address::generate(&s.env);
    let other = s
        .env
        .register_stellar_asset_contract_v2(other_admin)
        .address();
    s.pool
        .deposit(&s.user, &other, &500, &commitment(&s.env, 1));
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn deposit_rejects_nonpositive_amount() {
    let s = setup(true, None);
    s.pool
        .deposit(&s.user, &s.token.address, &0, &commitment(&s.env, 1));
}

#[test]
fn transfer_spends_nullifiers_and_inserts_commitments() {
    let s = setup(true, None);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &commitment(&s.env, 1));
    let root = s.pool.root();

    let nullifier = BytesN::from_array(&s.env, &[9u8; 32]);
    assert!(!s.pool.is_spent(&nullifier));

    s.pool.transfer(
        &dummy_proof(&s.env),
        &vec![&s.env, nullifier.clone()],
        &vec![&s.env, commitment(&s.env, 2), commitment(&s.env, 3)],
        &vec![
            &s.env,
            Bytes::from_slice(&s.env, b"ct-1"),
            Bytes::from_slice(&s.env, b"ct-2"),
        ],
        &root,
    );

    assert!(s.pool.is_spent(&nullifier));
    assert_eq!(s.pool.size(), 3);
    // Pool token balance is untouched by shielded transfers.
    assert_eq!(s.token.balance(&s.pool.address), 500);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn transfer_rejects_double_spend() {
    let s = setup(true, None);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &commitment(&s.env, 1));
    let root = s.pool.root();
    let nullifier = BytesN::from_array(&s.env, &[9u8; 32]);
    let notes = vec![&s.env, Bytes::from_slice(&s.env, b"ct")];

    s.pool.transfer(
        &dummy_proof(&s.env),
        &vec![&s.env, nullifier.clone()],
        &vec![&s.env, commitment(&s.env, 2)],
        &notes,
        &root,
    );
    // Same nullifier again, against the (still known) old root.
    s.pool.transfer(
        &dummy_proof(&s.env),
        &vec![&s.env, nullifier],
        &vec![&s.env, commitment(&s.env, 4)],
        &notes,
        &root,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn transfer_rejects_unknown_root() {
    let s = setup(true, None);
    s.pool.transfer(
        &dummy_proof(&s.env),
        &vec![&s.env, BytesN::from_array(&s.env, &[9u8; 32])],
        &vec![&s.env, commitment(&s.env, 2)],
        &vec![&s.env, Bytes::from_slice(&s.env, b"ct")],
        &BytesN::from_array(&s.env, &[7u8; 32]),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn transfer_rejects_invalid_proof() {
    let s = setup(false, None);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &commitment(&s.env, 1));
    let root = s.pool.root();
    s.pool.transfer(
        &dummy_proof(&s.env),
        &vec![&s.env, BytesN::from_array(&s.env, &[9u8; 32])],
        &vec![&s.env, commitment(&s.env, 2)],
        &vec![&s.env, Bytes::from_slice(&s.env, b"ct")],
        &root,
    );
}

#[test]
fn withdraw_pays_out_and_spends_nullifier() {
    let s = setup(true, None);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &commitment(&s.env, 1));
    let root = s.pool.root();
    let recipient = Address::generate(&s.env);
    let nullifier = BytesN::from_array(&s.env, &[9u8; 32]);

    s.pool
        .withdraw(&dummy_proof(&s.env), &nullifier, &recipient, &200, &root);

    assert_eq!(s.token.balance(&recipient), 200);
    assert_eq!(s.token.balance(&s.pool.address), 300);
    assert!(s.pool.is_spent(&nullifier));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn withdraw_rejects_spent_nullifier() {
    let s = setup(true, None);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &commitment(&s.env, 1));
    let root = s.pool.root();
    let recipient = Address::generate(&s.env);
    let nullifier = BytesN::from_array(&s.env, &[9u8; 32]);

    s.pool
        .withdraw(&dummy_proof(&s.env), &nullifier, &recipient, &200, &root);
    s.pool
        .withdraw(&dummy_proof(&s.env), &nullifier, &recipient, &200, &root);
}

#[test]
fn gated_pool_admits_attested_depositor() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    StellarAssetClient::new(&env, &asset.address()).mint(&user, &1_000);

    let verifier = env.register(MockVerifier, (true,));
    let registry = env.register(MockAttestations, (true,));
    let pool = ShieldedPoolClient::new(
        &env,
        &env.register(
            ShieldedPool,
            (
                admin,
                asset.address(),
                verifier.clone(),
                verifier,
                Some(GateConfig {
                    registry,
                    required_claim: ClaimType::KycLevel(2),
                }),
            ),
        ),
    );

    pool.deposit(&user, &asset.address(), &100, &commitment(&env, 1));
    assert_eq!(pool.size(), 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn gated_pool_rejects_unattested_depositor() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    StellarAssetClient::new(&env, &asset.address()).mint(&user, &1_000);

    let verifier = env.register(MockVerifier, (true,));
    let registry = env.register(MockAttestations, (false,));
    let pool = ShieldedPoolClient::new(
        &env,
        &env.register(
            ShieldedPool,
            (
                admin,
                asset.address(),
                verifier.clone(),
                verifier,
                Some(GateConfig {
                    registry,
                    required_claim: ClaimType::KycLevel(2),
                }),
            ),
        ),
    );

    pool.deposit(&user, &asset.address(), &100, &commitment(&env, 1));
}
