#![cfg(test)]

use super::*;
use attesta_interfaces::{ClaimType, Groth16Proof};
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger},
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

const ROTATION_DELAY: u64 = 86_400;

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
            ROTATION_DELAY,
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

/// An arbitrary but distinct, canonical field element — used both as a
/// stand-in `new_commitments` entry for `transfer` (which accepts them
/// opaquely) and as a component of a `deposit` note below.
fn commitment(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

/// `(owner_pk, blinding)` for a deposit note: `deposit` derives the
/// commitment itself, so tests only need to supply these two components.
fn owner_and_blinding(env: &Env, seed: u8) -> (BytesN<32>, BytesN<32>) {
    (
        commitment(env, seed),
        commitment(env, seed.wrapping_add(50)),
    )
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

    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &owner_pk, &blinding);

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
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool.deposit(&s.user, &other, &500, &owner_pk, &blinding);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn deposit_rejects_nonpositive_amount() {
    let s = setup(true, None);
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &0, &owner_pk, &blinding);
}

#[test]
fn transfer_spends_nullifiers_and_inserts_commitments() {
    let s = setup(true, None);
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &owner_pk, &blinding);
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
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &owner_pk, &blinding);
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
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &owner_pk, &blinding);
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
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &owner_pk, &blinding);
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
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &owner_pk, &blinding);
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
                ROTATION_DELAY,
                Some(GateConfig {
                    registry,
                    required_claim: ClaimType::KycLevel(2),
                }),
            ),
        ),
    );

    let (owner_pk, blinding) = owner_and_blinding(&env, 1);
    pool.deposit(&user, &asset.address(), &100, &owner_pk, &blinding);
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
                ROTATION_DELAY,
                Some(GateConfig {
                    registry,
                    required_claim: ClaimType::KycLevel(2),
                }),
            ),
        ),
    );

    let (owner_pk, blinding) = owner_and_blinding(&env, 1);
    pool.deposit(&user, &asset.address(), &100, &owner_pk, &blinding);
}

#[test]
fn poseidon_matches_circuit_vector() {
    // Cross-check vector printed by circuits/scripts/build-artifacts.sh:
    // hash2(1, 2) must agree between the circuits crate and this
    // contract's host-Fr implementation.
    let env = Env::default();
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut two = [0u8; 32];
    two[31] = 2;
    let h = crate::poseidon::hash2(
        &env,
        &BytesN::from_array(&env, &one),
        &BytesN::from_array(&env, &two),
    );
    let expected = hex_literal("28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a");
    assert_eq!(h, BytesN::from_array(&env, &expected));
}

fn hex_literal(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        out[i] = hi * 16 + lo;
    }
    out
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn deposit_rejects_amount_above_note_range() {
    // Circuit note values are 64-bit; a larger deposit could never be
    // spent or withdrawn, so the pool refuses to strand it.
    let s = setup(true, None);
    let too_big = (u64::MAX as i128) + 1;
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &too_big, &owner_pk, &blinding);
}

#[test]
fn deposit_commitment_is_derived_from_amount_and_owner() {
    // The regression test for the inflation bug: `deposit` must not trust
    // a caller-supplied commitment. It derives `H(H(amount, owner_pk),
    // blinding)` itself, so the inserted leaf — and therefore the note a
    // depositor can later spend — is pinned to the tokens they actually
    // transferred in. This reproduces that derivation independently (via
    // the same on-chain Poseidon hash2 used everywhere else) and checks
    // the resulting root against the pool's, rather than trusting
    // whatever the pool decided to insert.
    let s = setup(true, None);
    let owner_pk = BytesN::from_array(&s.env, &[7u8; 32]);
    let blinding = BytesN::from_array(&s.env, &[9u8; 32]);
    let amount: i128 = 500;

    s.pool
        .deposit(&s.user, &s.token.address, &amount, &owner_pk, &blinding);

    let mut value_bytes = [0u8; 32];
    value_bytes[16..].copy_from_slice(&amount.to_be_bytes());
    let value_field = BytesN::from_array(&s.env, &value_bytes);
    let expected_commitment = crate::poseidon::hash2(
        &s.env,
        &crate::poseidon::hash2(&s.env, &value_field, &owner_pk),
        &blinding,
    );

    // First leaf in an empty tree: the root is the commitment hashed up
    // the all-zero sibling chain, exactly as `insert_commitment` computes
    // it for index 0.
    let mut node = expected_commitment.clone();
    for z in crate::poseidon_params::ZEROS
        .iter()
        .take(TREE_DEPTH as usize)
    {
        node = crate::poseidon::hash2(&s.env, &node, &BytesN::from_array(&s.env, z));
    }
    assert_eq!(s.pool.root(), node);

    // A depositor cannot claim a shielded value other than what they paid
    // in: a note built from a different amount produces a different leaf
    // and therefore a different root.
    let mut other_value_bytes = [0u8; 32];
    other_value_bytes[16..].copy_from_slice(&(amount + 1).to_be_bytes());
    let other_value_field = BytesN::from_array(&s.env, &other_value_bytes);
    let mismatched_commitment = crate::poseidon::hash2(
        &s.env,
        &crate::poseidon::hash2(&s.env, &other_value_field, &owner_pk),
        &blinding,
    );
    assert_ne!(expected_commitment, mismatched_commitment);
}

#[test]
fn verifier_rotation_respects_timelock() {
    let s = setup(true, None);
    let new_verifier = s.env.register(MockVerifier, (false,));

    assert!(s.pool.pending_rotation(&VerifierSlot::Transfer).is_none());
    s.pool
        .queue_verifier_rotation(&VerifierSlot::Transfer, &new_verifier);
    let pending = s.pool.pending_rotation(&VerifierSlot::Transfer).unwrap();
    assert_eq!(pending.verifier, new_verifier);

    // Before the delay elapses execution must fail...
    assert!(s
        .pool
        .try_execute_verifier_rotation(&VerifierSlot::Transfer)
        .is_err());
    let old = s.pool.verifier(&VerifierSlot::Transfer);

    // ...after it, the slot rebinds (and only that slot).
    s.env.ledger().with_mut(|l| l.timestamp += ROTATION_DELAY);
    s.pool.execute_verifier_rotation(&VerifierSlot::Transfer);
    assert_eq!(s.pool.verifier(&VerifierSlot::Transfer), new_verifier);
    assert_ne!(s.pool.verifier(&VerifierSlot::Transfer), old);
    assert_ne!(s.pool.verifier(&VerifierSlot::Withdraw), new_verifier);
    assert!(s.pool.pending_rotation(&VerifierSlot::Transfer).is_none());

    // The rotated-in verifier rejects everything: transfers now fail.
    let (owner_pk, blinding) = owner_and_blinding(&s.env, 1);
    s.pool
        .deposit(&s.user, &s.token.address, &500, &owner_pk, &blinding);
    let root = s.pool.root();
    let result = s.pool.try_transfer(
        &dummy_proof(&s.env),
        &vec![&s.env, BytesN::from_array(&s.env, &[9u8; 32])],
        &vec![&s.env, commitment(&s.env, 2)],
        &vec![&s.env, Bytes::from_slice(&s.env, b"ct")],
        &root,
    );
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn canceled_rotation_cannot_execute() {
    let s = setup(true, None);
    let new_verifier = s.env.register(MockVerifier, (true,));
    s.pool
        .queue_verifier_rotation(&VerifierSlot::Withdraw, &new_verifier);
    s.pool.cancel_verifier_rotation(&VerifierSlot::Withdraw);
    s.env.ledger().with_mut(|l| l.timestamp += ROTATION_DELAY);
    s.pool.execute_verifier_rotation(&VerifierSlot::Withdraw);
}

#[test]
fn requeue_replaces_pending_rotation_and_restarts_clock() {
    let s = setup(true, None);
    let first = s.env.register(MockVerifier, (true,));
    let second = s.env.register(MockVerifier, (true,));

    s.pool
        .queue_verifier_rotation(&VerifierSlot::Transfer, &first);
    s.env
        .ledger()
        .with_mut(|l| l.timestamp += ROTATION_DELAY - 1);
    s.pool
        .queue_verifier_rotation(&VerifierSlot::Transfer, &second);

    // The old eta is gone: one second later (old eta reached) the
    // replacement is still locked.
    s.env.ledger().with_mut(|l| l.timestamp += 1);
    assert!(s
        .pool
        .try_execute_verifier_rotation(&VerifierSlot::Transfer)
        .is_err());

    s.env.ledger().with_mut(|l| l.timestamp += ROTATION_DELAY);
    s.pool.execute_verifier_rotation(&VerifierSlot::Transfer);
    assert_eq!(s.pool.verifier(&VerifierSlot::Transfer), second);
}

#[test]
fn admin_rotation_respects_timelock_and_takes_effect() {
    let s = setup(true, None);
    let old_admin = s.pool.admin();
    let new_admin = Address::generate(&s.env);
    assert_ne!(old_admin, new_admin);

    assert!(s.pool.pending_admin_rotation().is_none());
    s.pool.queue_admin_rotation(&new_admin);
    let pending = s.pool.pending_admin_rotation().unwrap();
    assert_eq!(pending.admin, new_admin);
    assert_eq!(s.pool.admin(), old_admin); // unchanged until executed

    // Before the delay elapses, execution must fail.
    assert!(s.pool.try_execute_admin_rotation().is_err());

    s.env.ledger().with_mut(|l| l.timestamp += ROTATION_DELAY);
    s.pool.execute_admin_rotation();
    assert_eq!(s.pool.admin(), new_admin);
    assert!(s.pool.pending_admin_rotation().is_none());
}

#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn canceled_admin_rotation_cannot_execute() {
    let s = setup(true, None);
    let new_admin = Address::generate(&s.env);
    s.pool.queue_admin_rotation(&new_admin);
    s.pool.cancel_admin_rotation();
    s.env.ledger().with_mut(|l| l.timestamp += ROTATION_DELAY);
    s.pool.execute_admin_rotation();
}

#[test]
fn requeue_replaces_pending_admin_rotation_and_restarts_clock() {
    let s = setup(true, None);
    let first = Address::generate(&s.env);
    let second = Address::generate(&s.env);

    s.pool.queue_admin_rotation(&first);
    s.env
        .ledger()
        .with_mut(|l| l.timestamp += ROTATION_DELAY - 1);
    s.pool.queue_admin_rotation(&second);

    s.env.ledger().with_mut(|l| l.timestamp += 1);
    assert!(s.pool.try_execute_admin_rotation().is_err());

    s.env.ledger().with_mut(|l| l.timestamp += ROTATION_DELAY);
    s.pool.execute_admin_rotation();
    assert_eq!(s.pool.admin(), second);
}
