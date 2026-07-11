#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, String,
};

const DELAY: u64 = 86_400; // 24h timelock

fn setup() -> (Env, IssuerRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(IssuerRegistry, (admin.clone(), DELAY));
    let client = IssuerRegistryClient::new(&env, &id);
    (env, client, admin)
}

fn key(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

fn advance(env: &Env, secs: u64) {
    env.ledger().with_mut(|l| l.timestamp += secs);
}

fn add_issuer(env: &Env, client: &IssuerRegistryClient, issuer: &Address, k: BytesN<32>) {
    let id = client.queue(&Action::AddIssuer(
        issuer.clone(),
        k,
        String::from_str(env, "Anchor One"),
    ));
    advance(env, DELAY);
    client.execute(&id);
}

#[test]
fn add_issuer_after_timelock() {
    let (env, client, _) = setup();
    let issuer = Address::generate(&env);

    let id = client.queue(&Action::AddIssuer(
        issuer.clone(),
        key(&env, 1),
        String::from_str(&env, "Anchor One"),
    ));
    assert!(client.pending(&id).is_some());
    assert!(!client.is_issuer(&issuer));

    advance(&env, DELAY);
    client.execute(&id);

    assert!(client.is_issuer(&issuer));
    assert!(client.is_key_active(&key(&env, 1)));
    assert!(client.pending(&id).is_none());
    let info = client.get_issuer(&issuer).unwrap();
    assert_eq!(info.signing_key, key(&env, 1));
    assert!(info.active);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn execute_before_timelock_fails() {
    let (env, client, _) = setup();
    let id = client.queue(&Action::AddIssuer(
        Address::generate(&env),
        key(&env, 1),
        String::from_str(&env, "Too Eager"),
    ));
    advance(&env, DELAY - 1);
    client.execute(&id);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn canceled_action_cannot_execute() {
    let (env, client, _) = setup();
    let id = client.queue(&Action::AddIssuer(
        Address::generate(&env),
        key(&env, 1),
        String::from_str(&env, "Canceled"),
    ));
    client.cancel(&id);
    advance(&env, DELAY);
    client.execute(&id);
}

#[test]
fn rotate_key_deactivates_old_key() {
    let (env, client, _) = setup();
    let issuer = Address::generate(&env);
    add_issuer(&env, &client, &issuer, key(&env, 1));

    let id = client.queue(&Action::RotateKey(issuer.clone(), key(&env, 2)));
    advance(&env, DELAY);
    client.execute(&id);

    assert!(!client.is_key_active(&key(&env, 1)));
    assert!(client.is_key_active(&key(&env, 2)));
    assert!(client.is_issuer(&issuer));
}

#[test]
fn remove_issuer_deactivates_keys() {
    let (env, client, _) = setup();
    let issuer = Address::generate(&env);
    add_issuer(&env, &client, &issuer, key(&env, 1));

    let id = client.queue(&Action::RemoveIssuer(issuer.clone()));
    advance(&env, DELAY);
    client.execute(&id);

    assert!(!client.is_issuer(&issuer));
    assert!(!client.is_key_active(&key(&env, 1)));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn duplicate_signing_key_rejected() {
    let (env, client, _) = setup();
    add_issuer(&env, &client, &Address::generate(&env), key(&env, 1));

    let id = client.queue(&Action::AddIssuer(
        Address::generate(&env),
        key(&env, 1),
        String::from_str(&env, "Copycat"),
    ));
    advance(&env, DELAY);
    client.execute(&id);
}
