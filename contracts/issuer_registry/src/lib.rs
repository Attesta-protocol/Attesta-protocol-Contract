//! # issuer_registry
//!
//! Governance-curated list of credential issuers (anchors, KYC providers)
//! with published signing keys. Attestation circuits verify credentials
//! against these keys, so this registry is the trust root of the
//! attestation layer.
//!
//! - **Timelocked and evented:** additions, removals, and key rotations are
//!   queued by governance and only executable after the configured delay,
//!   with events at every step — integrators can watch pending changes
//!   before they take effect.
//! - **Multi-issuer by design:** no single KYC provider becomes a
//!   chokepoint for the ecosystem.
//! - **Governance path:** launches under a multi-sig admin; the documented
//!   milestone path migrates curation to the community (see COMPLIANCE.md).
//!
//! ## Storage
//! - Instance: `Admin`, `Delay`, `NextActionId`.
//! - Persistent: `Pending(id)` queued actions, `Issuer(address)` records,
//!   `KeyOwner(signing_key)` reverse index for `is_key_active`.

#![no_std]

use attesta_interfaces::Issuers;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    BytesN, Env, String,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerInfo {
    /// Public signing key credentials are verified against (as a public
    /// input to attestation circuits).
    pub signing_key: BytesN<32>,
    /// Display name / metadata pointer (e.g. anchor name, SEP-1 TOML URL).
    pub name: String,
    pub registered_at: u64,
    pub active: bool,
}

/// Governance actions that must pass through the timelock.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    AddIssuer(Address, BytesN<32>, String),
    RemoveIssuer(Address),
    RotateKey(Address, BytesN<32>),
}

#[contracttype]
#[derive(Clone)]
pub struct PendingAction {
    pub action: Action,
    /// Earliest ledger timestamp at which the action may execute.
    pub eta: u64,
}

#[contracttype]
enum DataKey {
    Admin,
    Delay,
    NextActionId,
    Pending(u64),
    Issuer(Address),
    KeyOwner(BytesN<32>),
}

/// A curation action entered the timelock queue. Integrators should watch
/// these to see registry changes before they take effect.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionQueued {
    #[topic]
    pub id: u64,
    pub action: Action,
    pub eta: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionCanceled {
    #[topic]
    pub id: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionExecuted {
    #[topic]
    pub id: u64,
    pub action: Action,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    UnknownAction = 1,
    TimelockNotElapsed = 2,
    IssuerExists = 3,
    UnknownIssuer = 4,
    KeyInUse = 5,
}

#[contract]
pub struct IssuerRegistry;

#[contractimpl]
impl IssuerRegistry {
    /// * `admin` — the governance multi-sig.
    /// * `delay` — timelock delay in seconds for every curation action.
    pub fn __constructor(env: Env, admin: Address, delay: u64) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Delay, &delay);
        env.storage().instance().set(&DataKey::NextActionId, &0u64);
    }

    /// Queue a curation action behind the timelock. Returns the action id.
    pub fn queue(env: Env, action: Action) -> u64 {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let delay: u64 = env.storage().instance().get(&DataKey::Delay).unwrap();
        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextActionId)
            .unwrap();
        let eta = env.ledger().timestamp() + delay;
        env.storage().persistent().set(
            &DataKey::Pending(id),
            &PendingAction {
                action: action.clone(),
                eta,
            },
        );
        env.storage()
            .instance()
            .set(&DataKey::NextActionId, &(id + 1));

        ActionQueued { id, action, eta }.publish(&env);
        id
    }

    /// Cancel a queued action before execution.
    pub fn cancel(env: Env, id: u64) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        if !env.storage().persistent().has(&DataKey::Pending(id)) {
            panic_with_error!(&env, RegistryError::UnknownAction);
        }
        env.storage().persistent().remove(&DataKey::Pending(id));
        ActionCanceled { id }.publish(&env);
    }

    /// Execute a queued action once its timelock has elapsed.
    pub fn execute(env: Env, id: u64) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let pending: PendingAction = env
            .storage()
            .persistent()
            .get(&DataKey::Pending(id))
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::UnknownAction));
        if env.ledger().timestamp() < pending.eta {
            panic_with_error!(&env, RegistryError::TimelockNotElapsed);
        }
        env.storage().persistent().remove(&DataKey::Pending(id));

        match pending.action.clone() {
            Action::AddIssuer(issuer, key, name) => add_issuer(&env, issuer, key, name),
            Action::RemoveIssuer(issuer) => remove_issuer(&env, issuer),
            Action::RotateKey(issuer, new_key) => rotate_key(&env, issuer, new_key),
        }

        ActionExecuted {
            id,
            action: pending.action,
        }
        .publish(&env);
    }

    /// A queued action, for integrators watching pending changes.
    pub fn pending(env: Env, id: u64) -> Option<PendingAction> {
        env.storage().persistent().get(&DataKey::Pending(id))
    }

    pub fn get_issuer(env: Env, issuer: Address) -> Option<IssuerInfo> {
        env.storage().persistent().get(&DataKey::Issuer(issuer))
    }
}

#[contractimpl]
impl Issuers for IssuerRegistry {
    fn is_issuer(env: Env, issuer: Address) -> bool {
        env.storage()
            .persistent()
            .get::<_, IssuerInfo>(&DataKey::Issuer(issuer))
            .is_some_and(|info| info.active)
    }

    fn is_key_active(env: Env, signing_key: BytesN<32>) -> bool {
        let Some(owner) = env
            .storage()
            .persistent()
            .get::<_, Address>(&DataKey::KeyOwner(signing_key))
        else {
            return false;
        };
        Self::is_issuer(env, owner)
    }
}

fn add_issuer(env: &Env, issuer: Address, key: BytesN<32>, name: String) {
    if env
        .storage()
        .persistent()
        .has(&DataKey::Issuer(issuer.clone()))
    {
        panic_with_error!(env, RegistryError::IssuerExists);
    }
    claim_key(env, &key, &issuer);
    env.storage().persistent().set(
        &DataKey::Issuer(issuer),
        &IssuerInfo {
            signing_key: key,
            name,
            registered_at: env.ledger().timestamp(),
            active: true,
        },
    );
}

fn remove_issuer(env: &Env, issuer: Address) {
    let mut info: IssuerInfo = env
        .storage()
        .persistent()
        .get(&DataKey::Issuer(issuer.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownIssuer));
    // Deactivate rather than delete: history stays queryable, and
    // is_key_active goes false immediately for all of the issuer's keys.
    info.active = false;
    env.storage()
        .persistent()
        .set(&DataKey::Issuer(issuer), &info);
}

fn rotate_key(env: &Env, issuer: Address, new_key: BytesN<32>) {
    let mut info: IssuerInfo = env
        .storage()
        .persistent()
        .get(&DataKey::Issuer(issuer.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownIssuer));
    claim_key(env, &new_key, &issuer);
    // The old key stops validating immediately.
    env.storage()
        .persistent()
        .remove(&DataKey::KeyOwner(info.signing_key.clone()));
    info.signing_key = new_key;
    env.storage()
        .persistent()
        .set(&DataKey::Issuer(issuer), &info);
}

fn claim_key(env: &Env, key: &BytesN<32>, issuer: &Address) {
    if env
        .storage()
        .persistent()
        .has(&DataKey::KeyOwner(key.clone()))
    {
        panic_with_error!(env, RegistryError::KeyInUse);
    }
    env.storage()
        .persistent()
        .set(&DataKey::KeyOwner(key.clone()), issuer);
}

#[cfg(test)]
mod test;
