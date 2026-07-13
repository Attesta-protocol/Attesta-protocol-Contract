//! # shielded_pool
//!
//! Confidential value for a single Stellar asset: deposits become note
//! commitments in an incremental Merkle tree, transfers are validated by
//! ZK proofs (balance preserved, notes owned, no double-spend) without
//! revealing amounts, and withdrawals exit back to the public token.
//!
//! **Deliberate scope (v1):** amounts are shielded; the sender/receiver
//! graph is not. Deposits and withdrawals are public token movements, and
//! `transfer` callers are visible on-chain — only the values inside the
//! pool are hidden.
//!
//! **Per-token pools:** one instance wraps exactly one token (USDC pool,
//! EURC pool), so value can never cross assets invisibly. The contract's
//! token balance always equals the sum of shielded notes — insolvency or
//! inflation bugs are externally detectable even though individual amounts
//! are hidden.
//!
//! **Compliant-by-construction (optional):** the pool may be constructed
//! with an attestation gate; deposits then require a valid compliance
//! attestation from the `attestation_registry`, making this a gated
//! privacy pool rather than a mixer.
//!
//! ## Merkle hash — pinned (M1)
//! The tree hashes with the protocol Poseidon instance over the
//! BLS12-381 scalar field (see [`poseidon`]), computed via the Protocol
//! 25 Fr host functions. It is constant-for-constant identical to the
//! hash the transfer/withdraw circuits evaluate in-circuit; the
//! constants are generated from `circuits/` by
//! `circuits/scripts/build-artifacts.sh`.
//!
//! ## Storage
//! - Instance: pool config, `NextIndex`, `FilledSubtrees`, `Zeros`,
//!   `CurrentRoot`.
//! - Persistent: `KnownRoot(root)` — recent-root validity for provers;
//!   `Nullifier(nf)` — the spent set.

#![no_std]

use attesta_interfaces::{AttestationClient, ClaimType, Groth16Proof, VerifierClient};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, token,
    vec, Address, Bytes, BytesN, Env, Vec,
};

mod poseidon;
mod poseidon_params;

/// Merkle tree depth: capacity 2^20 ≈ 1M notes per pool instance.
pub const TREE_DEPTH: u32 = 20;

#[contracttype]
#[derive(Clone)]
pub struct GateConfig {
    /// The attestation registry consulted on deposit.
    pub registry: Address,
    /// The claim a depositor must hold (e.g. `KycLevel(2)`).
    pub required_claim: ClaimType,
}

/// The two verifier bindings a pool holds, addressable for rotation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifierSlot {
    Transfer,
    Withdraw,
}

/// A queued verifier rotation, executable once its timelock elapses.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRotation {
    pub verifier: Address,
    /// Earliest ledger timestamp at which the rotation may execute.
    pub eta: u64,
}

#[contracttype]
enum DataKey {
    Admin,
    Token,
    TransferVerifier,
    WithdrawVerifier,
    Gate,
    RotationDelay,
    PendingRotation(VerifierSlot),
    NextIndex,
    FilledSubtrees,
    Zeros,
    CurrentRoot,
    KnownRoot(BytesN<32>),
    Nullifier(BytesN<32>),
}

/// A note commitment entered the pool.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deposit {
    #[topic]
    pub from: Address,
    pub commitment: BytesN<32>,
    pub amount: i128,
    pub leaf_index: u32,
    pub new_root: BytesN<32>,
}

/// A shielded transfer: nullifiers spent, commitments inserted, and
/// ciphertexts for the recipients (readable only with their viewing keys).
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldedTransfer {
    pub nullifiers: Vec<BytesN<32>>,
    pub new_commitments: Vec<BytesN<32>>,
    pub encrypted_notes: Vec<Bytes>,
    pub new_root: BytesN<32>,
}

/// A note exited the pool to a public balance.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdraw {
    #[topic]
    pub to: Address,
    pub nullifier: BytesN<32>,
    pub amount: i128,
}

/// A verifier rotation entered the timelock queue. Integrators and
/// provers should watch these: after execution, proofs must target the
/// new verifier's circuit and keys.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationQueued {
    #[topic]
    pub slot: VerifierSlot,
    pub verifier: Address,
    pub eta: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationCanceled {
    #[topic]
    pub slot: VerifierSlot,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationExecuted {
    #[topic]
    pub slot: VerifierSlot,
    pub verifier: Address,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PoolError {
    WrongToken = 1,
    InvalidAmount = 2,
    TreeFull = 3,
    UnknownRoot = 4,
    AlreadySpent = 5,
    InvalidProof = 6,
    AttestationRequired = 7,
    MalformedRequest = 8,
    UnknownRotation = 9,
    TimelockNotElapsed = 10,
}

#[contract]
pub struct ShieldedPool;

#[contractimpl]
impl ShieldedPool {
    /// * `token` — the single asset this pool wraps.
    /// * `transfer_verifier` / `withdraw_verifier` — `zk_verifier` instances
    ///   pinned to the transfer and withdraw circuits.
    /// * `rotation_delay` — timelock delay in seconds for verifier
    ///   rotations (circuit upgrades deploy new verifier instances and
    ///   switch the pool over through [`Self::queue_verifier_rotation`]).
    /// * `gate` — optional attestation requirement for deposits.
    pub fn __constructor(
        env: Env,
        admin: Address,
        token: Address,
        transfer_verifier: Address,
        withdraw_verifier: Address,
        rotation_delay: u64,
        gate: Option<GateConfig>,
    ) {
        let storage = env.storage().instance();
        storage.set(&DataKey::Admin, &admin);
        storage.set(&DataKey::Token, &token);
        storage.set(&DataKey::TransferVerifier, &transfer_verifier);
        storage.set(&DataKey::WithdrawVerifier, &withdraw_verifier);
        storage.set(&DataKey::RotationDelay, &rotation_delay);
        if let Some(g) = gate {
            storage.set(&DataKey::Gate, &g);
        }

        // The all-empty subtree hashes per level, precomputed alongside
        // the Poseidon constants (ZEROS[i+1] = H(z_i, z_i)).
        let mut zeros: Vec<BytesN<32>> = vec![&env];
        for z in poseidon_params::ZEROS.iter() {
            zeros.push_back(BytesN::from_array(&env, z));
        }
        let empty_root = zeros.get_unchecked(TREE_DEPTH);
        storage.set(&DataKey::Zeros, &zeros);
        storage.set(&DataKey::FilledSubtrees, &zeros.slice(0..TREE_DEPTH));
        storage.set(&DataKey::NextIndex, &0u32);
        storage.set(&DataKey::CurrentRoot, &empty_root);
        env.storage()
            .persistent()
            .set(&DataKey::KnownRoot(empty_root), &true);
    }

    /// Public → shielded: locks `amount` of the pool token and inserts the
    /// client-computed note `commitment` into the Merkle tree.
    ///
    /// The commitment binds `(value, owner_pk, blinding)`; the contract
    /// never learns the note's internal structure beyond `amount` (which is
    /// necessarily public at the pool boundary).
    pub fn deposit(env: Env, from: Address, token: Address, amount: i128, commitment: BytesN<32>) {
        from.require_auth();
        // Note values are 64-bit in the circuits (range-checked by bit
        // decomposition), so an amount above u64::MAX could enter the
        // pool but never be spent or withdrawn — reject it here.
        if amount <= 0 || amount > u64::MAX as i128 {
            panic_with_error!(&env, PoolError::InvalidAmount);
        }
        // The tree is keyed on commitment bytes; only the canonical
        // field-element encoding may enter (the host reduces mod r
        // silently, so a non-canonical byte string would name a leaf the
        // prover-side tree spells differently).
        if !attesta_interfaces::fr::is_canonical(&commitment.to_array()) {
            panic_with_error!(&env, PoolError::MalformedRequest);
        }
        let pool_token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        if token != pool_token {
            panic_with_error!(&env, PoolError::WrongToken);
        }
        if let Some(gate) = env
            .storage()
            .instance()
            .get::<_, GateConfig>(&DataKey::Gate)
        {
            let attested =
                AttestationClient::new(&env, &gate.registry).check(&from, &gate.required_claim);
            if !attested {
                panic_with_error!(&env, PoolError::AttestationRequired);
            }
        }

        let pool_address = env.current_contract_address();
        token::TokenClient::new(&env, &pool_token).transfer(&from, &pool_address, &amount);
        let (index, new_root) = insert_commitment(&env, &commitment);

        Deposit {
            from,
            commitment,
            amount,
            leaf_index: index,
            new_root,
        }
        .publish(&env);
    }

    /// Shielded transfer. The proof (against the transfer circuit) attests:
    /// the spent notes exist under `root` and are owned by the prover, the
    /// nullifiers are correctly derived, and input value equals output
    /// value — all without revealing any amount.
    ///
    /// `encrypted_notes` are opaque ciphertexts for the recipients, emitted
    /// in the event stream for the note relay/indexer; the contract cannot
    /// read them.
    pub fn transfer(
        env: Env,
        proof: Groth16Proof,
        nullifiers: Vec<BytesN<32>>,
        new_commitments: Vec<BytesN<32>>,
        encrypted_notes: Vec<Bytes>,
        root: BytesN<32>,
    ) {
        if nullifiers.is_empty()
            || new_commitments.is_empty()
            || encrypted_notes.len() != new_commitments.len()
        {
            panic_with_error!(&env, PoolError::MalformedRequest);
        }
        require_known_root(&env, &root);

        // Reject double-spends, including duplicates within this call.
        for (i, nf) in nullifiers.iter().enumerate() {
            if is_nullifier_spent(&env, &nf) {
                panic_with_error!(&env, PoolError::AlreadySpent);
            }
            for j in 0..i {
                if nullifiers.get_unchecked(j as u32) == nf {
                    panic_with_error!(&env, PoolError::AlreadySpent);
                }
            }
        }

        // Public inputs, in circuit order: root, nullifiers, new commitments.
        let mut public_inputs: Vec<BytesN<32>> = vec![&env, root.clone()];
        for nf in nullifiers.iter() {
            public_inputs.push_back(nf);
        }
        for c in new_commitments.iter() {
            public_inputs.push_back(c);
        }
        let verifier: Address = env
            .storage()
            .instance()
            .get(&DataKey::TransferVerifier)
            .unwrap();
        if !VerifierClient::new(&env, &verifier).verify(&proof, &public_inputs) {
            panic_with_error!(&env, PoolError::InvalidProof);
        }

        for nf in nullifiers.iter() {
            env.storage()
                .persistent()
                .set(&DataKey::Nullifier(nf.clone()), &true);
        }
        let mut new_root = root;
        for c in new_commitments.iter() {
            let (_, r) = insert_commitment(&env, &c);
            new_root = r;
        }

        ShieldedTransfer {
            nullifiers,
            new_commitments,
            encrypted_notes,
            new_root,
        }
        .publish(&env);
    }

    /// Shielded → public: exits `amount` of the pool token to `to`, proving
    /// ownership of an unspent note of exactly that value under `root`.
    /// The proof binds the recipient, so a relayer cannot redirect funds.
    pub fn withdraw(
        env: Env,
        proof: Groth16Proof,
        nullifier: BytesN<32>,
        to: Address,
        amount: i128,
        root: BytesN<32>,
    ) {
        if amount <= 0 {
            panic_with_error!(&env, PoolError::InvalidAmount);
        }
        require_known_root(&env, &root);
        if is_nullifier_spent(&env, &nullifier) {
            panic_with_error!(&env, PoolError::AlreadySpent);
        }

        // Public inputs: root, nullifier, recipient binding, amount.
        let public_inputs: Vec<BytesN<32>> = vec![
            &env,
            root,
            nullifier.clone(),
            address_binding(&env, &to),
            amount_to_field(&env, amount),
        ];
        let verifier: Address = env
            .storage()
            .instance()
            .get(&DataKey::WithdrawVerifier)
            .unwrap();
        if !VerifierClient::new(&env, &verifier).verify(&proof, &public_inputs) {
            panic_with_error!(&env, PoolError::InvalidProof);
        }

        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(nullifier.clone()), &true);
        let pool_token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let pool_address = env.current_contract_address();
        token::TokenClient::new(&env, &pool_token).transfer(&pool_address, &to, &amount);

        Withdraw {
            to,
            nullifier,
            amount,
        }
        .publish(&env);
    }

    // ── Verifier rotation (timelocked circuit upgrades) ─────────────────

    /// Queue a rotation of `slot` to `new_verifier`, executable after the
    /// pool's rotation delay. Verifying keys are immutable per verifier
    /// instance, so this is the only path by which the circuits a pool
    /// accepts proofs from can change — and it is announced on-chain for
    /// the full delay before taking effect. Re-queuing a slot replaces
    /// its pending rotation (and restarts the clock).
    pub fn queue_verifier_rotation(env: Env, slot: VerifierSlot, new_verifier: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let delay: u64 = env
            .storage()
            .instance()
            .get(&DataKey::RotationDelay)
            .unwrap();
        let eta = env.ledger().timestamp() + delay;
        env.storage().instance().set(
            &DataKey::PendingRotation(slot.clone()),
            &PendingRotation {
                verifier: new_verifier.clone(),
                eta,
            },
        );
        RotationQueued {
            slot,
            verifier: new_verifier,
            eta,
        }
        .publish(&env);
    }

    /// Cancel the pending rotation of `slot` before execution.
    pub fn cancel_verifier_rotation(env: Env, slot: VerifierSlot) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        if !env
            .storage()
            .instance()
            .has(&DataKey::PendingRotation(slot.clone()))
        {
            panic_with_error!(&env, PoolError::UnknownRotation);
        }
        env.storage()
            .instance()
            .remove(&DataKey::PendingRotation(slot.clone()));
        RotationCanceled { slot }.publish(&env);
    }

    /// Execute the pending rotation of `slot` once its timelock has
    /// elapsed. From this call on, the pool verifies proofs against the
    /// new instance's pinned circuit and key; in-flight proofs for the
    /// old circuit stop verifying.
    pub fn execute_verifier_rotation(env: Env, slot: VerifierSlot) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let pending: PendingRotation = env
            .storage()
            .instance()
            .get(&DataKey::PendingRotation(slot.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, PoolError::UnknownRotation));
        if env.ledger().timestamp() < pending.eta {
            panic_with_error!(&env, PoolError::TimelockNotElapsed);
        }
        env.storage()
            .instance()
            .remove(&DataKey::PendingRotation(slot.clone()));
        let key = match slot {
            VerifierSlot::Transfer => DataKey::TransferVerifier,
            VerifierSlot::Withdraw => DataKey::WithdrawVerifier,
        };
        env.storage().instance().set(&key, &pending.verifier);
        RotationExecuted {
            slot,
            verifier: pending.verifier,
        }
        .publish(&env);
    }

    /// The pending rotation of `slot`, for integrators watching upgrades.
    pub fn pending_rotation(env: Env, slot: VerifierSlot) -> Option<PendingRotation> {
        env.storage().instance().get(&DataKey::PendingRotation(slot))
    }

    /// The verifier currently bound to `slot`, for provers picking the
    /// circuit and keys to prove against.
    pub fn verifier(env: Env, slot: VerifierSlot) -> Address {
        let key = match slot {
            VerifierSlot::Transfer => DataKey::TransferVerifier,
            VerifierSlot::Withdraw => DataKey::WithdrawVerifier,
        };
        env.storage().instance().get(&key).unwrap()
    }

    // ── Public state queries for provers and indexers ──────────────────

    /// The current Merkle root.
    pub fn root(env: Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::CurrentRoot).unwrap()
    }

    /// Whether `root` is a root this tree has ever had (proofs may lag the
    /// tip, so recent historical roots stay valid).
    pub fn is_known_root(env: Env, root: BytesN<32>) -> bool {
        env.storage().persistent().has(&DataKey::KnownRoot(root))
    }

    /// Whether `nullifier` has been spent.
    pub fn is_spent(env: Env, nullifier: BytesN<32>) -> bool {
        is_nullifier_spent(&env, &nullifier)
    }

    /// Number of commitments inserted so far (== next leaf index).
    pub fn size(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::NextIndex).unwrap()
    }

    /// The token this pool wraps.
    pub fn token(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Token).unwrap()
    }
}

/// Incremental (append-only) Merkle insertion, tracking one filled subtree
/// per level. Returns the leaf index and the new root. The node hash is
/// the circuit-pinned Poseidon instance (see the [`poseidon`] module docs
/// for the lockstep rule with `circuits/`).
fn insert_commitment(env: &Env, commitment: &BytesN<32>) -> (u32, BytesN<32>) {
    let storage = env.storage().instance();
    let index: u32 = storage.get(&DataKey::NextIndex).unwrap();
    if index >= 1u32 << TREE_DEPTH {
        panic_with_error!(env, PoolError::TreeFull);
    }
    let zeros: Vec<BytesN<32>> = storage.get(&DataKey::Zeros).unwrap();
    let mut filled: Vec<BytesN<32>> = storage.get(&DataKey::FilledSubtrees).unwrap();

    let mut node = commitment.clone();
    let mut idx = index;
    for level in 0..TREE_DEPTH {
        if idx & 1 == 0 {
            filled.set(level, node.clone());
            node = poseidon::hash2(env, &node, &zeros.get_unchecked(level));
        } else {
            node = poseidon::hash2(env, &filled.get_unchecked(level), &node);
        }
        idx >>= 1;
    }

    storage.set(&DataKey::FilledSubtrees, &filled);
    storage.set(&DataKey::NextIndex, &(index + 1));
    storage.set(&DataKey::CurrentRoot, &node);
    env.storage()
        .persistent()
        .set(&DataKey::KnownRoot(node.clone()), &true);
    (index, node)
}

fn require_known_root(env: &Env, root: &BytesN<32>) {
    if !env
        .storage()
        .persistent()
        .has(&DataKey::KnownRoot(root.clone()))
    {
        panic_with_error!(env, PoolError::UnknownRoot);
    }
}

fn is_nullifier_spent(env: &Env, nullifier: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Nullifier(nullifier.clone()))
}

/// Binds a withdrawal to its recipient as a field element: SHA-256 of the
/// address XDR with the top byte cleared so the value is canonical in the
/// BLS12-381 scalar field. The withdraw circuit computes the same binding.
fn address_binding(env: &Env, address: &Address) -> BytesN<32> {
    use soroban_sdk::xdr::ToXdr;
    let digest = env.crypto().sha256(&address.clone().to_xdr(env));
    let mut bytes = digest.to_array();
    bytes[0] = 0;
    BytesN::from_array(env, &bytes)
}

/// Encodes a token amount as a big-endian field element.
fn amount_to_field(env: &Env, amount: i128) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&amount.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_e2e;
