#![cfg(test)]
//! The full protocol flow with nothing mocked: real notes proven with
//! `attesta-circuits`, real `ZkVerifier` instances pinned to freshly
//! generated keys, and this pool contract — deposit → shielded transfer
//! → withdraw.
//!
//! Beyond exercising the state machine, this pins two cross-layer
//! invariants that unit tests cannot:
//!
//! 1. **Tree lockstep** — after every insertion, the contract's
//!    incremental Poseidon root equals the prover-side
//!    `attesta_circuits::merkle::MerkleTree` root, so paths proven
//!    client-side verify against on-chain roots.
//! 2. **Binding lockstep** — the contract's `address_binding` /
//!    `amount_to_field` encodings match what the withdraw circuit was
//!    proven over.

extern crate std;

use super::*;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use attesta_circuits::encoding::{fr_from_bytes, fr_to_bytes, proof_to_bytes, vk_to_bytes};
use attesta_circuits::merkle::{MerkleTree, POOL_TREE_DEPTH};
use attesta_circuits::note::{derive_nullifier, derive_pk, Note};
use attesta_circuits::transfer::{NewNote, SpentNote, TransferCircuit};
use attesta_circuits::withdraw::WithdrawCircuit;
use attesta_interfaces::VerificationKey;
use attesta_zk_verifier::ZkVerifier;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use soroban_sdk::{
    symbol_short,
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    vec, Address, Bytes, Env,
};

fn to_soroban_vk(env: &Env, vk: &ark_groth16::VerifyingKey<Bls12_381>) -> VerificationKey {
    let b = vk_to_bytes(vk);
    let mut ic = vec![env];
    for p in &b.ic {
        ic.push_back(BytesN::from_array(env, p));
    }
    VerificationKey {
        alpha: BytesN::from_array(env, &b.alpha),
        beta: BytesN::from_array(env, &b.beta),
        gamma: BytesN::from_array(env, &b.gamma),
        delta: BytesN::from_array(env, &b.delta),
        ic,
    }
}

fn to_soroban_proof(env: &Env, proof: &ark_groth16::Proof<Bls12_381>) -> Groth16Proof {
    let b = proof_to_bytes(proof);
    Groth16Proof {
        a: BytesN::from_array(env, &b.a),
        b: BytesN::from_array(env, &b.b),
        c: BytesN::from_array(env, &b.c),
    }
}

fn bytes32(env: &Env, x: Fr) -> BytesN<32> {
    BytesN::from_array(env, &fr_to_bytes(x))
}

/// The contract's recipient binding, recomputed test-side so the
/// withdraw proof can be generated over it.
fn recipient_binding(env: &Env, address: &Address) -> Fr {
    use soroban_sdk::xdr::ToXdr;
    let digest = env.crypto().sha256(&address.clone().to_xdr(env));
    let mut bytes = digest.to_array();
    bytes[0] = 0;
    fr_from_bytes(&bytes)
}

#[test]
fn full_flow_deposit_transfer_withdraw_with_real_proofs() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xf10f);
    let (transfer_pk, transfer_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        TransferCircuit::blank(POOL_TREE_DEPTH, 2, 2),
        &mut rng,
    )
    .unwrap();
    let (withdraw_pk, withdraw_vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        WithdrawCircuit::blank(POOL_TREE_DEPTH),
        &mut rng,
    )
    .unwrap();

    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let payout = Address::generate(&env);
    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    let token = TokenClient::new(&env, &asset.address());
    StellarAssetClient::new(&env, &asset.address()).mint(&user, &1_000);

    let transfer_verifier = env.register(
        ZkVerifier,
        (symbol_short!("transfer"), to_soroban_vk(&env, &transfer_vk)),
    );
    let withdraw_verifier = env.register(
        ZkVerifier,
        (symbol_short!("withdraw"), to_soroban_vk(&env, &withdraw_vk)),
    );
    let pool = ShieldedPoolClient::new(
        &env,
        &env.register(
            ShieldedPool,
            (
                admin,
                asset.address(),
                transfer_verifier,
                withdraw_verifier,
                None::<GateConfig>,
            ),
        ),
    );

    // ── Deposit: two notes enter the pool ───────────────────────────────
    let sk1 = Fr::from(11u64);
    let sk2 = Fr::from(22u64);
    let n1 = Note {
        value: 600,
        owner_pk: derive_pk(sk1),
        blinding: Fr::from(101u64),
    };
    let n2 = Note {
        value: 400,
        owner_pk: derive_pk(sk2),
        blinding: Fr::from(102u64),
    };

    let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
    pool.deposit(&user, &token.address, &600, &bytes32(&env, n1.commitment()));
    let i1 = tree.insert(n1.commitment());
    pool.deposit(&user, &token.address, &400, &bytes32(&env, n2.commitment()));
    let i2 = tree.insert(n2.commitment());

    // Tree lockstep: the on-chain Poseidon tree tracks the prover's.
    assert_eq!(pool.root(), bytes32(&env, tree.root()));
    assert_eq!(token.balance(&pool.address), 1_000);

    // ── Shielded transfer: 600 + 400 → 750 (payout's key) + 250 change ──
    let payout_sk = Fr::from(33u64);
    let out1 = NewNote {
        value: 750,
        owner_pk: derive_pk(payout_sk),
        blinding: Fr::from(201u64),
    };
    let out2 = NewNote {
        value: 250,
        owner_pk: derive_pk(sk1),
        blinding: Fr::from(202u64),
    };
    let root = tree.root();
    let nf1 = derive_nullifier(sk1, i1);
    let nf2 = derive_nullifier(sk2, i2);
    let circuit = TransferCircuit {
        depth: POOL_TREE_DEPTH,
        root: Some(root),
        nullifiers: std::vec![Some(nf1), Some(nf2)],
        new_commitments: std::vec![Some(out1.commitment()), Some(out2.commitment())],
        spent: std::vec![
            Some(SpentNote {
                value: n1.value,
                sk: sk1,
                blinding: n1.blinding,
                path: tree.path(i1),
            }),
            Some(SpentNote {
                value: n2.value,
                sk: sk2,
                blinding: n2.blinding,
                path: tree.path(i2),
            }),
        ],
        created: std::vec![Some(out1.clone()), Some(out2.clone())],
    };
    let proof = Groth16::<Bls12_381>::prove(&transfer_pk, circuit, &mut rng).unwrap();

    pool.transfer(
        &to_soroban_proof(&env, &proof),
        &vec![&env, bytes32(&env, nf1), bytes32(&env, nf2)],
        &vec![
            &env,
            bytes32(&env, out1.commitment()),
            bytes32(&env, out2.commitment()),
        ],
        &vec![
            &env,
            Bytes::from_slice(&env, b"ciphertext-for-payout"),
            Bytes::from_slice(&env, b"ciphertext-change"),
        ],
        &bytes32(&env, root),
    );

    let i_out1 = tree.insert(out1.commitment());
    tree.insert(out2.commitment());
    assert_eq!(pool.root(), bytes32(&env, tree.root()));
    assert!(pool.is_spent(&bytes32(&env, nf1)));
    assert!(pool.is_spent(&bytes32(&env, nf2)));
    // Amounts moved shielded: the public token balance is unchanged.
    assert_eq!(token.balance(&pool.address), 1_000);

    // ── Withdraw: payout exits their 750 note to a public balance ───────
    let root = tree.root();
    let nf_out1 = derive_nullifier(payout_sk, i_out1);
    let binding = recipient_binding(&env, &payout);
    let circuit = WithdrawCircuit {
        depth: POOL_TREE_DEPTH,
        root: Some(root),
        nullifier: Some(nf_out1),
        recipient_binding: Some(binding),
        amount: Some(Fr::from(out1.value)),
        sk: Some(payout_sk),
        blinding: Some(out1.blinding),
        path: Some(tree.path(i_out1)),
    };
    let proof = Groth16::<Bls12_381>::prove(&withdraw_pk, circuit, &mut rng).unwrap();

    pool.withdraw(
        &to_soroban_proof(&env, &proof),
        &bytes32(&env, nf_out1),
        &payout,
        &750,
        &bytes32(&env, root),
    );

    assert_eq!(token.balance(&payout), 750);
    assert_eq!(token.balance(&pool.address), 250);
    assert!(pool.is_spent(&bytes32(&env, nf_out1)));
}
