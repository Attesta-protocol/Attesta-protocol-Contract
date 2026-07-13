//! Byte encodings bridging arkworks objects to the Soroban contract
//! layer.
//!
//! The Protocol 25 host functions (and therefore
//! `attesta_interfaces::{Groth16Proof, VerificationKey}`) use:
//!
//! - **Fr**: 32-byte big-endian integer.
//! - **G1** (96 bytes): `be(x) || be(y)`, each coordinate 48 bytes.
//! - **G2** (192 bytes): `be(x.c1) || be(x.c0) || be(y.c1) || be(y.c0)`.
//! - Points at infinity set the infinity flag (bit 1) of the first byte,
//!   all other bits zero.
//!
//! arkworks' own `CanonicalSerialize` is little-endian and
//! flag-incompatible, so the conversions live here and are pinned by
//! tests against the standard generator encodings.

use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};

/// Byte length of an encoded G1 point.
pub const G1_LEN: usize = 96;
/// Byte length of an encoded G2 point.
pub const G2_LEN: usize = 192;
/// The infinity flag: bit 1 of the first byte.
const INFINITY_FLAG: u8 = 0x40;

/// Encodes an Fr scalar as the 32-byte big-endian public-input encoding.
pub fn fr_to_bytes(x: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

/// Decodes a 32-byte big-endian scalar (must be canonical, < r).
pub fn fr_from_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

fn fq_be(x: Fq) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

/// Encodes a G1 point in the 96-byte uncompressed host encoding.
pub fn g1_to_bytes(p: &G1Affine) -> [u8; G1_LEN] {
    let mut out = [0u8; G1_LEN];
    match p.xy() {
        Some((x, y)) => {
            out[..48].copy_from_slice(&fq_be(x));
            out[48..].copy_from_slice(&fq_be(y));
        }
        None => out[0] = INFINITY_FLAG,
    }
    out
}

/// Encodes a G2 point in the 192-byte uncompressed host encoding.
pub fn g2_to_bytes(p: &G2Affine) -> [u8; G2_LEN] {
    let mut out = [0u8; G2_LEN];
    match p.xy() {
        Some((x, y)) => {
            out[..48].copy_from_slice(&fq_be(x.c1));
            out[48..96].copy_from_slice(&fq_be(x.c0));
            out[96..144].copy_from_slice(&fq_be(y.c1));
            out[144..].copy_from_slice(&fq_be(y.c0));
        }
        None => out[0] = INFINITY_FLAG,
    }
    out
}

fn fq_from_be(bytes: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(bytes)
}

/// Decodes a 96-byte host-encoded G1 point. Inverse of [`g1_to_bytes`]
/// for the encodings this crate produces; assumes canonical coordinates
/// and does not re-check curve membership (the host does, on use).
pub fn g1_from_bytes(bytes: &[u8; G1_LEN]) -> G1Affine {
    if bytes[0] & INFINITY_FLAG != 0 {
        return G1Affine::identity();
    }
    G1Affine::new_unchecked(fq_from_be(&bytes[..48]), fq_from_be(&bytes[48..]))
}

/// Decodes a 192-byte host-encoded G2 point (see [`g1_from_bytes`]).
pub fn g2_from_bytes(bytes: &[u8; G2_LEN]) -> G2Affine {
    use ark_bls12_381::Fq2;
    if bytes[0] & INFINITY_FLAG != 0 {
        return G2Affine::identity();
    }
    G2Affine::new_unchecked(
        Fq2::new(fq_from_be(&bytes[48..96]), fq_from_be(&bytes[..48])),
        Fq2::new(fq_from_be(&bytes[144..]), fq_from_be(&bytes[96..144])),
    )
}

/// A Groth16 proof in host encoding — the byte-for-byte contents of
/// `attesta_interfaces::Groth16Proof`.
pub struct ProofBytes {
    /// `proof.a`, G1.
    pub a: [u8; G1_LEN],
    /// `proof.b`, G2.
    pub b: [u8; G2_LEN],
    /// `proof.c`, G1.
    pub c: [u8; G1_LEN],
}

/// Encodes an arkworks proof for submission to the contract layer.
pub fn proof_to_bytes(proof: &Proof<Bls12_381>) -> ProofBytes {
    ProofBytes {
        a: g1_to_bytes(&proof.a),
        b: g2_to_bytes(&proof.b),
        c: g1_to_bytes(&proof.c),
    }
}

/// A verifying key in host encoding — the byte-for-byte contents of
/// `attesta_interfaces::VerificationKey`, i.e. what a `zk_verifier`
/// instance is constructed with.
pub struct VerificationKeyBytes {
    /// `vk.alpha_g1`.
    pub alpha: [u8; G1_LEN],
    /// `vk.beta_g2`.
    pub beta: [u8; G2_LEN],
    /// `vk.gamma_g2`.
    pub gamma: [u8; G2_LEN],
    /// `vk.delta_g2`.
    pub delta: [u8; G2_LEN],
    /// `vk.gamma_abc_g1` — one point per public input, plus one.
    pub ic: Vec<[u8; G1_LEN]>,
}

/// Encodes an arkworks verifying key for pinning into a `zk_verifier`.
pub fn vk_to_bytes(vk: &VerifyingKey<Bls12_381>) -> VerificationKeyBytes {
    VerificationKeyBytes {
        alpha: g1_to_bytes(&vk.alpha_g1),
        beta: g2_to_bytes(&vk.beta_g2),
        gamma: g2_to_bytes(&vk.gamma_g2),
        delta: g2_to_bytes(&vk.delta_g2),
        ic: vk.gamma_abc_g1.iter().map(g1_to_bytes).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use std::ops::Neg;

    // The standard uncompressed generator encodings, as documented for
    // the Soroban host functions (soroban-sdk `Bls12381G1Affine` /
    // `Bls12381G2Affine` docs) and the IETF BLS suites.
    const G1_GEN_HEX: &str = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    const G2_GEN_HEX: &str = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";

    #[test]
    fn g1_generator_matches_host_encoding() {
        assert_eq!(hex::encode(g1_to_bytes(&G1Affine::generator())), G1_GEN_HEX);
    }

    #[test]
    fn g2_generator_matches_host_encoding() {
        assert_eq!(hex::encode(g2_to_bytes(&G2Affine::generator())), G2_GEN_HEX);
    }

    #[test]
    fn infinity_sets_flag_bit() {
        let g1 = g1_to_bytes(&G1Affine::identity());
        assert_eq!(g1[0], 0x40);
        assert!(g1[1..].iter().all(|b| *b == 0));
        let g2 = g2_to_bytes(&G2Affine::identity());
        assert_eq!(g2[0], 0x40);
        assert!(g2[1..].iter().all(|b| *b == 0));
    }

    #[test]
    fn random_points_roundtrip() {
        use ark_ec::PrimeGroup;
        use ark_ff::UniformRand;
        use rand_chacha::rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        for _ in 0..32 {
            let s = Fr::rand(&mut rng);
            let g1: G1Affine = (ark_bls12_381::G1Projective::generator() * s).into();
            let g2: G2Affine = (ark_bls12_381::G2Projective::generator() * s).into();
            assert_eq!(g1_from_bytes(&g1_to_bytes(&g1)), g1);
            assert_eq!(g2_from_bytes(&g2_to_bytes(&g2)), g2);
            assert_eq!(fr_from_bytes(&fr_to_bytes(s)), s);
        }
        assert_eq!(
            g1_from_bytes(&g1_to_bytes(&G1Affine::identity())),
            G1Affine::identity()
        );
        assert_eq!(
            g2_from_bytes(&g2_to_bytes(&G2Affine::identity())),
            G2Affine::identity()
        );
    }

    #[test]
    fn fr_roundtrip_and_boundaries() {
        let one = fr_to_bytes(Fr::one());
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(one, expected);

        let x = Fr::from(0xdeadbeefu64).neg();
        assert_eq!(fr_from_bytes(&fr_to_bytes(x)), x);
    }
}
