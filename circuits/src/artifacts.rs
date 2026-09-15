//! Loading the published circuit artifacts.
//!
//! `artifacts/<circuit>/verifying_key.hex` is the host-encoded verifying
//! key a `zk_verifier` instance is constructed with;
//! `proving_key.bin` / `verifying_key.bin` are the arkworks canonical
//! serializations the prover consumes. This module parses both so the
//! CLI and tests share one loader — and the committed forms are
//! cross-checked against each other in this module's tests.

use crate::encoding::{g1_from_bytes, g2_from_bytes, VerificationKeyBytes, G1_LEN, G2_LEN};
use ark_bls12_381::Bls12_381;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Parses the `key=hexvalue` lines of a `verifying_key.hex` artifact.
pub fn parse_vk_hex(text: &str) -> Result<VerificationKeyBytes, String> {
    let mut alpha = None;
    let mut beta = None;
    let mut gamma = None;
    let mut delta = None;
    let mut ic: Vec<(usize, Vec<u8>)> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("malformed line: {line}"))?;
        let bytes = hex::decode(value).map_err(|e| format!("{key}: {e}"))?;
        match key {
            "alpha" => alpha = Some(bytes),
            "beta" => beta = Some(bytes),
            "gamma" => gamma = Some(bytes),
            "delta" => delta = Some(bytes),
            _ => {
                let idx: usize = key
                    .strip_prefix("ic.")
                    .and_then(|i| i.parse().ok())
                    .ok_or_else(|| format!("unknown key: {key}"))?;
                ic.push((idx, bytes));
            }
        }
    }
    ic.sort_by_key(|(i, _)| *i);

    let g1 = |v: Option<Vec<u8>>, name: &str| -> Result<[u8; G1_LEN], String> {
        v.ok_or_else(|| format!("missing {name}"))?
            .try_into()
            .map_err(|_| format!("{name}: wrong length"))
    };
    let g2 = |v: Option<Vec<u8>>, name: &str| -> Result<[u8; G2_LEN], String> {
        v.ok_or_else(|| format!("missing {name}"))?
            .try_into()
            .map_err(|_| format!("{name}: wrong length"))
    };
    Ok(VerificationKeyBytes {
        alpha: g1(alpha, "alpha")?,
        beta: g2(beta, "beta")?,
        gamma: g2(gamma, "gamma")?,
        delta: g2(delta, "delta")?,
        ic: ic
            .into_iter()
            .map(|(i, v)| v.try_into().map_err(|_| format!("ic.{i}: wrong length")))
            .collect::<Result<_, _>>()?,
    })
}

/// Renders the `key=hexvalue` lines a `verifying_key.hex` artifact is made
/// of — the exact inverse of [`parse_vk_hex`] (modulo the free-form
/// comment/blank lines `parse_vk_hex` also tolerates). Used by
/// `build_artifacts.rs` so the artifact writer and the parser share one
/// definition of the format, and by the roundtrip property test below.
pub fn render_vk_hex(vk: &VerificationKeyBytes) -> String {
    let mut out = String::new();
    writeln!(out, "alpha={}", hex::encode(vk.alpha)).unwrap();
    writeln!(out, "beta={}", hex::encode(vk.beta)).unwrap();
    writeln!(out, "gamma={}", hex::encode(vk.gamma)).unwrap();
    writeln!(out, "delta={}", hex::encode(vk.delta)).unwrap();
    for (i, ic) in vk.ic.iter().enumerate() {
        writeln!(out, "ic.{i}={}", hex::encode(ic)).unwrap();
    }
    out
}

/// Reconstructs an arkworks verifying key from host-encoded bytes.
pub fn vk_from_bytes(bytes: &VerificationKeyBytes) -> VerifyingKey<Bls12_381> {
    VerifyingKey {
        alpha_g1: g1_from_bytes(&bytes.alpha),
        beta_g2: g2_from_bytes(&bytes.beta),
        gamma_g2: g2_from_bytes(&bytes.gamma),
        delta_g2: g2_from_bytes(&bytes.delta),
        gamma_abc_g1: bytes.ic.iter().map(g1_from_bytes).collect(),
    }
}

/// Loads a Groth16 proving key (arkworks compressed canonical form) from
/// `path`, as emitted by `scripts/build-artifacts.sh`.
///
/// `ProvingKey::deserialize_compressed` validates every curve point on
/// the way in, which is cryptographically redundant once the file's
/// SHA-256 already matches a trusted manifest — and it dominates prover
/// startup for the 4MB transfer key. If a sibling `SHA256SUMS` file (the
/// same directory, `build_artifacts.rs`'s `<hex>  <filename>` format)
/// records a hash for `path`'s filename and it matches, this uses the
/// unchecked deserializer instead. There is no way to opt into the
/// unchecked path without a matching hash — a missing or mismatched
/// `SHA256SUMS` entry always falls back to full validation.
pub fn load_proving_key(path: &Path) -> Result<ProvingKey<Bls12_381>, String> {
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    load_proving_key_bytes(&data, expected_sha256_for(path).as_deref())
}

/// Same as [`load_proving_key`], from already-read bytes with an
/// explicit expected hash (or `None` to always fully validate) — the
/// primitive `load_proving_key` and the benchmarks build on, for callers
/// that want to control the fast/slow path directly rather than relying
/// on a `SHA256SUMS` file on disk.
pub fn load_proving_key_bytes(
    data: &[u8],
    expected_sha256_hex: Option<&str>,
) -> Result<ProvingKey<Bls12_381>, String> {
    if let Some(expected) = expected_sha256_hex {
        if sha256_hex(data).eq_ignore_ascii_case(expected) {
            return ProvingKey::deserialize_compressed_unchecked(data).map_err(|e| format!("{e}"));
        }
    }
    ProvingKey::deserialize_compressed(data).map_err(|e| format!("{e}"))
}

fn expected_sha256_for(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_str()?;
    let sums_text = fs::read_to_string(path.with_file_name("SHA256SUMS")).ok()?;
    find_sha256(&sums_text, file_name)
}

/// Reads the SHA-256 hex digest recorded for `filename` in a
/// `SHA256SUMS` manifest (`build_artifacts.rs`'s format: `<hex>
/// <filename>` per line, `#`-comments and blank lines ignored).
pub fn find_sha256(sums_text: &str, filename: &str) -> Option<String> {
    sums_text.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let name = parts.next()?;
        (name == filename).then(|| hash.to_string())
    })
}

/// SHA-256 of `data`, lowercase hex — the single implementation shared
/// by the artifact writer (`build_artifacts.rs`) and this loader's
/// integrity check, so the two can never silently disagree.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Loads a circuit's host-encoded verifying key from
/// `<dir>/<circuit>/verifying_key.hex`.
pub fn load_vk_hex(dir: &Path, circuit: &str) -> Result<VerificationKeyBytes, String> {
    let path = dir.join(circuit).join("verifying_key.hex");
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_vk_hex(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::vk_to_bytes;
    use crate::layout;

    fn artifacts_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts")
    }

    /// The committed artifacts must agree with each other and with the
    /// layouts the contract layer builds public inputs against. Catches
    /// a stale `verifying_key.hex` after a circuit change (the artifact
    /// pipeline regenerates both; this fails if someone edits one).
    #[test]
    fn committed_artifacts_are_consistent() {
        for (circuit, n_inputs) in [
            ("transfer", layout::transfer_public_inputs(2, 2)),
            ("withdraw", layout::WITHDRAW_PUBLIC_INPUTS),
        ] {
            let hex_vk = load_vk_hex(&artifacts_dir(), circuit).unwrap();
            assert_eq!(
                hex_vk.ic.len(),
                n_inputs + 1,
                "{circuit}: IC count vs layout"
            );

            let bin = fs::read(artifacts_dir().join(circuit).join("verifying_key.bin")).unwrap();
            let bin_vk = VerifyingKey::<Bls12_381>::deserialize_compressed(bin.as_slice()).unwrap();
            let reencoded = vk_to_bytes(&bin_vk);
            assert_eq!(reencoded.alpha, hex_vk.alpha, "{circuit}: alpha");
            assert_eq!(reencoded.beta, hex_vk.beta, "{circuit}: beta");
            assert_eq!(reencoded.gamma, hex_vk.gamma, "{circuit}: gamma");
            assert_eq!(reencoded.delta, hex_vk.delta, "{circuit}: delta");
            assert_eq!(reencoded.ic, hex_vk.ic, "{circuit}: ic");

            // And the hex round-trips through the arkworks form.
            assert_eq!(vk_to_bytes(&vk_from_bytes(&hex_vk)).ic, hex_vk.ic);
        }
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn g1_bytes() -> impl Strategy<Value = [u8; G1_LEN]> {
            prop::collection::vec(any::<u8>(), G1_LEN).prop_map(|v| v.try_into().unwrap())
        }
        fn g2_bytes() -> impl Strategy<Value = [u8; G2_LEN]> {
            prop::collection::vec(any::<u8>(), G2_LEN).prop_map(|v| v.try_into().unwrap())
        }
        fn vk_bytes() -> impl Strategy<Value = VerificationKeyBytes> {
            (
                g1_bytes(),
                g2_bytes(),
                g2_bytes(),
                g2_bytes(),
                prop::collection::vec(g1_bytes(), 1..6),
            )
                .prop_map(|(alpha, beta, gamma, delta, ic)| VerificationKeyBytes {
                    alpha,
                    beta,
                    gamma,
                    delta,
                    ic,
                })
        }

        proptest! {
            /// `parse_vk_hex . render_vk_hex` is identity on random VKs.
            /// `parse_vk_hex` only validates hex + per-field byte length
            /// (it never checks curve membership — the host does, on
            /// use), so arbitrary bytes are valid grist here.
            #[test]
            fn parse_render_roundtrips(vk in vk_bytes()) {
                let rendered = render_vk_hex(&vk);
                let parsed = parse_vk_hex(&rendered).unwrap();
                prop_assert_eq!(parsed, vk);
            }

            /// `parse_vk_hex` must never panic on arbitrary text — it sits
            /// on a trust boundary (published artifact files) and should
            /// reject malformed input as a typed `Err`, not crash.
            #[test]
            fn parse_vk_hex_never_panics(text in ".{0,2048}") {
                let _ = parse_vk_hex(&text);
            }
        }
    }
}
