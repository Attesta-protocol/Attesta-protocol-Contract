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
            .map(|(i, v)| {
                v.try_into()
                    .map_err(|_| format!("ic.{i}: wrong length"))
            })
            .collect::<Result<_, _>>()?,
    })
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

/// Loads a circuit's proving key from `<dir>/<circuit>/proving_key.bin`
/// (arkworks compressed canonical form, as emitted by
/// `scripts/build-artifacts.sh`).
pub fn load_proving_key(dir: &Path, circuit: &str) -> Result<ProvingKey<Bls12_381>, String> {
    let path = dir.join(circuit).join("proving_key.bin");
    let data = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    ProvingKey::deserialize_compressed(data.as_slice()).map_err(|e| format!("{e}"))
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
}
