//! `attesta-prover` — the M2 CLI prover.
//!
//! Runs entirely on the user's machine: spending keys, values, and
//! blindings stay local; the outputs are proof bundles whose fields map
//! one-to-one onto `shielded_pool::transfer` / `withdraw` arguments.
//!
//! ```text
//! attesta-prover keygen
//! attesta-prover pk --sk <hex>
//! attesta-prover note --value <n> --owner-pk <hex> [--blinding <hex>]
//! attesta-prover prove-transfer --proving-key <file> --commitments <file>
//!     --spend sk:value:blinding:leaf_index   (twice; value 0 = dummy)
//!     --output owner_pk:value:blinding       (twice)
//!     --out <bundle file>
//! attesta-prover prove-withdraw --proving-key <file> --commitments <file>
//!     --spend sk:value:blinding:leaf_index
//!     --recipient-binding <hex> --out <bundle file>
//! attesta-prover verify --vk <verifying_key.hex> --bundle <file>
//! ```
//!
//! `--commitments` is the pool's commitment log: one 32-byte hex leaf
//! per line, in leaf order (from `Deposit` / `ShieldedTransfer` events;
//! `#` comments allowed). Bundles are `key=hex` lines, the same format
//! as the published `verifying_key.hex` artifacts.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use attesta_circuits::artifacts::{parse_vk_hex, vk_from_bytes};
use attesta_circuits::encoding::{
    fr_from_bytes, fr_to_bytes, g1_from_bytes, g2_from_bytes, G1_LEN, G2_LEN,
};
use attesta_circuits::note::{derive_pk, Note};
use attesta_circuits::prover::{prove_transfer, prove_withdraw, Output, Spend};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("keygen") => cmd_keygen(),
        Some("pk") => cmd_pk(&args[1..]),
        Some("note") => cmd_note(&args[1..]),
        Some("prove-transfer") => cmd_prove_transfer(&args[1..]),
        Some("prove-withdraw") => cmd_prove_withdraw(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some(other) => Err(format!("unknown command: {other}\n{USAGE}")),
        None => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str =
    "usage: attesta-prover <keygen|pk|note|prove-transfer|prove-withdraw|verify> [options]
run with a command to see its options in the module docs";

// ── argument helpers ────────────────────────────────────────────────────

/// Parses `--key value` pairs; repeatable keys accumulate in order.
fn parse_flags(args: &[String]) -> Result<HashMap<String, Vec<String>>, String> {
    let mut flags: HashMap<String, Vec<String>> = HashMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let key = flag
            .strip_prefix("--")
            .ok_or_else(|| format!("expected --flag, got {flag}"))?;
        let value = it.next().ok_or_else(|| format!("--{key} needs a value"))?;
        flags
            .entry(key.to_string())
            .or_default()
            .push(value.clone());
    }
    Ok(flags)
}

fn one<'a>(flags: &'a HashMap<String, Vec<String>>, key: &str) -> Result<&'a str, String> {
    match flags.get(key).map(Vec::as_slice) {
        Some([v]) => Ok(v),
        Some(_) => Err(format!("--{key} given more than once")),
        None => Err(format!("missing --{key}")),
    }
}

fn parse_fr(hex_str: &str) -> Result<Fr, String> {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .map_err(|e| format!("bad hex: {e}"))?
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())?;
    if !canonical(&bytes) {
        return Err("not a canonical field element (≥ group order)".to_string());
    }
    Ok(fr_from_bytes(&bytes))
}

fn canonical(bytes: &[u8; 32]) -> bool {
    // r - 1, big-endian: the largest canonical scalar.
    const FR_MINUS_ONE: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];
    *bytes <= FR_MINUS_ONE
}

fn hex32(x: Fr) -> String {
    hex::encode(fr_to_bytes(x))
}

// ── key and note commands ───────────────────────────────────────────────

fn cmd_keygen() -> Result<(), String> {
    let sk = Fr::rand(&mut rand::rngs::OsRng);
    println!("sk={}", hex32(sk));
    println!("pk={}", hex32(derive_pk(sk)));
    eprintln!("keep sk secret; share pk with senders");
    Ok(())
}

fn cmd_pk(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let sk = parse_fr(one(&flags, "sk")?)?;
    println!("pk={}", hex32(derive_pk(sk)));
    Ok(())
}

fn cmd_note(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let value: u64 = one(&flags, "value")?
        .parse()
        .map_err(|e| format!("--value: {e}"))?;
    let owner_pk = parse_fr(one(&flags, "owner-pk")?)?;
    let blinding = match flags.get("blinding") {
        Some(_) => parse_fr(one(&flags, "blinding")?)?,
        None => Fr::rand(&mut rand::rngs::OsRng),
    };
    let note = Note {
        value,
        owner_pk,
        blinding,
    };
    println!("value={value}");
    println!("owner_pk={}", hex32(owner_pk));
    println!("blinding={}", hex32(blinding));
    println!("commitment={}", hex32(note.commitment()));
    eprintln!("deposit with `commitment`; keep `blinding` — spending needs it");
    Ok(())
}

// ── file loading ────────────────────────────────────────────────────────

fn load_proving_key(path: &str) -> Result<ProvingKey<Bls12_381>, String> {
    let data = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    ProvingKey::deserialize_compressed(data.as_slice()).map_err(|e| format!("{path}: {e}"))
}

/// Reads the commitment log: one 32-byte hex leaf per line, leaf order.
fn load_commitments(path: &str) -> Result<Vec<Fr>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut leaves = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        leaves.push(parse_fr(line).map_err(|e| format!("{path}:{}: {e}", i + 1))?);
    }
    Ok(leaves)
}

/// Reads a `key=value` bundle file (comments and blank lines allowed).
fn read_bundle(path: &str) -> Result<HashMap<String, String>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{path}: malformed line: {line}"))?;
        if map.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("{path}: duplicate key: {key}"));
        }
    }
    Ok(map)
}

fn bundle_field<'a>(bundle: &'a HashMap<String, String>, key: &str) -> Result<&'a str, String> {
    bundle
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("bundle is missing {key}"))
}

// ── proving commands ────────────────────────────────────────────────────

fn cmd_prove_transfer(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let proving_key = load_proving_key(one(&flags, "proving-key")?)?;
    let commitments = load_commitments(one(&flags, "commitments")?)?;
    let spends: [Spend; 2] = two(&flags, "spend")?;
    let outputs: [Output; 2] = two(&flags, "output")?;
    let out_path = one(&flags, "out")?;

    let bundle = prove_transfer(
        &proving_key,
        &commitments,
        &spends,
        &outputs,
        &mut rand::rngs::OsRng,
    )?;

    let mut text = String::from("# attesta transfer proof bundle\ncircuit=transfer\n");
    writeln!(text, "proof.a={}", hex::encode(bundle.proof.a)).unwrap();
    writeln!(text, "proof.b={}", hex::encode(bundle.proof.b)).unwrap();
    writeln!(text, "proof.c={}", hex::encode(bundle.proof.c)).unwrap();
    writeln!(text, "root={}", hex::encode(bundle.root)).unwrap();
    for (i, nf) in bundle.nullifiers.iter().enumerate() {
        writeln!(text, "nullifier.{i}={}", hex::encode(nf)).unwrap();
    }
    for (i, c) in bundle.new_commitments.iter().enumerate() {
        writeln!(text, "new_commitment.{i}={}", hex::encode(c)).unwrap();
    }
    fs::write(out_path, &text).map_err(|e| format!("{out_path}: {e}"))?;

    print_public_summary(&text);
    eprintln!("wrote {out_path}");
    Ok(())
}

fn cmd_prove_withdraw(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let proving_key = load_proving_key(one(&flags, "proving-key")?)?;
    let commitments = load_commitments(one(&flags, "commitments")?)?;
    let spend = Spend::try_parse(one(&flags, "spend")?)?;
    let recipient_binding = parse_fr(one(&flags, "recipient-binding")?)?;
    let out_path = one(&flags, "out")?;

    let bundle = prove_withdraw(
        &proving_key,
        &commitments,
        &spend,
        recipient_binding,
        &mut rand::rngs::OsRng,
    )?;

    let mut text = String::from("# attesta withdraw proof bundle\ncircuit=withdraw\n");
    writeln!(text, "proof.a={}", hex::encode(bundle.proof.a)).unwrap();
    writeln!(text, "proof.b={}", hex::encode(bundle.proof.b)).unwrap();
    writeln!(text, "proof.c={}", hex::encode(bundle.proof.c)).unwrap();
    writeln!(text, "root={}", hex::encode(bundle.root)).unwrap();
    writeln!(text, "nullifier={}", hex::encode(bundle.nullifier)).unwrap();
    writeln!(
        text,
        "recipient_binding={}",
        hex::encode(bundle.recipient_binding)
    )
    .unwrap();
    writeln!(text, "amount={}", bundle.amount).unwrap();
    fs::write(out_path, &text).map_err(|e| format!("{out_path}: {e}"))?;

    print_public_summary(&text);
    eprintln!("wrote {out_path}");
    Ok(())
}

/// Echoes the bundle's public fields (everything but the proof) so the
/// caller can assemble the contract call without opening the file.
fn print_public_summary(bundle_text: &str) {
    for line in bundle_text.lines() {
        if !line.starts_with('#') && !line.starts_with("proof.") {
            println!("{line}");
        }
    }
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let vk_path = one(&flags, "vk")?;
    let vk_text = fs::read_to_string(vk_path).map_err(|e| format!("{vk_path}: {e}"))?;
    let vk = vk_from_bytes(&parse_vk_hex(&vk_text)?);
    let bundle = read_bundle(one(&flags, "bundle")?)?;

    let circuit = bundle_field(&bundle, "circuit")?;
    let mut inputs = vec![parse_fr(bundle_field(&bundle, "root")?)?];
    match circuit {
        "transfer" => {
            for key in [
                "nullifier.0",
                "nullifier.1",
                "new_commitment.0",
                "new_commitment.1",
            ] {
                inputs.push(parse_fr(bundle_field(&bundle, key)?)?);
            }
        }
        "withdraw" => {
            inputs.push(parse_fr(bundle_field(&bundle, "nullifier")?)?);
            inputs.push(parse_fr(bundle_field(&bundle, "recipient_binding")?)?);
            let amount: u64 = bundle_field(&bundle, "amount")?
                .parse()
                .map_err(|e| format!("amount: {e}"))?;
            inputs.push(Fr::from(amount));
        }
        other => return Err(format!("unknown bundle circuit: {other}")),
    }
    if vk.gamma_abc_g1.len() != inputs.len() + 1 {
        return Err(format!(
            "vk expects {} public inputs, bundle has {} — wrong vk for this circuit?",
            vk.gamma_abc_g1.len() - 1,
            inputs.len()
        ));
    }

    // The bundle may come from an untrusted relayer: reject off-curve or
    // wrong-subgroup proof points instead of pairing on garbage.
    let proof = Proof::<Bls12_381> {
        a: checked_g1(bundle_field(&bundle, "proof.a")?, "proof.a")?,
        b: checked_g2(bundle_field(&bundle, "proof.b")?, "proof.b")?,
        c: checked_g1(bundle_field(&bundle, "proof.c")?, "proof.c")?,
    };

    let ok = Groth16::<Bls12_381>::verify(&vk, &inputs, &proof).map_err(|e| format!("{e}"))?;
    if !ok {
        return Err("proof does NOT verify against this vk and these public inputs".to_string());
    }
    println!(
        "OK: {circuit} proof verifies ({} public inputs)",
        inputs.len()
    );
    Ok(())
}

fn checked_g1(hex_str: &str, name: &str) -> Result<G1Affine, String> {
    let bytes: [u8; G1_LEN] = hex::decode(hex_str)
        .map_err(|e| format!("{name}: {e}"))?
        .try_into()
        .map_err(|_| format!("{name}: expected {G1_LEN} bytes"))?;
    let p = g1_from_bytes(&bytes);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!("{name}: not a valid G1 point"));
    }
    Ok(p)
}

fn checked_g2(hex_str: &str, name: &str) -> Result<G2Affine, String> {
    let bytes: [u8; G2_LEN] = hex::decode(hex_str)
        .map_err(|e| format!("{name}: {e}"))?
        .try_into()
        .map_err(|_| format!("{name}: expected {G2_LEN} bytes"))?;
    let p = g2_from_bytes(&bytes);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!("{name}: not a valid G2 point"));
    }
    Ok(p)
}

// ── descriptor parsing shared by the proving commands ───────────────────

trait TryParse: Sized {
    fn try_parse(s: &str) -> Result<Self, String>;
}

/// Parses a flag that must appear exactly twice (the 2-in/2-out arity).
fn two<T: TryParse>(flags: &HashMap<String, Vec<String>>, key: &str) -> Result<[T; 2], String> {
    match flags.get(key).map(Vec::as_slice) {
        Some([a, b]) => Ok([T::try_parse(a)?, T::try_parse(b)?]),
        _ => Err(format!("--{key} must be given exactly twice")),
    }
}

impl TryParse for Spend {
    /// `sk:value:blinding:leaf_index`, hex fields, decimal value/index.
    fn try_parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        let [sk, value, blinding, leaf_index] = parts.as_slice() else {
            return Err(format!(
                "--spend wants sk:value:blinding:leaf_index, got {s}"
            ));
        };
        Ok(Spend {
            sk: parse_fr(sk)?,
            value: value.parse().map_err(|e| format!("spend value: {e}"))?,
            blinding: parse_fr(blinding)?,
            leaf_index: leaf_index
                .parse()
                .map_err(|e| format!("spend leaf index: {e}"))?,
        })
    }
}

impl TryParse for Output {
    /// `owner_pk:value:blinding`, hex fields, decimal value.
    fn try_parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        let [owner_pk, value, blinding] = parts.as_slice() else {
            return Err(format!("--output wants owner_pk:value:blinding, got {s}"));
        };
        Ok(Output {
            owner_pk: parse_fr(owner_pk)?,
            value: value.parse().map_err(|e| format!("output value: {e}"))?,
            blinding: parse_fr(blinding)?,
        })
    }
}
