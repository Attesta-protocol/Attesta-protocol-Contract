//! `parse_vk_hex` sits on a trust boundary — it parses published
//! `verifying_key.hex` artifact files — and must never panic on
//! malformed input, only return a typed `Err`.
#![no_main]

use attesta_circuits::artifacts::parse_vk_hex;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = parse_vk_hex(&text);
});
