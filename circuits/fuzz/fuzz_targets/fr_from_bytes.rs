//! `fr_from_bytes` must accept every possible 32-byte input (mod-order
//! reduction handles values >= r) without panicking.
#![no_main]

use attesta_circuits::encoding::fr_from_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 32]| {
    let _ = fr_from_bytes(&data);
});
