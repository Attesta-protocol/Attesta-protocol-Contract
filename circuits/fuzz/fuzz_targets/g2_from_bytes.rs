//! Same as `g1_from_bytes`, for the 192-byte G2 encoding.
#![no_main]

use attesta_circuits::encoding::g2_from_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 192]| {
    let _ = g2_from_bytes(&data);
});
