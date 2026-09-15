//! `g1_from_bytes` must accept every possible 96-byte input without
//! panicking — it does not validate curve membership by design (the
//! host does, on use), so arbitrary coordinates must still decode into
//! a (possibly off-curve) point struct rather than crash.
#![no_main]

use attesta_circuits::encoding::g1_from_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 96]| {
    let _ = g1_from_bytes(&data);
});
