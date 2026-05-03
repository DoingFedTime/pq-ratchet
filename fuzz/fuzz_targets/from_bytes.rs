#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_ratchet::HybridRatchet;

// Fuzz `HybridRatchet::from_bytes` against arbitrary bytes.
// Goal: no panic, no UB - only Ok or Err.
fuzz_target!(|data: &[u8]| {
    let _ = HybridRatchet::from_bytes(data);
});
