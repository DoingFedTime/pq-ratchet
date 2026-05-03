// Criterion benchmarks for pq-ratchet.
//
// Run with: cargo bench
// HTML report at: target/criterion/report/index.html
//
// ML-KEM-768 key generation (triggered at each DH ratchet step) is the dominant
// cost. These benchmarks exist to surface regressions and give callers a
// realistic estimate of ratchet overhead.

use criterion::{criterion_group, criterion_main, Criterion};
use pq_ratchet::{Header, HybridRatchet};
use rand::rngs::StdRng;
use rand::SeedableRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn make_session() -> (HybridRatchet, HybridRatchet, StdRng, StdRng) {
    let mut rng_a = StdRng::seed_from_u64(1);
    let mut rng_b = StdRng::seed_from_u64(2);
    let shared = [0u8; 32];
    let bob_sk = StaticSecret::random_from_rng(&mut rng_b);
    let bob_pk = PublicKey::from(&bob_sk);
    let alice = HybridRatchet::init_sender(&shared, bob_pk.as_bytes(), &mut rng_a);
    let bob = HybridRatchet::init_receiver(&shared, bob_sk, &mut rng_b);
    (alice, bob, rng_a, rng_b)
}

fn bench_ratchet_encrypt(c: &mut Criterion) {
    // Warm up: receive first Bob message so Alice has a sending chain in a stable epoch.
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session();
    let (h0, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    bob.ratchet_decrypt(&h0, &mut rng_b).unwrap();
    let (h1, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
    alice.ratchet_decrypt(&h1, &mut rng_a).unwrap();

    c.bench_function("ratchet_encrypt (within-epoch)", |b| {
        b.iter(|| alice.ratchet_encrypt(&mut rng_a).unwrap())
    });
}

fn bench_dh_ratchet_step(c: &mut Criterion) {
    // Each call to ratchet_decrypt with a new DH key triggers a DH ratchet step
    // (the expensive path: X25519 + ML-KEM keygen + 2× HKDF).
    c.bench_function("dh_ratchet_step (decrypt triggering ratchet)", |b| {
        b.iter(|| {
            let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session();
            let (h1, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
            bob.ratchet_decrypt(&h1, &mut rng_b).unwrap();
            let (h2, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
            alice.ratchet_decrypt(&h2, &mut rng_a).unwrap();
        })
    });
}

fn bench_header_encode(c: &mut Criterion) {
    let h = Header::new([0xab; 32], 42, 7, None, None);
    c.bench_function("header_encode (no PQ)", |b| b.iter(|| h.encode()));
}

fn bench_header_decode(c: &mut Criterion) {
    let h = Header::new([0xab; 32], 42, 7, None, None);
    let encoded = h.encode();
    c.bench_function("header_decode (no PQ)", |b| {
        b.iter(|| Header::decode(&encoded).unwrap())
    });
}

fn bench_state_serialize(c: &mut Criterion) {
    let (mut alice, _, mut rng_a, _) = make_session();
    alice.ratchet_encrypt(&mut rng_a).unwrap();

    c.bench_function("state_serialize (to_bytes)", |b| {
        b.iter(|| alice.to_bytes())
    });
}

criterion_group!(
    benches,
    bench_ratchet_encrypt,
    bench_dh_ratchet_step,
    bench_header_encode,
    bench_header_decode,
    bench_state_serialize,
);
criterion_main!(benches);
