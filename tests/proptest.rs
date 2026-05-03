// Property-based tests using proptest.
//
// Run with: cargo test --tests
// For exhaustive shrinking: PROPTEST_CASES=10000 cargo test --tests

use proptest::prelude::*;
use pq_ratchet::{Header, HybridRatchet};
use rand::SeedableRng;
use rand::rngs::StdRng;
use x25519_dalek::{PublicKey, StaticSecret};

proptest! {
    /// `Header::decode(header.encode())` must succeed and reproduce the same fields.
    #[test]
    fn header_encode_decode_roundtrip(
        dh_pk_bytes in any::<[u8; 32]>(),
        n in 0u32..=u32::MAX,
        pn in 0u32..=u32::MAX,
    ) {
        let h = Header::new(dh_pk_bytes, n, pn, None, None);
        let encoded = h.encode();
        let h2 = Header::decode(&encoded).unwrap();
        prop_assert_eq!(h.dh_pk(), h2.dh_pk());
        prop_assert_eq!(h.n(), h2.n());
        prop_assert_eq!(h.pn(), h2.pn());
    }

    /// Arbitrary byte slices fed to `Header::decode` must not panic.
    #[test]
    fn header_decode_never_panics(data in any::<Vec<u8>>()) {
        let _ = Header::decode(&data);
    }

    /// Arbitrary byte slices fed to `HybridRatchet::from_bytes` must not panic.
    #[test]
    fn from_bytes_never_panics(data in any::<Vec<u8>>()) {
        let _ = HybridRatchet::from_bytes(&data);
    }

    /// For any seed pair, Alice and Bob derive the same message key on the first exchange.
    #[test]
    fn message_key_agreement_arbitrary_seeds(seed_a in 0u64..=u64::MAX, seed_b in 0u64..=u64::MAX) {
        let mut rng_a = StdRng::seed_from_u64(seed_a);
        let mut rng_b = StdRng::seed_from_u64(seed_b);

        let shared_secret = [0u8; 32];
        let bob_sk = StaticSecret::random_from_rng(&mut rng_b);
        let bob_pk = PublicKey::from(&bob_sk);

        let mut alice = HybridRatchet::init_sender(&shared_secret, bob_pk.as_bytes(), &mut rng_a);
        let mut bob   = HybridRatchet::init_receiver(&shared_secret, bob_sk, &mut rng_b);

        let (header, mk_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        let mk_b = bob.ratchet_decrypt(&header, &mut rng_b).unwrap();

        prop_assert_eq!(mk_a.as_bytes(), mk_b.as_bytes());
    }
}
