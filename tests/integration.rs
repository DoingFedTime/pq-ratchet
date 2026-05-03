// Integration tests for the hybrid double ratchet.
//
// Each test exercises one aspect of the protocol.  All tests use a zeroed
// shared secret - real usage would derive this via PQXDH / X3DH.

use pq_ratchet::{Header, HybridRatchet, RatchetError, MAX_SKIP, MAX_SKIP_TOTAL};
use rand::rngs::StdRng;
use rand::SeedableRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn make_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn make_session(seed_alice: u64, seed_bob: u64) -> (HybridRatchet, HybridRatchet, StdRng, StdRng) {
    let mut rng_a = make_rng(seed_alice);
    let mut rng_b = make_rng(seed_bob);

    let shared_secret = [42u8; 32];
    let bob_dh_sk = StaticSecret::random_from_rng(&mut rng_b);
    let bob_dh_pk = PublicKey::from(&bob_dh_sk);

    let alice = HybridRatchet::init_sender(&shared_secret, bob_dh_pk.as_bytes(), &mut rng_a);
    let bob = HybridRatchet::init_receiver(&shared_secret, bob_dh_sk, &mut rng_b);

    (alice, bob, rng_a, rng_b)
}

// ── Basic exchange ────────────────────────────────────────────────────────────

#[test]
fn alice_to_bob_single_message() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(1, 2);

    let (header, mk_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let mk_b = bob.ratchet_decrypt(&header, &mut rng_b).unwrap();

    assert_eq!(mk_a.as_bytes(), mk_b.as_bytes(), "message keys must agree");
}

#[test]
fn bidirectional_exchange() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(3, 4);

    // Alice → Bob
    let (h1, mk_a1) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let mk_b1 = bob.ratchet_decrypt(&h1, &mut rng_b).unwrap();
    assert_eq!(mk_a1.as_bytes(), mk_b1.as_bytes());

    // Bob → Alice  (triggers Bob's first DH ratchet)
    let (h2, mk_b2) = bob.ratchet_encrypt(&mut rng_b).unwrap();
    let mk_a2 = alice.ratchet_decrypt(&h2, &mut rng_a).unwrap();
    assert_eq!(mk_b2.as_bytes(), mk_a2.as_bytes());

    // Alice → Bob again  (Alice ratchets with Bob's new DH key)
    let (h3, mk_a3) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let mk_b3 = bob.ratchet_decrypt(&h3, &mut rng_b).unwrap();
    assert_eq!(mk_a3.as_bytes(), mk_b3.as_bytes());
}

#[test]
fn multiple_sends_one_direction() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(5, 6);

    let n = 8usize;
    let mut headers = Vec::with_capacity(n);
    let mut keys_a = Vec::with_capacity(n);

    for _ in 0..n {
        let (h, mk) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        headers.push(h);
        keys_a.push(mk);
    }
    for i in 0..n {
        let mk_b = bob.ratchet_decrypt(&headers[i], &mut rng_b).unwrap();
        assert_eq!(
            keys_a[i].as_bytes(),
            mk_b.as_bytes(),
            "msg {i} key mismatch"
        );
    }
}

// ── Out-of-order delivery ─────────────────────────────────────────────────────

#[test]
fn out_of_order_same_epoch() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(7, 8);

    let (h0, mk0) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let (h1, mk1) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let (h2, mk2) = alice.ratchet_encrypt(&mut rng_a).unwrap();

    // Deliver in reverse order
    let r2 = bob.ratchet_decrypt(&h2, &mut rng_b).unwrap();
    let r1 = bob.ratchet_decrypt(&h1, &mut rng_b).unwrap();
    let r0 = bob.ratchet_decrypt(&h0, &mut rng_b).unwrap();

    assert_eq!(mk2.as_bytes(), r2.as_bytes());
    assert_eq!(mk1.as_bytes(), r1.as_bytes());
    assert_eq!(mk0.as_bytes(), r0.as_bytes());
}

// ── Key uniqueness ────────────────────────────────────────────────────────────

#[test]
fn all_message_keys_distinct() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(9, 10);

    let mut seen = std::collections::HashSet::new();

    // Alice sends 5
    for _ in 0..5 {
        let (h, mk) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        bob.ratchet_decrypt(&h, &mut rng_b).unwrap();
        assert!(
            seen.insert(*mk.as_bytes()),
            "duplicate message key detected"
        );
    }

    // Bob sends 5
    for _ in 0..5 {
        let (h, mk) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        alice.ratchet_decrypt(&h, &mut rng_a).unwrap();
        assert!(
            seen.insert(*mk.as_bytes()),
            "duplicate message key detected"
        );
    }
}

// ── PQ material propagation ───────────────────────────────────────────────────

#[test]
fn pq_ek_present_in_headers() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(11, 12);

    // Alice's first header should carry her ML-KEM EK
    let (h1, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    assert!(
        h1.pq_ek().is_some(),
        "Alice's initial header must contain a PQ EK"
    );

    // After Bob ratchets (first decrypt), his header should carry a PQ EK too
    bob.ratchet_decrypt(&h1, &mut rng_b).unwrap();
    let (h2, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
    assert!(
        h2.pq_ek().is_some(),
        "Bob's response header must contain a PQ EK"
    );

    // Bob's header should carry a CT (response to Alice's EK)
    assert!(
        h2.pq_ct().is_some(),
        "Bob's response header must contain a PQ CT for Alice's EK"
    );
}

#[test]
fn full_pq_exchange_produces_agreement() {
    // Three full epochs to exercise the PQ ratchet.
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(13, 14);

    for epoch in 0..3usize {
        let (ha, mka) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        let mkb = bob.ratchet_decrypt(&ha, &mut rng_b).unwrap();
        assert_eq!(
            mka.as_bytes(),
            mkb.as_bytes(),
            "epoch {epoch}: A→B key mismatch"
        );

        let (hb, mkb2) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        let mka2 = alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();
        assert_eq!(
            mkb2.as_bytes(),
            mka2.as_bytes(),
            "epoch {epoch}: B→A key mismatch"
        );
    }
}

// ── Security: skip-cache exhaustion ──────────────────────────────────────────

#[test]
fn per_batch_skip_limit_enforced() {
    // Skipping more than MAX_SKIP messages in a single chain step must fail.
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(20, 21);

    // Alice sends MAX_SKIP + 2 messages without Bob receiving any.
    let mut headers = Vec::new();
    for _ in 0..=(MAX_SKIP + 1) {
        let (h, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        headers.push(h);
    }

    // Bob tries to receive the very last one - requires skipping MAX_SKIP + 1 messages.
    match bob.ratchet_decrypt(headers.last().unwrap(), &mut rng_b) {
        Err(RatchetError::TooManySkipped(_)) => { /* expected */ }
        Ok(_) => panic!("expected TooManySkipped error, got Ok"),
        Err(e) => panic!("expected TooManySkipped error, got {:?}", e),
    }
}

#[test]
fn global_skip_limit_prevents_cross_epoch_exhaustion() {
    // A malicious peer can ratchet through many DH epochs while leaving messages
    // undelivered.  Without MAX_SKIP_TOTAL the cache grows without bound.
    // Each epoch here skips (BATCH - 1) entries; after enough epochs the global
    // limit must fire even though no single epoch exceeds MAX_SKIP.
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(22, 23);

    const BATCH: usize = 100; // skip 99 entries per epoch; well within MAX_SKIP
                              // Epochs needed to exceed MAX_SKIP_TOTAL:  ceil(MAX_SKIP_TOTAL / (BATCH-1)) + 1
    let max_epochs = MAX_SKIP_TOTAL / (BATCH - 1) + 2;

    let mut error_seen = false;

    for _ in 0..max_epochs {
        // Alice sends BATCH messages in her current epoch.
        let mut headers = Vec::new();
        for _ in 0..BATCH {
            let (h, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
            headers.push(h);
        }

        // Bob receives only the last one (BATCH-1 entries cached per epoch).
        match bob.ratchet_decrypt(headers.last().unwrap(), &mut rng_b) {
            Err(RatchetError::TooManySkipped(_)) => {
                error_seen = true;
                break;
            }
            Err(e) => panic!("unexpected error: {:?}", e),
            Ok(_) => {}
        }

        // Bob ratchets back so the next round uses a fresh DH epoch.
        let (hb, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();
    }

    assert!(
        error_seen,
        "MAX_SKIP_TOTAL global limit should have fired before {} epochs",
        max_epochs
    );
}

// ── Header encoding ───────────────────────────────────────────────────────────

#[test]
fn header_encode_decode_roundtrip_full() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(30, 31);

    // First header carries EK; after Bob replies his header carries both EK and CT.
    let (h1, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    bob.ratchet_decrypt(&h1, &mut rng_b).unwrap();
    let (h2, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();

    assert!(
        h2.pq_ek().is_some() && h2.pq_ct().is_some(),
        "need a header with both EK and CT"
    );

    let encoded = h2.encode();
    let decoded = Header::decode(&encoded).expect("decode must succeed");

    assert_eq!(h2.dh_pk(), decoded.dh_pk());
    assert_eq!(h2.n(), decoded.n());
    assert_eq!(h2.pn(), decoded.pn());
    assert_eq!(
        h2.pq_ek().map(|e| e.0),
        decoded.pq_ek().map(|e| e.0)
    );
    assert_eq!(
        h2.pq_ct().map(|c| c.0),
        decoded.pq_ct().map(|c| c.0)
    );
}

#[test]
fn header_encode_decode_no_pq() {
    // Manually construct a minimal header (no PQ fields).
    use pq_ratchet::Header;
    let h = Header::new([0xab; 32], 7, 3, None, None);
    let encoded = h.encode();
    assert_eq!(encoded.len(), 41, "no-PQ header must be exactly 41 bytes");
    let decoded = Header::decode(&encoded).unwrap();
    assert_eq!(decoded.dh_pk(), [0xab; 32]);
    assert_eq!(decoded.n(), 7);
    assert_eq!(decoded.pn(), 3);
    assert!(decoded.pq_ek().is_none() && decoded.pq_ct().is_none());
}

#[test]
fn header_decode_rejects_bad_input() {
    assert!(matches!(
        Header::decode(&[]),
        Err(RatchetError::MalformedHeader(_))
    ));
    // Valid header then one extra byte of garbage.
    let h = Header::new([1u8; 32], 0, 0, None, None);
    let mut enc = h.encode();
    enc.push(0xff);
    assert!(matches!(
        Header::decode(&enc),
        Err(RatchetError::MalformedHeader(_))
    ));
}

// ── State serialization ───────────────────────────────────────────────────────

#[test]
fn state_serialize_deserialize_roundtrip() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(40, 41);

    // Exchange a few messages to build up ratchet state.
    for _ in 0..3 {
        let (h, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        bob.ratchet_decrypt(&h, &mut rng_b).unwrap();
        let (h, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        alice.ratchet_decrypt(&h, &mut rng_a).unwrap();
    }

    // Round-trip both sides through to_bytes / from_bytes.
    let alice2 = HybridRatchet::from_bytes(&alice.to_bytes()).expect("alice roundtrip");
    let bob2 = HybridRatchet::from_bytes(&bob.to_bytes()).expect("bob roundtrip");

    // Drop originals so we prove we're using the restored state.
    drop(alice);
    drop(bob);

    // Restored sessions must still agree on message keys.
    let (mut alice2, mut bob2) = (alice2, bob2);
    let (h, mk_a) = alice2.ratchet_encrypt(&mut rng_a).unwrap();
    let mk_b = bob2.ratchet_decrypt(&h, &mut rng_b).unwrap();
    assert_eq!(
        mk_a.as_bytes(),
        mk_b.as_bytes(),
        "post-restore message key mismatch"
    );
}

#[test]
fn state_deserialize_rejects_bad_input() {
    assert!(matches!(
        HybridRatchet::from_bytes(&[]),
        Err(RatchetError::MalformedState(_))
    ));
    assert!(matches!(
        HybridRatchet::from_bytes(&[0x02]), // unknown version
        Err(RatchetError::MalformedState(_))
    ));
}

// ── Redacted Debug ────────────────────────────────────────────────────────────

#[test]
fn debug_does_not_leak_key_material() {
    let (alice, _, _, _) = make_session(50, 51);
    let s = format!("{alice:?}");
    // Must not contain hex sequences that look like raw key bytes.
    assert!(s.contains("HybridRatchet"), "should contain struct name");
    assert!(s.contains("ns"), "should contain counter fields");
    // The DH secret key is 32 bytes of non-ASCII data; its hex would be 64 chars.
    // We can't check absence of *all* key data, but we verify the known secret
    // fields are absent from the output.
    assert!(!s.contains("dh_sk"), "must not expose dh_sk");
    assert!(!s.contains("rk"), "must not expose root key field");
}

// ── Error conditions ──────────────────────────────────────────────────────────

#[test]
fn receiver_cannot_encrypt_before_first_decrypt() {
    let (_, mut bob, _, mut rng_b) = make_session(60, 61);
    // Bob is init_receiver - cks is None until he processes Alice's first message.
    match bob.ratchet_encrypt(&mut rng_b) {
        Err(RatchetError::NoSendingChain) => { /* expected */ }
        Ok(_) => panic!("expected NoSendingChain, got Ok"),
        Err(e) => panic!("expected NoSendingChain, got {:?}", e),
    }
}

#[test]
fn message_counters_increment_correctly() {
    // Counters (u32) increment per message. Sessions must be re-keyed before
    // they exhaust 2^32 messages - this test documents the starting state.
    let (mut alice, _, mut rng_a, _) = make_session(70, 71);
    for expected_n in 0u32..5 {
        let (h, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        assert_eq!(h.n(), expected_n, "message counter mismatch at step {expected_n}");
    }
}
