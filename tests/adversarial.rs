// Adversarial test suite for pq-ratchet.
//
// Goal: actively attempt to disprove the protocol implementation - find any
// case where correctness, security, or safety properties are violated.
//
// Each test asserts both the positive case (things that must work) and the
// negative case (things that must fail or produce distinguishable output).

use pq_ratchet::{Header, HybridRatchet, RatchetError, MAX_SKIP, MAX_SKIP_TOTAL};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::HashSet;
use x25519_dalek::{PublicKey, StaticSecret};

// ── Session construction helpers ──────────────────────────────────────────────

fn make_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Build a full (alice, bob) session from seeded RNGs and a given shared secret.
fn make_session_with_secret(
    shared_secret: &[u8; 32],
    seed_alice: u64,
    seed_bob: u64,
) -> (HybridRatchet, HybridRatchet, StdRng, StdRng) {
    let mut rng_a = make_rng(seed_alice);
    let mut rng_b = make_rng(seed_bob);

    let bob_dh_sk = StaticSecret::random_from_rng(&mut rng_b);
    let bob_dh_pk = PublicKey::from(&bob_dh_sk);

    let alice = HybridRatchet::init_sender(shared_secret, bob_dh_pk.as_bytes(), &mut rng_a);
    let bob = HybridRatchet::init_receiver(shared_secret, bob_dh_sk, &mut rng_b);

    (alice, bob, rng_a, rng_b)
}

/// Build a session with the default shared secret [42u8; 32].
fn make_session(seed_alice: u64, seed_bob: u64) -> (HybridRatchet, HybridRatchet, StdRng, StdRng) {
    make_session_with_secret(&[42u8; 32], seed_alice, seed_bob)
}

// ── Protocol invariants ───────────────────────────────────────────────────────

/// 1. 500 alternating messages; every key must be unique and both sides must agree.
#[test]
fn long_running_key_uniqueness() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(1001, 1002);
    let mut seen: HashSet<[u8; 32]> = HashSet::new();

    for i in 0..250usize {
        // Alice → Bob
        let (h, mk_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        let mk_b = bob.ratchet_decrypt(&h, &mut rng_b).unwrap();
        assert_eq!(
            mk_a.as_bytes(),
            mk_b.as_bytes(),
            "A→B key disagreement at step {i}"
        );
        assert!(
            seen.insert(*mk_a.as_bytes()),
            "duplicate key detected at A→B step {i}"
        );

        // Bob → Alice
        let (h, mk_b2) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        let mk_a2 = alice.ratchet_decrypt(&h, &mut rng_a).unwrap();
        assert_eq!(
            mk_b2.as_bytes(),
            mk_a2.as_bytes(),
            "B→A key disagreement at step {i}"
        );
        assert!(
            seen.insert(*mk_b2.as_bytes()),
            "duplicate key detected at B→A step {i}"
        );
    }

    assert_eq!(seen.len(), 500, "must have collected exactly 500 distinct keys");
}

/// 2. Decrypt a message, then re-decrypt the same header → MessageKeyNotFound.
#[test]
fn replay_attack_rejected() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(2001, 2002);

    let (header, mk_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let mk_b = bob.ratchet_decrypt(&header, &mut rng_b).unwrap();
    assert_eq!(mk_a.as_bytes(), mk_b.as_bytes(), "first decrypt must agree");

    // Replay attempt.
    match bob.ratchet_decrypt(&header, &mut rng_b) {
        Err(RatchetError::MessageKeyNotFound) => { /* expected: key was consumed */ }
        Ok(replayed_mk) => panic!(
            "replay succeeded - returned key {:?}",
            replayed_mk.as_bytes()
        ),
        Err(e) => panic!("unexpected error on replay: {:?}", e),
    }
}

/// 3. Skip cache key is single-use: consuming a cached key then re-requesting it
///    must return MessageKeyNotFound.
#[test]
fn skip_cache_key_single_use() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(3001, 3002);

    // Alice sends 6 messages.
    let mut headers = Vec::new();
    let mut keys_a = Vec::new();
    for _ in 0..6 {
        let (h, mk) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        headers.push(h);
        keys_a.push(mk);
    }

    // Bob jumps to msg 5 - msgs 0-4 are cached as skipped keys.
    let mk5 = bob.ratchet_decrypt(&headers[5], &mut rng_b).unwrap();
    assert_eq!(mk5.as_bytes(), keys_a[5].as_bytes(), "msg 5 key mismatch");

    // Bob retrieves cached msg 3.
    let mk3 = bob.ratchet_decrypt(&headers[3], &mut rng_b).unwrap();
    assert_eq!(mk3.as_bytes(), keys_a[3].as_bytes(), "msg 3 key mismatch");

    // Second attempt at msg 3 must be rejected.
    match bob.ratchet_decrypt(&headers[3], &mut rng_b) {
        Err(RatchetError::MessageKeyNotFound) => { /* expected */ }
        Ok(_) => panic!("duplicate cache retrieval of msg 3 succeeded"),
        Err(e) => panic!("unexpected error on second msg-3 attempt: {:?}", e),
    }
}

/// 4. Out-of-order delivery across an epoch boundary: a message cached from the
///    old epoch must still decrypt correctly after both sides ratchet.
#[test]
fn cross_epoch_out_of_order() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(4001, 4002);

    // Alice sends two messages.
    let (h0, mk_a0) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let (h1, mk_a1) = alice.ratchet_encrypt(&mut rng_a).unwrap();

    // Bob receives msg 1 first - msg 0 is cached.
    let mk_b1 = bob.ratchet_decrypt(&h1, &mut rng_b).unwrap();
    assert_eq!(mk_a1.as_bytes(), mk_b1.as_bytes(), "msg 1 key mismatch");

    // Now Bob ratchets (sends a message, Alice receives it) - new DH epoch.
    let (hb, _mk_b) = bob.ratchet_encrypt(&mut rng_b).unwrap();
    alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();

    // Bob now retrieves the old cached msg 0 from the skip cache.
    let mk_b0 = bob.ratchet_decrypt(&h0, &mut rng_b).unwrap();
    assert_eq!(
        mk_a0.as_bytes(),
        mk_b0.as_bytes(),
        "cached msg 0 key mismatch after epoch change"
    );
}

/// 5. Two independent sessions (different DH keys, same shared secret) must
///    never produce the same message key.
#[test]
fn independent_sessions_never_share_keys() {
    let shared = [42u8; 32];

    // Session 1: alice1 ↔ bob1
    let (mut alice1, mut bob1, mut rng_a1, mut rng_b1) =
        make_session_with_secret(&shared, 5001, 5002);
    // Session 2: alice2 ↔ bob2 - different DH keypairs (different seeds).
    let (mut alice2, mut bob2, mut rng_a2, mut rng_b2) =
        make_session_with_secret(&shared, 5003, 5004);

    let mut keys1: HashSet<[u8; 32]> = HashSet::new();
    let mut keys2: HashSet<[u8; 32]> = HashSet::new();

    for _ in 0..10 {
        let (h, mk) = alice1.ratchet_encrypt(&mut rng_a1).unwrap();
        bob1.ratchet_decrypt(&h, &mut rng_b1).unwrap();
        keys1.insert(*mk.as_bytes());

        let (h, mk) = alice2.ratchet_encrypt(&mut rng_a2).unwrap();
        bob2.ratchet_decrypt(&h, &mut rng_b2).unwrap();
        keys2.insert(*mk.as_bytes());
    }

    let intersection: Vec<_> = keys1.intersection(&keys2).collect();
    assert!(
        intersection.is_empty(),
        "sessions with different DH keys share message keys: {:?}",
        intersection
    );
}

/// 6. Same DH keypair, different shared secrets - keys must differ completely.
#[test]
fn session_isolation_different_shared_secrets() {
    // Use the same seeds for DH key generation but different shared secrets.
    let (mut alice1, mut bob1, mut rng_a1, mut rng_b1) =
        make_session_with_secret(&[0x11u8; 32], 6001, 6002);
    let (mut alice2, mut bob2, mut rng_a2, mut rng_b2) =
        make_session_with_secret(&[0x22u8; 32], 6001, 6002);

    let mut keys1: HashSet<[u8; 32]> = HashSet::new();
    let mut keys2: HashSet<[u8; 32]> = HashSet::new();

    for _ in 0..10 {
        let (h, mk) = alice1.ratchet_encrypt(&mut rng_a1).unwrap();
        bob1.ratchet_decrypt(&h, &mut rng_b1).unwrap();
        keys1.insert(*mk.as_bytes());

        let (h, mk) = alice2.ratchet_encrypt(&mut rng_a2).unwrap();
        bob2.ratchet_decrypt(&h, &mut rng_b2).unwrap();
        keys2.insert(*mk.as_bytes());
    }

    let intersection: Vec<_> = keys1.intersection(&keys2).collect();
    assert!(
        intersection.is_empty(),
        "sessions with different shared secrets share message keys: {:?}",
        intersection
    );
}

/// 7. Alice sends 3 messages before Bob receives any.  All 3 headers should
///    carry the same PQ CT (retransmission), and all 3 must decrypt correctly.
#[test]
fn pq_ct_retransmission() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(7001, 7002);

    // Alice produces 3 headers before Bob decrypts any.
    let (h0, mk_a0) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let (h1, mk_a1) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let (h2, mk_a2) = alice.ratchet_encrypt(&mut rng_a).unwrap();

    // All three must carry the same PQ CT bytes (retransmission guarantee).
    // The first header may not carry a CT (no PQ round-trip yet), so only
    // assert uniformity among headers that do carry a CT.
    let ct0 = h0.pq_ct().map(|c| c.0);
    let ct1 = h1.pq_ct().map(|c| c.0);
    let ct2 = h2.pq_ct().map(|c| c.0);
    assert_eq!(ct0, ct1, "CT in msg 0 and msg 1 must match (retransmit)");
    assert_eq!(ct1, ct2, "CT in msg 1 and msg 2 must match (retransmit)");

    // All three must decrypt correctly and agree with the sender's keys.
    let mk_b0 = bob.ratchet_decrypt(&h0, &mut rng_b).unwrap();
    let mk_b1 = bob.ratchet_decrypt(&h1, &mut rng_b).unwrap();
    let mk_b2 = bob.ratchet_decrypt(&h2, &mut rng_b).unwrap();

    assert_eq!(mk_a0.as_bytes(), mk_b0.as_bytes(), "msg 0 key disagrees");
    assert_eq!(mk_a1.as_bytes(), mk_b1.as_bytes(), "msg 1 key disagrees");
    assert_eq!(mk_a2.as_bytes(), mk_b2.as_bytes(), "msg 2 key disagrees");
}

/// 8. After retrieving a skipped key from the cache, the slot must be evicted
///    (replay of the same key must fail with MessageKeyNotFound).
#[test]
fn skipped_keys_evicted_after_use() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(8001, 8002);

    // Alice sends 4 messages.
    let mut headers = Vec::new();
    for _ in 0..4 {
        let (h, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        headers.push(h);
    }

    // Bob skips to msg 3, caching msgs 0-2.
    bob.ratchet_decrypt(&headers[3], &mut rng_b).unwrap();

    // Bob retrieves msg 1 from the cache.
    bob.ratchet_decrypt(&headers[1], &mut rng_b).unwrap();

    // Replay of msg 1 must be rejected.
    match bob.ratchet_decrypt(&headers[1], &mut rng_b) {
        Err(RatchetError::MessageKeyNotFound) => { /* expected: evicted after use */ }
        Ok(_) => panic!("evicted cached key was returned a second time"),
        Err(e) => panic!("unexpected error: {:?}", e),
    }
}

/// 9. Build up 5 skipped keys, save state, restore, then retrieve all 5 from
///    the restored state.  The skip cache must survive serialization.
#[test]
fn state_save_restore_preserves_skipped_cache() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(9001, 9002);

    // Alice sends 6 messages.
    let mut headers = Vec::new();
    let mut keys_a = Vec::new();
    for _ in 0..6 {
        let (h, mk) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        headers.push(h);
        keys_a.push(mk);
    }

    // Bob receives only msg 5 - skips msgs 0-4 into the cache.
    let mk5 = bob.ratchet_decrypt(&headers[5], &mut rng_b).unwrap();
    assert_eq!(mk5.as_bytes(), keys_a[5].as_bytes(), "msg 5 pre-save");

    // Save and restore Bob's state.
    let bob_bytes = bob.to_bytes();
    let mut bob2 = HybridRatchet::from_bytes(&bob_bytes).expect("restore failed");

    // Retrieve all 5 cached keys from the restored state.
    for i in 0..5 {
        let mk = bob2
            .ratchet_decrypt(&headers[i], &mut rng_b)
            .unwrap_or_else(|e| panic!("post-restore decrypt of msg {i} failed: {:?}", e));
        assert_eq!(
            mk.as_bytes(),
            keys_a[i].as_bytes(),
            "post-restore key mismatch for msg {i}"
        );
    }
}

/// 10. Save/restore both sides mid-epoch and continue exchange - keys must agree.
#[test]
fn state_save_restore_mid_epoch() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(10001, 10002);

    // Alice sends 10, Bob receives first 5.
    let mut headers = Vec::new();
    let mut keys_a = Vec::new();
    for _ in 0..10 {
        let (h, mk) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        headers.push(h);
        keys_a.push(mk);
    }
    for i in 0..5 {
        let mk = bob.ratchet_decrypt(&headers[i], &mut rng_b).unwrap();
        assert_eq!(mk.as_bytes(), keys_a[i].as_bytes(), "pre-save msg {i}");
    }

    // Save and restore both sides.
    let mut alice2 = HybridRatchet::from_bytes(&alice.to_bytes()).expect("alice restore");
    let mut bob2 = HybridRatchet::from_bytes(&bob.to_bytes()).expect("bob restore");

    // Bob receives the remaining 5 messages from the restored state.
    for i in 5..10 {
        let mk = bob2
            .ratchet_decrypt(&headers[i], &mut rng_b)
            .unwrap_or_else(|e| panic!("post-restore msg {i} failed: {:?}", e));
        assert_eq!(
            mk.as_bytes(),
            keys_a[i].as_bytes(),
            "post-restore key mismatch for msg {i}"
        );
    }

    // Alice's restored state must produce keys that agree with Bob.
    let (h, mk_a) = alice2.ratchet_encrypt(&mut rng_a).unwrap();
    let mk_b = bob2.ratchet_decrypt(&h, &mut rng_b).unwrap();
    assert_eq!(
        mk_a.as_bytes(),
        mk_b.as_bytes(),
        "post-restore continued exchange key mismatch"
    );
}

/// 11. A fresh receiver restored from serialized state (never decrypted) still
///     cannot encrypt - NoSendingChain must fire.
#[test]
fn no_sending_chain_after_restore_of_receiver() {
    let (_, bob, _, mut rng_b) = make_session(11001, 11002);

    // Serialize and restore the pristine receiver.
    let bob_bytes = bob.to_bytes();
    let mut bob2 = HybridRatchet::from_bytes(&bob_bytes).expect("restore failed");

    match bob2.ratchet_encrypt(&mut rng_b) {
        Err(RatchetError::NoSendingChain) => { /* expected */ }
        Ok(_) => panic!("fresh receiver encrypt succeeded after restore"),
        Err(e) => panic!("unexpected error: {:?}", e),
    }
}

/// 12. 20 full epochs - every key across all epochs must be globally unique.
#[test]
fn many_epochs_key_uniqueness() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(12001, 12002);
    let mut seen: HashSet<[u8; 32]> = HashSet::new();

    for epoch in 0..20usize {
        // A → B (triggers DH ratchet on Bob).
        let (h, mk_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        let mk_b = bob.ratchet_decrypt(&h, &mut rng_b).unwrap();
        assert_eq!(
            mk_a.as_bytes(),
            mk_b.as_bytes(),
            "epoch {epoch} A→B key mismatch"
        );
        assert!(
            seen.insert(*mk_a.as_bytes()),
            "duplicate key at epoch {epoch} A→B"
        );

        // B → A (triggers DH ratchet on Alice).
        let (h, mk_b2) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        let mk_a2 = alice.ratchet_decrypt(&h, &mut rng_a).unwrap();
        assert_eq!(
            mk_b2.as_bytes(),
            mk_a2.as_bytes(),
            "epoch {epoch} B→A key mismatch"
        );
        assert!(
            seen.insert(*mk_b2.as_bytes()),
            "duplicate key at epoch {epoch} B→A"
        );
    }
}

/// 13. Alice sends in epoch 1, then epoch 2 starts.  Bob gets epoch-2 messages
///     first, then retrieves epoch-1 message from the skip cache.
#[test]
fn out_of_order_across_epochs() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(13001, 13002);

    // Epoch 1: Alice sends one message (held back).
    let (h_ep1, mk_ep1) = alice.ratchet_encrypt(&mut rng_a).unwrap();

    // Epoch 2: Bob sends, Alice receives → Alice ratchets her DH.
    // But first Bob must see Alice's msg to have her DH pk.
    // Deliver Alice epoch-1 msg to Bob first to establish the session,
    // then trigger the epoch transition.
    let mk_b_ep1 = bob.ratchet_decrypt(&h_ep1, &mut rng_b).unwrap();
    assert_eq!(mk_ep1.as_bytes(), mk_b_ep1.as_bytes(), "ep1 key must agree");

    // Bob sends a reply → Alice ratchets into epoch 2.
    let (hb, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
    alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();

    // Alice sends 2 messages in her new sending epoch.
    let (h2_a, mk2_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    let (h2_b, mk2_b) = alice.ratchet_encrypt(&mut rng_a).unwrap();

    // Bob skips to Alice's epoch-2 msg 1 (caching epoch-2 msg 0).
    let mk_b2b = bob.ratchet_decrypt(&h2_b, &mut rng_b).unwrap();
    assert_eq!(mk2_b.as_bytes(), mk_b2b.as_bytes(), "ep2 msg1 key mismatch");

    // Bob retrieves the skipped epoch-2 msg 0 from the cache.
    let mk_b2a = bob.ratchet_decrypt(&h2_a, &mut rng_b).unwrap();
    assert_eq!(mk2_a.as_bytes(), mk_b2a.as_bytes(), "cached ep2 msg0 key mismatch");
}

/// 14. Feed 100 different malformed byte patterns to Header::decode - none must panic.
#[test]
fn malformed_header_bytes_fuzz() {
    let mut rng = make_rng(14001);

    // Patterns: empty, 1 byte, 40 bytes (just under MIN), 41 bytes with bad flags,
    // valid-length but corrupted fields, trailing garbage, etc.
    let cases: Vec<Vec<u8>> = (0..100)
        .map(|i: usize| {
            use rand::RngCore;
            match i % 10 {
                0 => vec![],
                1 => vec![0xFF],
                2 => vec![0u8; 40], // one short of minimum
                3 => {
                    // 41 bytes but flags = 0xFF (unknown flags)
                    let mut v = vec![0u8; 41];
                    v[40] = 0xFF;
                    v
                }
                4 => {
                    // Valid header prefix, truncated EK (flags say EK present but body is short)
                    let mut v = vec![0u8; 41];
                    v[40] = 0x01; // has_ek=true
                    v
                }
                5 => {
                    // Valid header prefix, truncated CT
                    let mut v = vec![0u8; 41];
                    v[40] = 0x02; // has_ct=true
                    v
                }
                6 => {
                    // Correct length for EK but trailing byte after EK
                    let mut v = vec![0u8; 41 + 1184 + 1];
                    v[40] = 0x01;
                    v
                }
                7 => {
                    // All zeros - might parse as a valid no-PQ header
                    vec![0u8; 41]
                }
                8 => {
                    // Random bytes of random length (1..=300)
                    let len = (i * 3 + 7) % 300 + 1;
                    let mut v = vec![0u8; len];
                    rng.fill_bytes(&mut v);
                    v
                }
                _ => {
                    // Large random blob
                    let len = 1184 + 1088 + 41 + (i % 50);
                    let mut v = vec![0u8; len];
                    rng.fill_bytes(&mut v);
                    v
                }
            }
        })
        .collect();

    for (idx, bytes) in cases.iter().enumerate() {
        // Must not panic - return value is either Ok or Err, both are fine.
        let result = Header::decode(bytes);
        // For any result that succeeds, the decode-encode roundtrip must be stable.
        if let Ok(h) = result {
            let reencoded = h.encode();
            let h2 = Header::decode(&reencoded)
                .unwrap_or_else(|e| panic!("case {idx}: roundtrip decode failed: {:?}", e));
            assert_eq!(h.dh_pk(), h2.dh_pk(), "case {idx}: dh_pk changed on roundtrip");
            assert_eq!(h.n(), h2.n(), "case {idx}: n changed on roundtrip");
            assert_eq!(h.pn(), h2.pn(), "case {idx}: pn changed on roundtrip");
        }
    }
}

/// 15. Flip one byte in dh_pk of a valid header - the returned key must NOT
///     match the original (tampered DH key leads to a different chain).
///
///     Strategy: serialize Bob's pristine state, use one clone for the tampered
///     attempt (which may mutate state), and the other clone for the clean-path
///     assertion.  Both clones start from identical state.
#[test]
fn tampered_dh_key_in_header() {
    let (mut alice, bob, mut rng_a, mut rng_b) = make_session(15001, 15002);

    let (original_header, mk_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();

    // Serialize Bob's pristine state so we can make two independent receivers.
    let bob_bytes = bob.to_bytes();
    let mut bob_tampered = HybridRatchet::from_bytes(&bob_bytes).expect("bob clone");
    let mut bob_clean = HybridRatchet::from_bytes(&bob_bytes).expect("bob clone");

    // Build a tampered header with one byte of dh_pk flipped.
    let mut tampered_dh_pk = original_header.dh_pk();
    tampered_dh_pk[0] ^= 0xFF;
    let tampered_header = Header::new(
        tampered_dh_pk,
        original_header.n(),
        original_header.pn(),
        original_header.pq_ek().cloned(),
        original_header.pq_ct().cloned(),
    );

    // Decrypt with tampered header must either fail or produce a DIFFERENT key.
    match bob_tampered.ratchet_decrypt(&tampered_header, &mut rng_b) {
        Ok(tampered_mk) => {
            assert_ne!(
                tampered_mk.as_bytes(),
                mk_a.as_bytes(),
                "tampered DH key produced the same message key - key binding broken"
            );
        }
        Err(_) => { /* Any error is acceptable - tampered material rejected */ }
    }

    // The original header on the clean clone must still work correctly.
    let mk_b = bob_clean
        .ratchet_decrypt(&original_header, &mut rng_b)
        .expect("untampered header must decrypt correctly");
    assert_eq!(
        mk_a.as_bytes(),
        mk_b.as_bytes(),
        "original (untampered) key must still agree"
    );
}

/// 16. After Alice sends 5 messages in epoch 1, then ratchets into epoch 2,
///     her first epoch-2 header must have pn == 5.
#[test]
fn pn_field_correctness() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(16001, 16002);

    // Use a fresh session for clean counting.

    let mut headers_ep1 = Vec::new();
    for _ in 0..5 {
        let (h, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        headers_ep1.push(h);
    }
    // Bob receives all 5 to set up his state.
    for i in 0..5 {
        bob.ratchet_decrypt(&headers_ep1[i], &mut rng_b).unwrap();
    }

    // Bob ratchets → Alice receives his new DH key → Alice's pn must be 5.
    let (hb, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
    alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();

    // Alice's next message is epoch 2, n=0.  pn must equal 5 (previous chain length).
    let (h_ep2, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
    assert_eq!(h_ep2.n(), 0, "first epoch-2 message must have n=0");
    assert_eq!(
        h_ep2.pn(),
        5,
        "epoch-2 header pn must equal epoch-1 chain length (5)"
    );
}

/// 17. 10 independent sessions (different DH keys, same shared secret).
///     No key from session N may appear in session M's key set.
#[test]
fn concurrent_session_state_independence() {
    let shared = [99u8; 32];
    let n_sessions = 10usize;
    let msgs_per_session = 5usize;

    let mut all_keys: Vec<HashSet<[u8; 32]>> = Vec::with_capacity(n_sessions);

    for s in 0..n_sessions {
        let seed_a = (17000 + s * 2) as u64;
        let seed_b = (17001 + s * 2) as u64;
        let (mut alice, mut bob, mut rng_a, mut rng_b) =
            make_session_with_secret(&shared, seed_a, seed_b);

        let mut session_keys: HashSet<[u8; 32]> = HashSet::new();
        for _ in 0..msgs_per_session {
            let (h, mk) = alice.ratchet_encrypt(&mut rng_a).unwrap();
            bob.ratchet_decrypt(&h, &mut rng_b).unwrap();
            session_keys.insert(*mk.as_bytes());
        }
        all_keys.push(session_keys);
    }

    for i in 0..n_sessions {
        for j in (i + 1)..n_sessions {
            let overlap: Vec<_> = all_keys[i].intersection(&all_keys[j]).collect();
            assert!(
                overlap.is_empty(),
                "sessions {i} and {j} share message keys: {:?}",
                overlap
            );
        }
    }
}

/// 18. Fill the global skip cache near MAX_SKIP_TOTAL across multiple small epochs,
///     then trigger a new skip that would overflow - must get a clean error, no panic.
#[test]
fn skip_limit_cross_epoch_boundary() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(18001, 18002);

    // Each epoch we skip BATCH-1 messages.  Stop just before the global limit.
    const BATCH: usize = 50;
    let epochs_to_fill = MAX_SKIP_TOTAL / (BATCH - 1);

    let mut error_seen = false;

    for _ in 0..=epochs_to_fill {
        let mut headers = Vec::new();
        for _ in 0..BATCH {
            let (h, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
            headers.push(h);
        }

        // Bob receives only the last message (caching BATCH-1 per epoch).
        let result = bob.ratchet_decrypt(headers.last().unwrap(), &mut rng_b);

        match result {
            Err(RatchetError::TooManySkipped(_)) => {
                error_seen = true;
                break;
            }
            Err(e) => panic!("unexpected error during skip-limit test: {:?}", e),
            Ok(_) => {}
        }

        // Bob ratchets so the next iteration uses a fresh epoch.
        let (hb, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();
    }

    assert!(
        error_seen,
        "TooManySkipped should have fired before {} epochs",
        epochs_to_fill + 1
    );
}

/// 19. A header with an all-zero DH key must not panic - either it returns a key
///     (if the protocol accepts it) or a clean error.
#[test]
fn header_with_zero_dh_key_rejected_gracefully() {
    let (_, mut bob, _, mut rng_b) = make_session(19001, 19002);

    let zero_header = Header::new([0u8; 32], 0, 0, None, None);

    // Must not panic.  Any outcome (Ok or Err) is valid as long as it doesn't crash.
    let result = bob.ratchet_decrypt(&zero_header, &mut rng_b);
    // We only assert no panic; the result variant is intentionally unconstrained.
    let _ = result;
}

/// 20. All produced message keys must be exactly 32 bytes and not all-zero.
#[test]
fn message_key_is_32_bytes_and_nonzero() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(20001, 20002);

    for round in 0..20 {
        let (h, mk_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        let mk_b = bob.ratchet_decrypt(&h, &mut rng_b).unwrap();

        // as_bytes() returns &[u8; 32] - length is statically 32.
        let a_bytes: &[u8; 32] = mk_a.as_bytes();
        let b_bytes: &[u8; 32] = mk_b.as_bytes();

        assert_eq!(a_bytes.len(), 32, "round {round}: sender key not 32 bytes");
        assert_eq!(b_bytes.len(), 32, "round {round}: receiver key not 32 bytes");

        assert_ne!(
            a_bytes,
            &[0u8; 32],
            "round {round}: sender message key is all-zero"
        );
        assert_ne!(
            b_bytes,
            &[0u8; 32],
            "round {round}: receiver message key is all-zero"
        );

        // Bidirectional reply to trigger new epochs.
        let (hb, mk_b2) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        let mk_a2 = alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();
        assert_ne!(mk_b2.as_bytes(), &[0u8; 32], "round {round}: B→A key is all-zero");
        assert_ne!(mk_a2.as_bytes(), &[0u8; 32], "round {round}: A recv key is all-zero");
    }
}

// ── Security properties ───────────────────────────────────────────────────────

/// 21. Run 5 epochs; collect the first key from each epoch's sending chain.
///     All 5 must be unique - epoch keys must not repeat.
#[test]
fn message_keys_differ_across_epochs() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(21001, 21002);
    let mut epoch_first_keys: Vec<[u8; 32]> = Vec::new();

    for epoch in 0..5usize {
        // Alice sends the first message of this epoch.
        let (h, mk_a) = alice.ratchet_encrypt(&mut rng_a).unwrap();
        let mk_b = bob.ratchet_decrypt(&h, &mut rng_b).unwrap();
        assert_eq!(
            mk_a.as_bytes(),
            mk_b.as_bytes(),
            "epoch {epoch} first-key mismatch"
        );
        epoch_first_keys.push(*mk_a.as_bytes());

        // Bob replies to ratchet Alice into the next epoch.
        let (hb, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();
    }

    // All 5 epoch-opening keys must be unique.
    let unique: HashSet<_> = epoch_first_keys.iter().collect();
    assert_eq!(
        unique.len(),
        5,
        "epoch-opening keys are not all unique: {:?}",
        epoch_first_keys
    );
}

/// 22. TooManySkipped fires before the combined skip count can exceed
///     MAX_SKIP_TOTAL + MAX_SKIP total insertions.
#[test]
fn skipped_key_cache_bounded() {
    let (mut alice, mut bob, mut rng_a, mut rng_b) = make_session(22001, 22002);

    // Attempt to skip MAX_SKIP_TOTAL + MAX_SKIP messages across multiple epochs.
    // The error must fire; the cache must never grow beyond MAX_SKIP_TOTAL.
    let target = MAX_SKIP_TOTAL + MAX_SKIP;
    let batch = MAX_SKIP; // maximum allowed in one step

    let mut total_cached = 0usize;
    let mut error_seen = false;

    while total_cached <= target {
        // Alice sends batch+1 messages.
        let mut headers = Vec::new();
        for _ in 0..=(batch) {
            let (h, _) = alice.ratchet_encrypt(&mut rng_a).unwrap();
            headers.push(h);
        }

        // Bob tries to receive the last one, skipping `batch` entries.
        match bob.ratchet_decrypt(headers.last().unwrap(), &mut rng_b) {
            Err(RatchetError::TooManySkipped(n)) => {
                // The error value must not exceed the hard cap.
                assert!(
                    n <= MAX_SKIP_TOTAL + MAX_SKIP,
                    "TooManySkipped reported {n} which exceeds hard cap of {}",
                    MAX_SKIP_TOTAL + MAX_SKIP
                );
                error_seen = true;
                break;
            }
            Err(e) => panic!("unexpected error: {:?}", e),
            Ok(_) => {
                total_cached += batch;
            }
        }

        // Bob ratchets so next iteration uses a fresh epoch.
        let (hb, _) = bob.ratchet_encrypt(&mut rng_b).unwrap();
        alice.ratchet_decrypt(&hb, &mut rng_a).unwrap();
    }

    assert!(
        error_seen,
        "TooManySkipped never fired; cache may be unbounded (total attempted: {total_cached})"
    );
}
