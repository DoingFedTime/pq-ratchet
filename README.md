# pq-ratchet

[![Crates.io](https://img.shields.io/crates/v/pq-ratchet)](https://crates.io/crates/pq-ratchet)
[![docs.rs](https://img.shields.io/docsrs/pq-ratchet)](https://docs.rs/pq-ratchet)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-informational)](https://blog.rust-lang.org/2024/10/17/Rust-1.82.0.html)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)

A post-quantum hybrid double ratchet for Rust.

Extends the [Signal Double Ratchet] with an ML-KEM-768 (NIST FIPS 203) post-quantum
layer. It follows the epoch idea behind Signal's Sparse Continuous Key Agreement (SCKA),
the building block of the Sparse Post-Quantum Ratchet (SPQR) that Signal announced in
October 2025. Signal's earlier PQXDH (September 2023) covers session setup only.

An attacker must break **both** X25519 **and** ML-KEM-768 to compromise any session key.

---

## The problem with classical ratchets

The classical Signal Double Ratchet is broken by a sufficiently powerful quantum
computer via Shor's algorithm on X25519. Adding a post-quantum KEM is non-trivial
because ML-KEM is a *one-shot* KEM -- it doesn't have the commutativity property of
Diffie-Hellman -- so naively inserting it into the ratchet breaks out-of-order delivery.

Signal's SPQR design handles this with epochs. This crate uses a simpler variant of
that idea: the ML-KEM round-trip is tied to each DH ratchet step, and full encapsulation
keys and ciphertexts travel in the message header. It does not implement the incremental
KEM or the erasure-coded chunking of Signal's ML-KEM Braid. All messages in one epoch
use the same PQ base material, so the symmetric chain ratchet handles reordering as usual.

---

## Architecture

Each DHRatchet step performs two hybrid root-KDF invocations:

```
Receiving chain:  KDF_RK(rk,  DH(old_dh, their_dh) || decap(their_ct))
Sending chain:    KDF_RK(rk', DH(new_dh, their_dh) || encap(their_ek).ss)
```

Where:
- `DH(...)` = X25519 shared secret (32 bytes)
- `decap(their_ct)` = ML-KEM-768 shared secret from decapsulating their ciphertext
- `encap(their_ek).ss` = ML-KEM-768 shared secret from encapsulating to their EK

The hybrid input `DH || PQ` (64 bytes) is fed into HKDF-SHA256 with domain-separated
info strings. The protocol degrades gracefully to classical-only security if no PQ
material is present in a header (first message, or peer without PQ support).

```
              ┌──────────────────────────────────────────────────────┐
              │  Each DHRatchet step                                  │
              │                                                       │
  old_rk  ──► HKDF-SHA256(DH(old,peer) ║ PQ_recv)  ──► ckr, new_rk │
              │                                                       │
  new_rk  ──► HKDF-SHA256(DH(new,peer) ║ PQ_send)  ──► cks, new_rk'│
              └──────────────────────────────────────────────────────┘
              PQ_recv = ML-KEM-768.Decaps(our_dk, header.pq_ct)
              PQ_send = ML-KEM-768.Encaps(header.pq_ek).ss
```

---

## Usage

```rust
use pq_ratchet::HybridRatchet;
use x25519_dalek::{PublicKey, StaticSecret};
use rand::thread_rng;

let mut rng = thread_rng();
let shared_secret = [0u8; 32]; // from PQXDH / X3DH

// Bob's ratchet key (from his prekey bundle)
let bob_dh_sk = StaticSecret::random_from_rng(&mut rng);
let bob_dh_pk = PublicKey::from(&bob_dh_sk);

// Initialise
let mut alice = HybridRatchet::init_sender(&shared_secret, bob_dh_pk.as_bytes(), &mut rng);
let mut bob   = HybridRatchet::init_receiver(&shared_secret, bob_dh_sk, &mut rng);

// Alice → Bob
let (header, mk_alice) = alice.ratchet_encrypt(&mut rng).unwrap();
let mk_bob = bob.ratchet_decrypt(&header, &mut rng).unwrap();
assert_eq!(mk_alice.as_bytes(), mk_bob.as_bytes());

// Use mk_alice / mk_bob with ChaCha20-Poly1305 or AES-256-GCM
// Authenticate the header as AEAD additional data
```

---

## Header authentication

Every ratchet message must be authenticated. Pass the header as AEAD additional data.
`Header::encode()` produces a canonical byte string for this; the peer uses
`Header::decode()` to reconstruct the header from wire bytes:

```rust
let (header, mk) = alice.ratchet_encrypt(&mut rng).unwrap();
let aad = header.encode();   // authenticate this alongside the ciphertext

// Receiver:
let header = Header::decode(&aad).unwrap();
let mk = bob.ratchet_decrypt(&header, &mut rng).unwrap();
```

---

## Session persistence

`HybridRatchet::to_bytes()` serializes the full session state (all key material) to a
`Zeroizing<Vec<u8>>` using a versioned binary format. `from_bytes()` restores it:

```rust
// Persist
let blob = alice.to_bytes();                      // Zeroizing<Vec<u8>>
store_encrypted_to_disk(&blob);                   // caller encrypts at rest

// Restore
let blob = load_and_decrypt_from_disk();
let alice = HybridRatchet::from_bytes(&blob).unwrap();
```

Enable the optional `serde` feature for `Serialize`/`Deserialize` on `HybridRatchet`:

```toml
pq-ratchet = { version = "0.2", features = ["serde"] }
```

The serde representation is the same binary blob, compatible with any serde format
that handles byte sequences (bincode, messagepack, etc.).

---

## Security properties

| Property | Provided by |
|---|---|
| Forward secrecy | X25519 DH ratchet + message-key deletion |
| Post-quantum forward secrecy | ML-KEM-768 per-epoch key exchange |
| Break-in recovery | Both DH and PQ ratchets regenerate keys |
| Out-of-order delivery | Symmetric chain + skipped-key cache |
| Hybrid security | Attacker must break X25519 **and** ML-KEM-768 |

**What this crate does NOT provide:**
- Encryption (bring your own AEAD)
- Authentication (authenticate headers as AEAD additional data)
- Initial key agreement (use X3DH or PQXDH)
- A security audit

---

## Crate parameters

| Parameter | Value |
|---|---|
| PQ KEM | ML-KEM-768 (NIST FIPS 203, 128-bit post-quantum security) |
| Classical DH | X25519 |
| Root KDF | HKDF-SHA256, 64-byte hybrid IKM |
| Chain KDF | HKDF-SHA256 with domain-separated labels |
| Skipped-key cache limit | 1,000 entries |
| EK size (in header) | 1,184 bytes |
| CT size (in header) | 1,088 bytes |

---

## Security notice

This crate has **not been independently audited**. The underlying `ml-kem` crate
(RustCrypto) also carries this caveat. Do not deploy in production without a
security review.

---

## References

- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal PQXDH Specification](https://signal.org/docs/specifications/pqxdh/)
- [Signal SPQR Blog Post](https://signal.org/blog/spqr/)
- [Signal ML-KEM Braid Specification](https://signal.org/docs/specifications/mlkembraid/)
- [NIST FIPS 203 -- ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [RustCrypto ml-kem](https://crates.io/crates/ml-kem)

---

## License

GPL-3.0-only -- see [LICENSE](LICENSE).
