#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! # pq-ratchet
//!
//! Post-quantum hybrid double ratchet. ML-KEM-768 meets X25519.
//!
//! Signal added post-quantum key agreement (PQXDH) in 2023 and announced a
//! post-quantum ratchet (SPQR) in 2025. This crate follows the epoch idea from
//! that design in a simpler form: tie an ML-KEM-768 round-trip to each DH
//! ratchet step so the symmetric chain handles reordering like it always did. An attacker has to break X25519 AND ML-KEM-768 to touch
//! any session key.
//!
//! ## What you get
//!
//! A key derivation state machine. Not encryption, not transport, not initial
//! key agreement. You bring ChaCha20-Poly1305 or AES-256-GCM for the AEAD layer
//! and whatever wire protocol you use. This crate derives the keys.
//!
//! ## Usage
//!
//! ```no_run
//! use pq_ratchet::HybridRatchet;
//!
//! // Shared secret from PQXDH or X3DH
//! let shared_secret = [0u8; 32];
//! let mut rng = rand::thread_rng();
//!
//! let bob_dh_sk = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
//! let bob_dh_pk = x25519_dalek::PublicKey::from(&bob_dh_sk);
//!
//! let mut alice = HybridRatchet::init_sender(&shared_secret, bob_dh_pk.as_bytes(), &mut rng);
//! let mut bob   = HybridRatchet::init_receiver(&shared_secret, bob_dh_sk, &mut rng);
//!
//! let (header, mk) = alice.ratchet_encrypt(&mut rng).unwrap();
//! let mk2 = bob.ratchet_decrypt(&header, &mut rng).unwrap();
//! assert_eq!(mk.as_bytes(), mk2.as_bytes());
//! ```
//!
//! ## Key confirmation
//!
//! There's no explicit handshake to verify both sides derived the same keys.
//! This matches Signal's design. You confirm implicitly: if AEAD decryption
//! succeeds, the keys matched. If it fails, the session is out of sync or
//! someone's tampering with your traffic. Surface those failures. Don't
//! silently retry.
//!
//! ## Performance
//!
//! ML-KEM-768 key generation is the expensive part (triggered at each DH ratchet
//! step). Run `cargo bench` to measure on your hardware. Within-epoch encrypt
//! is just HKDF-SHA256. Cheap.
//!
//! ## Security
//!
//! Not independently audited. The underlying `ml-kem` crate isn't either.
//! Don't deploy without a review.
//!
//! [Signal Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/

mod error;
mod kdf;
mod ratchet;
mod scka;

pub use error::RatchetError;
pub use ratchet::{Header, HybridRatchet, MessageKey, MAX_SKIP, MAX_SKIP_TOTAL};
pub use scka::{PqCt, PqEk, PQ_CT_LEN, PQ_DK_LEN, PQ_EK_LEN, PQ_SS_LEN};
