//! HKDF-SHA256 wrappers for the three ratchet KDF layers.
//!
//! All info strings are domain-separated and version-tagged so a future
//! protocol revision can change them without key confusion.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

// Domain-separation labels  --  must never collide across KDF roles.
// The "v1" tag is a protocol version: increment it only when the wire format
// or KDF construction changes in a way that produces different outputs from
// the same inputs (e.g. new hash, new IKM layout, new info string structure).
// Changing the tag is a breaking protocol change  --  all existing sessions become
// incompatible. Do NOT increment for internal refactors that preserve outputs.
const INFO_ROOT: &[u8] = b"pq-ratchet v1 root";
const INFO_CHAIN: &[u8] = b"pq-ratchet v1 chain-key";
const INFO_MSG: &[u8] = b"pq-ratchet v1 msg-key";

/// Root chain step: KDF_RK(root_key, dh_output || pq_output) → (new_root, new_chain_key).
///
/// Hybrid security: the KDF input binds both the X25519 DH shared secret and the
/// ML-KEM shared secret. An attacker must break both to recover the root key.
pub fn kdf_rk(
    root_key: &[u8; 32],
    dh_output: &[u8; 32],
    pq_output: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    // IKM = DH || PQ  (64 bytes; both contributions mandatory)
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh_output);
    ikm[32..].copy_from_slice(pq_output);

    let h = Hkdf::<Sha256>::new(Some(root_key.as_ref()), &ikm);
    ikm.zeroize();

    let mut out = [0u8; 64];
    h.expand(INFO_ROOT, &mut out)
        .expect("HKDF-SHA256 output length 64 is always valid");

    let mut new_root = [0u8; 32];
    let mut new_chain = [0u8; 32];
    new_root.copy_from_slice(&out[..32]);
    new_chain.copy_from_slice(&out[32..]);
    out.zeroize();

    (new_root, new_chain)
}

/// Chain step: KDF_CK(chain_key) → (new_chain_key, message_key).
///
/// Advances the symmetric ratchet one step. Produces a single-use message key
/// and a fresh chain key for the next call.
///
/// Signal's reference spec uses HMAC-SHA256(ck, 0x01/0x02). This crate uses
/// HKDF-SHA256 instead. Cryptographically equivalent for high-entropy chain
/// keys. Not wire-compatible with libsignal-protocol. The HKDF construction
/// gives stronger domain separation via its info labels.
pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Two independent HKDF-Expand calls on the same PRK, different info labels.
    let h = Hkdf::<Sha256>::new(None, chain_key.as_ref());

    let mut new_chain = [0u8; 32];
    let mut msg_key = [0u8; 32];

    h.expand(INFO_CHAIN, &mut new_chain)
        .expect("HKDF-SHA256 output length 32 is always valid");
    h.expand(INFO_MSG, &mut msg_key)
        .expect("HKDF-SHA256 output length 32 is always valid");

    (new_chain, msg_key)
}
