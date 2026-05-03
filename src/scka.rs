//! SCKA epoch state for the post-quantum ratchet.
//!
//! ML-KEM-768 is a one-shot KEM. It doesn't have the commutativity of
//! Diffie-Hellman, so you can't just drop it into a double ratchet and
//! expect out-of-order delivery to keep working.
//!
//! The approach here is a simplified take on the epoch idea in Signal's 2025
//! SPQR design: tie the PQ ratchet step directly to the DH ratchet step.
//! Each DHRatchet call does two things:
//!
//! 1. Receiving step: DH(our_old_dh, their_new_dh) || PQ_recv
//!    PQ_recv comes from decapsulating the CT the peer sent (their response
//!    to our previous EK announcement).
//!
//! 2. Sending step: DH(our_new_dh, their_new_dh) || PQ_send
//!    PQ_send comes from encapsulating to the EK the peer announced. The
//!    resulting CT gets stored and sent in our next outgoing header.
//!
//! Both PQ operations happen inside the same DHRatchet call, so the PQ
//! shared secret is always bound to a specific DH epoch. Messages within
//! an epoch all use the same chain key, so out-of-order delivery works
//! like it always did. The symmetric chain ratchet handles it.

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::RatchetError;

/// Byte length of an ML-KEM-768 encapsulation key (public key).
pub const PQ_EK_LEN: usize = 1184;
/// Byte length of an ML-KEM-768 ciphertext.
pub const PQ_CT_LEN: usize = 1088;
/// Byte length of the ML-KEM-768 shared secret output.
pub const PQ_SS_LEN: usize = 32;
/// Byte length of an ML-KEM-768 decapsulation key (private key, per FIPS 203 §7.2).
pub const PQ_DK_LEN: usize = 2400;

// Compile-time guard: catches ML-KEM spec changes across crate version bumps.
const _: () = assert!(
    core::mem::size_of::<Encoded<DK768>>() == PQ_DK_LEN,
    "PQ_DK_LEN mismatch  --  update the constant if ml-kem changes the DK size"
);
const _: () = assert!(
    core::mem::size_of::<Encoded<EK768>>() == PQ_EK_LEN,
    "PQ_EK_LEN mismatch  --  update the constant if ml-kem changes the EK size"
);
const _: () = assert!(
    core::mem::size_of::<CT768>() == PQ_CT_LEN,
    "PQ_CT_LEN mismatch  --  update the constant if ml-kem changes the CT size"
);

// Concrete ML-KEM-768 associated types resolved through KemCore.
type EK768 = <MlKem768 as KemCore>::EncapsulationKey;
type DK768 = <MlKem768 as KemCore>::DecapsulationKey;
/// `Ciphertext<MlKem768>` = `Array<u8, U1088>` (from hybrid-array)
type CT768 = Ciphertext<MlKem768>;

/// Serialised ML-KEM-768 encapsulation key (1184 bytes, carried in ratchet headers).
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PqEk(pub [u8; PQ_EK_LEN]);

/// Serialised ML-KEM-768 ciphertext (1088 bytes, carried in ratchet headers).
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PqCt(pub [u8; PQ_CT_LEN]);

/// ML-KEM epoch state for one party in a hybrid ratchet session.
///
/// Tracks the current keypair and any outgoing CT waiting to be delivered.
/// PQ shared-secrets are consumed immediately inside DHRatchet and never persist here.
pub struct SckaState {
    /// ML-KEM private key for the current epoch  --  used to decapsulate the
    /// peer's CT (their response to our announced EK).
    our_dk: DK768,

    /// Pre-serialised copy of our current EK, ready for insertion into headers.
    our_ek: PqEk,

    /// CT to include in the next outgoing header (our encapsulation response to
    /// the peer's most recently received EK).  `None` until the peer sends an EK.
    pending_ct: Option<PqCt>,
}

impl Drop for SckaState {
    fn drop(&mut self) {
        self.our_ek.0.zeroize();
    }
}

impl SckaState {
    /// Generate a fresh ML-KEM-768 keypair and return the initial SCKA state.
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let (dk, ek) = MlKem768::generate(rng);
        Self {
            our_ek: PqEk(ek_to_bytes(&ek)),
            our_dk: dk,
            pending_ct: None,
        }
    }

    /// Encapsulate to the peer's EK received in an incoming header.
    ///
    /// Returns `(pq_shared_secret, ciphertext)`.  The caller mixes the shared-secret
    /// into the root KDF for the sending chain step, and stores the CT for the next
    /// outgoing header.
    pub fn encap_to(
        &self,
        peer_ek: &PqEk,
        rng: &mut impl CryptoRngCore,
    ) -> Result<([u8; PQ_SS_LEN], PqCt), RatchetError> {
        // ek_from_bytes accepts any correctly-sized slice; InvalidPqEk is unreachable
        // with current ml-kem but retained for forward-compatibility.
        let ek = ek_from_bytes(&peer_ek.0).ok_or(RatchetError::InvalidPqEk)?;

        let (ct, ss) = ek.encapsulate(rng).map_err(|_| RatchetError::EncapFailed)?;

        let mut ct_bytes = [0u8; PQ_CT_LEN];
        ct_bytes.copy_from_slice(ct.as_slice());

        let mut ss_bytes = [0u8; PQ_SS_LEN];
        ss_bytes.copy_from_slice(ss.as_slice());

        Ok((ss_bytes, PqCt(ct_bytes)))
    }

    /// Decapsulate a CT received in an incoming header.
    ///
    /// Returns the PQ shared-secret for the receiving chain root-KDF step.
    pub fn decap(&self, peer_ct: &PqCt) -> Result<[u8; PQ_SS_LEN], RatchetError> {
        let ct = ct_from_bytes(&peer_ct.0).ok_or(RatchetError::InvalidPqCt)?;

        let ss = self
            .our_dk
            .decapsulate(&ct)
            .map_err(|_| RatchetError::DecapFailed)?;

        let mut ss_bytes = [0u8; PQ_SS_LEN];
        ss_bytes.copy_from_slice(ss.as_slice());
        Ok(ss_bytes)
    }

    /// Return a reference to the current EK (serialised) for insertion into outgoing headers.
    ///
    /// Returns a reference to avoid copying the 1184-byte key on every call.
    /// Clone the result when an owned [`PqEk`] is needed.
    pub fn our_ek(&self) -> &PqEk {
        &self.our_ek
    }

    /// Serialize the decapsulation key for state persistence.
    pub(crate) fn dk_bytes(&self) -> [u8; PQ_DK_LEN] {
        let encoded = self.our_dk.as_bytes();
        let mut buf = [0u8; PQ_DK_LEN];
        buf.copy_from_slice(encoded.as_slice());
        buf
    }

    /// Reference to the raw EK bytes for state persistence.
    pub(crate) fn ek_bytes_raw(&self) -> &[u8; PQ_EK_LEN] {
        &self.our_ek.0
    }

    /// Reference to any pending CT for state persistence.
    pub(crate) fn pending_ct_ref(&self) -> Option<&PqCt> {
        self.pending_ct.as_ref()
    }

    /// Restore SCKA state from serialized parts.  Returns `None` if the DK bytes
    /// are invalid (wrong length or malformed ML-KEM encoding).
    pub(crate) fn from_parts(
        dk_bytes: &[u8; PQ_DK_LEN],
        ek_bytes: [u8; PQ_EK_LEN],
        pending_ct: Option<PqCt>,
    ) -> Option<Self> {
        let arr = Encoded::<DK768>::try_from(dk_bytes.as_slice()).ok()?;
        let dk = DK768::from_bytes(&arr);
        Some(Self {
            our_dk: dk,
            our_ek: PqEk(ek_bytes),
            pending_ct,
        })
    }

    /// Store the CT that should be included in the next outgoing header.
    pub fn set_pending_ct(&mut self, ct: PqCt) {
        self.pending_ct = Some(ct);
    }

}

// ── byte-level conversion helpers ─────────────────────────────────────────────

/// Serialise an EK to a fixed-size byte array via [`EncodedSizeUser::as_bytes`].
fn ek_to_bytes(ek: &EK768) -> [u8; PQ_EK_LEN] {
    let encoded = ek.as_bytes(); // Encoded<EK768> = Array<u8, EncapsulationKeySize>
    let mut buf = [0u8; PQ_EK_LEN];
    buf.copy_from_slice(encoded.as_slice()); // Array<T,U>::as_slice()
    buf
}

/// Deserialise an EK from a fixed-size byte array via [`EncodedSizeUser::from_bytes`].
fn ek_from_bytes(bytes: &[u8; PQ_EK_LEN]) -> Option<EK768> {
    // Array<T, U>: TryFrom<&[T]>  --  verifies length at runtime.
    let arr = Encoded::<EK768>::try_from(bytes.as_slice()).ok()?;
    Some(EK768::from_bytes(&arr))
}

/// Deserialise a ciphertext. CT768 = Array<u8, U1088>, which is TryFrom<&[u8]>.
fn ct_from_bytes(bytes: &[u8; PQ_CT_LEN]) -> Option<CT768> {
    CT768::try_from(bytes.as_slice()).ok()
}
