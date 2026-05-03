//! Hybrid Double Ratchet state machine.
//!
//! Extends the Signal Double Ratchet algorithm with ML-KEM-768 post-quantum
//! ratcheting through the SCKA epoch model. Two root-KDF invocations per step:
//!
//! Receiving chain: `KDF_RK(rk, DH(old_dh, their_dh) || decap(their_ct))`
//! Sending chain:   `KDF_RK(rk, DH(new_dh, their_dh) || encap(their_ek).ss)`
//!
//! Attackers have to break X25519 AND ML-KEM-768. If one falls, the other
//! still provides full security.

use std::collections::HashMap;
use std::fmt;

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    error::RatchetError,
    kdf::{kdf_ck, kdf_rk},
    scka::{PqCt, PqEk, SckaState, PQ_CT_LEN, PQ_DK_LEN, PQ_EK_LEN, PQ_SS_LEN},
};

/// Maximum skipped messages in a single chain step. Signal's recommended value.
/// Raise it if your transport layer reorders deeper than 1,000 messages.
pub const MAX_SKIP: usize = 1_000;

/// Hard cap on the total number of entries in the skipped-key cache across all
/// DH epochs.  Without this, a malicious peer can force unbounded memory growth
/// by ratcheting through many epochs each with skipped messages.
pub const MAX_SKIP_TOTAL: usize = 2_000;

// ── Public types ──────────────────────────────────────────────────────────────

/// Per-message header transmitted alongside each ciphertext.
///
/// Callers are responsible for authenticating this header (e.g. AEAD additional
/// data)  --  this crate derives keys only, it does not encrypt.
///
/// Fields are not publicly settable to prevent construction of invalid headers.
/// Use [`Header::new`] to create a header, or read fields through the accessor
/// methods after receiving one from [`HybridRatchet::ratchet_encrypt`].
#[derive(Clone, Debug)]
pub struct Header {
    /// Sender's current X25519 DH ratchet public key.
    pub(crate) dh_pk: [u8; 32],
    /// Index of this message within the current sending chain.
    pub(crate) n: u32,
    /// Length of the *previous* sending chain (needed to skip stale messages).
    pub(crate) pn: u32,
    /// Sender's current ML-KEM-768 encapsulation key.
    /// Receiver encapsulates to this and returns a ciphertext in their next header.
    pub(crate) pq_ek: Option<PqEk>,
    /// ML-KEM-768 ciphertext  --  the sender's encapsulation response to the receiver's
    /// most recently seen EK.  Receiver decapsulates to obtain the PQ shared-secret.
    pub(crate) pq_ct: Option<PqCt>,
}

/// Single-use message key derived from the symmetric ratchet chain.
///
/// Use this to key an AEAD cipher (e.g. ChaCha20-Poly1305).  Zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

impl MessageKey {
    /// Return the raw 32-byte message key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MessageKey").field(&"[REDACTED]").finish()
    }
}

// ── Header constructors and accessors ────────────────────────────────────────

impl Header {
    /// Construct a [`Header`] with the given fields.
    pub fn new(
        dh_pk: [u8; 32],
        n: u32,
        pn: u32,
        pq_ek: Option<PqEk>,
        pq_ct: Option<PqCt>,
    ) -> Self {
        Self {
            dh_pk,
            n,
            pn,
            pq_ek,
            pq_ct,
        }
    }

    /// Sender's current X25519 DH ratchet public key.
    pub fn dh_pk(&self) -> [u8; 32] {
        self.dh_pk
    }

    /// Index of this message within the current sending chain.
    pub fn n(&self) -> u32 {
        self.n
    }

    /// Length of the previous sending chain.
    pub fn pn(&self) -> u32 {
        self.pn
    }

    /// Sender's current ML-KEM-768 encapsulation key, if present.
    pub fn pq_ek(&self) -> Option<&PqEk> {
        self.pq_ek.as_ref()
    }

    /// ML-KEM-768 ciphertext response to receiver's EK, if present.
    pub fn pq_ct(&self) -> Option<&PqCt> {
        self.pq_ct.as_ref()
    }
}

// ── Header wire encoding ──────────────────────────────────────────────────────

impl Header {
    /// Encode to a canonical byte string for use as AEAD additional data.
    ///
    /// Format (all integers little-endian):
    /// ```text
    /// dh_pk (32) | n (4) | pn (4) | flags (1) | [pq_ek (1184)] | [pq_ct (1088)]
    /// ```
    /// `flags` bit 0 = EK present; bit 1 = CT present.
    ///
    /// Allocates a new `Vec`.  Use [`write_to`](Self::write_to) to append into
    /// a reusable buffer instead.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            41 + self.pq_ek.as_ref().map_or(0, |_| PQ_EK_LEN)
                + self.pq_ct.as_ref().map_or(0, |_| PQ_CT_LEN),
        );
        self.write_to(&mut buf);
        buf
    }

    /// Append the canonical encoding to an existing buffer.
    ///
    /// Prefer this over [`encode`](Self::encode) when the caller already has a
    /// pre-allocated `Vec` (e.g. a per-connection AEAD header buffer) to avoid
    /// a per-message allocation.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        let flags: u8 = (self.pq_ek.is_some() as u8) | ((self.pq_ct.is_some() as u8) << 1);
        buf.extend_from_slice(&self.dh_pk);
        buf.extend_from_slice(&self.n.to_le_bytes());
        buf.extend_from_slice(&self.pn.to_le_bytes());
        buf.push(flags);
        if let Some(ek) = &self.pq_ek {
            buf.extend_from_slice(&ek.0);
        }
        if let Some(ct) = &self.pq_ct {
            buf.extend_from_slice(&ct.0);
        }
    }

    /// Decode from the canonical byte representation produced by [`Header::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetError> {
        const MIN: usize = 41; // dh_pk(32) + n(4) + pn(4) + flags(1)
        if bytes.len() < MIN {
            return Err(RatchetError::MalformedHeader("too short"));
        }
        // Slices are guaranteed to be the right length by the MIN check above.
        let dh_pk: [u8; 32] = bytes[..32].try_into().expect("32-byte slice after MIN check");
        let n = u32::from_le_bytes(bytes[32..36].try_into().expect("4-byte slice after MIN check"));
        let pn = u32::from_le_bytes(bytes[36..40].try_into().expect("4-byte slice after MIN check"));
        let flags = bytes[40];
        if flags & !0x03 != 0 {
            return Err(RatchetError::MalformedHeader("unknown flags"));
        }
        let has_ek = flags & 0x01 != 0;
        let has_ct = flags & 0x02 != 0;

        let mut pos = MIN;
        let pq_ek = if has_ek {
            let end = pos + PQ_EK_LEN;
            if bytes.len() < end {
                return Err(RatchetError::MalformedHeader("truncated EK"));
            }
            let ek: [u8; PQ_EK_LEN] = bytes[pos..end].try_into().expect("slice length guaranteed by bounds check");
            pos = end;
            Some(PqEk(ek))
        } else {
            None
        };
        let pq_ct = if has_ct {
            let end = pos + PQ_CT_LEN;
            if bytes.len() < end {
                return Err(RatchetError::MalformedHeader("truncated CT"));
            }
            let ct: [u8; PQ_CT_LEN] = bytes[pos..end].try_into().expect("slice length guaranteed by bounds check");
            pos = end;
            Some(PqCt(ct))
        } else {
            None
        };
        if pos != bytes.len() {
            return Err(RatchetError::MalformedHeader("trailing bytes"));
        }
        Ok(Header {
            dh_pk,
            n,
            pn,
            pq_ek,
            pq_ct,
        })
    }
}

// ── State ─────────────────────────────────────────────────────────────────────

/// Hybrid Double Ratchet session state.
///
/// Holds all key material for one end of a conversation.  Zeroes all secret
/// fields on drop via [`ZeroizeOnDrop`] and manual [`Drop`].
pub struct HybridRatchet {
    // ── DH ratchet ───────────────────────────────────────────────────────────
    dh_sk: StaticSecret,            // our current DH private key
    dh_pk: PublicKey,               // our current DH public key
    dh_pk_remote: Option<[u8; 32]>, // peer's latest DH public key; None until first recv

    // ── Root & chain keys ────────────────────────────────────────────────────
    rk: [u8; 32],          // root key, mixed at each DH ratchet step
    cks: Option<[u8; 32]>, // sending chain key  (None for receiver before first decrypt)
    ckr: Option<[u8; 32]>, // receiving chain key (None for sender before first decrypt)

    // ── Message counters ─────────────────────────────────────────────────────
    ns: u32, // messages sent in current sending chain
    nr: u32, // messages received in current receiving chain
    pn: u32, // length of *previous* sending chain

    // ── Out-of-order cache ───────────────────────────────────────────────────
    /// (remote_dh_pk, message_index) → message_key
    ///
    /// Values are wrapped in `Zeroizing` so they are explicitly zeroed when
    /// removed or when the map is dropped.  The map is pre-allocated at
    /// `MAX_SKIP_TOTAL` capacity on construction so it never reallocates  -- 
    /// preventing freed backing memory from retaining plaintext key material.
    skipped: HashMap<([u8; 32], u32), Zeroizing<[u8; 32]>>,

    // ── Post-quantum state ───────────────────────────────────────────────────
    scka: SckaState,
}

impl Drop for HybridRatchet {
    fn drop(&mut self) {
        self.rk.zeroize();
        if let Some(ref mut k) = self.cks {
            k.zeroize();
        }
        if let Some(ref mut k) = self.ckr {
            k.zeroize();
        }
        // Zeroizing<[u8;32]> values already zero themselves on drop, but
        // explicitly zeroing here clears the memory before the HashMap
        // allocator reclaims it.
        for v in self.skipped.values_mut() {
            v.zeroize();
        }
    }
}

// ── Constructors ──────────────────────────────────────────────────────────────

impl HybridRatchet {
    /// Initialise as the **sending** party (e.g. Alice in Signal X3DH).
    ///
    /// Performs an immediate DH ratchet step against `peer_dh_pk`, deriving the
    /// initial sending chain key.  The result can call `ratchet_encrypt` immediately.
    ///
    /// # Arguments
    /// * `shared_secret`  --  32-byte pre-shared secret from the key agreement phase
    ///   (e.g. the output of PQXDH or X3DH).
    /// * `peer_dh_pk`     --  peer's X25519 ratchet public key (from their prekey bundle).
    pub fn init_sender(
        shared_secret: &[u8; 32],
        peer_dh_pk: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let dh_sk = StaticSecret::random_from_rng(&mut *rng);
        let dh_pk = PublicKey::from(&dh_sk);
        let peer_pk = PublicKey::from(*peer_dh_pk);

        let dh_ss = dh_sk.diffie_hellman(&peer_pk);
        // No PQ exchange has occurred yet; contribute zero bytes for this first step.
        let (rk, cks) = kdf_rk(shared_secret, dh_ss.as_bytes(), &[0u8; PQ_SS_LEN]);

        let scka = SckaState::new(rng);

        Self {
            dh_sk,
            dh_pk,
            dh_pk_remote: Some(*peer_dh_pk),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::with_capacity(MAX_SKIP_TOTAL),
            scka,
        }
    }

    /// Initialise as the **receiving** party (e.g. Bob in Signal X3DH).
    ///
    /// Does not perform a DH ratchet step yet; call `ratchet_decrypt` on the first
    /// incoming message to derive both the receiving and sending chain keys.
    ///
    /// # Arguments
    /// * `shared_secret`  --  32-byte pre-shared secret (same as sender's).
    /// * `our_dh_sk`      --  our X25519 ratchet secret key (the one whose public key
    ///   was shared with the sender in the prekey bundle).
    pub fn init_receiver(
        shared_secret: &[u8; 32],
        our_dh_sk: StaticSecret,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let dh_pk = PublicKey::from(&our_dh_sk);
        let scka = SckaState::new(rng);

        Self {
            dh_sk: our_dh_sk,
            dh_pk,
            dh_pk_remote: None,
            rk: *shared_secret,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::with_capacity(MAX_SKIP_TOTAL),
            scka,
        }
    }

    /// Return our current X25519 DH public key (for sharing in a prekey bundle).
    ///
    /// Returns raw bytes.  X25519 public keys are conventionally exchanged as
    /// byte arrays; use [`x25519_dalek::PublicKey::from`] to convert if needed.
    /// The PQ equivalent, [`our_pq_ek`](Self::our_pq_ek), returns a typed
    /// [`PqEk`] wrapper instead  --  the difference is intentional since ML-KEM
    /// keys are less commonly manipulated as raw bytes.
    pub fn our_dh_pk(&self) -> [u8; 32] {
        *self.dh_pk.as_bytes()
    }

    /// Return our current ML-KEM-768 encapsulation key (for sharing in a prekey bundle).
    ///
    /// Returns a typed [`PqEk`] wrapper around the 1184-byte encoding.
    pub fn our_pq_ek(&self) -> PqEk {
        self.scka.our_ek().clone()
    }
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

impl HybridRatchet {
    /// Advance the sending chain and return a `(Header, MessageKey)` pair.
    ///
    /// The message key is derived from the current sending chain key.  Use it to
    /// AEAD-encrypt the plaintext, then transmit `header` alongside the ciphertext.
    ///
    /// The `rng` parameter is reserved for future protocol extensions and is not
    /// consumed by this call.  Any [`CryptoRngCore`] implementor is accepted.
    ///
    /// **PQ ciphertext retransmission**: if a pending ML-KEM ciphertext exists (set
    /// during the last DH ratchet step), it is included in every outgoing header
    /// until the peer's next DH ratchet step replaces it.  This ensures the PQ
    /// shared-secret is established even if the first message carrying the CT is
    /// lost in transit.  A caller MUST NOT assume the CT was received until the
    /// peer's subsequent DH ratchet is observed.
    ///
    /// # Errors
    /// Returns [`RatchetError::NoSendingChain`] if the sending chain has not been
    /// initialised yet (receiver must call `ratchet_decrypt` at least once first).
    pub fn ratchet_encrypt(
        &mut self,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Header, MessageKey), RatchetError> {
        let cks = self.cks.as_mut().ok_or(RatchetError::NoSendingChain)?;

        let (new_ck, mk) = kdf_ck(cks);
        *cks = new_ck;

        let n = self.ns;
        self.ns += 1;

        let header = Header {
            dh_pk: *self.dh_pk.as_bytes(),
            n,
            pn: self.pn,
            pq_ek: Some(self.scka.our_ek().clone()),
            // Peek (clone without consuming) so the CT is retransmitted in every
            // message until the peer's next DH ratchet generates a replacement.
            pq_ct: self.scka.pending_ct_ref().cloned(),
        };

        Ok((header, MessageKey(mk)))
    }

    /// Advance the receiving chain and return the `MessageKey` for this message.
    ///
    /// Handles DH ratchet steps, out-of-order delivery (caching skipped keys), and
    /// the hybrid PQ key exchange within each DH ratchet step.
    ///
    /// The `rng` parameter is only consumed when the incoming header carries a new
    /// DH public key (triggering a full DH ratchet step with ML-KEM encapsulation).
    /// For within-epoch messages  --  including cache hits from out-of-order delivery  -- 
    /// the RNG is untouched.
    ///
    /// **Implicit key confirmation**: successful AEAD decryption by the caller
    /// serves as the only confirmation that both parties derived matching keys.
    /// There is no explicit key confirmation step  --  this matches Signal's design.
    ///
    /// # Errors
    /// - [`RatchetError::TooManySkipped`] if the out-of-order cache would overflow.
    /// - [`RatchetError::MessageKeyNotFound`] if this message was already decrypted
    ///   or is older than what remains in the cache.
    /// - Crypto errors from malformed PQ material in the header.
    pub fn ratchet_decrypt(
        &mut self,
        header: &Header,
        rng: &mut impl CryptoRngCore,
    ) -> Result<MessageKey, RatchetError> {
        // 1. Fast path: this key was already cached from a previous out-of-order scan.
        if let Some(mk) = self.skipped.remove(&(header.dh_pk, header.n)) {
            return Ok(MessageKey(*mk));
        }

        // 2. Determine if the remote DH key has changed (DHRatchet trigger).
        // Constant-time comparison prevents timing side-channels on the DH key.
        // DH public keys are public, but constant-time is best practice for all
        // cryptographic material.
        let is_new_dh = match self.dh_pk_remote {
            Some(pk) => pk.ct_ne(&header.dh_pk).into(),
            None => true,
        };

        if is_new_dh {
            // Skip over any remaining messages in the current receiving chain
            // (they were sent before the peer ratcheted their DH key).
            if self.ckr.is_some() {
                self.skip_message_keys(header.pn)?;
            }
            self.dh_ratchet(header, rng)?;
        }

        // 3. Skip to the target message number within the current receiving chain.
        // Reject within-epoch replays: n < nr means the key was already consumed.
        // (dh_ratchet resets nr to 0, so this check is only relevant for same-epoch msgs.)
        if header.n < self.nr {
            return Err(RatchetError::MessageKeyNotFound);
        }
        self.skip_message_keys(header.n)?;

        // 4. Derive the message key.
        let ckr = self.ckr.as_mut().ok_or(RatchetError::NoReceivingChain)?;
        let (new_ck, mk) = kdf_ck(ckr);
        *ckr = new_ck;
        self.nr += 1;

        Ok(MessageKey(mk))
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

impl HybridRatchet {
    /// Perform a full DHRatchet step (two root-KDF invocations) upon receiving a
    /// message with a new remote DH public key.
    fn dh_ratchet(
        &mut self,
        header: &Header,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), RatchetError> {
        // ── All fallible and panicking operations  --  state is NOT modified yet ─
        // Any error or panic leaves the session completely intact.

        // PQ receiving: decapsulate the CT the peer sent for our current EK.
        let pq_recv: [u8; PQ_SS_LEN] = match &header.pq_ct {
            Some(ct) => self.scka.decap(ct)?,
            None => [0u8; PQ_SS_LEN],
        };

        // PQ sending: encapsulate to the EK announced in this header.
        let (pq_send, opt_pending_ct): ([u8; PQ_SS_LEN], Option<PqCt>) = match &header.pq_ek {
            Some(ek) => {
                let (ss, ct) = self.scka.encap_to(ek, rng)?;
                (ss, Some(ct))
            }
            None => ([0u8; PQ_SS_LEN], None),
        };

        // When the peer sends no EK, preserve any pending CT from the current
        // epoch so it is not silently dropped when we rotate the SCKA state.
        let ct_to_carry = opt_pending_ct.or_else(|| self.scka.pending_ct_ref().cloned());

        // Generate new DH keypair  --  random_from_rng is allowed to panic.
        let new_dh_sk = StaticSecret::random_from_rng(&mut *rng);
        let new_dh_pk = PublicKey::from(&new_dh_sk);

        // Rotate to a fresh ML-KEM epoch  --  MlKem768::generate is allowed to panic.
        let mut new_scka = SckaState::new(rng);
        if let Some(ct) = ct_to_carry {
            new_scka.set_pending_ct(ct);
        }

        // ── All state mutations follow; every panicking operation is complete ─
        let peer_pk = PublicKey::from(header.dh_pk);

        // Step 1: Receiving chain (old DH secret × new peer key, PQ recv secret).
        let dh_recv = self.dh_sk.diffie_hellman(&peer_pk);
        let (rk1, ckr) = kdf_rk(&self.rk, dh_recv.as_bytes(), &pq_recv);

        // Step 2: Sending chain (new DH secret × new peer key, PQ send secret).
        let dh_send = new_dh_sk.diffie_hellman(&peer_pk);
        let (rk2, cks) = kdf_rk(&rk1, dh_send.as_bytes(), &pq_send);

        // Commit atomically  --  session is fully consistent after this block.
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dh_pk_remote = Some(header.dh_pk);
        self.rk = rk2;
        self.ckr = Some(ckr);
        self.cks = Some(cks);
        self.dh_sk = new_dh_sk;
        self.dh_pk = new_dh_pk;
        self.scka = new_scka;

        Ok(())
    }

    /// Cache message keys for messages `self.nr .. until` in the current receiving
    /// chain, enforcing the `MAX_SKIP` limit.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if until < self.nr {
            return Ok(());
        }

        let to_skip = (until - self.nr) as usize;
        // Per-batch limit: prevents a single malformed header from forcing a
        // huge number of symmetric-ratchet steps in one call.
        if to_skip > MAX_SKIP {
            return Err(RatchetError::TooManySkipped(to_skip));
        }
        // Global total limit: prevents a malicious peer from exhausting memory
        // across many DH epochs each with skipped messages.
        if self.skipped.len() + to_skip > MAX_SKIP_TOTAL {
            return Err(RatchetError::TooManySkipped(self.skipped.len() + to_skip));
        }

        if let Some(ref mut ckr) = self.ckr {
            let remote_pk = self.dh_pk_remote
                .expect("dh_pk_remote is always Some when ckr is Some  --  both set in dh_ratchet");
            for i in self.nr..until {
                let (new_ck, mk) = kdf_ck(ckr);
                *ckr = new_ck;
                self.skipped.insert((remote_pk, i), Zeroizing::new(mk));
            }
            self.nr = until;
        }

        Ok(())
    }
}

// ── State serialization ───────────────────────────────────────────────────────

impl HybridRatchet {
    /// Serialize the full session state to a zeroize-on-drop byte vector.
    ///
    /// The format is a versioned binary blob (v1).  Deserialize with
    /// [`from_bytes`](Self::from_bytes).  Callers are responsible for encrypting
    /// this blob at rest  --  it contains all secret key material.
    ///
    /// Binary layout (little-endian integers):
    /// ```text
    /// version(1) | dh_sk(32) | remote_flag(1) | [dh_pk_remote(32)]
    /// | rk(32) | cks_flag(1) | [cks(32)] | ckr_flag(1) | [ckr(32)]
    /// | ns(4) | nr(4) | pn(4)
    /// | skipped_count(4) | (remote_pk(32) | idx(4) | mk(32)) * count
    /// | scka_dk(2400) | scka_ek(1184) | pct_flag(1) | [pct(1088)]
    /// ```
    ///
    /// # Forward-compatibility warning
    /// The serialized format is versioned (`v1`) but no migration path exists.
    /// If the ml-kem crate changes key encoding (e.g., NIST FIPS 203 revision)
    /// or this crate changes the binary layout, ALL persisted sessions become
    /// unrecoverable with `from_bytes` returning an error on unknown versions.
    /// Re-key all sessions before upgrading the crate.  Treat persisted blobs
    /// as opaque  --  do not rely on their internal structure across crate versions.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let n_skip = self.skipped.len();
        let mut buf: Vec<u8> = Vec::with_capacity(
            1 + 32
                + 1
                + 32
                + 32
                + 1
                + 32
                + 1
                + 32
                + 4
                + 4
                + 4
                + 4
                + n_skip * 68
                + PQ_DK_LEN
                + PQ_EK_LEN
                + 1
                + PQ_CT_LEN,
        );

        buf.push(0x01); // format version

        buf.extend_from_slice(&self.dh_sk.to_bytes());

        match self.dh_pk_remote {
            Some(pk) => {
                buf.push(1);
                buf.extend_from_slice(&pk);
            }
            None => {
                buf.push(0);
            }
        }

        buf.extend_from_slice(&self.rk);

        for opt in [self.cks, self.ckr] {
            match opt {
                Some(k) => {
                    buf.push(1);
                    buf.extend_from_slice(&k);
                }
                None => {
                    buf.push(0);
                }
            }
        }

        buf.extend_from_slice(&self.ns.to_le_bytes());
        buf.extend_from_slice(&self.nr.to_le_bytes());
        buf.extend_from_slice(&self.pn.to_le_bytes());

        buf.extend_from_slice(&(n_skip as u32).to_le_bytes());
        for ((rpk, idx), mk) in &self.skipped {
            buf.extend_from_slice(rpk);
            buf.extend_from_slice(&idx.to_le_bytes());
            buf.extend_from_slice(mk.as_ref());
        }

        buf.extend_from_slice(&self.scka.dk_bytes());
        buf.extend_from_slice(self.scka.ek_bytes_raw());
        match self.scka.pending_ct_ref() {
            Some(ct) => {
                buf.push(1);
                buf.extend_from_slice(&ct.0);
            }
            None => {
                buf.push(0);
            }
        }

        Zeroizing::new(buf)
    }

    /// Restore session state from bytes produced by [`to_bytes`](Self::to_bytes).
    ///
    /// Fails with [`RatchetError::MalformedState`] if the version tag is not
    /// `0x01` (the only currently supported format).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        let err = |msg| RatchetError::MalformedState(msg);
        let mut pos = 0usize;

        macro_rules! read {
            ($n:expr) => {{
                let end = pos + $n;
                if end > bytes.len() {
                    return Err(err("truncated"));
                }
                let slice = &bytes[pos..end];
                pos = end;
                slice
            }};
        }
        macro_rules! read_arr {
            ($n:expr) => {{
                let s = read!($n);
                let arr: [u8; $n] = s.try_into().unwrap();
                arr
            }};
        }
        macro_rules! read_u32 {
            () => {
                u32::from_le_bytes(read_arr!(4))
            };
        }
        macro_rules! read_opt {
            ($n:expr) => {{
                let flag = read_arr!(1)[0];
                match flag {
                    0 => None,
                    1 => Some(read_arr!($n)),
                    _ => return Err(err("invalid flag")),
                }
            }};
        }

        // version
        if read_arr!(1)[0] != 0x01 {
            return Err(err("unknown version"));
        }

        let dh_sk_bytes = read_arr!(32);
        let dh_pk_remote = read_opt!(32);

        let rk = read_arr!(32);
        let cks = read_opt!(32);
        let ckr = read_opt!(32);
        let ns = read_u32!();
        let nr = read_u32!();
        let pn = read_u32!();

        // Reject counter values that are dangerously close to u32::MAX.  After
        // 2^31 messages on a single chain the session must be re-keyed anyway.
        if ns > (u32::MAX / 2) || nr > (u32::MAX / 2) || pn > (u32::MAX / 2) {
            return Err(err("message counter out of safe range"));
        }

        let n_skip = read_u32!() as usize;
        if n_skip > MAX_SKIP_TOTAL {
            return Err(err("skipped cache exceeds limit"));
        }
        // Pre-allocate at the maximum to prevent reallocation (which would leave
        // unzeroed key material in freed heap memory).
        let mut skipped = HashMap::with_capacity(MAX_SKIP_TOTAL);
        for _ in 0..n_skip {
            let rpk: [u8; 32] = read_arr!(32);
            let idx = read_u32!();
            let mk = read_arr!(32);
            skipped.insert((rpk, idx), Zeroizing::new(mk));
        }

        let dk_bytes: [u8; PQ_DK_LEN] = read_arr!(PQ_DK_LEN);
        let ek_bytes: [u8; PQ_EK_LEN] = read_arr!(PQ_EK_LEN);
        let pending_ct = read_opt!(PQ_CT_LEN).map(PqCt);

        if pos != bytes.len() {
            return Err(err("trailing bytes"));
        }

        let dh_sk = StaticSecret::from(dh_sk_bytes);
        let dh_pk = PublicKey::from(&dh_sk);
        let scka = SckaState::from_parts(&dk_bytes, ek_bytes, pending_ct)
            .ok_or_else(|| err("invalid ML-KEM DK"))?;

        Ok(HybridRatchet {
            dh_sk,
            dh_pk,
            dh_pk_remote,
            rk,
            cks,
            ckr,
            ns,
            nr,
            pn,
            skipped,
            scka,
        })
    }
}

// ── Redacted Debug ────────────────────────────────────────────────────────────

impl fmt::Debug for HybridRatchet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridRatchet")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped_count", &self.skipped.len())
            .field("has_cks", &self.cks.is_some())
            .field("has_ckr", &self.ckr.is_some())
            .finish_non_exhaustive()
    }
}

// ── Optional serde support ────────────────────────────────────────────────────

/// # Binary formats only
///
/// The `Serialize` impl calls `to_bytes()` and passes the raw key material to
/// the serializer.  With text-based formats (JSON, YAML, TOML) the serializer
/// base64-encodes the bytes into a `String` that is **not** zeroed on drop  -- 
/// key material may linger in heap memory.  Only use binary serializers
/// (bincode, postcard, messagepack) and encrypt the result immediately at rest.
#[cfg(feature = "serde")]
impl serde::Serialize for HybridRatchet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for HybridRatchet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = HybridRatchet;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "pq-ratchet session state as bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<HybridRatchet, E> {
                HybridRatchet::from_bytes(v).map_err(E::custom)
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<HybridRatchet, E> {
                self.visit_bytes(&v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<HybridRatchet, A::Error> {
                let mut buf = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    buf.push(b);
                }
                self.visit_bytes(&buf)
            }
        }
        d.deserialize_bytes(Visitor)
    }
}
