use thiserror::Error;

/// Errors returned by the hybrid Double Ratchet state machine.
#[derive(Debug, Error)]
pub enum RatchetError {
    /// Returned by `ratchet_encrypt` if the ML-KEM encapsulation step fails.  Not
    /// reachable with the current RustCrypto `ml-kem` crate  --  kept for
    /// forward-compatibility with ML-KEM implementations that may add key validation.
    #[error("ML-KEM encapsulation failed")]
    EncapFailed,

    /// Returned if ML-KEM decapsulation produces an error.  Not reachable in practice
    /// because ML-KEM uses *implicit rejection*: decapsulation of a forged or invalid
    /// ciphertext silently returns a pseudorandom shared secret rather than an error.
    #[error("ML-KEM decapsulation failed  --  ciphertext may be forged or corrupted")]
    DecapFailed,

    /// Returned by `ratchet_encrypt` if the peer's encapsulation key bytes fail
    /// structural validation.  Not reachable in the current `ml-kem` crate (any
    /// 1184-byte slice is accepted); reserved for future ML-KEM validation.
    #[error("Header contains invalid ML-KEM encapsulation key")]
    InvalidPqEk,

    /// Returned if the ML-KEM ciphertext bytes fail structural validation during
    /// decapsulation.  As with `InvalidPqEk`, not reachable in the current `ml-kem`
    /// crate  --  reserved for future ML-KEM validation.
    #[error("Header contains invalid ML-KEM ciphertext")]
    InvalidPqCt,

    /// Skipped message key cache is full; too many undelivered messages are in flight.
    #[error(
        "Skipped message key cache full ({0} entries)  --  too many undelivered messages in flight"
    )]
    TooManySkipped(usize),

    /// The requested message key was not found  --  message is too old or was already decrypted.
    #[error("Message key not found  --  message is too old or was already decrypted")]
    MessageKeyNotFound,

    /// The sending chain has not been initialised; the receiver must wait for the first sender message.
    #[error("Sending chain not initialised  --  receiver must wait for first sender message")]
    NoSendingChain,

    /// The receiving chain has not been initialised; no message has been received yet.
    #[error("Receiving chain not initialised  --  no message has been received yet")]
    NoReceivingChain,

    /// The wire-encoded message header could not be parsed.
    #[error("Malformed header: {0}")]
    MalformedHeader(&'static str),

    /// The serialized session state could not be decoded.
    #[error("Malformed session state: {0}")]
    MalformedState(&'static str),
}
