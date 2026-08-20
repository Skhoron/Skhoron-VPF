use thiserror::Error;

#[derive(Debug, Error)]
pub enum VbfError {
    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed (auth tag mismatch or corrupted data)")]
    DecryptionFailed,

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("key derivation failed")]
    KdfFailed,

    #[error("malformed frame: {0}")]
    MalformedFrame(&'static str),

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid signature")]
    InvalidSignature,
}