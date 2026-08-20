//! Долгосрочная identity узла.
//!
//! Master-ID = SHA-256(Ed25519 pubkey) — фиксировано архитектурой Skhoron
//! по всей экосистеме (VPN, Mesh, Wire). Здесь только структура,
//! без логики bootstrap/discovery — это уровень `net`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::crypto;

pub struct Identity {
    signing_key: SigningKey,
}

/// 32-байтовый Master-ID узла.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MasterId([u8; 32]);

impl MasterId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

impl Identity {
    /// Генерация новой identity. Приватный ключ никогда не должен
    /// сериализоваться в plaintext hex — см. известный баг в
    /// SmnOneTapConnect.kt, который эта структура призвана исключить
    /// на уровне типов (SigningKey не Display/Debug-печатается как raw bytes).
    pub fn generate() -> Self {
        Self {
            signing_key: crypto::ed25519_generate(),
        }
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn master_id(&self) -> MasterId {
        Self::master_id_from_pubkey(&self.public_key())
    }

    pub fn master_id_from_pubkey(pubkey: &VerifyingKey) -> MasterId {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        MasterId(out)
    }

    /// Доступ к signing key только для передачи в crypto::ed25519_sign —
    /// не выставляется наружу как raw bytes.
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}