//! Обёртки над аудированными крейтами (RustCrypto/dalek).
//!
//! Здесь НЕТ: генерации паролей, логики рукопожатия, установки канала.
//! Только строительные блоки — форкеры собирают протокол из них сами.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::VbfError;

pub const KEY_LEN: usize = 32; // 256 бит
pub const NONCE_LEN: usize = 24; // XChaCha20 extended nonce
pub const SALT_LEN: usize = 16;

/// Симметричный ключ. Обнуляется при drop.
#[derive(Clone)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// AEAD-шифрование. XChaCha20-Poly1305 фиксирован по всей экосистеме Skhoron —
/// не подменять на AES без пересмотра архитектуры (см. обсуждение в спеке VBF).
pub fn aead_encrypt(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VbfError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| VbfError::EncryptionFailed)?;
    let nonce = XNonce::from_slice(nonce);
    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(nonce, payload)
        .map_err(|_| VbfError::EncryptionFailed)
}

pub fn aead_decrypt(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VbfError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| VbfError::DecryptionFailed)?;
    let nonce = XNonce::from_slice(nonce);
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| VbfError::DecryptionFailed)
}

/// Генерация случайного nonce через ОС-CSPRNG.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

// ---------------------------------------------------------------------
// X25519 — эфемерный ECDH для PFS (ротация 5-10 мин / 50MB, см. архитектуру VPN)
// ---------------------------------------------------------------------

pub fn x25519_generate_ephemeral() -> (EphemeralSecret, X25519PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

pub fn x25519_generate_static() -> (StaticSecret, X25519PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

// ---------------------------------------------------------------------
// Ed25519 — долгосрочная identity (Master-ID = SHA256(pubkey))
// ---------------------------------------------------------------------

pub fn ed25519_generate() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn ed25519_sign(key: &SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
}

pub fn ed25519_verify(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), VbfError> {
    key.verify(message, signature)
        .map_err(|_| VbfError::InvalidSignature)
}

// ---------------------------------------------------------------------
// HKDF — деривация сессионных ключей из ECDH-материала (высокоэнтропийный вход)
// ---------------------------------------------------------------------

pub fn hkdf_derive(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, VbfError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).map_err(|_| VbfError::KdfFailed)?;
    Ok(okm)
}

// ---------------------------------------------------------------------
// Argon2id — только там, где в цепочке есть человеческий пароль/PIN
// (локальное хранение приватного ключа и т.п.). НЕ для сессионных ключей.
// ---------------------------------------------------------------------

pub struct Argon2Params {
    pub memory_kib: u32, // рекомендация: 19456 (19 MiB) минимум по RFC 9106
    pub iterations: u32, // 2-3
    pub parallelism: u32, // 1-2 на мобильных, выше на десктопе
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 3,
            parallelism: 1,
        }
    }
}

pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &Argon2Params,
) -> Result<SymmetricKey, VbfError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VbfError::KdfFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| VbfError::KdfFailed)?;

    Ok(SymmetricKey::from_bytes(out))
}

pub fn random_salt() -> [u8; SALT_LEN] {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}