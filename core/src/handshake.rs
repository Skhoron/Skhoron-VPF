//! Минимальный handshake для установки защищённого канала.
//!
//! Модель: обе стороны уже знают long-term Ed25519 pubkey друг друга
//! (TOFU / получено через DHT — соответствует identity-модели Skhoron).
//! Каждая сторона генерирует эфемерный X25519 ключ, подписывает его
//! своим долгосрочным Ed25519 ключом, отправляет пару (ephemeral_pubkey,
//! signature, identity_pubkey). Обе стороны проверяют подпись, считают
//! общий секрет через ECDH, из него через HKDF получают два разнонаправленных
//! ключа (tx/rx), чтобы не переиспользовать один ключ на приём и отправку.
//!
//! Что здесь НЕТ (сознательно, это уровень выше/форк):
//! - защита от MITM на этапе первого знакомства (если pubkey узнан
//!   не через доверенный канал — это не решается здесь)
//! - sliding-window anti-replay (здесь простой monotonic counter, см. session.rs)
//! - согласование протокольных версий/фич (только VBF_VERSION в TLV)

use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::crypto::{self, hkdf_derive, SymmetricKey};
use crate::error::VbfError;
use crate::identity::Identity;

pub const HANDSHAKE_MSG_LEN: usize = 32 + 32 + 64; // ephemeral_pubkey + identity_pubkey + signature

/// Сообщение, которым обмениваются стороны на старте.
/// Кладётся в payload Frame::Handshake без дополнительной обёртки.
pub struct HandshakeMessage {
    pub ephemeral_pubkey: [u8; 32],
    pub identity_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

impl HandshakeMessage {
    pub fn encode(&self) -> [u8; HANDSHAKE_MSG_LEN] {
        let mut out = [0u8; HANDSHAKE_MSG_LEN];
        out[0..32].copy_from_slice(&self.ephemeral_pubkey);
        out[32..64].copy_from_slice(&self.identity_pubkey);
        out[64..128].copy_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VbfError> {
        if bytes.len() != HANDSHAKE_MSG_LEN {
            return Err(VbfError::MalformedFrame("bad handshake message length"));
        }
        let mut ephemeral_pubkey = [0u8; 32];
        let mut identity_pubkey = [0u8; 32];
        let mut signature = [0u8; 64];
        ephemeral_pubkey.copy_from_slice(&bytes[0..32]);
        identity_pubkey.copy_from_slice(&bytes[32..64]);
        signature.copy_from_slice(&bytes[64..128]);
        Ok(Self {
            ephemeral_pubkey,
            identity_pubkey,
            signature,
        })
    }
}

/// Промежуточное состояние — держит эфемерный секрет между отправкой
/// своего сообщения и получением сообщения от собеседника.
pub struct HandshakeState {
    ephemeral_secret: EphemeralSecret,
    local_identity_pubkey: [u8; 32],
}

/// Итог успешного handshake — ключи для приёма/отправки, готовые
/// передаваться в Session (session.rs).
pub struct SessionKeys {
    pub tx: SymmetricKey,
    pub rx: SymmetricKey,
}

/// Шаг 1: сгенерировать своё сообщение. Вызывается на обеих сторонах
/// одинаково — протокол симметричный, ролей "initiator/responder" нет.
pub fn start(identity: &Identity) -> (HandshakeState, HandshakeMessage) {
    let (ephemeral_secret, ephemeral_public) = crypto::x25519_generate_ephemeral();
    let signature = crypto::ed25519_sign(identity.signing_key(), ephemeral_public.as_bytes());

    let msg = HandshakeMessage {
        ephemeral_pubkey: *ephemeral_public.as_bytes(),
        identity_pubkey: *identity.public_key().as_bytes(),
        signature: signature.to_bytes(),
    };

    let state = HandshakeState {
        ephemeral_secret,
        local_identity_pubkey: *identity.public_key().as_bytes(),
    };

    (state, msg)
}

/// Шаг 2: получив сообщение собеседника, проверить подпись и завершить
/// вычисление общих ключей. Требует ожидаемый (уже известный) pubkey
/// собеседника — сверяется явно, чтобы не подставили чужую identity.
pub fn finish(
    state: HandshakeState,
    peer_msg: &HandshakeMessage,
    expected_peer_pubkey: &VerifyingKey,
) -> Result<SessionKeys, VbfError> {
    if peer_msg.identity_pubkey != *expected_peer_pubkey.as_bytes() {
        return Err(VbfError::InvalidSignature);
    }

    let peer_verifying_key = *expected_peer_pubkey;
    let signature = Signature::from_bytes(&peer_msg.signature);
    crypto::ed25519_verify(&peer_verifying_key, &peer_msg.ephemeral_pubkey, &signature)?;

    let peer_ephemeral_pubkey = X25519PublicKey::from(peer_msg.ephemeral_pubkey);
    let shared_secret = state.ephemeral_secret.diffie_hellman(&peer_ephemeral_pubkey);

    // Детерминированный порядок для обеих сторон: сортируем identity pubkey
    // лексикографически, чтобы оба участника согласовали, какой ключ куда.
    let (salt_a, salt_b) = if state.local_identity_pubkey < peer_msg.identity_pubkey {
        (state.local_identity_pubkey, peer_msg.identity_pubkey)
    } else {
        (peer_msg.identity_pubkey, state.local_identity_pubkey)
    };
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&salt_a);
    salt.extend_from_slice(&salt_b);

    let key_a_to_b = hkdf_derive(
        shared_secret.as_bytes(),
        Some(&salt),
        b"skhoron-vbf-a2b",
        32,
    )?;
    let key_b_to_a = hkdf_derive(
        shared_secret.as_bytes(),
        Some(&salt),
        b"skhoron-vbf-b2a",
        32,
    )?;

    let mut a2b = [0u8; 32];
    let mut b2a = [0u8; 32];
    a2b.copy_from_slice(&key_a_to_b);
    b2a.copy_from_slice(&key_b_to_a);

    // "A" — тот, чей identity pubkey меньше. Локальная сторона решает,
    // какой из двух ключей — tx, какой — rx, в зависимости от того,
    // является ли она сама "A" или "B".
    let (tx, rx) = if state.local_identity_pubkey == salt_a {
        (a2b, b2a)
    } else {
        (b2a, a2b)
    };

    Ok(SessionKeys {
        tx: SymmetricKey::from_bytes(tx),
        rx: SymmetricKey::from_bytes(rx),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip_produces_matching_cross_keys() {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();

        let (state_a, msg_a) = start(&identity_a);
        let (state_b, msg_b) = start(&identity_b);

        let keys_a = finish(state_a, &msg_b, &identity_b.public_key()).unwrap();
        let keys_b = finish(state_b, &msg_a, &identity_a.public_key()).unwrap();

        // То, что A отправляет (tx), B должен получать тем же ключом (rx), и наоборот.
        assert_eq!(keys_a.tx.as_bytes(), keys_b.rx.as_bytes());
        assert_eq!(keys_b.tx.as_bytes(), keys_a.rx.as_bytes());
    }

    #[test]
    fn handshake_rejects_wrong_expected_pubkey() {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let identity_mallory = Identity::generate();

        let (state_a, _msg_a) = start(&identity_a);
        let (_state_b, msg_b) = start(&identity_b);

        // Ожидаем pubkey Mallory, а пришло сообщение от B — должно упасть.
        let result = finish(state_a, &msg_b, &identity_mallory.public_key());
        assert!(result.is_err());
    }
}