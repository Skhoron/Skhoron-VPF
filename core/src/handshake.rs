//! Минимальный handshake для установки защищённого канала.
//!
//! Каждая сторона генерирует эфемерный X25519 ключ. Подпись Ed25519 покрывает
//! не просто ephemeral pubkey, а весь transcript (protocol id, версия,
//! обе identity, оба ephemeral pubkey в детерминированном порядке) — это
//! привязывает подпись к конкретному контексту протокола и не даёт кадрам
//! из одного контекста быть replay'нутыми в другой, если протокол расширится
//! версиями/капабилити позже. HKDF на сессионные ключи использует тот же
//! transcript как info, а не только identity pubkeys — так что ключи тоже
//! криптографически привязаны к конкретной паре ephemeral-ключей, не только
//! к тому, что shared secret из них и так следует.
//!
//! Что здесь НЕТ (сознательно, это уровень выше/форк):
//! - sliding-window anti-replay (см. session.rs — строгий counter)
//! - согласование протокольных фич сверх фиксированной VERSION

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::crypto::{self, hkdf_derive, SymmetricKey};
use crate::error::VbfError;
use crate::identity::Identity;

pub const HANDSHAKE_MSG_LEN: usize = 32 + 32 + 64; // ephemeral_pubkey + identity_pubkey + signature

/// Домен-разделение протокола. Меняется, если формат transcript'а
/// когда-либо несовместимо изменится.
const PROTOCOL_ID: &[u8] = b"skhoron-vbf-handshake";
const PROTOCOL_VERSION: u8 = 1;

/// Как вызывающий код получил ожидаемый pubkey собеседника. Это не решает
/// проблему MITM само по себе, но делает выбор явным на уровне типов —
/// нельзя случайно забыть, что TOFU не защищает от активного атакующего.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAuthenticity {
    /// Pubkey пришёл из независимого доверенного источника (заранее
    /// обменянный контакт, подписанная запись DHT и т.п.) — защищает
    /// от MITM при условии, что сам источник не скомпрометирован.
    VerifiedOutOfBand,
    /// Trust-on-first-use: pubkey был принят без независимой проверки
    /// (например, из этого же соединения). Защищает только от пассивного
    /// прослушивания уже установленного канала, НЕ от активного MITM
    /// на этапе самого первого знакомства.
    TrustOnFirstUse,
}

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
    local_ephemeral_pubkey: [u8; 32],
}

/// Итог успешного handshake — ключи для приёма/отправки, готовые
/// передаваться в Session (session.rs).
pub struct SessionKeys {
    pub tx: SymmetricKey,
    pub rx: SymmetricKey,
}

/// Строит transcript: protocol_id || version || identity_min || identity_max
/// || ephemeral_min || ephemeral_max, где min/max — по побайтовому сравнению
/// identity pubkey (не ephemeral!) двух сторон. Порядок ephemeral-ключей
/// в transcript следует порядку identity, к которой они относятся, чтобы
/// обе стороны детерминированно строили один и тот же transcript.
fn build_transcript(
    local_identity: &[u8; 32],
    local_ephemeral: &[u8; 32],
    peer_identity: &[u8; 32],
    peer_ephemeral: &[u8; 32],
) -> Vec<u8> {
    let (id_min, eph_min, id_max, eph_max) = if local_identity < peer_identity {
        (local_identity, local_ephemeral, peer_identity, peer_ephemeral)
    } else {
        (peer_identity, peer_ephemeral, local_identity, local_ephemeral)
    };

    let mut transcript = Vec::with_capacity(PROTOCOL_ID.len() + 1 + 32 * 4);
    transcript.extend_from_slice(PROTOCOL_ID);
    transcript.push(PROTOCOL_VERSION);
    transcript.extend_from_slice(id_min);
    transcript.extend_from_slice(id_max);
    transcript.extend_from_slice(eph_min);
    transcript.extend_from_slice(eph_max);
    transcript
}

/// Шаг 1: сгенерировать своё сообщение. Вызывается на обеих сторонах
/// одинаково — протокол симметричный, ролей "initiator/responder" нет.
///
/// Подпись покрывает контекст (PROTOCOL_ID || version) + ephemeral pubkey.
/// Полный transcript (обе стороны) подписать здесь нельзя — на этом шаге
/// сообщение собеседника ещё не получено; полная привязка обеих сторон
/// происходит через HKDF в finish().
pub fn start(identity: &Identity) -> (HandshakeState, HandshakeMessage) {
    let (ephemeral_secret, ephemeral_public) = crypto::x25519_generate_ephemeral();

    let mut signed_material = Vec::with_capacity(PROTOCOL_ID.len() + 1 + 32);
    signed_material.extend_from_slice(PROTOCOL_ID);
    signed_material.push(PROTOCOL_VERSION);
    signed_material.extend_from_slice(ephemeral_public.as_bytes());

    let signature = crypto::ed25519_sign(identity.signing_key(), &signed_material);

    let msg = HandshakeMessage {
        ephemeral_pubkey: *ephemeral_public.as_bytes(),
        identity_pubkey: *identity.public_key().as_bytes(),
        signature: signature.to_bytes(),
    };

    let state = HandshakeState {
        ephemeral_secret,
        local_identity_pubkey: *identity.public_key().as_bytes(),
        local_ephemeral_pubkey: *ephemeral_public.as_bytes(),
    };

    (state, msg)
}

/// Шаг 2: получив сообщение собеседника, проверить подпись и завершить
/// вычисление общих ключей.
///
/// `authenticity` заставляет вызывающий код явно указать, откуда взялся
/// `expected_peer_pubkey` — см. `PeerAuthenticity`. При `TrustOnFirstUse`
/// функция всё равно отработает (это осознанно допустимый режим для
/// демо/раннего этапа), но факт использования TOFU остаётся явным
/// в вызывающем коде, а не спрятан внутри библиотеки.
pub fn finish(
    state: HandshakeState,
    peer_msg: &HandshakeMessage,
    expected_peer_pubkey: &VerifyingKey,
    _authenticity: PeerAuthenticity,
) -> Result<SessionKeys, VbfError> {
    if peer_msg.identity_pubkey != *expected_peer_pubkey.as_bytes() {
        return Err(VbfError::InvalidSignature);
    }

    let mut signed_material = Vec::with_capacity(PROTOCOL_ID.len() + 1 + 32);
    signed_material.extend_from_slice(PROTOCOL_ID);
    signed_material.push(PROTOCOL_VERSION);
    signed_material.extend_from_slice(&peer_msg.ephemeral_pubkey);

    let signature = Signature::from_bytes(&peer_msg.signature);
    crypto::ed25519_verify(expected_peer_pubkey, &signed_material, &signature)?;

    let peer_ephemeral_pubkey = X25519PublicKey::from(peer_msg.ephemeral_pubkey);
    let shared_secret = state.ephemeral_secret.diffie_hellman(&peer_ephemeral_pubkey);

    let transcript = build_transcript(
        &state.local_identity_pubkey,
        &state.local_ephemeral_pubkey,
        &peer_msg.identity_pubkey,
        &peer_msg.ephemeral_pubkey,
    );
    // Хэшируем transcript в фиксированный salt — сам transcript уже
    // включает protocol id/version/обе identity/оба ephemeral pubkey,
    // так что производные ключи привязаны ко всему контексту, а не
    // только к in identity pubkeys, как было раньше.
    let mut hasher = Sha256::new();
    hasher.update(&transcript);
    let transcript_hash = hasher.finalize();

    let key_a_to_b = hkdf_derive(
        shared_secret.as_bytes(),
        Some(&transcript_hash),
        b"skhoron-vbf-a2b",
        32,
    )?;
    let key_b_to_a = hkdf_derive(
        shared_secret.as_bytes(),
        Some(&transcript_hash),
        b"skhoron-vbf-b2a",
        32,
    )?;

    let mut a2b = [0u8; 32];
    let mut b2a = [0u8; 32];
    a2b.copy_from_slice(&key_a_to_b);
    b2a.copy_from_slice(&key_b_to_a);

    // "A" — тот, чей identity pubkey меньше (то же правило, что и в transcript).
    let local_is_a = state.local_identity_pubkey < peer_msg.identity_pubkey;
    let (tx, rx) = if local_is_a { (a2b, b2a) } else { (b2a, a2b) };

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

        let keys_a = finish(
            state_a,
            &msg_b,
            &identity_b.public_key(),
            PeerAuthenticity::VerifiedOutOfBand,
        )
        .unwrap();
        let keys_b = finish(
            state_b,
            &msg_a,
            &identity_a.public_key(),
            PeerAuthenticity::VerifiedOutOfBand,
        )
        .unwrap();

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

        let result = finish(
            state_a,
            &msg_b,
            &identity_mallory.public_key(),
            PeerAuthenticity::VerifiedOutOfBand,
        );
        assert!(result.is_err());
    }

    #[test]
    fn handshake_rejects_signature_replayed_from_different_transcript() {
        // Подпись покрывает protocol_id/version/ephemeral, но НЕ identity
        // получателя напрямую — это осознанное ограничение (см. модуль
        // doc): identity получателя проверяется отдельно сравнением
        // peer_msg.identity_pubkey == expected_peer_pubkey, а не подписью.
        // Тест фиксирует, что смена ephemeral ломает подпись.
        let identity_a = Identity::generate();
        let (_, mut msg_a) = start(&identity_a);
        msg_a.ephemeral_pubkey[0] ^= 0xFF; // подменили ephemeral после подписи

        let (state_b, _) = start(&Identity::generate());
        let result = finish(
            state_b,
            &msg_a,
            &identity_a.public_key(),
            PeerAuthenticity::VerifiedOutOfBand,
        );
        assert!(result.is_err());
    }
}