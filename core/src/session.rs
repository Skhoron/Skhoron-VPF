//! Сессия защищённого канала — то, что остаётся после успешного handshake.
//!
//! Простой monotonic-counter вместо nonce (не sliding window) — этого
//! достаточно для Base-tier поверх TCP (порядок и доставка гарантированы
//! транспортом). Sliding window anti-replay под UDP/QUIC — задача форка,
//! не этой базы.

use crate::crypto::{aead_decrypt, aead_encrypt, SymmetricKey, NONCE_LEN};
use crate::error::VbfError;
use crate::framing::{Frame, FrameType};

const COUNTER_LEN: usize = 8;

pub struct Session {
    tx_key: SymmetricKey,
    rx_key: SymmetricKey,
    tx_counter: u64,
    rx_counter: u64,
}

impl Session {
    pub fn new(tx_key: SymmetricKey, rx_key: SymmetricKey) -> Self {
        Self {
            tx_key,
            rx_key,
            tx_counter: 0,
            rx_counter: 0,
        }
    }

    /// Шифрует plaintext и заворачивает в Frame, готовый к отправке.
    /// Счётчик кладётся явным префиксом в payload — получатель не должен
    /// угадывать nonce, только проверять, что счётчик ожидаемый.
    pub fn encrypt_frame(&mut self, plaintext: &[u8]) -> Result<Frame, VbfError> {
        let nonce = counter_to_nonce(self.tx_counter);
        let ciphertext = aead_encrypt(&self.tx_key, &nonce, plaintext, &[])?;

        let mut payload = Vec::with_capacity(COUNTER_LEN + ciphertext.len());
        payload.extend_from_slice(&self.tx_counter.to_be_bytes());
        payload.extend_from_slice(&ciphertext);

        self.tx_counter = self
            .tx_counter
            .checked_add(1)
            .ok_or(VbfError::EncryptionFailed)?; // счётчик исчерпан — сессию нужно пересоздать (ротация ключей выше по стеку)

        Ok(Frame::new(FrameType::Data, payload))
    }

    /// Расшифровывает Frame::Data. Отклоняет кадр, если счётчик не совпадает
    /// с ожидаемым — это и есть anti-replay на уровне базы: строгий порядок,
    /// без окна допуска.
    pub fn decrypt_frame(&mut self, frame: &Frame) -> Result<Vec<u8>, VbfError> {
        if frame.frame_type != FrameType::Data {
            return Err(VbfError::MalformedFrame("expected Data frame"));
        }
        if frame.payload.len() < COUNTER_LEN {
            return Err(VbfError::MalformedFrame("payload shorter than counter"));
        }

        let mut counter_bytes = [0u8; COUNTER_LEN];
        counter_bytes.copy_from_slice(&frame.payload[0..COUNTER_LEN]);
        let counter = u64::from_be_bytes(counter_bytes);

        if counter != self.rx_counter {
            return Err(VbfError::MalformedFrame(
                "unexpected counter — out of order or replayed frame",
            ));
        }

        let nonce = counter_to_nonce(counter);
        let plaintext = aead_decrypt(&self.rx_key, &nonce, &frame.payload[COUNTER_LEN..], &[])?;

        self.rx_counter = self
            .rx_counter
            .checked_add(1)
            .ok_or(VbfError::DecryptionFailed)?;

        Ok(plaintext)
    }
}

fn counter_to_nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[NONCE_LEN - COUNTER_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{finish, start};
    use crate::identity::Identity;

    #[test]
    fn session_roundtrip_after_handshake() {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();

        let (state_a, msg_a) = start(&identity_a);
        let (state_b, msg_b) = start(&identity_b);

        let keys_a = finish(state_a, &msg_b, &identity_b.public_key()).unwrap();
        let keys_b = finish(state_b, &msg_a, &identity_a.public_key()).unwrap();

        let mut session_a = Session::new(keys_a.tx, keys_a.rx);
        let mut session_b = Session::new(keys_b.tx, keys_b.rx);

        let frame = session_a.encrypt_frame(b"hello from A").unwrap();
        let plaintext = session_b.decrypt_frame(&frame).unwrap();
        assert_eq!(plaintext, b"hello from A");

        // Обратное направление тем же механизмом
        let frame2 = session_b.encrypt_frame(b"hello from B").unwrap();
        let plaintext2 = session_a.decrypt_frame(&frame2).unwrap();
        assert_eq!(plaintext2, b"hello from B");
    }

    #[test]
    fn rejects_replayed_frame() {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();

        let (state_a, msg_a) = start(&identity_a);
        let (state_b, msg_b) = start(&identity_b);

        let keys_a = finish(state_a, &msg_b, &identity_b.public_key()).unwrap();
        let keys_b = finish(state_b, &msg_a, &identity_a.public_key()).unwrap();

        let mut session_a = Session::new(keys_a.tx, keys_a.rx);
        let mut session_b = Session::new(keys_b.tx, keys_b.rx);

        let frame = session_a.encrypt_frame(b"once").unwrap();
        session_b.decrypt_frame(&frame).unwrap();
        // Повторная отправка того же кадра — счётчик у получателя уже сдвинулся
        assert!(session_b.decrypt_frame(&frame).is_err());
    }
}