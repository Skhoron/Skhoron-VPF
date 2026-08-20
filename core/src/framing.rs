//! TLV (Type-Length-Value) framing — формат пакета на проводе.
//!
//! Поле версии заложено с самого начала, чтобы Standard/Pro тиры
//! (Hysteria2 masquerading, mixnet, Noise) могли добавлять новые
//! FrameType, не ломая совместимость с Base.
//!
//! Здесь только формат кадра. Anti-replay window, handshake, генерация
//! ключей канала — уровень протокола, реализуется поверх, не здесь.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::VbfError;
use crate::VBF_VERSION;

/// Тип полезной нагрузки кадра. Форкеры добавляют свои варианты
/// в диапазоне 0x80-0xFF, не трогая зарезервированный 0x00-0x7F.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameType {
    /// Зарезервировано под будущий handshake-протокол
    Handshake = 0x01,
    /// Зашифрованные данные (payload уже AEAD-ciphertext)
    Data = 0x02,
    /// Keepalive / heartbeat
    KeepAlive = 0x03,
    /// Управляющее сообщение протокола (DHT, peer discovery и т.п.)
    Control = 0x04,
    /// Неизвестный/расширяемый тип, значение хранится отдельно
    Extension(u8),
}

impl FrameType {
    fn to_u8(self) -> u8 {
        match self {
            FrameType::Handshake => 0x01,
            FrameType::Data => 0x02,
            FrameType::KeepAlive => 0x03,
            FrameType::Control => 0x04,
            FrameType::Extension(v) => v,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0x01 => FrameType::Handshake,
            0x02 => FrameType::Data,
            0x03 => FrameType::KeepAlive,
            0x04 => FrameType::Control,
            other => FrameType::Extension(other),
        }
    }
}

/// Один TLV-кадр: version(1) | type(1) | length(4, big-endian) | value(N)
#[derive(Clone, Debug)]
pub struct Frame {
    pub version: u8,
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}

const HEADER_LEN: usize = 1 + 1 + 4; // version + type + length

impl Frame {
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Self {
        Self {
            version: VBF_VERSION,
            frame_type,
            payload,
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        buf.put_u8(self.version);
        buf.put_u8(self.frame_type.to_u8());
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);
        buf
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, VbfError> {
        if buf.remaining() < HEADER_LEN {
            return Err(VbfError::MalformedFrame("buffer shorter than header"));
        }

        let version = buf.get_u8();
        if version != VBF_VERSION {
            // Форкеры/будущие тиры решают сами, поддерживать ли
            // downgrade/upgrade — база просто сигнализирует несовпадение.
            return Err(VbfError::UnsupportedVersion(version));
        }

        let frame_type = FrameType::from_u8(buf.get_u8());
        let length = buf.get_u32() as usize;

        if buf.remaining() < length {
            return Err(VbfError::MalformedFrame("payload shorter than declared length"));
        }

        let mut payload = vec![0u8; length];
        buf.copy_to_slice(&mut payload);

        Ok(Frame {
            version,
            frame_type,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let frame = Frame::new(FrameType::Data, vec![1, 2, 3, 4]);
        let mut encoded = frame.encode();
        let decoded = Frame::decode(&mut encoded).unwrap();
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
        assert_eq!(decoded.version, VBF_VERSION);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut buf = BytesMut::new();
        buf.put_u8(99);
        buf.put_u8(0x02);
        buf.put_u32(0);
        assert!(matches!(
            Frame::decode(&mut buf),
            Err(VbfError::UnsupportedVersion(99))
        ));
    }
}