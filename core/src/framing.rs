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
    /// pub(crate), не pub — наружу тип отдаётся только через FrameType-enum,
    /// не как голый байт, чтобы session.rs мог положить его в AAD (см. H4
    /// в ревью), но внешний код не мог обойти валидацию Extension-диапазона.
    pub(crate) fn to_u8(self) -> u8 {
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

    /// Единственный проверенный способ создать Extension-тип для отправки.
    /// `FrameType::Extension(v)` как конструктор тоже публичен (нельзя
    /// спрятать поле tuple-варианта в Rust без смены на struct-вариант),
    /// но `encode()` дополнительно проверяет диапазон при сериализации —
    /// так что даже обход этого конструктора не даст отправить кадр
    /// с зарезервированным (0x00-0x7F) значением в Extension.
    pub fn extension(value: u8) -> Result<Self, VbfError> {
        if (0x80..=0xFF).contains(&value) {
            Ok(FrameType::Extension(value))
        } else {
            Err(VbfError::MalformedFrame(
                "extension frame type must be in 0x80..=0xFF",
            ))
        }
    }
}

/// Один TLV-кадр: version(1) | type(1) | length(4, big-endian) | value(N)
#[derive(Clone, Debug)]
pub struct Frame {
    version: u8,
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}

const HEADER_LEN: usize = 1 + 1 + 4; // version + type + length

/// Жёсткий потолок размера кадра — 16 MiB. Не даёт удалённой стороне
/// заявить произвольную длину (до 4 GiB из u32) и заставить получателя
/// выделить неограниченный буфер. Значение с запасом под будущие
/// Standard/Pro-фичи (mixnet-обёртки и т.п.), но не "почти безлимит".
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

impl Frame {
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Self {
        Self {
            version: VBF_VERSION,
            frame_type,
            payload,
        }
    }

    /// Версия не мутируется после создания (поле приватное) — раньше
    /// `pub version: u8` можно было выставить в произвольное значение
    /// после `Frame::new()` и получить кадр с "видом" другой версии,
    /// не проходя через инвариант, который задаёт сам конструктор.
    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn encode(&self) -> Result<BytesMut, VbfError> {
        if self.payload.len() > MAX_FRAME_SIZE {
            return Err(VbfError::MalformedFrame("payload exceeds MAX_FRAME_SIZE"));
        }
        // Зарезервированный диапазон (0x00-0x7F) не должен уходить на
        // провод как Extension — это ломало бы совместимость с будущими
        // именованными FrameType в этом диапазоне.
        if let FrameType::Extension(v) = self.frame_type {
            if !(0x80..=0xFF).contains(&v) {
                return Err(VbfError::MalformedFrame(
                    "extension frame type must be in 0x80..=0xFF",
                ));
            }
        }
        // payload.len() гарантированно помещается в u32 после проверки выше —
        // без этой проверки usize->u32 на 64-бит системах мог молча обрезаться.
        let len_u32 = u32::try_from(self.payload.len())
            .map_err(|_| VbfError::MalformedFrame("payload length does not fit in u32"))?;

        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        buf.put_u8(self.version);
        buf.put_u8(self.frame_type.to_u8());
        buf.put_u32(len_u32);
        buf.put_slice(&self.payload);
        Ok(buf)
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

        if length > MAX_FRAME_SIZE {
            return Err(VbfError::MalformedFrame("declared length exceeds MAX_FRAME_SIZE"));
        }

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
        let mut encoded = frame.encode().unwrap();
        let decoded = Frame::decode(&mut encoded).unwrap();
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
        assert_eq!(decoded.version, VBF_VERSION);
    }

    #[test]
    fn rejects_oversized_payload_on_encode() {
        let frame = Frame::new(FrameType::Data, vec![0u8; MAX_FRAME_SIZE + 1]);
        assert!(frame.encode().is_err());
    }

    #[test]
    fn rejects_oversized_declared_length_on_decode() {
        let mut buf = BytesMut::new();
        buf.put_u8(VBF_VERSION);
        buf.put_u8(0x02);
        buf.put_u32((MAX_FRAME_SIZE + 1) as u32);
        assert!(matches!(
            Frame::decode(&mut buf),
            Err(VbfError::MalformedFrame(_))
        ));
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

    #[test]
    fn extension_constructor_rejects_reserved_range() {
        assert!(FrameType::extension(0x02).is_err()); // 0x02 == Data, зарезервировано
        assert!(FrameType::extension(0x80).is_ok());
    }

    #[test]
    fn encode_rejects_extension_in_reserved_range() {
        // Обходим FrameType::extension() напрямую через tuple-конструктор —
        // именно это encode() должен ловить сам, а не полагаться на то,
        // что вызывающий код использовал validated-конструктор.
        let frame = Frame::new(FrameType::Extension(0x02), vec![]);
        assert!(frame.encode().is_err());
    }
}