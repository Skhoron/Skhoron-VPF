//! Skhoron VBF Core — платформонезависимое ядро.
//!
//! Никаких прямых syscalls, никакого platform-specific I/O.
//! Всё, что требует ОС (сеть, файлы, время) — приходит снаружи
//! через traits, реализация подставляется в FFI-слоях
//! (ffi-android, ffi-desktop).
//!
//! Это БАЗА. Handshake-логика, генерация паролей, установка
//! защищённого канала — сознательно НЕ реализованы здесь.
//! Ниже — только примитивы и структуры данных, на которых
//! форкеры строят свой протокол.

pub mod crypto;
pub mod error;
pub mod framing;
pub mod handshake;
pub mod identity;
pub mod session;

pub use error::VbfError;

/// Версия каркаса. Используется в TLV framing (framing::Frame::version)
/// для будущей совместимости между Base/Standard/Pro тирами.
pub const VBF_VERSION: u8 = 1;