//! FFI-мост под Android/Kotlin через uniffi.
//!
//! TODO(следующий шаг): определить uniffi::export функции-обёртки
//! над skhoron_vbf_core (генерация identity, encode/decode Frame,
//! AEAD encrypt/decrypt) и .udl/proc-macro интерфейс.
//!
//! Не реализовывать здесь генерацию паролей / отправку handshake —
//! это протокольный уровень форка, не базового каркаса.

// Пример структуры на будущее (не реализовано):
// #[uniffi::export]
// fn generate_identity() -> Vec<u8> { ... }