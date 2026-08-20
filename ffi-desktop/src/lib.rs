//! FFI-мост под desktop (Linux/Windows/macOS) через обычный C ABI
//! (cbindgen для генерации заголовков, без MPL-зависимостей).
//!
//! TODO(следующий шаг): extern "C" обёртки над skhoron_vbf_core,
//! cbindgen.toml для генерации .h заголовка.

// Пример на будущее (не реализовано):
// #[no_mangle]
// pub extern "C" fn skhoron_generate_identity() -> *mut u8 { ... }