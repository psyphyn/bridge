//! FFI bindings for platform-native clients.
//!
//! Exposes bridge-core functionality via C-compatible functions for:
//! - Swift/Objective-C (Apple platforms)
//! - JNI (Android/Kotlin)
//! - C#/P/Invoke (Windows)

/// Returns the Bridge core version as a C string.
///
/// # Safety
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
pub extern "C" fn bridge_version() -> *const std::ffi::c_char {
    // Static string, valid for program lifetime
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const std::ffi::c_char
}
