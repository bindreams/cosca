//! Test-only support shared across the crate's unit tests.

// The debugger stand-in is `ptrace` on macOS.
#[cfg(target_os = "macos")]
pub(crate) mod tracer;
