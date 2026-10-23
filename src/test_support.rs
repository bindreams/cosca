//! Test-only support shared across the crate's unit tests.

// The debugger stand-in is `ptrace` on macOS.
#[cfg(target_os = "macos")]
pub(crate) mod tracer;

// The foreign tracer is a separate process that seizes a test child with `ptrace`, on Linux.
#[cfg(target_os = "linux")]
pub(crate) mod foreign_tracer;
