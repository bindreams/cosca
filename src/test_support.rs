//! Test-only support shared across the crate's unit tests.

// A `Root` with stated answers.
pub(crate) mod stated_root;

// The debugger stand-in is `ptrace` on macOS.
#[cfg(target_os = "macos")]
pub(crate) mod tracer;

// The foreign tracer: see the module doc.
#[cfg(target_os = "linux")]
pub(crate) mod foreign_tracer;

// The test thread as the tracer of its own child.
#[cfg(target_os = "linux")]
pub(crate) mod own_tracer;

/// The read of `pid` a policy test states as "could not be read": the identity read's own answer
/// when its `pidfd_open` is refused with `EMFILE`, cause included.
#[cfg(target_os = "linux")]
pub(crate) fn emfile_number_read(pid: u32) -> crate::identity::NumberRead {
    use crate::identity::{FakeKernel, HostKernel, ProcessId};
    let refused = FakeKernel::over(&HostKernel).on_pidfd_open(pid, Err(rustix::io::Errno::MFILE));
    ProcessId::of_with(&refused, pid)
}
