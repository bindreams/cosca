//! What cosca asks the Windows kernel about processes, and nothing else: the counterpart of
//! `identity::linux::kernel`. [`HostKernel`] makes the call; the test `FakeKernel` answers from
//! stated rows and models no kernel. Methods enter with their first caller.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::TerminateProcess;

use super::peb::StartupRead;
use crate::identity::Key;

pub(crate) trait Kernel: Sync {
    /// The creation time of the process `handle` names, as its start token (`GetProcessTimes`): the
    /// read of an identity from a handle the caller holds. The handle needs
    /// `PROCESS_QUERY_LIMITED_INFORMATION`. The caller decides what a failure means.
    fn creation_token(&self, handle: HANDLE) -> windows::core::Result<Key>;

    /// `TerminateProcess(handle, exit_code)` on a live process handle the caller holds. Never
    /// blocks. The caller decides what a refusal means (`terminate_held`).
    fn terminate(&self, handle: HANDLE, exit_code: u32) -> windows::core::Result<()>;

    /// How far the process `handle` names has got in starting ([`StartupRead`]), read once through the handle
    /// (needs `PROCESS_QUERY_LIMITED_INFORMATION` and `PROCESS_VM_READ`). A child not native to the host is
    /// `ErrorKind::Unsupported`; on an ARM64 build the read needs Windows 11. The caller decides what the
    /// state means.
    fn start_state(&self, handle: HANDLE) -> std::io::Result<StartupRead>;
}

pub(crate) struct HostKernel;

impl Kernel for HostKernel {
    fn creation_token(&self, handle: HANDLE) -> windows::core::Result<Key> {
        super::creation_token_result(handle)
    }

    fn terminate(&self, handle: HANDLE, exit_code: u32) -> windows::core::Result<()> {
        // SAFETY: the caller's live process handle.
        unsafe { TerminateProcess(handle, exit_code) }
    }

    fn start_state(&self, handle: HANDLE) -> std::io::Result<StartupRead> {
        super::peb::start_state(handle)
    }
}

forward_kernel! {
    fn creation_token(&self, handle: HANDLE) -> windows::core::Result<Key>;
    fn terminate(&self, handle: HANDLE, exit_code: u32) -> windows::core::Result<()>;
    fn start_state(&self, handle: HANDLE) -> std::io::Result<StartupRead>;
}

#[cfg(test)]
#[path = "kernel/fake.rs"]
pub(crate) mod fake;
