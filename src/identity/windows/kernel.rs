//! What cosca asks the Windows kernel about processes, and nothing else: the counterpart of
//! `identity::linux::kernel`. [`HostKernel`] makes the call; the test `FakeKernel` answers from
//! stated rows and models no kernel. Methods enter with their first caller.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::TerminateProcess;

use crate::identity::Key;

pub(crate) trait Kernel: Sync {
    /// The creation time of the process `handle` names, as its start token (`GetProcessTimes`): the
    /// read of an identity from a handle the caller holds. The handle needs
    /// `PROCESS_QUERY_LIMITED_INFORMATION`. The caller decides what a failure means.
    fn creation_token(&self, handle: HANDLE) -> windows::core::Result<Key>;

    /// `TerminateProcess(handle, exit_code)` on a live process handle the caller holds. Never
    /// blocks. The caller decides what a refusal means (`terminate_held`).
    fn terminate(&self, handle: HANDLE, exit_code: u32) -> windows::core::Result<()>;
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
}

forward_kernel! {
    fn creation_token(&self, handle: HANDLE) -> windows::core::Result<Key>;
    fn terminate(&self, handle: HANDLE, exit_code: u32) -> windows::core::Result<()>;
}

#[cfg(test)]
#[path = "kernel/fake.rs"]
pub(crate) mod fake;
