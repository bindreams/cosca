//! What cosca asks the Windows kernel about processes, and nothing else: the counterpart of
//! `identity::linux::kernel`. [`HostKernel`] makes the call; the test `FakeKernel` answers from
//! stated rows and models no kernel. Methods enter with their first caller.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::TerminateProcess;

pub(crate) trait Kernel: Sync {
    /// `TerminateProcess(handle, exit_code)` on a live process handle the caller holds. Never
    /// blocks. The caller decides what a refusal means (`terminate_held`).
    fn terminate(&self, handle: HANDLE, exit_code: u32) -> windows::core::Result<()>;
}

pub(crate) struct HostKernel;

impl Kernel for HostKernel {
    fn terminate(&self, handle: HANDLE, exit_code: u32) -> windows::core::Result<()> {
        // SAFETY: the caller's live process handle.
        unsafe { TerminateProcess(handle, exit_code) }
    }
}

forward_kernel! {
    fn terminate(&self, handle: HANDLE, exit_code: u32) -> windows::core::Result<()>;
}

#[cfg(test)]
#[path = "kernel/fake.rs"]
pub(crate) mod fake;
