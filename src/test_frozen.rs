//! Windows fixtures for the frozen-spawn tests: a suspended child, its initial thread's suspend
//! count, and a job's limit flags.
//!
//! The suspend count is a kernel fact, so "this child ran nothing yet" is asserted from it and never
//! from the absence of an event.

use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::JobObjects::{
    JobObjectBasicLimitInformation, QueryInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION, JOB_OBJECT_LIMIT,
};
use windows::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, CREATE_SUSPENDED, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

use crate::containment::windows::JobHandle;

/// A `findstr x` blocker created `CREATE_SUSPENDED` through std, with piped stdin the caller holds.
/// Closing that stdin is what lets the child exit by itself once it runs.
pub(crate) fn spawn_suspended_blocker() -> std::process::Child {
    let mut cmd = std::process::Command::new(crate::test_child::BLOCKER_ARGV[0]);
    cmd.args(&crate::test_child::BLOCKER_ARGV[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_SUSPENDED.0);
    crate::test_spawn::spawn(&mut cmd).expect("spawn a suspended blocker")
}

/// The initial thread of a process that is still alive, held by handle. Opened while the caller's
/// own handle on the process pins the pid.
pub(crate) struct InitialThread(HANDLE);

impl InitialThread {
    pub(crate) fn of(pid: u32) -> InitialThread {
        // SAFETY: standard Win32 snapshot walk; the snapshot handle is closed before return.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).expect("thread snapshot");
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            let mut step = Thread32First(snap, &mut entry);
            while step.is_ok() {
                if entry.th32OwnerProcessID == pid {
                    let thread = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                        false,
                        entry.th32ThreadID,
                    )
                    .expect("open the initial thread");
                    _ = CloseHandle(snap);
                    return InitialThread(thread);
                }
                step = Thread32Next(snap, &mut entry);
            }
            _ = CloseHandle(snap);
        }
        panic!("pid {pid} has no thread in the snapshot");
    }

    /// The suspend count, read by suspending and resuming once. Only meaningful while the thread
    /// is not running anything that matters (a frozen child), or when the count is the question.
    pub(crate) fn suspend_count(&self) -> u32 {
        let previous = self.suspend_once();
        self.release_one();
        previous
    }

    /// `SuspendThread`: returns the previous count.
    pub(crate) fn suspend_once(&self) -> u32 {
        // SAFETY: `self.0` is a live thread handle with suspend rights.
        let previous = unsafe { SuspendThread(self.0) };
        assert_ne!(
            previous,
            u32::MAX,
            "SuspendThread failed: {}",
            std::io::Error::last_os_error()
        );
        previous
    }

    /// `ResumeThread`: returns the previous count.
    pub(crate) fn release_one(&self) -> u32 {
        // SAFETY: as above.
        let previous = unsafe { ResumeThread(self.0) };
        assert_ne!(
            previous,
            u32::MAX,
            "ResumeThread failed: {}",
            std::io::Error::last_os_error()
        );
        previous
    }
}

impl Drop for InitialThread {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and closed once.
        unsafe { _ = CloseHandle(self.0) };
    }
}

/// The limit flags `job` holds now.
pub(crate) fn limit_flags(job: &JobHandle) -> JOB_OBJECT_LIMIT {
    let mut info = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
    job.with_handle(|handle| {
        // SAFETY: `handle` is live for the call, and `info` is a correctly sized out-parameter.
        unsafe {
            QueryInformationJobObject(
                Some(handle),
                JobObjectBasicLimitInformation,
                std::ptr::addr_of_mut!(info).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
                None,
            )
        }
        .expect("query the job's limits");
    })
    .expect("the job handle is live");
    info.LimitFlags
}

/// The raw process handle of a std child, as `attach` takes it.
pub(crate) fn raw(child: &std::process::Child) -> std::os::windows::io::RawHandle {
    child.as_raw_handle()
}
