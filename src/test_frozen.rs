//! Windows fixtures for the frozen-spawn tests: a suspended child, its initial thread's suspend
//! count, and a job's limit flags.
//!
//! The suspend count is a kernel fact, so "this child ran nothing yet" is asserted from it and never
//! from the absence of an event.

use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetThreadId, GetThreadTimes, OpenProcess, OpenThread, ResumeThread, SuspendThread,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, INFINITE, LPTHREAD_START_ROUTINE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, THREAD_QUERY_LIMITED_INFORMATION,
    THREAD_SUSPEND_RESUME,
};

use crate::containment::windows::JobHandle;

/// A `findstr x` blocker created `CREATE_SUSPENDED` through std, with piped stdin; closing it lets the
/// child exit once it runs.
pub(crate) fn spawn_suspended_blocker() -> std::process::Child {
    let mut cmd = std::process::Command::new(crate::test_child::BLOCKER_ARGV[0]);
    cmd.args(&crate::test_child::BLOCKER_ARGV[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_SUSPENDED.0 | CREATE_NO_WINDOW.0);
    crate::test_spawn::spawn(&mut cmd).expect("spawn a suspended blocker")
}

/// The initial thread of a process that is still alive, held by handle: its earliest-created
/// thread, the product's rule. Opened while the caller's own handle on the process pins the pid.
/// The handle is live, owned and closed once, with suspend rights, for as long as the value exists.
pub(crate) struct InitialThread(HANDLE);

impl InitialThread {
    pub(crate) fn of(pid: u32) -> InitialThread {
        let mut earliest: Option<(u64, HANDLE)> = None;
        // SAFETY: standard Win32 snapshot walk; the snapshot handle is closed before return, and
        // every thread handle is either kept in `earliest` or closed.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).expect("thread snapshot");
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            let mut step = Thread32First(snap, &mut entry);
            while step.is_ok() {
                if entry.th32OwnerProcessID == pid {
                    // A thread that has exited since the snapshot cannot be the initial one of a live child.
                    if let Ok(thread) = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                        false,
                        entry.th32ThreadID,
                    ) {
                        let (mut created, mut exited, mut kernel, mut user) = Default::default();
                        GetThreadTimes(thread, &mut created, &mut exited, &mut kernel, &mut user)
                            .expect("read the thread's creation time");
                        let created = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
                        match earliest {
                            Some((best, _)) if best <= created => _ = CloseHandle(thread),
                            _ => {
                                if let Some((_, older)) = earliest.replace((created, thread)) {
                                    _ = CloseHandle(older);
                                }
                            }
                        }
                    }
                }
                step = Thread32Next(snap, &mut entry);
            }
            _ = CloseHandle(snap);
        }
        let (_, thread) = earliest.unwrap_or_else(|| panic!("pid {pid} has no openable thread in the snapshot"));
        InitialThread(thread)
    }

    /// The thread id.
    pub(crate) fn tid(&self) -> u32 {
        // SAFETY: `self.0` is a live thread handle.
        unsafe { GetThreadId(self.0) }
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
        unsafe { _ = CloseHandle(self.0) };
    }
}

impl InitialThread {
    /// `ResumeThread` with its outcome ignored. A frozen child's drop releases the child's holders
    /// with this, so a drop whose kill sent nothing lets the child run to its natural exit (code 0)
    /// and fail the test's exit-code assertion rather than hang on a child that never runs. After a
    /// kill the thread is gone and the call fails, which is the expected case.
    pub(crate) fn resume_whatever_the_outcome(&self) {
        // SAFETY: `self.0` is a live thread handle with resume rights; a terminated thread only
        // makes the call fail.
        unsafe { _ = ResumeThread(self.0) };
    }
}

/// Resumes the frozen child's initial thread when dropped: held with the holders a drop's kill
/// releases (see [`InitialThread::resume_whatever_the_outcome`]).
pub(crate) struct ResumeOnDrop(pub(crate) InitialThread);

impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        self.0.resume_whatever_the_outcome();
    }
}

/// A thread another party started in a child, as an EDR agent or a debugger does: held by handle,
/// closed on drop. It is not the child's initial thread.
pub(crate) struct InjectedThread(HANDLE);

impl InjectedThread {
    /// The thread id.
    pub(crate) fn tid(&self) -> u32 {
        // SAFETY: `self.0` is a live thread handle.
        unsafe { GetThreadId(self.0) }
    }

    /// The suspend count, read by suspending and resuming once; meaningful because the thread is
    /// blocked for good (see [`inject_running_thread`]) and so never changes the count itself.
    pub(crate) fn suspend_count(&self) -> u32 {
        // SAFETY: `self.0` is a live thread handle with suspend/resume rights (the creator's).
        let previous = unsafe { SuspendThread(self.0) };
        assert_ne!(
            previous,
            u32::MAX,
            "SuspendThread failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: as above.
        let resumed = unsafe { ResumeThread(self.0) };
        assert_eq!(resumed, previous + 1, "the thread must be back at the count it had");
        previous
    }
}

impl Drop for InjectedThread {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and closed once.
        unsafe { _ = CloseHandle(self.0) };
    }
}

/// Start a second thread in the process behind `process` (a handle with thread-creation, memory
/// and query rights), released at once: its suspend count is 0 from
/// the moment this returns, and it stays alive, blocked for good on an SRW lock this function
/// writes into the child as already held. It starts in ntdll's `RtlAcquireSRWLockExclusive`,
/// whose address is the same in every process of this boot.
pub(crate) fn inject_running_thread(process: HANDLE) -> InjectedThread {
    let thread = inject_suspended_thread(process);
    // SAFETY: `thread` is a live handle; the new thread was created suspended once.
    assert_eq!(
        unsafe { ResumeThread(thread.0) },
        1,
        "the new thread was created suspended once"
    );
    thread
}

/// Like [`inject_running_thread`], but the thread is left at suspend count 1, as a debugger or an
/// EDR agent that holds a thread of the child suspended leaves it.
pub(crate) fn inject_suspended_thread(process: HANDLE) -> InjectedThread {
    // SAFETY: `process` is a live process handle with the rights above. The lock word is data in
    // memory this function allocates in the child; ntdll is mapped in every process, and
    // `RtlAcquireSRWLockExclusive` takes one pointer, which the thread gets as its argument. The
    // thread handle is owned by the returned value.
    unsafe {
        let lock = VirtualAllocEx(process, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        assert!(
            !lock.is_null(),
            "allocate the lock in the child: {}",
            std::io::Error::last_os_error()
        );
        // An SRW lock is held exclusively, with no waiters, when its word is 1.
        let held: usize = 1;
        WriteProcessMemory(process, lock, std::ptr::addr_of!(held).cast(), size_of::<usize>(), None)
            .expect("write the held lock into the child");
        let ntdll = GetModuleHandleA(windows::core::s!("ntdll.dll")).expect("ntdll is loaded");
        let start =
            GetProcAddress(ntdll, windows::core::s!("RtlAcquireSRWLockExclusive")).expect("RtlAcquireSRWLockExclusive");
        let thread = CreateRemoteThread(
            process,
            None,
            0,
            LPTHREAD_START_ROUTINE::Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(start)),
            Some(lock),
            CREATE_SUSPENDED.0,
            None,
        )
        .expect("start a thread in the child");
        InjectedThread(thread)
    }
}

/// [`inject_suspended_thread`] into a std child, whose handle has full access.
pub(crate) fn inject_suspended_thread_into_std_child(child: &std::process::Child) -> InjectedThread {
    inject_suspended_thread(HANDLE(raw(child)))
}

/// [`inject_running_thread`] into a std child, whose handle has full access.
pub(crate) fn inject_running_thread_into_std_child(child: &std::process::Child) -> InjectedThread {
    inject_running_thread(HANDLE(raw(child)))
}

/// [`inject_running_thread`] into the live process `pid`, which the caller keeps from being reaped.
pub(crate) fn inject_running_thread_into_pid(pid: u32) -> InjectedThread {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };
    // SAFETY: plain Win32 call; the handle is closed below, after the thread exists.
    let process = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            false,
            pid,
        )
    }
    .expect("open the frozen process");
    let thread = inject_running_thread(process);
    // SAFETY: owned and closed once; the thread does not depend on this handle.
    unsafe { _ = CloseHandle(process) };
    thread
}

/// The limit flags `job` holds now.
pub(crate) fn limit_flags(job: &JobHandle) -> JOB_OBJECT_LIMIT {
    crate::containment::windows::job_limit_flags(job)
        .expect("the job handle is live")
        .expect("query the job's limits")
}

/// The raw process handle of a std child, as `attach` takes it.
pub(crate) fn raw(child: &std::process::Child) -> std::os::windows::io::RawHandle {
    child.as_raw_handle()
}

thread_local! {
    static ROOT_TEARDOWNS: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Called by `ProcHandle::teardown_on_drop`; counts while a recorder lives on this thread.
pub(crate) fn note_root_teardown() {
    ROOT_TEARDOWNS.with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1));
        }
    });
}

/// Count every root teardown a drop or `tear_down_now` starts on THIS thread until the recorder
/// drops. The teardown still runs.
pub(crate) fn record_root_teardowns() -> RootTeardownRecorder {
    ROOT_TEARDOWNS.with(|c| c.set(Some(0)));
    RootTeardownRecorder(())
}

#[must_use = "recording stops as soon as the recorder is dropped"]
pub(crate) struct RootTeardownRecorder(());

impl RootTeardownRecorder {
    pub(crate) fn count(&self) -> u32 {
        ROOT_TEARDOWNS.with(|c| c.get().expect("the recorder is live"))
    }
}

impl Drop for RootTeardownRecorder {
    fn drop(&mut self) {
        ROOT_TEARDOWNS.with(|c| c.set(None));
    }
}

/// An owned handle on a process that can wait for it and end it, opened while the caller still
/// holds the process, so the pid names nothing else.
pub(crate) struct Remote(HANDLE);

impl Remote {
    pub(crate) fn open(pid: u32) -> Remote {
        // SAFETY: plain Win32 call; the handle is closed on drop.
        let handle = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )
        }
        .expect("open the child");
        Remote(handle)
    }

    /// The exit code of the process, once it is gone (see [`wait_for_death`](Self::wait_for_death)).
    #[cfg(feature = "tokio")]
    pub(crate) fn exit_code(&self) -> u32 {
        let mut code = 0u32;
        // SAFETY: `self.0` is live with `PROCESS_QUERY_LIMITED_INFORMATION`; `code` is a valid out-parameter.
        unsafe { windows::Win32::System::Threading::GetExitCodeProcess(self.0, &mut code) }
            .expect("read the exit code");
        code
    }

    /// Block until the process is gone; the process object signals, nothing here is a timer.
    pub(crate) fn wait_for_death(&self) {
        // SAFETY: `self.0` is live.
        unsafe { WaitForSingleObject(self.0, INFINITE) };
    }

    /// Whether the process is gone now. A single non-blocking look, used only after a drop that
    /// kills synchronously, so it is not a bet that enough time has passed.
    pub(crate) fn is_dead_now(&self) -> bool {
        // SAFETY: `self.0` is live.
        unsafe { WaitForSingleObject(self.0, 0) }.0 == 0
    }

    pub(crate) fn end(&self) {
        // SAFETY: `self.0` is live with `PROCESS_TERMINATE`.
        unsafe { TerminateProcess(self.0, 1) }.expect("end the child");
        self.wait_for_death();
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        // SAFETY: owned, closed once.
        unsafe { _ = CloseHandle(self.0) };
    }
}
