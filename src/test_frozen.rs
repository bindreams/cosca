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
use windows::Win32::System::JobObjects::{
    IsProcessInJob, JobObjectBasicLimitInformation, QueryInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetCurrentProcess, GetThreadId, OpenThread, ResumeThread, SuspendThread, CREATE_NO_WINDOW,
    CREATE_SUSPENDED, LPTHREAD_START_ROUTINE, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
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

/// The initial thread of a process that is still alive, held by handle. Opened while the caller's
/// own handle on the process pins the pid. The handle is live, owned and closed once, with suspend
/// rights, for as long as the value exists.
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

/// A thread another party started in a child, as an EDR agent or a debugger does: held by handle,
/// closed on drop. It is not the child's initial thread.
pub(crate) struct InjectedThread(HANDLE);

impl InjectedThread {
    /// The thread id.
    pub(crate) fn tid(&self) -> u32 {
        // SAFETY: `self.0` is a live thread handle.
        unsafe { GetThreadId(self.0) }
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
        assert_eq!(ResumeThread(thread), 1, "the new thread was created suspended once");
        InjectedThread(thread)
    }
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

/// The limit flags of this process's innermost job; `None` when it is in none.
pub(crate) fn own_job_limits() -> Option<JOB_OBJECT_LIMIT> {
    let mut in_job = windows::core::BOOL(0);
    // SAFETY: `GetCurrentProcess` is a pseudo-handle, and `in_job` is a valid out-parameter. A null
    // job handle asks about any job.
    unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut in_job) }.expect("IsProcessInJob on this process");
    if !in_job.as_bool() {
        return None;
    }
    let mut info = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
    // SAFETY: `info` is a correctly sized out-parameter; `None` asks about the calling process's job.
    unsafe {
        QueryInformationJobObject(
            None,
            JobObjectBasicLimitInformation,
            std::ptr::addr_of_mut!(info).cast(),
            std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            None,
        )
    }
    .expect("query this process's job");
    Some(info.LimitFlags)
}

/// Whether a child of this process, made without `CREATE_BREAKAWAY_FROM_JOB`, may use that flag
/// for its own children: it is in no job, or in one that carries `BREAKAWAY_OK`. A creator job with
/// silent breakaway puts the child in an ancestor this process cannot read, which counts as no.
pub(crate) fn child_may_break_away(child: &std::process::Child) -> bool {
    let mut in_job = windows::core::BOOL(0);
    // SAFETY: the std child owns a live process handle; a null job handle asks about any job.
    unsafe { IsProcessInJob(HANDLE(raw(child)), None, &mut in_job) }.expect("IsProcessInJob on the child");
    if !in_job.as_bool() {
        return true;
    }
    match own_job_limits() {
        Some(limits) => {
            limits.0 & JOB_OBJECT_LIMIT_BREAKAWAY_OK.0 != 0 && limits.0 & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK.0 == 0
        }
        None => false,
    }
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
