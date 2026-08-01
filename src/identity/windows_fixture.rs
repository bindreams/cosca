//! Test-only: a REAL live child process whose process-object DACL denies us rights.
#![allow(dead_code)] // consumed by later tasks' tests; without this the `-D warnings`
// pre-commit hook rejects this module's own commit.
//!
//! A live process we may not `OpenProcess` is needed to reproduce an access-denied identity
//! read. Depending on a system service will not do — an elevated CI runner can open those.
//! So we create one: `CreateProcessW` accepts a `SECURITY_ATTRIBUTES` for the new process
//! object, and a DACL holding a single access-allowed ACE for our own user SID denies every
//! right that ACE omits — to us and to an elevated caller with the same SID, since
//! `OpenProcess` never enables `SeDebugPrivilege` on our behalf.
//!
//! Teardown is safe: the handle `CreateProcessW` hands the creator carries full access
//! regardless of the DACL, and the child is assigned to a kill-on-close job object so any
//! grandchild dies with it.
//!
//! Both scratch buffers below are `Vec<u64>` / `Vec<u32>`, not `Vec<u8>`: `TOKEN_USER` holds
//! a pointer (align 8) and `InitializeAcl` requires a DWORD-aligned `ACL`. A `Vec<u8>` is
//! align-1, so casting one to either type is an unaligned access and can produce a malformed
//! DACL — which would silently grant more than intended and make every downstream denial
//! test pass for the wrong reason.

use std::mem::size_of;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE, WAIT_OBJECT_0};
use windows::Win32::Security::{
    AddAccessAllowedAce, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
    TokenUser, ACL, ACL_REVISION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, STARTUPINFOW,
};

/// Sentinel for [`spawn_with_ace`]: build the DACL with no ACE at all.
const NO_ACE: u32 = u32::MAX;

/// A live child whose process object grants us only the mask passed to [`spawn_restricted`].
/// Terminated and closed on drop.
pub(crate) struct RestrictedChild {
    handle: HANDLE,
    thread: HANDLE,
    /// Kills the whole tree when closed. `TerminateProcess` does NOT cascade, so without
    /// this `spawn_restricted_shell`'s `cmd.exe` would die while the `ping.exe` it launched
    /// ran on for an hour. That orphan is not just a leak: `wait_for_child` scans a
    /// host-wide `(pid, ppid)` snapshot, so a stranded grandchild whose dead parent pid
    /// Windows later recycles onto a new fixture shell would be mistaken for its child.
    job: HANDLE,
    pid: u32,
}

impl RestrictedChild {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// The creator's full-access handle — the only way to read this child's identity.
    pub(crate) fn handle(&self) -> HANDLE {
        self.handle
    }

    /// `STILL_ACTIVE` while running, else the recorded exit code. Read through the owned
    /// handle, so the DACL never affects it.
    pub(crate) fn exit_code(&self) -> u32 {
        let mut code = 0u32;
        // SAFETY: `self.handle` is our live, owned, full-access process handle.
        unsafe { GetExitCodeProcess(self.handle, &mut code) }.expect("GetExitCodeProcess on an owned handle");
        code
    }

    /// The fixture command is chosen so it never exits with 259, making this read
    /// unambiguous for our own child (it is not, in general, for arbitrary processes).
    pub(crate) fn is_running(&self) -> bool {
        self.exit_code() == STILL_ACTIVE.0 as u32
    }

    /// Block until the child's exit is recorded. Not a timeout: the wait is bounded by an
    /// exit someone has already requested (`terminate`, or a `kill_by_identity` under test).
    pub(crate) fn await_exit(&self) {
        // SAFETY: `self.handle` is our live, owned process handle.
        let waited = unsafe { WaitForSingleObject(self.handle, INFINITE) };
        assert_eq!(
            waited, WAIT_OBJECT_0,
            "fixture: wait on pid {} returned {waited:?}",
            self.pid
        );
    }

    /// The pid of this fixture's first child, once the shell has spawned it. Polls the
    /// `(pid, ppid)` snapshot the crate already builds — bounded by the child's appearance,
    /// which `cmd /c` guarantees, and asserted rather than timed out.
    pub(crate) fn wait_for_child(&self) -> u32 {
        // Windows never reparents and recycles pids from a small dense table, so a raw
        // `ppid == self.pid` scan can match a pre-existing orphan whose real parent exited
        // and whose pid was then handed to this fixture. Route through the crate-s own
        // stale-ppid defense (`children_of` applies the start-token order rule) so only a
        // genuine child is returned.
        let me = crate::identity::windows_identity_from_handle(self.handle, self.pid)
            .expect("the owned handle always yields an identity");
        loop {
            assert!(self.is_running(), "the fixture shell exited before spawning its child");
            let parents = crate::containment::enumerate::process_parents();
            if let Some(kid) = crate::containment::treewalk::children_of(me, &parents).first() {
                return kid.pid();
            }
            std::thread::yield_now();
        }
    }

    /// Terminate with exit code 1 and wait for the kernel to record it. Ask forgiveness, not
    /// permission: `TerminateProcess` on an already-exited child fails with ACCESS_DENIED,
    /// which is success here — a pre-check would race the child's own exit. Panics on a
    /// genuine teardown failure, so a test never quietly leaks a live process.
    pub(crate) fn terminate(&self) {
        if let Err(what) = self.try_terminate() {
            log::error!("{what}");
            if !std::thread::panicking() {
                panic!("{what}");
            }
        }
    }

    /// The non-panicking core, so `Drop` can report a failure without unwinding out of
    /// itself and skipping the handle closes.
    fn try_terminate(&self) -> Result<(), String> {
        // SAFETY: `self.handle` is our live, owned, full-access process handle.
        if let Err(e) = unsafe { TerminateProcess(self.handle, 1) } {
            if !self.is_running() {
                return Ok(()); // it exited on its own between our read and the call — fine
            }
            // Do NOT fall through to the wait: nothing asked the child to exit, so the wait
            // would park forever.
            return Err(format!(
                "fixture teardown: TerminateProcess(pid {}) failed: {e}",
                self.pid
            ));
        }
        // SAFETY: `self.handle` is live and we just asked the child to exit, so this wait is
        // bounded by that exit.
        let waited = unsafe { WaitForSingleObject(self.handle, INFINITE) };
        if waited != WAIT_OBJECT_0 {
            return Err(format!(
                "fixture teardown: wait on pid {} returned {waited:?}",
                self.pid
            ));
        }
        Ok(())
    }
}

impl Drop for RestrictedChild {
    fn drop(&mut self) {
        // Never let a teardown failure unwind out of `drop` before the closes below: the
        // child is still ALIVE on that path (that is what makes it a failure), so leaking
        // its handles would strand a process with no owner.
        let failure = self.try_terminate().err();
        // The job goes last: closing it is what kills any grandchildren.
        for (h, what) in [(self.thread, "thread"), (self.handle, "process"), (self.job, "job")] {
            // SAFETY: all three handles are ours and still open.
            if let Err(e) = unsafe { CloseHandle(h) } {
                log::error!("fixture teardown: CloseHandle({what}) for pid {} failed: {e}", self.pid);
            }
        }
        if let Some(what) = failure {
            log::error!("{what}");
            if !std::thread::panicking() {
                panic!("{what}");
            }
        }
    }
}

/// Spawn a long-running child whose process-object DACL allows our user SID exactly
/// `granted | PROCESS_TERMINATE` and nothing else.
pub(crate) fn spawn_restricted(granted: u32) -> RestrictedChild {
    spawn_with_ace(granted | PROCESS_TERMINATE.0)
}

/// Spawn a child that even `PROCESS_TERMINATE` cannot open by pid. `Drop` still tears it
/// down through the owned handle.
///
/// Uses an EMPTY DACL, not an ACE with a zero access mask: an empty DACL is Windows'
/// documented "grant nothing to anyone" form, whereas a zero-mask ACE is unspecified — it
/// might be rejected by `AddAccessAllowedAce` (panicking the fixture) or normalized away
/// (silently granting access, which would send all of its consumers down the `Opened::Found`
/// path while still reporting green).
pub(crate) fn spawn_unkillable() -> RestrictedChild {
    spawn_with_ace(NO_ACE)
}

/// Grants `PROCESS_QUERY_LIMITED_INFORMATION` and nothing else — identity is readable by pid
/// but `PROCESS_TERMINATE` is denied, which is the only shape that drives `wait::kill`'s
/// `Opened::Denied` arm (its mask is `TERMINATE | QUERY_LIMITED`, so `spawn_restricted` —
/// which always ORs in `PROCESS_TERMINATE` — opens successfully and never reaches it).
pub(crate) fn spawn_query_only() -> RestrictedChild {
    spawn_with_ace(PROCESS_QUERY_LIMITED_INFORMATION.0)
}

/// Like [`spawn_restricted`], but the restricted process is a shell that spawns an ordinary
/// grandchild. A DACL is not inherited, so the grandchild is freely openable while its
/// parent is not — the only way to build "my parent is access-denied" from a test.
pub(crate) fn spawn_restricted_shell(granted: u32) -> RestrictedChild {
    spawn_with_ace_cmdline(
        granted | PROCESS_TERMINATE.0,
        "C:\\Windows\\System32\\cmd.exe /c ping.exe -n 3600 127.0.0.1",
    )
}

fn spawn_with_ace(granted: u32) -> RestrictedChild {
    spawn_with_ace_cmdline(granted, "C:\\Windows\\System32\\ping.exe -n 3600 127.0.0.1")
}

/// Panics on any Win32 failure: a fixture that silently degrades would make its consumers
/// pass vacuously.
fn spawn_with_ace_cmdline(granted: u32, cmdline: &str) -> RestrictedChild {
    // Our own user SID, from our own token. `token` is a real handle — closed below.
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle needing no close.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.expect("OpenProcessToken");
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 is the documented size query; it fails with
    // ERROR_INSUFFICIENT_BUFFER and writes the required size.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    // u64-backed so the TOKEN_USER cast below is 8-aligned.
    let mut sid_buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `sid_buf` is at least `needed` bytes.
    let info = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(sid_buf.as_mut_ptr().cast()),
            (sid_buf.len() * 8) as u32,
            &mut needed,
        )
    };
    // SAFETY: `token` is an owned handle we are done with.
    unsafe { CloseHandle(token) }.expect("CloseHandle(process token)");
    info.expect("GetTokenInformation(TokenUser)");
    // SAFETY: the kernel wrote a TOKEN_USER at the head of an 8-aligned buffer, and
    // `sid_buf` outlives every use of `sid` (dropped at the end of this function, after
    // CreateProcessW).
    let sid = unsafe { (*sid_buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    // A DACL with ONE allow-ACE: everything it does not name is denied. u32-backed so the
    // ACL is DWORD-aligned, as InitializeAcl requires.
    let mut acl_buf = vec![0u32; 256];
    let acl = acl_buf.as_mut_ptr().cast::<ACL>();
    // SAFETY: `acl_buf` is 1024 bytes, far more than one ACE needs.
    unsafe { InitializeAcl(acl, (acl_buf.len() * 4) as u32, ACL_REVISION) }.expect("InitializeAcl");
    if granted != NO_ACE {
        // SAFETY: `acl` is initialized above; `sid` is a valid SID owned by `sid_buf`.
        unsafe { AddAccessAllowedAce(acl, ACL_REVISION, granted, sid) }.expect("AddAccessAllowedAce");
    }

    let mut sd = SECURITY_DESCRIPTOR::default();
    let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);
    // SAFETY: `sd` is a stack SECURITY_DESCRIPTOR; 1 is the only defined revision.
    unsafe { InitializeSecurityDescriptor(psd, 1) }.expect("InitializeSecurityDescriptor");
    // SAFETY: `psd` is initialized; `acl_buf` stays alive until after CreateProcessW.
    unsafe { SetSecurityDescriptorDacl(psd, true, Some(acl), false) }.expect("SetSecurityDescriptorDacl");

    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };

    // NUL-terminated HERE, centrally: `CreateProcessW` takes a `PWSTR` and reads until the
    // terminator, so a caller that forgot one would send it reading past the end of the
    // allocation. No call site can get this wrong.
    let mut cmdline: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: `cmdline` is a NUL-terminated writable UTF-16 buffer; `sa` and the DACL it
    // points at are alive for the duration of the call.
    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(cmdline.as_mut_ptr())),
            Some(&sa),
            None,
            false,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
    }
    .expect("CreateProcessW for the restricted fixture child");

    // SAFETY: an unnamed job object has no preconditions; the handle is owned by the
    // RestrictedChild and closed in Drop.
    let job = unsafe { CreateJobObjectW(None, None) }.expect("CreateJobObjectW");
    let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
            LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: `limits` matches the class being set.
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const core::ffi::c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .expect("SetInformationJobObject");
    // SAFETY: both handles are live and ours.
    unsafe { AssignProcessToJobObject(job, pi.hProcess) }.expect("AssignProcessToJobObject");

    // Only NOW may the child run. Windows enrols a process-s children in its job only from
    // the moment the parent is already a member, so a child that started running before the
    // assignment could spawn a grandchild permanently outside the job - which is exactly the
    // orphan the job exists to prevent. CREATE_SUSPENDED closes that window by construction.
    // SAFETY: `pi.hThread` is the freshly created, still-suspended main thread.
    let prev = unsafe { ResumeThread(pi.hThread) };
    assert_eq!(prev, 1, "the fixture child must resume from exactly one suspend");

    let child = RestrictedChild {
        handle: pi.hProcess,
        thread: pi.hThread,
        job,
        pid: pi.dwProcessId,
    };
    // A child that died on startup would still keep its kernel object alive through our
    // handle, so every OpenProcess verdict would look right while testing nothing.
    assert!(
        child.is_running(),
        "the fixture child exited immediately — the command line is wrong"
    );
    child
}

#[cfg(test)]
#[path = "windows_fixture_tests.rs"]
mod windows_fixture_tests;
