//! Test-only: a REAL live child process whose process-object DACL denies us rights.
//!
//! A live process we may not `OpenProcess` is needed to reproduce an access-denied identity
//! read. Depending on a system service will not do — an elevated CI runner can open those.
//! So we create one: `CreateProcessW` accepts a `SECURITY_ATTRIBUTES` for the new process
//! object, and a DACL holding a single access-allowed ACE for our own user SID denies every
//! right that ACE omits — to us and to an elevated caller with the same SID.
//!
//! One privilege defeats that: a token holding `SeDebugPrivilege` **enabled** bypasses the
//! DACL outright. An interactive session does not hold it enabled; CI runners do. So
//! [`drop_se_debug_privilege`] strips it from this process, making the DACL authoritative
//! everywhere; see it for why every fixture takes the [`Completion`] of `own_process`.
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
use std::os::windows::io::AsRawHandle as _;

use crate::test_own_process::Completion;
use crate::test_spawn::console_flags::Console;
use crate::test_spawn::raw_spawn::{spawn_locked_raw_with, RawChild, RawOptions, RawStdio};
use windows::core::PWSTR;
use windows::Win32::Foundation::LUID;
use windows::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE, WAIT_OBJECT_0};
use windows::Win32::Security::{
    AddAccessAllowedAce, AdjustTokenPrivileges, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    LookupPrivilegeValueW, SetKernelObjectSecurity, SetSecurityDescriptorDacl, TokenUser, ACL, ACL_REVISION,
    DACL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SE_DEBUG_NAME, SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, ResumeThread,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, DETACHED_PROCESS, INFINITE,
    PROCESS_CREATION_FLAGS, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    PROCESS_WRITE_DAC,
};

/// Remove `SeDebugPrivilege` from THIS process's token.
///
/// A token holding that privilege **enabled** bypasses a process object's DACL outright, so
/// every denial this module constructs would be quietly openable and every access-denied
/// test would report green while proving nothing. An interactive session does not hold it
/// enabled, which is why the fixture works locally; GitHub's Windows runners do, which is
/// why it does not work there.
///
/// Removing it makes the DACL authoritative on every runner, so this is a real fix rather
/// than a skip: if the precondition still fails to hold, `spawn_unkillable_denies_everything`
/// and its siblings fail loudly instead of passing vacuously.
///
/// `SE_PRIVILEGE_REMOVED` is irreversible for the token and the token is shared by every thread of
/// the process, so a test running beside others would change what they observe. Calling it
/// again is harmless: the privilege is already gone.
pub(crate) fn drop_se_debug_privilege(_alone: &Completion) {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle needing no close.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) }
        .expect("OpenProcessToken(TOKEN_ADJUST_PRIVILEGES)");
    let mut luid = LUID::default();
    // SAFETY: `SE_DEBUG_NAME` is a static NUL-terminated wide string.
    unsafe { LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid) }.expect("LookupPrivilegeValueW(SeDebugPrivilege)");
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_REMOVED,
        }],
    };
    // Succeeds with ERROR_NOT_ALL_ASSIGNED when the token never held the privilege —
    // the normal local case, and exactly the state we want either way.
    // SAFETY: `privileges` describes one LUID and `PrivilegeCount` matches.
    let adjusted = unsafe { AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None) };
    // SAFETY: `token` is an owned handle we are done with.
    unsafe { CloseHandle(token) }.expect("CloseHandle(process token)");
    adjusted.expect("AdjustTokenPrivileges(SeDebugPrivilege, SE_PRIVILEGE_REMOVED)");
}

/// Gives the live process `pid`, which we created, an empty DACL: no by-pid open of it succeeds
/// from now on, while a handle already held keeps the rights it was granted. For a test that
/// restricts a child the code under test has already started. The owner may always write the DACL,
/// so the open for it is the one that is not refused. A token holding `SeDebugPrivilege` enabled
/// opens it anyway: the caller first runs [`drop_se_debug_privilege`].
pub(crate) fn deny_every_open_by_pid(pid: u32) {
    // SAFETY: a plain open; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_WRITE_DAC, false, pid) }.expect("OpenProcess(PROCESS_WRITE_DAC)");
    let mut acl_buf = vec![0u32; 2];
    let acl = acl_buf.as_mut_ptr().cast::<ACL>();
    // SAFETY: `acl_buf` is 8 bytes, DWORD-aligned, and an empty ACL needs only its 8-byte header.
    unsafe { InitializeAcl(acl, (acl_buf.len() * 4) as u32, ACL_REVISION) }.expect("InitializeAcl");
    let mut sd = SECURITY_DESCRIPTOR::default();
    let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);
    // SAFETY: `sd` is a stack SECURITY_DESCRIPTOR; 1 is the only defined revision.
    unsafe { InitializeSecurityDescriptor(psd, 1) }.expect("InitializeSecurityDescriptor");
    // SAFETY: `psd` is initialized; `acl_buf` outlives the call below.
    unsafe { SetSecurityDescriptorDacl(psd, true, Some(acl), false) }.expect("SetSecurityDescriptorDacl");
    // SAFETY: `process` is a live handle with `WRITE_DAC`; `psd` holds a DACL.
    let set = unsafe { SetKernelObjectSecurity(process, DACL_SECURITY_INFORMATION, psd) };
    // SAFETY: `process` is an owned handle we are done with.
    unsafe { CloseHandle(process) }.expect("CloseHandle(process)");
    set.expect("SetKernelObjectSecurity(DACL)");
}

/// The image path of process `pid`, read on a handle of its own: `Ok(None)` once the process is gone,
/// `Err` when it cannot be opened or its image cannot be read while it is live. A process that exits
/// with 259 reads as live (the fixtures' never do, see `is_running`).
pub(crate) fn image_of(pid: u32) -> windows::core::Result<Option<String>> {
    use super::backend::{close, open_classified, Opened};
    let handle = match open_classified(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Opened::Found(handle) => handle,
        Opened::Gone => return Ok(None),
        Opened::Denied(e) => return Err(e),
    };
    // 32 767 UTF-16 units and a terminator: the longest path Windows has.
    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    // SAFETY: `handle` is a live handle with the query right, and `len` is `buffer`'s length in units.
    let read = unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut len) };
    let mut exit_code = 0u32;
    // SAFETY: `handle` is live and owned here.
    let exit = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    close(handle);
    match (read, exit) {
        (Ok(()), _) => Ok(Some(String::from_utf16_lossy(&buffer[..len as usize]))),
        (Err(_), Err(e)) => Err(e),
        (Err(e), Ok(())) if exit_code == STILL_ACTIVE.0 as u32 => Err(e),
        (Err(_), Ok(())) => Ok(None),
    }
}

/// [`image_of`] for the fixtures' children; panics where it errs.
fn image_file_name(pid: u32) -> Option<String> {
    image_of(pid).unwrap_or_else(|e| panic!("fixture: the image of the process {pid} cannot be read: {e}"))
}

/// Whether the image path `image` has the file name `file_name`, compared without case.
pub(crate) fn image_named(image: &str, file_name: &str) -> bool {
    std::path::Path::new(image)
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(file_name))
}

/// Whether process `pid` runs the image whose file name is `file_name` (`"more.com"`, the child the
/// fixtures hold, see [`crate::test_child::windows_more`]; `"cmd.exe"`); `false` once it is gone.
/// Needs a process this user can open and whose image reads, and panics otherwise (see [`image_of`]).
pub(crate) fn has_image(pid: u32, file_name: &str) -> bool {
    image_file_name(pid).is_some_and(|image| image_named(&image, file_name))
}

/// Sentinel for [`spawn_with_ace`]: build the DACL with no ACE at all.
const NO_ACE: u32 = u32::MAX;

/// A live child whose process object grants us only the mask passed to [`spawn_restricted`].
/// Terminated and closed on drop.
pub(crate) struct RestrictedChild {
    /// Holds the creator's full-access handles and kills the child on drop.
    child: RawChild,
    /// Kills the whole tree when closed. `TerminateProcess` does NOT cascade, so without
    /// this `spawn_restricted_shell`'s `cmd.exe` would die and leave the `more.com` it
    /// launched behind. `wait_for_child` reads this job's members.
    job: HANDLE,
    /// The write end of the stdin the `more.com` blocks on, held so that only a kill ends it.
    stdin: Option<std::io::PipeWriter>,
}

impl RestrictedChild {
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The creator's full-access handle — the only way to read this child's identity.
    pub(crate) fn handle(&self) -> HANDLE {
        HANDLE(self.child.process().as_raw_handle())
    }

    /// `STILL_ACTIVE` while running, else the recorded exit code. Read through the owned
    /// handle, so the DACL never affects it.
    pub(crate) fn exit_code(&self) -> u32 {
        let mut code = 0u32;
        // SAFETY: `self.handle` is our live, owned, full-access process handle.
        unsafe { GetExitCodeProcess(self.handle(), &mut code) }.expect("GetExitCodeProcess on an owned handle");
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
        let waited = unsafe { WaitForSingleObject(self.handle(), INFINITE) };
        assert_eq!(
            waited,
            WAIT_OBJECT_0,
            "fixture: wait on pid {} returned {waited:?}",
            self.pid()
        );
    }

    /// The pid of the `more.com` this fixture's shell launched, once it exists.
    ///
    /// Reads the fixture's job, not the process tree: the job lists exactly the processes
    /// created under the shell, so a pre-existing orphan whose creator pid was recycled onto
    /// this shell is not in it. The job also holds the console host (`conhost.exe`) the shell
    /// was given, listed before `more`, so the child is the member whose image is `more.com`.
    /// Nothing opens the shell, which may grant us no query right (`spawn_restricted_shell`
    /// with `PROCESS_SYNCHRONIZE`); the members are opened by pid, and they are not
    /// DACL-restricted.
    ///
    /// No event announces the child (a job's completion messages are not guaranteed to be
    /// delivered), so this re-reads the live member list until `cmd /c` has created it.
    pub(crate) fn wait_for_child(&self) -> u32 {
        loop {
            assert!(self.is_running(), "the fixture shell exited before spawning its child");
            let members = crate::containment::windows::query_job_pid_list(self.job).expect("the fixture job's members");
            if let Some(pid) = members
                .into_iter()
                .filter(|&pid| pid != self.pid())
                .find(|&pid| has_image(pid, "more.com"))
            {
                return pid;
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
        if let Err(e) = unsafe { TerminateProcess(self.handle(), 1) } {
            if !self.is_running() {
                return Ok(()); // it exited on its own between our read and the call — fine
            }
            // Do NOT fall through to the wait: nothing asked the child to exit, so the wait
            // would park forever.
            return Err(format!(
                "fixture teardown: TerminateProcess(pid {}) failed: {e}",
                self.pid()
            ));
        }
        // SAFETY: `self.handle` is live and we just asked the child to exit, so this wait is
        // bounded by that exit.
        let waited = unsafe { WaitForSingleObject(self.handle(), INFINITE) };
        if waited != WAIT_OBJECT_0 {
            return Err(format!(
                "fixture teardown: wait on pid {} returned {waited:?}",
                self.pid()
            ));
        }
        Ok(())
    }
}

impl Drop for RestrictedChild {
    fn drop(&mut self) {
        // Never let a teardown failure unwind out of `drop` before the close below: the
        // child is still ALIVE on that path (that is what makes it a failure), and the `RawChild`
        // field, dropped after this, kills it and closes its handles.
        let failure = self.try_terminate().err();
        // Closing the job is what kills any grandchildren.
        // SAFETY: the job handle is ours and still open.
        if let Err(e) = unsafe { CloseHandle(self.job) } {
            log::error!(
                "fixture teardown: CloseHandle(job) for pid {} failed: {report}",
                self.pid(),
                report = crate::error::Report(&e)
            );
        }
        if let Some(what) = failure {
            log::error!("{what}");
            // The `RawChild` field's own kill, run after this, ignores its result. Run it here once
            // too, so that a child it could not end is reported. A failure on a child that has
            // exited meanwhile is the ordinary harmless case.
            if let Err(e) = self.child.kill() {
                if self.is_running() {
                    log::error!(
                        "fixture teardown: the second TerminateProcess(pid {}) failed: {e}",
                        self.pid()
                    );
                }
            }
            if !std::thread::panicking() {
                panic!("{what}");
            }
        }
    }
}

/// Spawn a long-running child whose process-object DACL allows our user SID exactly
/// `granted | PROCESS_TERMINATE` and nothing else.
pub(crate) fn spawn_restricted(alone: &Completion, granted: u32) -> RestrictedChild {
    spawn_with_ace(alone, granted | PROCESS_TERMINATE.0)
}

/// Spawn a child that even `PROCESS_TERMINATE` cannot open by pid. `Drop` still tears it
/// down through the owned handle.
///
/// Uses an EMPTY DACL, not an ACE with a zero access mask: an empty DACL is Windows'
/// documented "grant nothing to anyone" form, whereas a zero-mask ACE is unspecified — it
/// might be rejected by `AddAccessAllowedAce` (panicking the fixture) or normalized away
/// (silently granting access, which would send all of its consumers down the `Opened::Found`
/// path while still reporting green).
pub(crate) fn spawn_unkillable(alone: &Completion) -> RestrictedChild {
    spawn_with_ace(alone, NO_ACE)
}

/// Grants `PROCESS_QUERY_LIMITED_INFORMATION` and nothing else — identity is readable by pid
/// but `PROCESS_TERMINATE` and `PROCESS_SYNCHRONIZE` are denied, which is the only shape that
/// opens with the query right alone (`spawn_restricted` always ORs in `PROCESS_TERMINATE`).
pub(crate) fn spawn_query_only(alone: &Completion) -> RestrictedChild {
    spawn_with_ace(alone, PROCESS_QUERY_LIMITED_INFORMATION.0)
}

/// [`spawn_query_only`] with no console (`DETACHED_PROCESS`, where the others pass
/// `CREATE_NO_WINDOW`), so the child brings no console host along: for a test that needs the
/// restricted child to be the only process of the job it is put in.
pub(crate) fn spawn_query_only_without_console(alone: &Completion) -> RestrictedChild {
    spawn_with_ace_running(
        alone,
        PROCESS_QUERY_LIMITED_INFORMATION.0,
        &crate::test_child::windows_more(),
        &[],
        DETACHED_PROCESS,
    )
}

/// Like [`spawn_restricted`], but the restricted process is a shell that spawns an ordinary
/// grandchild. A DACL is not inherited, so the grandchild is freely openable while its
/// parent is not — the only way to build "my parent is access-denied" from a test.
pub(crate) fn spawn_restricted_shell(alone: &Completion, granted: u32) -> RestrictedChild {
    let more = crate::test_child::windows_more();
    spawn_with_ace_running(
        alone,
        granted | PROCESS_TERMINATE.0,
        &crate::test_child::system32("cmd.exe"),
        &[std::path::Path::new("/c"), &more],
        CREATE_NO_WINDOW,
    )
}

/// Like [`spawn_restricted`], but the caller holds the write end of the child's stdin: dropping it
/// lets the child exit by itself, with code 0. For a test whose kill is the behaviour under test:
/// the child it spares ends on that release, so a kill that sent nothing fails an assertion on the
/// exit code (`1` for a kill) instead of leaving a wait on a child that never ends.
pub(crate) fn spawn_restricted_releasable(alone: &Completion, granted: u32) -> (RestrictedChild, std::io::PipeWriter) {
    let mut child = spawn_restricted(alone, granted);
    let writer = child.stdin.take().expect("the fixture holds the child's stdin");
    (child, writer)
}

fn spawn_with_ace(alone: &Completion, granted: u32) -> RestrictedChild {
    spawn_with_ace_running(
        alone,
        granted,
        &crate::test_child::windows_more(),
        &[],
        CREATE_NO_WINDOW,
    )
}

/// Panics on any Win32 failure: a fixture that silently degrades would make its consumers
/// pass vacuously. Runs `exe` with `args` (`raw_spawn`'s command line, `exe` always quoted). The child
/// reads a piped stdin whose write end the [`RestrictedChild`] holds, and writes to `NUL`.
///
/// `console` is every creation flag but `CREATE_SUSPENDED`, which the spawn adds (`Console::Asked`):
/// `CREATE_NO_WINDOW` or `DETACHED_PROCESS` for a hidden or absent console; `0` gives the child a
/// visible console window.
///
/// The caller must not hold the spawn lock, which the spawn takes.
fn spawn_with_ace_running(
    alone: &Completion,
    granted: u32,
    exe: &std::path::Path,
    args: &[&std::path::Path],
    console: PROCESS_CREATION_FLAGS,
) -> RestrictedChild {
    use std::os::windows::io::AsHandle as _;
    let (reader, writer) = std::io::pipe().expect("pipe");
    let null = std::fs::OpenOptions::new().write(true).open("NUL").expect("open NUL");

    // Before the child is created, so no denial assertion can observe a token that still
    // bypasses DACLs.
    drop_se_debug_privilege(alone);

    // Our own user SID, from our own token. `token` is a real handle — closed below.
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle needing no close.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.expect("OpenProcessToken");
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 is the documented size query; it fails with
    // ERROR_INSUFFICIENT_BUFFER and writes the required size.
    _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
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

    // `sa` and the DACL it points at are alive for the duration of the call. The child's console
    // is `console`, the whole flag word (`Console::Asked`), so `CREATE_NO_WINDOW` or
    // `DETACHED_PROCESS` is the caller's choice.
    let options = RawOptions {
        quote_exe: true,
        stdio: RawStdio::Given {
            stdin: Some(reader.as_handle()),
            output: null.as_handle(),
        },
        process_security: Some(&sa),
        ..Default::default()
    };
    let child = spawn_locked_raw_with(exe, args, &[], console.0 | CREATE_SUSPENDED.0, Console::Asked, options)
        .expect("the restricted fixture child");
    // The child holds its own copies; these ends stay with us only until here.
    drop((reader, null));

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
    unsafe { AssignProcessToJobObject(job, HANDLE(child.process().as_raw_handle())) }
        .expect("AssignProcessToJobObject");

    // Only NOW may the child run. Windows enrols a process-s children in its job only from
    // the moment the parent is already a member, so a child that started running before the
    // assignment could spawn a grandchild permanently outside the job - which is exactly the
    // orphan the job exists to prevent. CREATE_SUSPENDED closes that window by construction.
    // SAFETY: the thread is the freshly created, still-suspended main thread.
    let prev = unsafe { ResumeThread(HANDLE(child.thread().as_raw_handle())) };
    assert_eq!(prev, 1, "the fixture child must resume from exactly one suspend");

    let child = RestrictedChild {
        child,
        job,
        stdin: Some(writer),
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
