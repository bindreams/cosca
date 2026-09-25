//! Platform probes: can an UNELEVATED Windows process start an ELEVATED child without
//! `ShellExecuteEx("runas")`?
//!
//! cosca's Windows elevated path is `ShellExecuteExW` + the `runas` verb, which costs it stdio
//! handles, `fd >= 3`, environment control and — as `windows_shell_resolution.rs` measured —
//! control over which image actually loads. The documented alternatives (`CreateProcessAsUserW`,
//! `CreateProcessWithTokenW`, `CreateProcessWithLogonW`) all take an `lpApplicationName` that is
//! documented NOT to search and NOT to append an extension, and all take a `STARTUPINFOW`. If any
//! of them can produce an elevated child from a medium-integrity caller, cosca can leave
//! `ShellExecuteEx` behind.
//!
//! These are **probes, not assertions about cosca**. They print what they measured. Each still
//! FAILS if the measurement could not be taken, so an inconclusive run is never a silent pass.
//!
//! # Integrity level is part of every result
//!
//! The question is about an UNELEVATED caller, and every machine these run on (a GitHub-hosted
//! Windows runner, an OpenSSH admin session) hands the test an ELEVATED token. A measurement taken
//! at high integrity does not answer the question, so every report line carries the integrity RID
//! it was taken at.
//!
//! Two probes reach the unelevated case, and only one of them is trustworthy on every host:
//!
//! - [`does_create_process_with_logon_elevate`] logs a throwaway administrator on and runs the
//!   whole report inside the resulting child. That child is a REAL process from a REAL logon, and
//!   it is where the unelevated answers come from. It needs a disposable host.
//! - [`unelevated_caller_view`] derives a medium token from this process's own and starts a child
//!   under it, needing no account. On a desktop over SSH the lowered-integrity child can fail to
//!   open the caller's window station and die in loader init (0xC0000142); on a GitHub runner (run
//!   35850159223) it instead SUCCEEDS and produces a full report, so 0xC0000142 is a possible
//!   failure of this route, not its guaranteed outcome, and the probe fails loudly rather than
//!   reporting a misleading negative if it happens. Succeeding is not the same as measuring an
//!   unelevated caller, though: `TokenIsElevated` is fixed at token creation from the source
//!   logon's elevation type, so on a Default (non-split) admin token — what run 35850159223's
//!   GitHub runner has — synthesis cannot clear it, and the resulting child is a lowered-integrity
//!   ELEVATED caller, not an unelevated one. The probe prints and labels which case it measured;
//!   read its output before trusting its report as the unelevated answer.
//!
//! # Why they are `#[ignore]`d, and the two safety gates
//!
//! They create processes with derived tokens, and two of them change machine state. Opt in:
//!
//! ```text
//! cargo nextest run --test windows_elevation_routes --run-ignored only --no-capture
//! ```
//!
//! Three probes additionally refuse to run — loudly, by panicking, never by skipping — unless an
//! environment variable says the host is disposable:
//!
//! - `COSCA_PROBE_ALLOW_ACCOUNTS=1` — creates and deletes a local user account. Required by
//!   [`does_create_process_with_logon_elevate`] and [`which_logon_types_return_a_filtered_token`].
//! - `COSCA_PROBE_ALLOW_STATE=1` — registers and deletes a scheduled task. Required by
//!   [`can_this_caller_register_a_runlevel_highest_task`].
//!
//! `does_create_process_with_logon_elevate` and `which_logon_types_return_a_filtered_token` both
//! create their scratch accounts under the same two fixed names (`coscaprobeadm`,
//! `coscaprobestd`), so they must never run concurrently with each other; `--no-capture` already
//! forces nextest to run every test in this invocation serially, and the `windows-elevation-routes`
//! test group capped at one thread in `.config/nextest.toml` gives the same guarantee independent
//! of that flag.
//!
//! Both are set by the `executing` job of `.github/workflows/windows-probes.yaml`, which runs only
//! when dispatched with `run_executing_probes`, on a GitHub-hosted runner: an ephemeral VM
//! destroyed after the job. They must never be set on a machine anyone depends on.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::os::windows::io::BorrowedHandle;
use std::path::{Path, PathBuf};

use cosca::Job;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{
    AllocateAndInitializeSid, CreateRestrictedToken, DuplicateTokenEx, FreeSid, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, LogonUserW, LookupPrivilegeNameW, SecurityImpersonation,
    SetTokenInformation, TokenElevation, TokenElevationType, TokenIntegrityLevel, TokenLinkedToken, TokenPrimary,
    TokenPrivileges, DISABLE_MAX_PRIVILEGE, LOGON32_LOGON_BATCH, LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK,
    LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, PSID,
    SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_NT_AUTHORITY, SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK,
    TOKEN_ADJUST_DEFAULT, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_LINKED_TOKEN,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::SystemServices::{
    DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID, SECURITY_MANDATORY_MEDIUM_RID,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, CreateProcessWithLogonW, CreateProcessWithTokenW, GetCurrentProcess,
    GetExitCodeProcess, OpenProcess, OpenProcessToken, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, INFINITE,
    LOGON_WITH_PROFILE, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

/// A child is an external process that might never exit, so this is the honest failure bound
/// surfaced to whoever reads the log — not a synchronisation device. If it trips, [`wait_for`]
/// kills the child's whole job tree, then waits (unboundedly) on the child's OWN process handle
/// for that kill to land, and only then reports that the child did not finish; it never silently
/// continues, and never touches a file or account the child might still hold open. That final
/// wait covers only the immediate child: the job handle is already closed by the time the kill
/// call returns, so there is nothing left to wait on for the rest of the tree.
const CHILD_EXIT_BOUND_MS: u32 = 120_000;

// ── token inspection ═════════════════════════════════════════════════════════════════

/// An owned token handle. Closing twice or leaking across a probe would corrupt later
/// measurements, so ownership is never implicit.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: a token handle owned by this guard, closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// `GetTokenInformation`'s two-call protocol, into a `u64`-backed (8-byte-aligned) buffer —
/// `TOKEN_MANDATORY_LABEL` and `TOKEN_PRIVILEGES` both contain pointer-aligned fields, so a
/// `Vec<u8>` would be misaligned UB.
fn token_info(token: HANDLE, class: windows::Win32::Security::TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, String> {
    let mut needed = 0u32;
    // SAFETY: the sizing call is documented to fail with ERROR_INSUFFICIENT_BUFFER and write
    // `needed`; its Result is intentionally discarded.
    unsafe {
        let _ = GetTokenInformation(token, class, None, 0, &mut needed);
    }
    if needed == 0 {
        return Err(format!("could not size token class {}", class.0));
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // The length passed must be the EXACT size the kernel asked for, not the rounded-up
    // allocation: the fixed-size classes (`TokenElevation`, `TokenElevationType`) reject anything
    // longer with ERROR_BAD_LENGTH. Measured — an earlier version passed the padded capacity and
    // every elevation query on a real machine came back 0x80070018.
    let size = needed;
    // SAFETY: `buf` is 8-aligned and at least `size` bytes.
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), size, &mut needed) }
        .map_err(|e| format!("GetTokenInformation(class {}) failed: {e}", class.0))?;
    Ok(buf)
}

fn token_is_elevated(token: HANDLE) -> Result<bool, String> {
    let buf = token_info(token, TokenElevation)?;
    // SAFETY: the kernel wrote a TOKEN_ELEVATION at the head of an 8-aligned buffer.
    Ok(unsafe { buf.as_ptr().cast::<TOKEN_ELEVATION>().read() }.TokenIsElevated != 0)
}

/// 1 = Default (UAC off, or an account with no split), 2 = Full, 3 = Limited.
fn token_elevation_type(token: HANDLE) -> Result<i32, String> {
    let buf = token_info(token, TokenElevationType)?;
    // SAFETY: the kernel wrote a TOKEN_ELEVATION_TYPE (an i32) at the head of the buffer.
    Ok(unsafe { buf.as_ptr().cast::<i32>().read() })
}

fn elevation_type_name(t: i32) -> &'static str {
    match t {
        1 => "Default(no split token)",
        2 => "Full(elevated half of a split)",
        3 => "Limited(filtered half of a split)",
        _ => "unknown",
    }
}

fn token_integrity_rid(token: HANDLE) -> Result<u32, String> {
    let buf = token_info(token, TokenIntegrityLevel)?;
    // SAFETY: the kernel wrote a TOKEN_MANDATORY_LABEL; its `Sid` field is read unaligned, never
    // through a reference, and points into `buf`, which outlives this block.
    unsafe {
        let sid = std::ptr::read_unaligned(std::ptr::addr_of!(
            (*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid
        ));
        let count = GetSidSubAuthorityCount(sid);
        if count.is_null() || *count == 0 {
            return Err("integrity SID has no sub-authorities".into());
        }
        Ok(*GetSidSubAuthority(sid, u32::from(*count) - 1))
    }
}

fn integrity_name(rid: u32) -> &'static str {
    match rid {
        0x0000 => "Untrusted",
        0x1000 => "Low",
        0x2000 => "Medium",
        0x2100 => "Medium Plus",
        0x3000 => "High",
        0x4000 => "System",
        _ => "?",
    }
}

/// Every privilege in the token, with whether it is enabled. The answer to "which of
/// `SeImpersonatePrivilege` / `SeIncreaseQuotaPrivilege` / `SeAssignPrimaryTokenPrivilege` does
/// this caller hold" is the whole of question 2, and it is read here rather than assumed.
fn token_privileges(token: HANDLE) -> Result<Vec<String>, String> {
    let buf = token_info(token, TokenPrivileges)?;
    let mut out = Vec::new();
    // SAFETY: the kernel wrote a TOKEN_PRIVILEGES followed by `PrivilegeCount`
    // LUID_AND_ATTRIBUTES; the array is read through a raw pointer walked by index.
    unsafe {
        let head = buf.as_ptr().cast::<TOKEN_PRIVILEGES>();
        let count = std::ptr::read_unaligned(std::ptr::addr_of!((*head).PrivilegeCount));
        let first = std::ptr::addr_of!((*head).Privileges).cast::<windows::Win32::Security::LUID_AND_ATTRIBUTES>();
        for i in 0..count as usize {
            let entry = std::ptr::read_unaligned(first.add(i));
            let mut len = 0u32;
            let _ = LookupPrivilegeNameW(PCWSTR::null(), &entry.Luid, None, &mut len);
            let mut name = vec![0u16; len.max(1) as usize];
            let ok =
                LookupPrivilegeNameW(PCWSTR::null(), &entry.Luid, Some(PWSTR(name.as_mut_ptr())), &mut len).is_ok();
            let label = if ok {
                String::from_utf16_lossy(&name[..len as usize])
            } else {
                format!("LUID({:x}:{:x})", entry.Luid.HighPart, entry.Luid.LowPart)
            };
            // SE_PRIVILEGE_ENABLED is 0x2; anything else is present-but-disabled, which is still
            // usable (a holder can enable it with AdjustTokenPrivileges), so both are reported.
            let state = if entry.Attributes.0 & 0x2 != 0 {
                "enabled"
            } else {
                "disabled"
            };
            out.push(format!("{label}({state})"));
        }
    }
    Ok(out)
}

/// The linked token, if this is half of a UAC split. `TokenLinkedToken` is the one documented way
/// a filtered process can even NAME its elevated counterpart, so whether the query succeeds at
/// medium integrity is load-bearing.
fn linked_token(token: HANDLE) -> Result<Token, String> {
    let buf = token_info(token, TokenLinkedToken)?;
    // SAFETY: the kernel wrote a TOKEN_LINKED_TOKEN (a single HANDLE) at the head of the buffer.
    // The handle it contains is OURS to close, which `Token` does.
    let h = unsafe { buf.as_ptr().cast::<TOKEN_LINKED_TOKEN>().read() }.LinkedToken;
    if h.is_invalid() {
        return Err("TokenLinkedToken returned an invalid handle".into());
    }
    Ok(Token(h))
}

fn open_own_token(access: TOKEN_ACCESS_MASK) -> Result<Token, String> {
    let mut h = HANDLE::default();
    // SAFETY: a standard token open on the current process; the handle is wrapped immediately.
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut h) }
        .map_err(|e| format!("OpenProcessToken({access:?}) failed: {e}"))?;
    Ok(Token(h))
}

/// A one-line summary plus the privilege list, for any token.
fn describe(out: &mut String, label: &str, token: HANDLE) {
    let elevated = token_is_elevated(token).map_or_else(|e| e, |v| v.to_string());
    let etype = token_elevation_type(token).map_or_else(|e| e, |v| format!("{v} {}", elevation_type_name(v)));
    let rid = token_integrity_rid(token).map_or_else(|e| e, |v| format!("0x{v:04x} {}", integrity_name(v)));
    let _ = writeln!(
        out,
        "  {label}: elevated={elevated} elevation_type={etype} integrity={rid}"
    );
    match token_privileges(token) {
        Ok(p) if p.is_empty() => {
            let _ = writeln!(out, "    privileges: (none)");
        }
        Ok(p) => {
            let _ = writeln!(out, "    privileges: {}", p.join(", "));
        }
        Err(e) => {
            let _ = writeln!(out, "    privileges: <{e}>");
        }
    }
}

// ── the measurement ══════════════════════════════════════════════════════════════════

/// Builds an environment block for a child. Doubles as a measurement in its own right: if a
/// token-based spawn API accepts this and the child sees the variables, then cosca's `.env()` —
/// which `ShellExecuteEx` cannot honour at all — is supportable on that route.
///
/// Built from an allowlist, not a copy of this process's whole environment: several routes here
/// hand the block to a DIFFERENT account (a scratch logon, a medium token derived from this
/// process's own), and carrying this process's full environment across would leak whatever this
/// caller happens to have set — including any secrets a CI runner exports — into a child running
/// as, or purporting to measure, someone else. Only what a freshly logged-on account needs to run
/// anything at all (`SystemRoot`, `PATH`, `TEMP`/`TMP`, `COMSPEC`, `PATHEXT`), plus any
/// `COSCA_PROBE_*` variable this file itself uses to talk to its children, plus whatever the
/// caller passes in `extra`.
fn env_block(extra: &[(&str, String)]) -> Vec<u16> {
    const ALLOWLIST: [&str; 6] = ["SYSTEMROOT", "PATH", "TEMP", "TMP", "COMSPEC", "PATHEXT"];
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in std::env::vars_os() {
        let k = k.to_string_lossy().into_owned();
        let upper = k.to_ascii_uppercase();
        if ALLOWLIST.contains(&upper.as_str()) || upper.starts_with("COSCA_PROBE_") {
            map.insert(k, v.to_string_lossy().into_owned());
        }
    }
    for (k, v) in extra {
        map.insert((*k).to_string(), v.clone());
    }
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in &map {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// The command line that re-runs this test binary's `measure_this_token`. `--exact` pins it to
/// that one test, so a child never re-enters the spawning probes and recursion is structural
/// rather than bounded by a counter.
fn report_cmdline(exe: &Path) -> String {
    format!(
        "\"{}\" measure_this_token --exact --ignored --nocapture --test-threads=1",
        exe.display()
    )
}

fn self_report_cmdline() -> String {
    report_cmdline(&std::env::current_exe().expect("the test binary knows its own path"))
}

/// Assign a just-created SUSPENDED child to a fresh `KILL_ON_JOB_CLOSE` job, then resume its
/// initial thread — the mandatory sequence [`cosca::Job::assign`]'s own docs require, closing the
/// race where a resumed-too-early child (or a grandchild it forks) escapes containment before
/// assignment lands. Every `CreateProcess*` call in this file that hands back a
/// `PROCESS_INFORMATION` uses `CREATE_SUSPENDED` and routes through this function, so `wait_for`
/// can always terminate the whole tree — not just the immediate child — on a timeout.
///
/// Panics rather than returning an error: an uncontained child defeats the reason every spawn in
/// this file goes through a job at all, and `Job::assign`'s own contract forbids resuming a
/// process that failed to join one, so there is no safe fallback measurement to report instead. On
/// an assign failure the child is still suspended and was never given to any job, so it is torn
/// down here directly — `TerminateProcess`, waited out, both handles closed — before panicking,
/// rather than leaking a suspended, uncontained process behind a panicking test.
fn contain(pi: &PROCESS_INFORMATION, context: &str) -> Job {
    // SAFETY: `pi.hProcess` is a live, just-created suspended process handle; the borrow lasts
    // only for the duration of this call, and the process outlives it (owned by the caller).
    let job = match Job::assign(unsafe { BorrowedHandle::borrow_raw(pi.hProcess.0.cast()) }) {
        Ok(job) => job,
        Err(e) => {
            // SAFETY: `pi.hProcess` is a live, still-suspended process handle that was never
            // assigned to any job (assign just failed), so terminating and waiting it out
            // directly is the only way to reap it; both handles are closed exactly once after.
            unsafe {
                let _ = TerminateProcess(pi.hProcess, 1);
                let _ = WaitForSingleObject(pi.hProcess, INFINITE);
                let _ = CloseHandle(pi.hThread);
                let _ = CloseHandle(pi.hProcess);
            }
            panic!("{context}: could not contain the child in a kill-on-close job: {e}");
        }
    };
    // SAFETY: the job now has kill authority over this still-suspended thread, so resuming it now
    // — the last step of the mandated sequence — cannot let anything escape containment.
    let resumed = unsafe { ResumeThread(pi.hThread) };
    assert_ne!(
        resumed,
        u32::MAX,
        "{context}: ResumeThread failed (returned -1) on a child just assigned to its containing job"
    );
    job
}

/// Wait for a child held in `job`, and return its exit code — or a description of why it could
/// not be measured. `CHILD_EXIT_BOUND_MS` is given to this one, outermost wait only: on a timeout
/// it kills the whole job, then waits on the CHILD'S OWN process handle for that kill to actually
/// land — not `job.wait_tree()`, which would return an error at once here: `Job::kill_tree`
/// closes the underlying job handle as part of tearing the job down (see its doc), so by the time
/// `wait_tree` could run there is nothing left for it to wait on. That final wait has no bound of
/// its own because it is waiting on a real kernel outcome (the kill taking effect), not racing a
/// clock — so by the time this returns, the immediate child is provably gone and it is safe for
/// the caller to touch any file or account it might otherwise still hold open. It only covers the
/// immediate child, not the rest of the tree: once the job handle is closed there is no longer a
/// way to wait on the tree as a whole.
fn wait_for(pi: &PROCESS_INFORMATION, job: &Job) -> Result<u32, String> {
    // SAFETY: `pi.hProcess` was just returned by CreateProcess* and is closed exactly once below.
    let waited = unsafe { WaitForSingleObject(pi.hProcess, CHILD_EXIT_BOUND_MS) };
    if waited != WAIT_OBJECT_0 {
        let killed = job.kill_tree();
        // `kill_tree` already closed the job handle, so `job.wait_tree()` would fail immediately
        // here instead of waiting for anything (see this function's doc comment). Wait on the
        // child's own process handle instead — the one primitive still open that can actually
        // observe the kill landing.
        // SAFETY: `pi.hProcess` is still a valid, open handle to the child; waiting on it does
        // not consume or invalidate it, so it is still safe to close below.
        let waited_after_kill = unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
        // SAFETY: the wait above means the immediate child is confirmed gone (or the wait itself
        // failed, which `waited_after_kill` reports); both handles are closed exactly once.
        unsafe {
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
        }
        return Err(format!(
            "the child did not exit within {CHILD_EXIT_BOUND_MS}ms; kill_tree={killed:?} \
             wait_after_kill={waited_after_kill:?}"
        ));
    }
    // SAFETY: the process signalled within the bound above; both handles are closed exactly once.
    unsafe {
        let mut code = 0u32;
        let got = GetExitCodeProcess(pi.hProcess, &mut code);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        got.map_err(|e| format!("GetExitCodeProcess failed: {e}"))?;
        Ok(code)
    }
}

/// Read back a report a child wrote, indented so nesting is visible in the log.
fn splice_child_report(out: &mut String, path: &Path) {
    match std::fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => {
            for line in text.lines() {
                let _ = writeln!(out, "    | {line}");
            }
        }
        Ok(_) => {
            let _ = writeln!(out, "    | <the child produced an EMPTY report>");
        }
        Err(e) => {
            let _ = writeln!(out, "    | <no report at {}: {e}>", path.display());
        }
    }
}

/// Everything this process can find out about its own token, and about what its token lets it do.
/// Written into a string so a child can hand it back through a file.
fn measure(out: &mut String) {
    let _ = writeln!(out, "=== token report (pid {}) ===", std::process::id());
    match open_own_token(TOKEN_QUERY | TOKEN_DUPLICATE) {
        Ok(t) => describe(out, "current process token", t.0),
        Err(e) => {
            let _ = writeln!(out, "  current process token: <{e}>");
        }
    }

    // The linked token: does a filtered caller get to see its elevated counterpart, and can it
    // turn that into something spawnable?
    let _ = writeln!(out, "=== TokenLinkedToken chain ===");
    match open_own_token(TOKEN_QUERY | TOKEN_DUPLICATE) {
        Err(e) => {
            let _ = writeln!(out, "  step 1 OpenProcessToken: FAILED <{e}>");
        }
        Ok(own) => match linked_token(own.0) {
            Err(e) => {
                let _ = writeln!(out, "  step 1 GetTokenInformation(TokenLinkedToken): FAILED <{e}>");
            }
            Ok(linked) => {
                let _ = writeln!(out, "  step 1 GetTokenInformation(TokenLinkedToken): OK");
                describe(out, "linked token", linked.0);
                let mut primary = HANDLE::default();
                // SAFETY: `linked` is a live token handle; the duplicate is wrapped below.
                let dup = unsafe {
                    DuplicateTokenEx(
                        linked.0,
                        TOKEN_ALL_ACCESS,
                        None,
                        SecurityImpersonation,
                        TokenPrimary,
                        &mut primary,
                    )
                };
                match dup {
                    Err(e) => {
                        let _ = writeln!(out, "  step 2 DuplicateTokenEx(->primary): FAILED <{e}>");
                    }
                    Ok(()) => {
                        let primary = Token(primary);
                        let _ = writeln!(out, "  step 2 DuplicateTokenEx(->primary): OK");
                        describe(out, "duplicated primary token", primary.0);
                        spawn_attempts_with(out, "linked", primary.0);
                    }
                }
            }
        },
    }

    // Independently of whether the linked token was reachable: does this caller hold the
    // privileges the token-based spawn APIs require at all? Handing them the caller's OWN token
    // asks exactly that and nothing else — the token is unquestionably valid and assignable, so a
    // failure here can only be ERROR_PRIVILEGE_NOT_HELD or ERROR_ACCESS_DENIED, naming the
    // privilege that is missing. Without this, "the chain broke at step 2" would leave open
    // whether steps 3 and 4 might have worked with some other token.
    let _ = writeln!(
        out,
        "=== do the token-based spawn APIs work for this caller at all? ==="
    );
    match open_own_token(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY) {
        Err(e) => {
            let _ = writeln!(out, "  could not reopen own token: <{e}>");
        }
        Ok(own) => spawn_attempts_with(out, "own", own.0),
    }

    // Task Scheduler's gating question, asked from wherever this process is running. The docs say
    // a low-privilege process cannot register a RunLevel=HIGHEST task; when this runs inside a
    // medium-integrity child it is that claim under test rather than restated.
    if std::env::var_os("COSCA_PROBE_ALLOW_STATE").is_some_and(|v| v == "1") {
        let _ = writeln!(out, "=== can this caller register a RunLevel=HIGHEST task? ===");
        let (lines, _any_create_exited) = schtasks_registration_report();
        for line in lines {
            let _ = writeln!(out, "  {line}");
        }
    }
}

/// Try to register a scheduled task at each run level and report what `schtasks` said, plus
/// whether at least one `/create` call actually exited with a status — a caller for whom `schtasks`
/// itself could never even be launched measured nothing, no matter how many report lines come back.
/// Always attempts to delete what it created, on every path, and reports whether each `/delete`
/// succeeded rather than discarding that result.
fn schtasks_registration_report() -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut any_create_exited = false;
    let name = format!("cosca-probe-{}", std::process::id());
    for level in ["HIGHEST", "LIMITED"] {
        let tn = format!("{name}-{level}");
        match std::process::Command::new("schtasks")
            .args([
                "/create",
                "/tn",
                &tn,
                "/tr",
                "cmd.exe /c exit 0",
                "/sc",
                "ONCE",
                "/st",
                "23:59",
                "/rl",
                level,
                "/f",
            ])
            .output()
        {
            Ok(out) => {
                any_create_exited = true;
                lines.push(format!(
                    "/rl {level} -> {} {} {}",
                    out.status,
                    String::from_utf8_lossy(&out.stdout).trim(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            Err(e) => lines.push(format!("/rl {level} -> schtasks could not be run: {e}")),
        }
        match std::process::Command::new("schtasks")
            .args(["/delete", "/tn", &tn, "/f"])
            .output()
        {
            Ok(out) => lines.push(format!("/rl {level} delete -> {}", out.status)),
            Err(e) => lines.push(format!("/rl {level} delete -> schtasks could not be run: {e}")),
        }
    }
    (lines, any_create_exited)
}

/// Try to actually START something with `token`, by both documented routes, and report the exact
/// failure. If the linked elevated token is spawnable from a filtered caller, UAC's consent gate
/// is bypassable and these succeed; if it is not, the error code names the privilege that stopped
/// it. The child is this same test binary in report-only mode, so success is not taken on trust —
/// its integrity level is read back out of the report it writes.
fn spawn_attempts_with(out: &mut String, which: &str, token: HANDLE) {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");

    for (step, use_seclogon) in [("CreateProcessAsUserW", false), ("CreateProcessWithTokenW", true)] {
        let report = dir
            .path()
            .join(format!("{}.txt", if use_seclogon { "withtoken" } else { "asuser" }));
        let _ = std::fs::remove_file(&report);
        let block = env_block(&[
            ("COSCA_PROBE_REPORT_TO", report.display().to_string()),
            ("COSCA_PROBE_CHILD", "1".into()),
        ]);
        let mut cmd = wide(&self_report_cmdline());
        let si = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `cmd` is a NUL-terminated writable UTF-16 buffer and `block` a NUL-NUL-terminated
        // environment block; both outlive the call. `CREATE_SUSPENDED`: the child must not run
        // before `contain` has assigned it to a kill-on-close job.
        let res = unsafe {
            if use_seclogon {
                CreateProcessWithTokenW(
                    token,
                    CREATE_PROCESS_LOGON_FLAGS(0),
                    None,
                    Some(PWSTR(cmd.as_mut_ptr())),
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    Some(block.as_ptr().cast()),
                    None,
                    &si,
                    &mut pi,
                )
            } else {
                CreateProcessAsUserW(
                    Some(token),
                    None,
                    Some(PWSTR(cmd.as_mut_ptr())),
                    None,
                    None,
                    false,
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    Some(block.as_ptr().cast()),
                    None,
                    &si,
                    &mut pi,
                )
            }
        };
        match res {
            Err(e) => {
                let _ = writeln!(out, "  {step} [{which} token]: FAILED {e:?}");
            }
            Ok(()) => {
                let job = contain(&pi, &format!("PROBE spawn-attempts[{which}/{step}]"));
                let exit = wait_for(&pi, &job).map_or_else(|e| e, |c| format!("exit=0x{c:08x}"));
                let _ = writeln!(out, "  {step} [{which} token]: STARTED, {exit}. The child reports:");
                splice_child_report(out, &report);
            }
        }
    }
    // `dir` is a `tempfile::TempDir`; it removes itself on drop.
}

// ── probes ═══════════════════════════════════════════════════════════════════════════

/// The body a child runs when a spawning probe re-execs this binary: `COSCA_PROBE_REPORT_TO` names
/// the file to answer through, and `COSCA_PROBE_CHILD` suppresses the nested spawn attempts so a
/// child never recurses. [`logon_one_account`] deliberately spawns its child WITHOUT
/// `COSCA_PROBE_CHILD` set — see that function's doc comment — so that child runs the full chain,
/// the same as [`linked_token_chain_here`] does when run directly.
///
/// A direct, unspawned `--ignored` run (no `COSCA_PROBE_REPORT_TO`) has no report destination to
/// answer through and nothing spawned it, so it is given its own, narrower purpose here rather than
/// duplicating [`linked_token_chain_here`]'s whole-chain probe: report just this process's own
/// token, nothing more.
#[test]
#[ignore = "platform probe; opt in with --ignored"]
fn measure_this_token() {
    let mut out = String::new();
    // `ShellExecuteEx` cannot carry an environment at all, so whether an explicitly built block
    // survives a token-based spawn is one of the capabilities being measured. The canary is only
    // set by a probe that passed one.
    if let Ok(v) = std::env::var("COSCA_PROBE_ENV_CANARY") {
        let _ = writeln!(out, "  env block: the caller's COSCA_PROBE_ENV_CANARY arrived as {v:?}");
    }
    let report_to = std::env::var_os("COSCA_PROBE_REPORT_TO");
    if report_to.is_some() && std::env::var_os("COSCA_PROBE_CHILD").is_none() {
        // Spawned by `logon_one_account`: the child runs the whole chain.
        measure(&mut out);
    } else {
        // Either a child of `spawn_attempts_with` (`COSCA_PROBE_CHILD` is set, so it does not
        // recurse into more spawn attempts of its own), or a direct, unspawned `--ignored` run
        // with nothing to answer through — both get the same minimal, own-purpose report.
        let _ = writeln!(out, "=== token report (pid {}) ===", std::process::id());
        match open_own_token(TOKEN_QUERY | TOKEN_DUPLICATE) {
            Ok(t) => describe(&mut out, "current process token", t.0),
            Err(e) => {
                let _ = writeln!(out, "  current process token: <{e}>");
            }
        }
    }
    print!("{out}");
    if let Some(dest) = report_to {
        std::fs::write(&dest, &out)
            .unwrap_or_else(|e| panic!("could not write the report to {}: {e}", PathBuf::from(&dest).display()));
    }
}

/// Read ANOTHER process's token, named by PID in `COSCA_PROBE_INSPECT_PID`.
///
/// This is the only way to see a genuine UAC-FILTERED administrator token without logging on
/// interactively: point it at the `explorer.exe` of a signed-in split-token administrator and it
/// prints the exact privilege set that survives filtering. Microsoft documents only that "the
/// administrative Windows privileges and SIDs are removed" — no page enumerates which remain — so
/// the list this prints is a measurement filling a documented gap, and it decides whether the
/// `CreateProcessAsUser`/`CreateProcessWithToken` chain is even reachable from a filtered caller.
///
/// Read-only: `PROCESS_QUERY_LIMITED_INFORMATION` plus `TOKEN_QUERY`, nothing else.
#[test]
#[ignore = "platform probe; opt in with --ignored and COSCA_PROBE_INSPECT_PID=<pid>"]
fn measure_another_process_token() {
    let pid: u32 = match std::env::var("COSCA_PROBE_INSPECT_PID") {
        Ok(v) => v.trim().parse().expect("COSCA_PROBE_INSPECT_PID must be a decimal PID"),
        // With no target named, go looking for the interesting one: the shell of a signed-in
        // user. `tasklist` is read-only.
        Err(_) => {
            let out = std::process::Command::new("tasklist")
                .args(["/fi", "IMAGENAME eq explorer.exe", "/fo", "csv", "/nh"])
                .output()
                .expect("tasklist must be runnable to find a target process");
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .find_map(|l| l.split(',').nth(1)?.trim_matches('"').parse().ok())
                .expect(
                    "no explorer.exe is running, so this host has no signed-in desktop whose \
                     filtered token could be read. Point the probe at a specific process with \
                     COSCA_PROBE_INSPECT_PID=<pid>, or run it on a machine with an interactive \
                     session — a headless CI runner cannot take this measurement.",
                )
        }
    };

    // SAFETY: a query-only open of a live PID; both handles are closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .unwrap_or_else(|e| panic!("could not open pid {pid} for query: {e}"));
    let mut token = HANDLE::default();
    // SAFETY: `handle` is live; the token is wrapped in a guard immediately.
    let opened = unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) };
    // SAFETY: our own process handle, closed once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    opened.unwrap_or_else(|e| panic!("could not open pid {pid}'s token: {e}"));
    let token = Token(token);

    let mut out = String::new();
    let _ = writeln!(out, "=== token of pid {pid} ===");
    describe(&mut out, "that process's token", token.0);
    match linked_token(token.0) {
        Ok(linked) => describe(&mut out, "its TokenLinkedToken", linked.0),
        Err(e) => {
            let _ = writeln!(out, "  its TokenLinkedToken: <{e}>");
        }
    }
    print!("{out}");
    assert!(
        out.contains("integrity="),
        "the target process's token could not be described, so nothing was measured"
    );
}

/// The UAC policy in force. Without these values a token-shape measurement is uninterpretable: on
/// a machine with `EnableLUA=0` there is no filtering to observe and every result below would be
/// a misleading "elevation just works".
#[test]
#[ignore = "platform probe; opt in with --ignored"]
fn measure_uac_policy() {
    const KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let mut any = false;
    for name in [
        "EnableLUA",
        "ConsentPromptBehaviorAdmin",
        "ConsentPromptBehaviorUser",
        "FilterAdministratorToken",
        "LocalAccountTokenFilterPolicy",
        "EnableInstallerDetection",
        "PromptOnSecureDesktop",
    ] {
        // `reg query` is read-only; nothing here writes to the registry.
        let out = std::process::Command::new("reg")
            .args(["query", KEY, "/v", name])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                any = true;
                let text = String::from_utf8_lossy(&o.stdout);
                let value = text
                    .lines()
                    .find(|l| l.contains(name))
                    .map_or("<unparsed>", str::trim)
                    .to_string();
                println!("PROBE uac-policy: {value}");
            }
            Ok(_) => println!("PROBE uac-policy: {name} = <not set>"),
            Err(e) => println!("PROBE uac-policy: {name} = <reg query failed: {e}>"),
        }
    }
    assert!(
        any,
        "not one UAC policy value could be read, so no token result below is interpretable"
    );
}

/// Question 2, measured at whatever integrity this process runs at. Read together with
/// [`unelevated_caller_view`], which takes the same measurement at medium integrity and is the one
/// that can actually answer the question — but only when its own report confirms
/// `TokenIsElevated=false`; see that function's doc for when it cannot.
#[test]
#[ignore = "platform probe; opt in with --ignored"]
fn linked_token_chain_here() {
    let mut out = String::new();
    measure(&mut out);
    print!("{out}");
    // `out.contains("step 1")` alone can never fail: `measure` always emits a "step 1 ..." line,
    // whether it succeeded or not, so that check asserts nothing. Require the line to actually
    // show a result — a successful open, or a failure carrying a real (non-empty) error — so a
    // future report-format change that dropped the outcome would fail this loudly instead of
    // sailing through a vacuous substring match.
    assert!(
        out.contains("step 1 GetTokenInformation(TokenLinkedToken): OK")
            || out.contains("step 1 OpenProcessToken: FAILED <")
            || out.contains("step 1 GetTokenInformation(TokenLinkedToken): FAILED <"),
        "the chain's step 1 produced neither a success nor a real error code, so nothing was \
         measured:\n{out}"
    );
}

/// **Question 2, properly.** Derive a medium-integrity token, start this binary under it, and read
/// its report. Where this process is the FULL half of a UAC split, the medium token is its own
/// `TokenLinkedToken` — the genuine filtered token Windows made, not an imitation. Otherwise one
/// is synthesised by disabling the Administrators SID and stamping the medium integrity label,
/// which is close but NOT identical, and the report says which was used.
#[test]
#[ignore = "platform probe; opt in with --ignored"]
fn unelevated_caller_view() {
    let own = open_own_token(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT)
        .expect("the probe needs its own token to derive a medium one");

    let etype = token_elevation_type(own.0)
        .unwrap_or_else(|e| panic!("could not read this process's own TokenElevationType: {e}"));
    println!(
        "PROBE unelevated-view: this process is elevation_type={etype} {}",
        elevation_type_name(etype)
    );

    let (medium, provenance) = if etype == 2 {
        match linked_token(own.0) {
            Ok(linked) => {
                let mut primary = HANDLE::default();
                // SAFETY: `linked` is live; the duplicate is wrapped in a `Token` immediately.
                unsafe {
                    DuplicateTokenEx(
                        linked.0,
                        TOKEN_ALL_ACCESS,
                        None,
                        SecurityImpersonation,
                        TokenPrimary,
                        &mut primary,
                    )
                }
                .expect("DuplicateTokenEx on the linked filtered token");
                (Token(primary), "the genuine UAC-filtered linked token")
            }
            Err(e) => panic!("this process is the full half of a split but its linked token is unreadable: {e}"),
        }
    } else {
        (
            synthesise_medium_token(&own),
            "a SYNTHESISED medium token (no UAC split on this account)",
        )
    };
    println!("PROBE unelevated-view: medium token provenance = {provenance}");

    let mut report = String::new();
    describe(&mut report, "medium token about to be used", medium.0);
    print!("{report}");

    // `describe` above already prints this token's `elevated=` flag buried among privileges;
    // surface it again on its own, because it is the one bit that decides whether what follows is
    // actually a measurement of an unelevated caller. Measured in run 35850159223: on a GitHub
    // runner (a Default, non-split admin token, `elevation_type=1`), synthesis disables the
    // Administrators SID and lowers integrity to Medium, but `TokenIsElevated` is fixed at token
    // creation from the source logon's elevation type and neither of those adjustments touches it
    // — so the synthesised token still reads `elevated=true`. Only the genuine
    // `TokenLinkedToken` route (`etype == 2`, a real UAC split) clears it. Print this prominently
    // instead of asserting it false: on a non-split admin account it is EXPECTED to stay true, so
    // asserting false would fail this probe on exactly the hosts it is meant to run on.
    let medium_is_elevated = token_is_elevated(medium.0)
        .unwrap_or_else(|e| panic!("could not read the medium token's own TokenIsElevated flag: {e}"));
    if medium_is_elevated {
        println!(
            "PROBE unelevated-view: medium token TokenIsElevated=true -- NOT a genuine unelevated \
             view. Integrity was lowered and the Administrators SID disabled, but this token was \
             derived from a non-split admin token, and TokenIsElevated cannot be cleared that way. \
             Read everything below as \"lowered integrity, still an elevated token\", not as an \
             unelevated caller's report."
        );
    } else {
        println!("PROBE unelevated-view: medium token TokenIsElevated=false -- a genuine unelevated view.");
    }

    let dir = tempfile::tempdir().expect("probe needs a temp dir");

    // Two routes, because `CreateProcessAsUserW` hands the child the caller's window station and
    // desktop unchanged, and a lowered-integrity token cannot always open them, which can make the
    // child die in loader init (STATUS_DLL_INIT_FAILED, 0xC0000142) before it can report anything
    // — measured on a desktop over SSH. On a GitHub runner (run 35850159223) this route instead
    // SUCCEEDED and produced a full report, so 0xC0000142 is a possible failure mode of this route,
    // not its guaranteed outcome. `CreateProcessWithTokenW` goes through the Secondary Logon
    // service, which sets the station and desktop up itself. Either one that yields a report
    // answers the question; both are tried so a station ACL cannot be mistaken for "elevation is
    // impossible".
    let mut spliced = String::new();
    for (route, use_seclogon) in [("CreateProcessAsUserW", false), ("CreateProcessWithTokenW", true)] {
        let child_report = dir.path().join(format!("{route}.txt"));
        let _ = std::fs::remove_file(&child_report);
        let block = env_block(&[("COSCA_PROBE_REPORT_TO", child_report.display().to_string())]);
        let mut cmd = wide(&self_report_cmdline());
        let si = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `cmd` and `block` are correctly terminated and outlive the call. `CREATE_SUSPENDED`:
        // the child must not run before `contain` assigns it to a kill-on-close job.
        let started = unsafe {
            if use_seclogon {
                CreateProcessWithTokenW(
                    medium.0,
                    CREATE_PROCESS_LOGON_FLAGS(0),
                    None,
                    Some(PWSTR(cmd.as_mut_ptr())),
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    Some(block.as_ptr().cast()),
                    None,
                    &si,
                    &mut pi,
                )
            } else {
                CreateProcessAsUserW(
                    Some(medium.0),
                    None,
                    Some(PWSTR(cmd.as_mut_ptr())),
                    None,
                    None,
                    false,
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    Some(block.as_ptr().cast()),
                    None,
                    &si,
                    &mut pi,
                )
            }
        };
        match started {
            Err(e) => println!("PROBE unelevated-view: {route} with the medium token FAILED {e:?}"),
            Ok(()) => {
                let job = contain(&pi, &format!("PROBE unelevated-view[{route}]"));
                let exit = wait_for(&pi, &job).map_or_else(|e| e, |c| format!("exit=0x{c:08x}"));
                println!("PROBE unelevated-view: {route} started a medium child, {exit}. It reports:");
                splice_child_report(&mut spliced, &child_report);
                print!("{spliced}");
            }
        }
        if spliced.contains("token report") {
            break;
        }
        spliced.clear();
    }
    // `dir` is a `tempfile::TempDir`; it removes itself on drop.
    assert!(
        spliced.contains("token report"),
        "no medium-integrity child produced a report, so the unelevated caller's view was NOT \
         measured. Every other result in this file was taken at this process's own integrity level \
         and must not be read as an unelevated result."
    );
    if medium_is_elevated {
        println!(
            "PROBE unelevated-view: measured, but LABEL AS ELEVATED: the medium token's \
             TokenIsElevated stayed true (see above), so this is a lowered-integrity elevated \
             caller's view, not an unelevated one."
        );
    } else {
        println!("PROBE unelevated-view: measured, and correctly labelled as an unelevated caller's view.");
    }
}

/// A medium-integrity token for an account that has no UAC split to borrow one from: disable the
/// Administrators SID (what filtering does to the groups) and stamp the medium integrity label
/// (what filtering does to the label). It is NOT a real filtered token — notably the privilege set
/// is whatever `DISABLE_MAX_PRIVILEGE` leaves — so any result taken under it is weaker evidence,
/// and the caller says so.
fn synthesise_medium_token(own: &Token) -> Token {
    let mut admins = PSID::default();
    // SAFETY: the standard S-1-5-32-544 construction; freed below.
    unsafe {
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admins,
        )
    }
    .expect("AllocateAndInitializeSid(BUILTIN\\Administrators)");
    let disable = [SID_AND_ATTRIBUTES {
        Sid: admins,
        Attributes: 0,
    }];
    let mut restricted = HANDLE::default();
    // SAFETY: `own` is live and `disable` outlives the call.
    let made = unsafe {
        CreateRestrictedToken(
            own.0,
            DISABLE_MAX_PRIVILEGE,
            Some(&disable),
            None,
            None,
            &mut restricted,
        )
    };
    // SAFETY: `admins` came from AllocateAndInitializeSid and is freed exactly once.
    unsafe {
        FreeSid(admins);
    }
    made.expect("CreateRestrictedToken");
    let restricted = Token(restricted);

    let mut medium = PSID::default();
    // SAFETY: the standard S-1-16-8192 construction; freed below.
    unsafe {
        AllocateAndInitializeSid(
            &SECURITY_MANDATORY_LABEL_AUTHORITY,
            1,
            SECURITY_MANDATORY_MEDIUM_RID as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut medium,
        )
    }
    .expect("AllocateAndInitializeSid(Medium Mandatory Level)");
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: medium,
            Attributes: 0x20, // SE_GROUP_INTEGRITY
        },
    };
    // SAFETY: `label` matches TokenIntegrityLevel and `medium` is alive for the call.
    let set = unsafe {
        SetTokenInformation(
            restricted.0,
            TokenIntegrityLevel,
            std::ptr::addr_of!(label).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        )
    };
    // SAFETY: `medium` came from AllocateAndInitializeSid and is freed exactly once.
    unsafe {
        FreeSid(medium);
    }
    set.expect("SetTokenInformation(TokenIntegrityLevel = Medium)");
    restricted
}

/// Does `CreateProcessW`'s `lpApplicationName` really behave as documented — "The function does not
/// use the search path. This parameter must include the file name extension; no default extension
/// is assumed"? `windows_shell_resolution.rs` measured `ShellExecuteEx` violating the intuitive
/// reading of ITS docs twice, so this claim is measured rather than trusted. It is the whole
/// reason a `CreateProcess*` route would be an improvement.
#[test]
#[ignore = "plants a batch file next to the target; opt in with --ignored"]
fn does_createprocessw_lpapplicationname_apply_pathext() {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    let marker = dir.path().join("bat-marker.txt");
    std::fs::write(
        dir.path().join("tool.bat"),
        format!("@echo off\r\necho ran > \"{}\"\r\n", marker.display()),
    )
    .expect("plant tool.bat");

    // Absolute, extensionless, NONEXISTENT — the shape `raw_executable("tool")` produces.
    let missing = dir.path().join("tool");
    let app = wide_path(&missing);
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: `app` is NUL-terminated and outlives the call; no command line is supplied, which is
    // legal when lpApplicationName is present. `CREATE_SUSPENDED`: the child must not run before
    // `contain` assigns it to a kill-on-close job.
    let res = unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            None,
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
    };
    let started = res.is_ok();
    if started {
        let job = contain(&pi, "PROBE createprocessw-pathext");
        wait_for(&pi, &job).unwrap_or_else(|e| panic!("PROBE createprocessw-pathext: child did not exit cleanly: {e}"));
    }
    let bat_ran = marker.exists();
    println!(
        "PROBE createprocessw-pathext: started={started} bat_ran={bat_ran} err={:?}",
        res.err()
    );
    if bat_ran {
        println!(
            "  => CreateProcessW DOES extend an absolute lpApplicationName. The documented \
             'no default extension is assumed' is FALSE, and a CreateProcess route carries the \
             same planting hazard as ShellExecuteEx."
        );
    } else if started {
        panic!("PROBE createprocessw-pathext: INCONCLUSIVE: something started but was not the planted batch.");
    } else {
        println!(
            "  => CreateProcessW refused a nonexistent extensionless lpApplicationName rather than \
             extending it. The documented exact-image semantics hold: this is the property a \
             CreateProcess-based route would buy."
        );
    }
}

// ── credential-gated probes (throwaway hosts only) ═══════════════════════════════════

/// Panics rather than skipping: a probe that quietly does nothing is worse than one that fails,
/// because its silence reads as a negative result.
fn require_gate(var: &str, what: &str) {
    assert!(
        std::env::var_os(var).is_some_and(|v| v == "1"),
        "this probe {what}, so it refuses to run unless {var}=1 marks the host as disposable. \
         Set it ONLY on an ephemeral CI runner or a throwaway VM, never on a machine in use."
    );
}

/// A throwaway local account, deleted on drop whatever the probe does.
struct ScratchAccount {
    user: String,
    password: String,
    admin: bool,
}

impl ScratchAccount {
    fn create(user: &str, admin: bool) -> Result<Self, String> {
        // Satisfies the default complexity policy and stays within 14 characters: `net user` turns
        // anything longer into an interactive "Windows prior to Windows 2000..." Y/N prompt, which
        // a non-interactive child cannot answer — measured, it hung the account creation and took
        // three probes down with it. The account exists for seconds on a host whose whole disk is
        // discarded afterwards.
        let password = format!(
            "Pb!{:04}aZ9{}",
            std::process::id() % 10_000,
            if admin { "A" } else { "S" }
        );
        let out = std::process::Command::new("net")
            .args(["user", user, &password, "/add"])
            .output()
            .map_err(|e| format!("could not run `net user`: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "`net user {user} /add` failed: status={:?} stdout={} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        if admin {
            let out = std::process::Command::new("net")
                .args(["localgroup", "Administrators", user, "/add"])
                .output()
                .map_err(|e| format!("could not run `net localgroup`: {e}"))?;
            if !out.status.success() {
                let _ = std::process::Command::new("net")
                    .args(["user", user, "/delete"])
                    .output();
                return Err(format!(
                    "adding {user} to Administrators failed: status={:?} stdout={} stderr={}",
                    out.status,
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
        }
        Ok(Self {
            user: user.to_string(),
            password,
            admin,
        })
    }
}

impl Drop for ScratchAccount {
    fn drop(&mut self) {
        let _ = std::process::Command::new("net")
            .args(["user", &self.user, "/delete"])
            .output();
    }
}

/// **Question 1.** Does `CreateProcessWithLogonW`, handed the credentials of a local
/// ADMINISTRATOR, produce an ELEVATED child? `runas.exe` is built on this API and is widely
/// reported not to elevate; this reads the child's own `TokenElevation` / `TokenElevationType` /
/// integrity label rather than relying on that reputation.
///
/// Also measures, in the same call, the two capabilities `ShellExecuteEx` cannot offer: an
/// explicit environment block, and `STARTF_USESTDHANDLES` redirection of the child's stdout.
#[test]
#[ignore = "creates a local user account; opt in with --ignored on a throwaway host"]
fn does_create_process_with_logon_elevate() {
    require_gate(
        "COSCA_PROBE_ALLOW_ACCOUNTS",
        "creates and deletes a local administrator account",
    );
    let mut measured_admin = false;
    let mut measured_std = false;
    for (name, admin) in [("coscaprobeadm", true), ("coscaprobestd", false)] {
        match ScratchAccount::create(name, admin) {
            Ok(account) => {
                if logon_one_account(&account) {
                    if admin {
                        measured_admin = true;
                    } else {
                        measured_std = true;
                    }
                }
            }
            Err(e) => println!("PROBE createprocesswithlogon: could not create {name}: {e}"),
        }
    }
    // Both accounts must be measured, not just either one: the administrator account is the one
    // the whole probe exists to answer (does a real logon reach an elevated token?), and the
    // standard-user account is the contrast that result needs to mean anything at all.
    assert!(
        measured_admin,
        "the Administrators-member scratch account produced no token report, so \
         CreateProcessWithLogonW's elevation result was never actually measured — an account being \
         created is not the same as a report coming back."
    );
    assert!(
        measured_std,
        "the standard-user scratch account produced no token report, so the contrast against the \
         Administrators account — the whole point of running both — was never measured."
    );
}

/// The body of the probe above, for one account. Split out so the administrator and the standard
/// user are measured by identical code: the ONLY difference between the two runs is the group the
/// account is in, which is exactly the variable UAC token filtering keys on.
///
/// The child runs the FULL chain rather than a bare report. It is the most valuable process in
/// this file: a real process, from a real logon, owned by a real account of known group
/// membership — the caller cosca's question is actually about. If a freshly logged-on
/// administrator could reach its own elevated token and spawn with it, it would show up here.
///
/// Returns whether the child actually produced a token report — the account being created and
/// `CreateProcessWithLogonW` returning `Ok` are both necessary but not sufficient: the child can
/// still start and exit without ever writing its report. The caller must count only this, not
/// account creation, as "measured".
fn logon_one_account(account: &ScratchAccount) -> bool {
    let role = if account.admin {
        "local ADMINISTRATOR"
    } else {
        "STANDARD user"
    };
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    // The scratch user is not the user who owns this checkout, so it can reach neither the test
    // binary under `target/` nor this process's `%TEMP%`. Give it one directory that holds both
    // the image and its scratch space, and point the child's `%TEMP%` at it.
    let _ = std::process::Command::new("icacls")
        .args([
            dir.path().to_str().unwrap(),
            "/grant",
            &format!("{}:(OI)(CI)F", account.user),
        ])
        .output();
    let exe = dir.path().join("probe.exe");
    std::fs::copy(
        std::env::current_exe().expect("the test binary knows its own path"),
        &exe,
    )
    .expect("copy the probe where the scratch user can execute it");
    let report = dir.path().join("logon.txt");
    let _ = std::fs::remove_file(&report);
    let stdout_file = dir.path().join("stdout.txt");
    let _ = std::fs::remove_file(&stdout_file);

    // An inheritable duplicate of a real file handle: the STARTF_USESTDHANDLES half of the
    // measurement. If seclogon drops it, the file stays empty and that IS the answer.
    let file = std::fs::File::create(&stdout_file).expect("probe stdout file");
    let mut inheritable = HANDLE::default();
    {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: duplicating a live file handle into this same process, marked inheritable.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                HANDLE(file.as_raw_handle()),
                GetCurrentProcess(),
                &mut inheritable,
                0,
                true,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .expect("DuplicateHandle for an inheritable stdout");
    }

    // NOT `COSCA_PROBE_CHILD` — see this function's doc comment: the child runs the whole chain.
    let block = env_block(&[
        ("COSCA_PROBE_REPORT_TO", report.display().to_string()),
        ("COSCA_PROBE_ENV_CANARY", "carried-through".into()),
        ("TEMP", dir.path().display().to_string()),
        ("TMP", dir.path().display().to_string()),
    ]);
    let mut cmd = wide(&report_cmdline(&exe));
    let user = wide(&account.user);
    let domain = wide(".");
    let password = wide(&account.password);
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: inheritable,
        hStdError: inheritable,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: every wide buffer is NUL-terminated and outlives the call; `block` is NUL-NUL
    // terminated, matching CREATE_UNICODE_ENVIRONMENT. `CREATE_SUSPENDED`: the child must not run
    // before `contain` assigns it to a kill-on-close job.
    let res = unsafe {
        CreateProcessWithLogonW(
            PCWSTR(user.as_ptr()),
            PCWSTR(domain.as_ptr()),
            PCWSTR(password.as_ptr()),
            LOGON_WITH_PROFILE,
            None,
            Some(PWSTR(cmd.as_mut_ptr())),
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            Some(block.as_ptr().cast()),
            None,
            &si,
            &mut pi,
        )
    };
    // SAFETY: our own duplicate, closed once.
    unsafe {
        let _ = CloseHandle(inheritable);
    }

    let mut spliced = String::new();
    match res {
        Err(e) => println!("PROBE createprocesswithlogon[{role}]: FAILED {e:?} — nothing to measure"),
        Ok(()) => {
            let job = contain(&pi, &format!("PROBE createprocesswithlogon[{role}]"));
            let exit = wait_for(&pi, &job).map_or_else(|e| e, |c| format!("exit=0x{c:08x}"));
            println!("PROBE createprocesswithlogon[{role}]: STARTED, {exit}. The child reports:");
            splice_child_report(&mut spliced, &report);
            print!("{spliced}");
            let captured = std::fs::read_to_string(&stdout_file).unwrap_or_default();
            println!(
                "PROBE createprocesswithlogon-stdio[{role}]: STARTF_USESTDHANDLES captured {} bytes of child stdout",
                captured.len()
            );
            if captured.is_empty() {
                println!("  => seclogon did NOT carry the caller's stdout handle to the child.");
            } else {
                println!(
                    "  => the caller's stdout handle DID reach the child. First line: {:?}",
                    captured.lines().next()
                );
            }
        }
    }
    // `dir` is a `tempfile::TempDir`; it removes itself on drop.
    spliced.contains("token report")
}

/// **Question 2's first step.** Which logon types return a FILTERED token for an account in
/// Administrators, and which return the full one? `LogonUser` is where UAC token filtering is
/// applied, so this is where the chain either starts or dies.
#[test]
#[ignore = "creates a local user account; opt in with --ignored on a throwaway host"]
fn which_logon_types_return_a_filtered_token() {
    require_gate("COSCA_PROBE_ALLOW_ACCOUNTS", "creates and deletes local user accounts");
    let mut measured = 0usize;
    for admin in [true, false] {
        let name = if admin { "coscaprobeadm" } else { "coscaprobestd" };
        let account = match ScratchAccount::create(name, admin) {
            Ok(a) => a,
            Err(e) => {
                println!("PROBE logon-types: could not create {name}: {e}");
                continue;
            }
        };
        let user = wide(&account.user);
        let domain = wide(".");
        let password = wide(&account.password);
        for (label, kind) in [
            ("INTERACTIVE", LOGON32_LOGON_INTERACTIVE),
            ("NETWORK", LOGON32_LOGON_NETWORK),
            ("NETWORK_CLEARTEXT", LOGON32_LOGON_NETWORK_CLEARTEXT),
            ("BATCH", LOGON32_LOGON_BATCH),
            ("SERVICE", LOGON32_LOGON_SERVICE),
        ] {
            let mut h = HANDLE::default();
            // SAFETY: all three wide strings are NUL-terminated and outlive the call.
            let res = unsafe {
                LogonUserW(
                    PCWSTR(user.as_ptr()),
                    PCWSTR(domain.as_ptr()),
                    PCWSTR(password.as_ptr()),
                    kind,
                    LOGON32_PROVIDER_DEFAULT,
                    &mut h,
                )
            };
            let group = if account.admin {
                "Administrators member"
            } else {
                "standard user"
            };
            match res {
                Err(e) => println!("PROBE logon-type {label} ({group}): LogonUser FAILED {e:?}"),
                Ok(()) => {
                    measured += 1;
                    let t = Token(h);
                    let mut out = String::new();
                    let _ = writeln!(out, "PROBE logon-type {label} ({group}): LogonUser OK");
                    describe(&mut out, "returned token", t.0);
                    match linked_token(t.0) {
                        Ok(linked) => describe(&mut out, "its TokenLinkedToken", linked.0),
                        Err(e) => {
                            let _ = writeln!(out, "  its TokenLinkedToken: <{e}>");
                        }
                    }
                    print!("{out}");
                }
            }
        }
    }
    assert!(
        measured > 0,
        "not one LogonUser call returned a token, so nothing was measured"
    );
}

/// Question 3's Task Scheduler arm, reduced to its gating question: can a caller REGISTER a task
/// that runs with `RunLevel=Highest`? If registration needs elevation the route is dead for an
/// unelevated caller regardless of what a registered task could do.
///
/// Deliberately does NOT run the task. Observing the resulting process's integrity would mean
/// waiting on the Task Scheduler service with no handle to wait on, and the registration answer is
/// the one that decides the route.
#[test]
#[ignore = "registers and deletes a scheduled task; opt in with --ignored on a throwaway host"]
fn can_this_caller_register_a_runlevel_highest_task() {
    require_gate("COSCA_PROBE_ALLOW_STATE", "registers and deletes a scheduled task");
    let etype_str = open_own_token(TOKEN_QUERY)
        .and_then(|t| token_elevation_type(t.0))
        .map_or_else(
            |e| format!("<error: {e}>"),
            |v| format!("{v} {}", elevation_type_name(v)),
        );
    let rid_str = open_own_token(TOKEN_QUERY)
        .and_then(|t| token_integrity_rid(t.0))
        .map_or_else(
            |e| format!("<error: {e}>"),
            |v| format!("0x{v:04x} {}", integrity_name(v)),
        );
    println!("PROBE schtasks-highest: measured at integrity {rid_str} (elevation_type {etype_str})");
    let (lines, any_create_exited) = schtasks_registration_report();
    for line in lines {
        println!("PROBE schtasks-highest: {line}");
    }
    assert!(
        any_create_exited,
        "not one schtasks /create call exited with a status, so nothing was measured — schtasks \
         itself could not be launched"
    );
}
