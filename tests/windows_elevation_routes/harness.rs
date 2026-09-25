//! Shared harness for the token-and-elevation probes in this folder: token inspection, the
//! contain/wait/reap sequence every spawned child goes through, the allowlisted environment block,
//! and the throwaway scratch account. See `tests/windows_elevation_routes.rs`'s module doc for what
//! these probes measure and why.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::os::windows::io::BorrowedHandle;
use std::path::Path;

use cosca::Job;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN};
use windows::Win32::Security::{
    DuplicateTokenEx, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupPrivilegeNameW,
    SecurityImpersonation, TokenElevation, TokenElevationType, TokenIntegrityLevel, TokenLinkedToken, TokenPrimary,
    TokenPrivileges, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION,
    TOKEN_LINKED_TOKEN, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessWithTokenW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS,
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
};

/// A child is an external process that might never exit, so this is the honest failure bound
/// surfaced to whoever reads the log — not a synchronisation device. If it trips, [`wait_for`]
/// kills the child's whole job tree, then waits (unboundedly) on the child's OWN process handle
/// for that kill to land, and only then reports that the child did not finish; it never silently
/// continues, and never touches a file or account the child might still hold open. That final
/// wait covers only the immediate child: the job handle is already closed by the time the kill
/// call returns, so there is nothing left to wait on for the rest of the tree.
///
/// This is the bound for a process this test binary spawns and waits on directly. Some of those
/// children — `logon_routes::logon_one_account`'s and `token_filtering::unelevated_caller_view`'s,
/// both spawned without `COSCA_PROBE_CHILD` set — themselves run the full chain, so they spawn and
/// wait on a grandchild through [`spawn_attempts_with`]. That inner wait is given
/// [`GRANDCHILD_EXIT_BOUND_MS`], a strictly smaller bound, on purpose: if the grandchild hangs, the
/// child's own `wait_for` call trips, kills, and recovers well within this constant's 120s, so this
/// outer wait still finishes on schedule. If this outer wait ever trips instead, that names the
/// immediate child itself as stuck — not a grandchild the child was already recovering from.
pub(crate) const CHILD_EXIT_BOUND_MS: u32 = 120_000;

/// The bound for [`spawn_attempts_with`]'s own wait on the children it spawns. Kept well under
/// [`CHILD_EXIT_BOUND_MS`] (a tenth of it) so that whenever `spawn_attempts_with` runs inside a
/// process that is itself someone else's child — which happens whenever `COSCA_PROBE_CHILD` is
/// left unset — there is enough headroom left in the outer bound for this inner one to trip, kill,
/// and recover before the outer wait could plausibly trip too. See `CHILD_EXIT_BOUND_MS`'s doc.
///
/// The real worst case this has to clear is FOUR sequential grandchild waits, not two: [`measure`]
/// calls `spawn_attempts_with` twice — once for the linked token, once for the caller's own — and
/// each of those calls itself loops over `CreateProcessAsUserW` then `CreateProcessWithTokenW`,
/// each with its own `wait_for(GRANDCHILD_EXIT_BOUND_MS)`. That is 2 calls × 2 waits, all of which
/// can trip in turn before the outer `wait_for` in `logon_routes::logon_one_account` /
/// `token_filtering::unelevated_caller_view` needs to see the whole thing finished. Each
/// trip-kill-recover can itself take up to twice its own bound (the minimum ×2 margin
/// `CHILD_EXIT_BOUND_MS`'s doc relies on), so the real worst case is
/// `4 * (2 * GRANDCHILD_EXIT_BOUND_MS)` = `8 * GRANDCHILD_EXIT_BOUND_MS` before the outer wait
/// could plausibly see it done. At a tenth of `CHILD_EXIT_BOUND_MS`, that leaves only about ×1.25
/// of headroom over the bare minimum — tight, not the wide margin a "kept well under" framing might
/// suggest, but `const _` below still asserts the real relationship
/// (`4 * 2 * GRANDCHILD_EXIT_BOUND_MS < CHILD_EXIT_BOUND_MS`) holds, so a future change to either
/// constant cannot silently erode it below break-even.
const GRANDCHILD_EXIT_BOUND_MS: u32 = CHILD_EXIT_BOUND_MS / 10;
const _: () = assert!(4 * 2 * GRANDCHILD_EXIT_BOUND_MS < CHILD_EXIT_BOUND_MS);

// ── token inspection ═════════════════════════════════════════════════════════════════

/// An owned token handle. Closing twice or leaking across a probe would corrupt later
/// measurements, so ownership is never implicit. The field is `pub(crate)` — not just `pub(super)`
/// — because sibling probe modules (`logon_routes`, `token_filtering`) construct and read it
/// directly (e.g. wrapping a freshly opened token, or reading `.0` to pass to `describe`), the same
/// way this module does.
pub(crate) struct Token(pub(crate) HANDLE);

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

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn wide_path(p: &Path) -> Vec<u16> {
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

pub(crate) fn token_is_elevated(token: HANDLE) -> Result<bool, String> {
    let buf = token_info(token, TokenElevation)?;
    // SAFETY: the kernel wrote a TOKEN_ELEVATION at the head of an 8-aligned buffer.
    Ok(unsafe { buf.as_ptr().cast::<TOKEN_ELEVATION>().read() }.TokenIsElevated != 0)
}

/// 1 = Default (UAC off, or an account with no split), 2 = Full, 3 = Limited.
pub(crate) fn token_elevation_type(token: HANDLE) -> Result<i32, String> {
    let buf = token_info(token, TokenElevationType)?;
    // SAFETY: the kernel wrote a TOKEN_ELEVATION_TYPE (an i32) at the head of the buffer.
    Ok(unsafe { buf.as_ptr().cast::<i32>().read() })
}

pub(crate) fn elevation_type_name(t: i32) -> &'static str {
    match t {
        1 => "Default(no split token)",
        2 => "Full(elevated half of a split)",
        3 => "Limited(filtered half of a split)",
        _ => "unknown",
    }
}

pub(crate) fn token_integrity_rid(token: HANDLE) -> Result<u32, String> {
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

pub(crate) fn integrity_name(rid: u32) -> &'static str {
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
pub(crate) fn linked_token(token: HANDLE) -> Result<Token, String> {
    let buf = token_info(token, TokenLinkedToken)?;
    // SAFETY: the kernel wrote a TOKEN_LINKED_TOKEN (a single HANDLE) at the head of the buffer.
    // The handle it contains is OURS to close, which `Token` does.
    let h = unsafe { buf.as_ptr().cast::<TOKEN_LINKED_TOKEN>().read() }.LinkedToken;
    if h.is_invalid() {
        return Err("TokenLinkedToken returned an invalid handle".into());
    }
    Ok(Token(h))
}

pub(crate) fn open_own_token(access: TOKEN_ACCESS_MASK) -> Result<Token, String> {
    let mut h = HANDLE::default();
    // SAFETY: a standard token open on the current process; the handle is wrapped immediately.
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut h) }
        .map_err(|e| format!("OpenProcessToken({access:?}) failed: {e}"))?;
    Ok(Token(h))
}

/// A one-line summary plus the privilege list, for any token.
pub(crate) fn describe(out: &mut String, label: &str, token: HANDLE) {
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

/// An environment-variable key ordered the same case-insensitive, `CompareStringOrdinal`-based way
/// `CreateProcess*`'s own environment block is looked up (and the way `src/child/spawn/windows_raw/
/// env_key.rs`'s crate-private `EnvKey` orders it — that type is `pub(crate)` to the library and
/// unreachable from an integration test, so the same comparison is reproduced here rather than
/// trusted to differ by accident). Without this, [`env_block`]'s allowlist and `extra` entries could
/// collide on case alone (e.g. the allowlisted `PATH` and a caller-supplied `Path`) and silently
/// duplicate a key, which `CreateProcess*`'s contract leaves undefined.
///
/// The map keeps the first spelling it saw for a key (`BTreeMap::insert` replaces the value but not
/// an already-present, merely-equal key), so `extra` entries replace the VALUE of any parent entry
/// that is equal case-insensitively, while the emitted key text is whichever spelling was inserted
/// first — the same behaviour `EnvKey`-backed maps have.
#[derive(Clone, Debug)]
struct EnvKeyIgnoreCase {
    name: String,
    wide: Vec<u16>,
}

impl EnvKeyIgnoreCase {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            wide: name.encode_utf16().collect(),
        }
    }
}

impl Ord for EnvKeyIgnoreCase {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // SAFETY: both slices are valid UTF-16 buffers that outlive the call; the API only reads
        // them.
        match unsafe { CompareStringOrdinal(&self.wide, &other.wide, true) } {
            CSTR_EQUAL => std::cmp::Ordering::Equal,
            CSTR_LESS_THAN => std::cmp::Ordering::Less,
            CSTR_GREATER_THAN => std::cmp::Ordering::Greater,
            // Fails only on invalid parameters, which the slices rule out.
            _ => panic!("comparing environment keys failed: {}", std::io::Error::last_os_error()),
        }
    }
}

impl PartialOrd for EnvKeyIgnoreCase {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for EnvKeyIgnoreCase {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for EnvKeyIgnoreCase {}

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
/// caller passes in `extra`. `COSCA_PROBE_MARKERS` is carved out of that `COSCA_PROBE_*` pass-
/// through: it names a directory this process's OWN account can write to, and a child spawned
/// here under a different account (the whole point of several of these routes) cannot create or
/// overwrite files there. A child that inherited it would panic trying to mark itself passed,
/// which corrupts the very measurement being taken — so a spawned child never sees it and never
/// marks a probe passed on the spawning process's behalf.
///
/// Keyed by [`EnvKeyIgnoreCase`] rather than a plain `String`, so the allowlist and `extra` are
/// merged the same case-insensitive way `CreateProcess*` itself looks up the block — see that
/// type's doc.
pub(crate) fn env_block(extra: &[(&str, String)]) -> Vec<u16> {
    const ALLOWLIST: [&str; 6] = ["SYSTEMROOT", "PATH", "TEMP", "TMP", "COMSPEC", "PATHEXT"];
    let mut map: BTreeMap<EnvKeyIgnoreCase, String> = BTreeMap::new();
    for (k, v) in std::env::vars_os() {
        let k = k.to_string_lossy().into_owned();
        let upper = k.to_ascii_uppercase();
        if ALLOWLIST.contains(&upper.as_str()) || (upper.starts_with("COSCA_PROBE_") && upper != "COSCA_PROBE_MARKERS")
        {
            map.insert(EnvKeyIgnoreCase::new(&k), v.to_string_lossy().into_owned());
        }
    }
    for (k, v) in extra {
        map.insert(EnvKeyIgnoreCase::new(k), v.clone());
    }
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in &map {
        block.extend(format!("{}={v}", k.name).encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// The command line that re-runs this test binary's `token_filtering::measure_this_token`.
/// `--exact` pins it to that one test, so a child never re-enters the spawning probes and
/// recursion is structural rather than bounded by a counter.
pub(crate) fn report_cmdline(exe: &Path) -> String {
    format!(
        "\"{}\" token_filtering::measure_this_token --exact --ignored --nocapture --test-threads=1",
        exe.display()
    )
}

pub(crate) fn self_report_cmdline() -> String {
    report_cmdline(&std::env::current_exe().expect("the test binary knows its own path"))
}

/// Assign a just-created SUSPENDED child to a fresh `KILL_ON_JOB_CLOSE` job, then resume its
/// initial thread — the mandatory sequence [`cosca::Job::assign`]'s own docs require, closing the
/// race where a resumed-too-early child (or a grandchild it forks) escapes containment before
/// assignment lands. Every `CreateProcess*` call in this folder that hands back a
/// `PROCESS_INFORMATION` uses `CREATE_SUSPENDED` and routes through this function, so `wait_for`
/// can always terminate the whole tree — not just the immediate child — on a timeout.
///
/// Panics rather than returning an error: an uncontained child defeats the reason every spawn in
/// this folder goes through a job at all, and `Job::assign`'s own contract forbids resuming a
/// process that failed to join one, so there is no safe fallback measurement to report instead. On
/// an assign failure the child is still suspended and was never given to any job, so it is torn
/// down here directly — `TerminateProcess`, waited out, both handles closed — before panicking,
/// rather than leaking a suspended, uncontained process behind a panicking test.
pub(crate) fn contain(pi: &PROCESS_INFORMATION, context: &str) -> Job {
    // SAFETY: `pi.hProcess` is a live, just-created suspended process handle; the borrow lasts
    // only for the duration of this call, and the process outlives it (owned by the caller).
    let job = match Job::assign(unsafe { BorrowedHandle::borrow_raw(pi.hProcess.0.cast()) }) {
        Ok(job) => job,
        Err(e) => {
            // SAFETY: `pi.hProcess` is a live, still-suspended process handle that was never
            // assigned to any job (assign just failed), so terminating and waiting it out
            // directly is the only way to reap it; both handles are closed exactly once after.
            let terminated = unsafe { TerminateProcess(pi.hProcess, 1) };
            if let Err(term_err) = terminated {
                // Waiting INFINITE on a process this code could not even ask to terminate would
                // be exactly the unbounded hang containment exists to prevent — abandon the
                // handles instead of blocking forever on an exit nothing here can obtain.
                unsafe {
                    let _ = CloseHandle(pi.hThread);
                    let _ = CloseHandle(pi.hProcess);
                }
                panic!(
                    "{context}: could not contain the child in a kill-on-close job ({e}), and then \
                     could not even terminate it directly ({term_err}) — it has been abandoned \
                     rather than waited on unboundedly for an exit that TerminateProcess itself \
                     could not obtain"
                );
            }
            unsafe {
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
/// not be measured. `bound_ms` is given to this one, outermost wait only: on a timeout it kills
/// the whole job, then waits (unboundedly) on the CHILD'S OWN process handle for that kill to
/// actually land — not `job.wait_tree()`, which would return an error at once here: `Job::kill_tree`
/// closes the underlying job handle as part of tearing the job down (see its doc), so by the time
/// `wait_tree` could run there is nothing left for it to wait on. That final wait has no bound of
/// its own because it is waiting on a real kernel outcome (the kill taking effect), not racing a
/// clock — so by the time this returns, the immediate child is provably gone and it is safe for
/// the caller to touch any file or account it might otherwise still hold open. It only covers the
/// immediate child, not the rest of the tree: once the job handle is closed there is no longer a
/// way to wait on the tree as a whole.
///
/// The first wait's result is matched explicitly rather than treated as a bare timeout: only
/// `WAIT_TIMEOUT` means the child is still running after `bound_ms`. Any other non-`WAIT_OBJECT_0`
/// result — `WAIT_FAILED`, or an unrecognised code — means the wait itself could not be taken, and
/// is reported with `GetLastError` rather than mislabelled as a timeout that never happened.
/// Teardown is identical either way: a child this call cannot confirm has exited is not left
/// running just because the reason it could not be confirmed differs.
///
/// Callers pass [`CHILD_EXIT_BOUND_MS`] for a process they spawned and wait on directly, or
/// [`GRANDCHILD_EXIT_BOUND_MS`] inside [`spawn_attempts_with`] — see that constant's doc for why
/// the two must stay different.
pub(crate) fn wait_for(pi: &PROCESS_INFORMATION, job: &Job, bound_ms: u32) -> Result<u32, String> {
    // SAFETY: `pi.hProcess` was just returned by CreateProcess* and is closed exactly once below.
    let waited = unsafe { WaitForSingleObject(pi.hProcess, bound_ms) };
    if waited != WAIT_OBJECT_0 {
        let reason = if waited == WAIT_TIMEOUT {
            format!("the child did not exit within {bound_ms}ms")
        } else {
            format!(
                "WaitForSingleObject on the child failed ({waited:?}): {}",
                std::io::Error::last_os_error()
            )
        };
        let killed = job.kill_tree();
        if let Err(kill_err) = &killed {
            // `kill_tree` itself failed, so nothing has confirmed the job's members were ever
            // actually asked to terminate. Fall back to terminating the immediate child directly,
            // and check THAT result too, rather than waiting INFINITE below on a process nothing
            // here has managed to ask to exit.
            // SAFETY: `pi.hProcess` is still a valid, open handle to the child.
            let terminated = unsafe { TerminateProcess(pi.hProcess, 1) };
            if let Err(term_err) = terminated {
                unsafe {
                    let _ = CloseHandle(pi.hThread);
                    let _ = CloseHandle(pi.hProcess);
                }
                return Err(format!(
                    "{reason}; kill_tree failed ({kill_err}) and the direct child could not be \
                     terminated either ({term_err}) — it has been abandoned rather than waited on \
                     unboundedly for an exit nothing here could obtain"
                ));
            }
        }
        // `kill_tree` already closed the job handle on success, so `job.wait_tree()` would fail
        // immediately here instead of waiting for anything (see this function's doc comment).
        // Either `kill_tree` succeeded, or the fallback `TerminateProcess` above did — either way
        // the child has genuinely been asked to exit, so waiting on its own process handle now
        // observes a real kernel outcome, not a clock race.
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
            "{reason}; kill_tree={killed:?} wait_after_kill={waited_after_kill:?}"
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
pub(crate) fn splice_child_report(out: &mut String, path: &Path) {
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
pub(crate) fn measure(out: &mut String) {
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
pub(crate) fn schtasks_registration_report() -> (Vec<String>, bool) {
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
                let exit =
                    wait_for(&pi, &job, GRANDCHILD_EXIT_BOUND_MS).map_or_else(|e| e, |c| format!("exit=0x{c:08x}"));
                let _ = writeln!(out, "  {step} [{which} token]: STARTED, {exit}. The child reports:");
                splice_child_report(out, &report);
            }
        }
    }
    // `dir` is a `tempfile::TempDir`; it removes itself on drop.
}

// ── credential-gated probes (throwaway hosts only) ═══════════════════════════════════

/// Panics rather than skipping: a probe that quietly does nothing is worse than one that fails,
/// because its silence reads as a negative result.
pub(crate) fn require_gate(var: &str, what: &str) {
    assert!(
        std::env::var_os(var).is_some_and(|v| v == "1"),
        "this probe {what}, so it refuses to run unless {var}=1 marks the host as disposable. \
         Set it ONLY on an ephemeral CI runner or a throwaway VM, never on a machine in use."
    );
}

/// A throwaway local account, deleted on drop whatever the probe does.
pub(crate) struct ScratchAccount {
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) admin: bool,
}

impl ScratchAccount {
    /// Creates the account, first deleting any account of the same name left behind by an earlier
    /// run on this host: `does_create_process_with_logon_elevate` and
    /// `which_logon_types_return_a_filtered_token` both create their scratch accounts under the
    /// same two fixed names (`coscaprobeadm`/`coscaprobestd`; see this crate's module doc), so a
    /// leftover from a run that crashed before `Drop` ran would otherwise make `/add` fail and
    /// cascade into every other probe in the `windows-elevation-routes` test group. The pre-create
    /// `/delete`'s result is printed either way — "account not found" is the expected, silent case
    /// on a clean host, but a genuine permissions failure here should be visible rather than
    /// swallowed into `/add`'s own error.
    pub(crate) fn create(user: &str, admin: bool) -> Result<Self, String> {
        match std::process::Command::new("net")
            .args(["user", user, "/delete"])
            .output()
        {
            Ok(out) if out.status.success() => {
                println!("PROBE scratch-account: deleted a leftover account {user} before creating it fresh");
            }
            Ok(out) => println!(
                "PROBE scratch-account: pre-create `net user {user} /delete` -> {} (expected when no \
                 leftover account exists)",
                out.status
            ),
            Err(e) => println!("PROBE scratch-account: pre-create `net user {user} /delete` could not be run: {e}"),
        }

        // Satisfies the default complexity policy and stays within 14 characters: `net user` turns
        // anything longer into an interactive "Windows prior to Windows 2000..." Y/N prompt, which
        // a non-interactive child cannot answer. The account exists for seconds on a host whose
        // whole disk is discarded afterwards.
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
                match std::process::Command::new("net")
                    .args(["user", user, "/delete"])
                    .output()
                {
                    Ok(o) if o.status.success() => {
                        println!("PROBE scratch-account: rolled back {user} after a failed Administrators add")
                    }
                    Ok(o) => println!(
                        "PROBE scratch-account: rollback `net user {user} /delete` FAILED: status={} \
                         stdout={} stderr={}",
                        o.status,
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    ),
                    Err(e) => {
                        println!("PROBE scratch-account: rollback `net user {user} /delete` could not be run: {e}");
                    }
                }
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
        match std::process::Command::new("net")
            .args(["user", &self.user, "/delete"])
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => println!(
                "PROBE scratch-account: `net user {} /delete` in Drop FAILED: status={} stdout={} stderr={}",
                self.user,
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => println!(
                "PROBE scratch-account: `net user {} /delete` in Drop could not be run: {e}",
                self.user
            ),
        }
    }
}
