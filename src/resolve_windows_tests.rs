//! A REAL Windows ACL proof for [`resolve`]'s undeterminable-candidate disposition.
//!
//! `src/resolve_base_tests.rs` has Unix-side tests that simulate the Windows grammar
//! (`windows: true`) on a Unix HOST — via a directory this process is denied read access to, or
//! (once a separate, in-flight PR lands) a symlink loop that always yields `ELOOP` — useful for
//! pinning the DISPOSITION (fail closed under `loadable_only`, skip and continue otherwise), but
//! not a real Windows `ERROR_ACCESS_DENIED` (raw code 5) from a real Windows ACL, since none of
//! those run on a Windows host. This file is that: it builds an actual deny ACE with the Win32
//! Authorization APIs and checks the same two dispositions against it.
//!
//! # Where the deny ACE has to sit
//!
//! `std::fs::metadata` on Windows (`library/std/src/sys/fs/windows.rs`'s `fn metadata`, checked
//! against rustc 1.98.1's own source) opens the target via `CreateFileW`, which ends up
//! requesting `SYNCHRONIZE | FILE_READ_ATTRIBUTES` on the handle. Denying only the candidate
//! FILE is not enough on its own: that primary open does fail, but `metadata`'s own fallback —
//! taken on exactly `ERROR_ACCESS_DENIED` or `ERROR_SHARING_VIOLATION` — retries via
//! `FindFirstFileExW` on the same path, a directory-listing operation gated on
//! `FILE_LIST_DIRECTORY` (`0x1`) on the PARENT directory, which a deny ACE on the file cannot
//! reach at all; `FindFirstFileExW` then succeeds and `metadata` returns `Ok`. So the deny ACE
//! below sits on the DIRECTORY instead, denying both `FILE_LIST_DIRECTORY` (closing that
//! fallback) and `FILE_TRAVERSE` (`0x20`, the same bit as `FILE_EXECUTE` — closing the primary
//! open's own route to a file under it).
//!
//! `FILE_TRAVERSE` alone is not sufficient either: every ordinary token holds
//! `SeChangeNotifyPrivilege` ("bypass traverse checking") by default — an interactive session
//! included, this is not a CI-runner peculiarity — which skips the ACL check for that bit
//! entirely regardless of what the DACL says. [`ImpersonationGuard`] strips the privilege from a
//! DUPLICATE of this process's own token and impersonates the CURRENT THREAD with it, so the
//! DACL becomes authoritative for `FILE_TRAVERSE` too, for the probe and the [`resolve`] call
//! that follow — and nothing else: the strip lives on a thread-scoped impersonation token, never
//! this process's own, so no other thread and no later test is affected. See
//! [`ImpersonationGuard::without_change_notify`]'s doc for why a process-wide, irreversible strip
//! is unsound here.
//!
//! Only the combination above — both bits denied on the directory, `SeChangeNotifyPrivilege`
//! stripped for the probing thread — was actually measured to work, on GitHub's Windows CI
//! runners; there is no Windows host to develop this against directly.
//! [`locked_then_open`]'s own precondition assertion is what still proves it holds on whichever
//! host runs this test, rather than resting on the reasoning above.

use super::*;
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, LUID};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, SE_FILE_OBJECT, TRUSTEE_W,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, LookupPrivilegeValueW, SecurityImpersonation,
    TokenImpersonation, TokenUser, ACL, DACL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR, PSID, SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE,
    TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{FILE_LIST_DIRECTORY, FILE_TRAVERSE};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, SetThreadToken};

fn search_tool(path_var: &OsStr, loadable_only: bool) -> Result<PathBuf, Error> {
    resolve(ResolveInput {
        program: Path::new("tool"),
        cwd: None,
        system_dirs: &no_system_dirs,
        path_var: Some(path_var),
        windows: true,
        loadable_only,
        normalise: &as_written,
    })
}

/// Reads the raw OS error [`crate::error::io_context`] wrapped: it keeps the original
/// [`std::io::Error`] as `source()` precisely so the code survives being wrapped (several codes
/// share one [`std::io::ErrorKind`]), and this is what pins the exact code rather than the
/// coarser kind. Mirrors `resolve_base_tests.rs`'s own `wrapped_raw_os_error` (that one is
/// `#[cfg(unix)]`-gated in its file, this whole file already is).
fn wrapped_raw_os_error(e: &std::io::Error) -> Option<i32> {
    std::error::Error::source(e)
        .and_then(|s| s.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
}

/// This process's own user SID, from its own token — the trustee for the deny ACE. `Everyone`
/// would do too, but the current user's SID needs no elevated or domain-joined runner to be
/// meaningful, and it is what actually issues the `std::fs::metadata` call below.
///
/// Returned as the raw `TOKEN_USER` buffer rather than the `PSID` alone: the SID borrows from
/// it, so a caller that dropped the buffer first would hold a dangling `PSID`.
fn current_user_sid_buf() -> Vec<u64> {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no close.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.expect("OpenProcessToken");
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 is the documented size query; it fails with
    // ERROR_INSUFFICIENT_BUFFER and writes the required size.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    // u64-backed so the `TOKEN_USER` cast below is 8-aligned, as `TOKEN_USER` requires.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` is at least `needed` bytes.
    let info = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    };
    // SAFETY: `token` is an owned handle this function is done with.
    unsafe { CloseHandle(token) }.expect("CloseHandle(process token)");
    info.expect("GetTokenInformation(TokenUser)");
    buf
}

/// The `PSID` inside a buffer [`current_user_sid_buf`] returned. Borrows from `buf`, so it must
/// not outlive it.
fn sid_from_buf(buf: &[u64]) -> PSID {
    // SAFETY: the kernel wrote a `TOKEN_USER` at the head of an 8-aligned buffer, and every
    // caller keeps `buf` alive for at least as long as the returned `PSID` is used.
    unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid }
}

/// Report a `Drop` failure without risking a double panic during an unwind: real failures panic
/// (loud, since nothing else would report this), an unwind-time failure — this `Drop` running
/// because a panic elsewhere is already propagating — goes to stderr instead, since a second
/// panic during unwind aborts the process outright rather than reporting either one.
fn panic_or_eprint(msg: String) {
    if std::thread::panicking() {
        eprintln!("{msg}");
    } else {
        panic!("{msg}");
    }
}

/// Impersonates the CURRENT THREAD with a duplicate of this process's own token, missing
/// `SeChangeNotifyPrivilege`, so a `FILE_TRAVERSE` deny becomes authoritative for whatever this
/// thread opens while the guard is alive — see the module doc for why that privilege matters
/// here. Reverted on drop.
///
/// Scoped to one thread's impersonation token rather than stripping the privilege from this
/// process's own token: `AdjustTokenPrivileges(..., SE_PRIVILEGE_REMOVED)` is irreversible for a
/// token, so a process-wide strip can never be undone for the rest of this test binary's life —
/// every OTHER test still to run in this same process (`cargo test`/`cargo nextest` reuse the
/// process across tests) would lose the privilege too, and re-enabling it afterwards would still
/// leave a window where a concurrently running test observes the stripped process token, a data
/// race on shared, mutable process state. A thread's impersonation token is not shared: setting
/// and reverting it here touches only the thread these two tests run on.
struct ImpersonationGuard;

impl ImpersonationGuard {
    fn without_change_notify() -> Self {
        let mut token = HANDLE::default();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no close.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut token) }
            .expect("OpenProcessToken(TOKEN_DUPLICATE)");
        let mut dup = HANDLE::default();
        // SAFETY: `token` is a live, owned handle with `TOKEN_DUPLICATE` access; `dup` is a
        // valid `&mut` out-param.
        let duplicated = unsafe {
            DuplicateTokenEx(
                token,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_QUERY,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut dup,
            )
        };
        // SAFETY: `token` is an owned handle this function is done with.
        unsafe { CloseHandle(token) }.expect("CloseHandle(process token)");
        duplicated.expect("DuplicateTokenEx");

        let mut luid = LUID::default();
        // SAFETY: `SE_CHANGE_NOTIFY_NAME` is a static NUL-terminated wide string.
        unsafe { LookupPrivilegeValueW(None, SE_CHANGE_NOTIFY_NAME, &mut luid) }.expect("LookupPrivilegeValueW");
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_REMOVED,
            }],
        };
        // Succeeds with `ERROR_NOT_ALL_ASSIGNED` when the token never held the privilege — not
        // the case here (`SeChangeNotifyPrivilege` is assigned to everyone by default), but the
        // call still succeeds either way, so nothing extra needs checking for that case.
        // SAFETY: `privileges` describes one LUID and `PrivilegeCount` matches; `dup` is this
        // function's own fresh, owned duplicate.
        let adjusted = unsafe { AdjustTokenPrivileges(dup, false, Some(&privileges), 0, None, None) };
        if let Err(e) = adjusted {
            // SAFETY: `dup` is an owned handle, and this branch panics without ever handing it
            // to `SetThreadToken`, so nothing else will close it.
            unsafe { CloseHandle(dup) }.expect("CloseHandle(duplicate token)");
            panic!("AdjustTokenPrivileges(SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_REMOVED): {e}");
        }

        // SAFETY: `dup` is a valid, owned impersonation-type token for this same process's own
        // identity, missing only the one privilege just removed.
        let set = unsafe { SetThreadToken(None, Some(dup)) };
        // SAFETY: `dup` is an owned handle; `SetThreadToken` references the underlying kernel
        // object for the thread's impersonation slot rather than borrowing this specific handle
        // value, so closing it here does not invalidate the thread's impersonation.
        unsafe { CloseHandle(dup) }.expect("CloseHandle(duplicate token)");
        set.expect("SetThreadToken");

        ImpersonationGuard
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: reverts THIS thread's impersonation token to none, the exact counterpart to
        // `SetThreadToken(None, Some(dup))` above.
        if let Err(e) = unsafe { SetThreadToken(None, None) } {
            panic_or_eprint(format!("could not revert thread impersonation: {e}"));
        }
    }
}

/// Denies `FILE_TRAVERSE`/`FILE_LIST_DIRECTORY` on a single Windows DIRECTORY object for the
/// current user, via `SetNamedSecurityInfoW`, and restores the ORIGINAL DACL on drop (not a
/// guessed default) so `tempfile::TempDir`'s own `Drop` can subsequently delete the tree without
/// an access-denied error of its own.
struct DenyAclGuard {
    /// For the failure message on [`Drop`] — kept separately from `wide` (below) because
    /// formatting `Vec<u16>` with `{:?}` prints raw UTF-16 code units, not a readable path.
    path: PathBuf,
    wide: Vec<u16>,
    // The whole security descriptor `GetNamedSecurityInfoW` allocated, freed with `LocalFree` on
    // drop — AFTER the DACL it holds has been reapplied, since `original_dacl` points INTO this
    // buffer and is invalid once it is freed.
    original_sd: PSECURITY_DESCRIPTOR,
    original_dacl: *mut ACL,
}

impl DenyAclGuard {
    /// `dir` is the directory object to deny — see the module doc for why this must be a
    /// directory in the path, not a file under it.
    fn deny_traversal_and_listing(dir: &Path) -> Self {
        let path = dir.to_path_buf();
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

        let mut original_dacl: *mut ACL = std::ptr::null_mut();
        let mut original_sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated; `original_dacl` and `original_sd` are valid `&mut`
        // out-params that outlive the call.
        unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut original_dacl),
                None,
                &mut original_sd,
            )
        }
        .ok()
        .expect("GetNamedSecurityInfoW");
        // From here on `original_sd` holds a `LocalAlloc`-backed allocation that must be freed
        // on every exit path — including the two panics below, which free it explicitly before
        // firing, since no `DenyAclGuard` will exist yet to do it in `Drop`.

        let sid_buf = current_user_sid_buf();
        let sid = sid_from_buf(&sid_buf);
        let mut trustee = TRUSTEE_W::default();
        // SAFETY: `trustee` is a freshly zeroed, correctly sized `TRUSTEE_W`; `sid` borrows from
        // `sid_buf`, which outlives this call.
        unsafe { BuildTrusteeWithSidW(&mut trustee, Some(sid)) };
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_TRAVERSE.0 | FILE_LIST_DIRECTORY.0,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        };

        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `entry` is fully initialized and borrows only from `sid_buf`, alive for this
        // call; `original_dacl` is the live ACL `GetNamedSecurityInfoW` just returned.
        let entries_set = unsafe { SetEntriesInAclW(Some(&[entry]), Some(original_dacl.cast_const()), &mut new_dacl) };
        if let Err(e) = entries_set.ok() {
            // SAFETY: `original_sd` was allocated by `GetNamedSecurityInfoW` above; this
            // function panics right after with no guard constructed to free it otherwise.
            unsafe { LocalFree(Some(HLOCAL(original_sd.0))) };
            panic!("SetEntriesInAclW: {e}");
        }

        // SAFETY: `wide` is NUL-terminated; `new_dacl` is the ACL `SetEntriesInAclW` just built.
        let set = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_dacl.cast_const()),
                None,
            )
        };
        // SAFETY: `new_dacl` was allocated by `SetEntriesInAclW` (a `LocalAlloc`-backed ACL);
        // `SetNamedSecurityInfoW` copies it into the object's own security descriptor rather
        // than retaining the pointer, whether that call succeeded or failed, so it is safe to
        // free here either way.
        unsafe { LocalFree(Some(HLOCAL(new_dacl.cast()))) };
        if let Err(e) = set.ok() {
            // SAFETY: same as the `SetEntriesInAclW` failure branch above.
            unsafe { LocalFree(Some(HLOCAL(original_sd.0))) };
            panic!("SetNamedSecurityInfoW: {e}");
        }

        DenyAclGuard {
            path,
            wide,
            original_sd,
            original_dacl,
        }
    }
}

impl Drop for DenyAclGuard {
    fn drop(&mut self) {
        // SAFETY: `self.wide` is still NUL-terminated; `self.original_dacl` still points into
        // `self.original_sd`'s buffer, not yet freed below.
        let restored = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(self.wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(self.original_dacl.cast_const()),
                None,
            )
        };
        // SAFETY: `self.original_sd` was allocated by `GetNamedSecurityInfoW`; the DACL it holds
        // has just been reapplied above (or the attempt is about to be reported as failed) —
        // either way nothing still borrows from it, and every other field of this guard is done
        // with it too, this being the guard's own `Drop`.
        unsafe { LocalFree(Some(HLOCAL(self.original_sd.0))) };
        if let Err(e) = restored.ok() {
            panic_or_eprint(format!(
                "could not restore the original ACL on {:?}: {e} — it may be left locked in %TEMP%",
                self.path
            ));
        }
    }
}

/// A `PATH` entry whose directory is denied at the Win32 ACL level, followed by one that holds
/// the name.
///
/// Binding order in each caller's `let` matters for correctness, not just tidiness: tuple
/// bindings from one `let` drop right-to-left, so with `_impersonation` named last it reverts
/// BEFORE `_guard` restores the ACL (irrelevant to correctness here, since the restore relies on
/// owner rights `SeChangeNotifyPrivilege` does not touch, but keeping the two guards' drop order
/// the mirror of their setup order is the less surprising default), which in turn restores the
/// ACL BEFORE `root`'s own `TempDir::drop` tries to delete the tree — the one drop-order
/// dependency that IS load-bearing, since deleting `locked` while it is still denied would fail.
fn locked_then_open() -> (
    tempfile::TempDir,
    PathBuf,
    std::ffi::OsString,
    DenyAclGuard,
    ImpersonationGuard,
) {
    let root = tempfile::tempdir().unwrap();
    let locked = root.path().join("locked");
    let open = root.path().join("open");
    std::fs::create_dir(&locked).unwrap();
    std::fs::create_dir(&open).unwrap();
    std::fs::write(open.join("tool.exe"), b"x").unwrap();
    let locked_tool = locked.join("tool.exe");
    std::fs::write(&locked_tool, b"x").unwrap();

    let mut path = locked.clone().into_os_string();
    path.push(";");
    path.push(&open);

    // Denies the DIRECTORY, not `locked_tool` — see the module doc.
    let guard = DenyAclGuard::deny_traversal_and_listing(&locked);
    let impersonation = ImpersonationGuard::without_change_notify();

    // The precondition lives HERE, not in each `#[test]`, so it covers BOTH tests: an ordinary
    // (non-`loadable_only`) search treats an absence code and an undeterminable one identically
    // (skip and continue), so a caller that only checked this from the `loadable_only` test could
    // have the ACL silently produce an absence code instead of code 5, and the ordinary-search
    // test would still pass — for the wrong reason, proving nothing about the ACL this file
    // exists to build.
    let probe = std::fs::metadata(&locked_tool).unwrap_err();
    assert_eq!(probe.raw_os_error(), Some(5), "precondition: {probe}");

    (root, open, path, guard, impersonation)
}

/// Under `loadable_only`, a candidate a real Windows ACL denies fails the search closed: the
/// entry after it must not win because a check errored with `ERROR_ACCESS_DENIED`.
///
/// [`locked_then_open`]'s own precondition assertion is what proves the ACL built there really
/// does yield raw Windows code 5 on THIS host, not merely a failure that happens to also map to
/// `PermissionDenied` — see the module doc for how easy that is to get wrong on Windows
/// specifically. This test additionally checks the same raw code survives through to
/// [`resolve`]'s own returned error, via its wrapped `source()`.
#[test]
fn an_undeterminable_windows_acl_fails_a_loadable_only_search_closed() {
    let (_root, _open, path, _guard, _impersonation) = locked_then_open();

    match search_tool(&path, true) {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
            assert_eq!(wrapped_raw_os_error(&e), Some(5), "{e}");
        }
        other => panic!("a loadable_only search must not skip an undeterminable candidate: {other:?}"),
    }
}

/// An ordinary spawn skips the denied candidate and goes on, as before, so one ACL-denied `PATH`
/// directory does not break every unelevated spawn.
#[test]
fn an_undeterminable_windows_acl_is_skipped_by_an_ordinary_search() {
    let (_root, open, path, _guard, _impersonation) = locked_then_open();
    assert_eq!(search_tool(&path, false).unwrap(), open.join("tool.exe"));
}
