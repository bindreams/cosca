//! A REAL Windows ACL proof for [`resolve`]'s undeterminable-candidate disposition.
//!
//! [`resolve_base_tests`]'s `an_undeterminable_candidate_*` tests simulate the Windows grammar
//! (`windows: true`) on a Unix HOST, using a chmod-000 directory to produce a Unix `EACCES` —
//! useful for pinning the DISPOSITION (fail closed under `loadable_only`, skip and continue
//! otherwise), but not a real Windows `ERROR_ACCESS_DENIED` (raw code 5) from a real Windows
//! ACL, since no test here runs on a Windows host. This file is that: it builds an actual deny
//! ACE with the Win32 Authorization APIs and checks the same two dispositions against it.
//!
//! The deny ACE sits on a FILE (`locked\tool.exe`), not the `locked` directory itself: Windows
//! grants `SeChangeNotifyPrivilege` ("bypass traverse checking") to every ordinary token by
//! default, which skips the ACL check for `FILE_TRAVERSE`/`FILE_LIST_DIRECTORY` on an
//! intermediate directory entirely — so a deny ACE on `locked` alone would not reproduce
//! `ERROR_ACCESS_DENIED` for a query on a file under it; `GetFileAttributesExW`'s access check
//! on the FINAL target object is not subject to that bypass. Denying `FILE_GENERIC_READ` on the
//! file itself is what the precondition check below exists to confirm — on THIS host, not by
//! reasoning about the platform in the abstract.

use super::*;
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, SE_FILE_OBJECT, TRUSTEE_W,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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

/// Denies `FILE_GENERIC_READ` on a single Windows file object for the current user, via
/// `SetNamedSecurityInfoW`, and restores the ORIGINAL DACL on drop (not a guessed default) so
/// `tempfile::TempDir`'s own `Drop` can subsequently delete the tree without an access-denied
/// error of its own.
struct DenyAclGuard {
    path: Vec<u16>,
    // The whole security descriptor `GetNamedSecurityInfoW` allocated, freed with `LocalFree` on
    // drop — AFTER the DACL it holds has been reapplied, since `original_dacl` points INTO this
    // buffer and is invalid once it is freed.
    original_sd: PSECURITY_DESCRIPTOR,
    original_dacl: *mut ACL,
}

impl DenyAclGuard {
    fn deny_read(path: &Path) -> Self {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

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

        let sid_buf = current_user_sid_buf();
        let sid = sid_from_buf(&sid_buf);
        let mut trustee = TRUSTEE_W::default();
        // SAFETY: `trustee` is a freshly zeroed, correctly sized `TRUSTEE_W`; `sid` borrows from
        // `sid_buf`, which outlives this call.
        unsafe { BuildTrusteeWithSidW(&mut trustee, Some(sid)) };
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ.0,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        };

        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `entry` is fully initialized and borrows only from `sid_buf`, alive for this
        // call; `original_dacl` is the live ACL `GetNamedSecurityInfoW` just returned.
        unsafe { SetEntriesInAclW(Some(&[entry]), Some(original_dacl.cast_const()), &mut new_dacl) }
            .ok()
            .expect("SetEntriesInAclW");

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
        set.ok().expect("SetNamedSecurityInfoW");

        DenyAclGuard {
            path: wide,
            original_sd,
            original_dacl,
        }
    }
}

impl Drop for DenyAclGuard {
    fn drop(&mut self) {
        // SAFETY: `self.path` is still NUL-terminated; `self.original_dacl` still points into
        // `self.original_sd`'s buffer, not yet freed below.
        let restored = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(self.path.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(self.original_dacl.cast_const()),
                None,
            )
        };
        if let Err(e) = restored.ok() {
            log::warn!("could not restore the original ACL on {:?}: {e}", self.path);
        }
        // SAFETY: `self.original_sd` was allocated by `GetNamedSecurityInfoW`; the DACL it holds
        // has just been reapplied above (or the attempt logged), so nothing still borrows from
        // it, and every other field of this guard is done with it too — this is the guard's own
        // `Drop`.
        unsafe { LocalFree(Some(HLOCAL(self.original_sd.0))) };
    }
}

/// A `PATH` entry whose only candidate is denied at the Win32 ACL level, followed by one that
/// holds the name. `_guard` must outlive `_open`/`path`/`locked_tool` (it does: tuple bindings
/// from one `let` drop right-to-left) and, crucially, must drop before `root`'s own `TempDir`
/// `Drop` runs — true here for the same reason, since `root` is named first.
fn locked_then_open() -> (tempfile::TempDir, PathBuf, std::ffi::OsString, PathBuf, DenyAclGuard) {
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

    let guard = DenyAclGuard::deny_read(&locked_tool);
    (root, open, path, locked_tool, guard)
}

/// Under `loadable_only`, a candidate a real Windows ACL denies fails the search closed: the
/// entry after it must not win because a check errored with `ERROR_ACCESS_DENIED`.
///
/// The precondition assertion is the point of this test over [`resolve_base_tests`]'s simulated
/// equivalent: it proves the ACL built above really does yield raw Windows code 5 on THIS host,
/// not merely a failure that happens to also map to `PermissionDenied`.
#[test]
fn an_undeterminable_windows_acl_fails_a_loadable_only_search_closed() {
    let (_root, _open, path, locked_tool, _guard) = locked_then_open();

    let probe = std::fs::metadata(&locked_tool).unwrap_err();
    assert_eq!(probe.raw_os_error(), Some(5), "precondition: {probe}");

    match search_tool(&path, true) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}"),
        other => panic!("a loadable_only search must not skip an undeterminable candidate: {other:?}"),
    }
}

/// An ordinary spawn skips the denied candidate and goes on, as before, so one ACL-denied `PATH`
/// directory does not break every unelevated spawn.
#[test]
fn an_undeterminable_windows_acl_is_skipped_by_an_ordinary_search() {
    let (_root, open, path, _locked_tool, _guard) = locked_then_open();
    assert_eq!(search_tool(&path, false).unwrap(), open.join("tool.exe"));
}
