//! A REAL Windows ACL proof for [`resolve`]'s undeterminable-candidate disposition.
//!
//! [`resolve_base_tests`]'s `an_undeterminable_candidate_*` tests simulate the Windows grammar
//! (`windows: true`) on a Unix HOST, using a chmod-000 directory to produce a Unix `EACCES` —
//! useful for pinning the DISPOSITION (fail closed under `loadable_only`, skip and continue
//! otherwise), but not a real Windows `ERROR_ACCESS_DENIED` (raw code 5) from a real Windows
//! ACL, since no test here runs on a Windows host. This file is that: it builds an actual deny
//! ACE with the Win32 Authorization APIs and checks the same two dispositions against it.
//!
//! # Where the deny ACE has to sit, and why two earlier attempts here did not work
//!
//! `std::fs::metadata` on Windows (`library/std/src/sys/fs/windows.rs`, `fn metadata`) opens the
//! target with `access_mode(0)` — "No read or write permissions are necessary", per its own
//! comment — plus `FILE_FLAG_BACKUP_SEMANTICS`. A zero-access open has nothing for a DACL on the
//! FILE ITSELF to deny, so a deny ACE placed on `locked\tool.exe` (this file's first version,
//! denying `FILE_GENERIC_READ`) has no effect at all — measured on GitHub's Windows runners: the
//! probe returned `Ok` with real metadata every time, ACE or no ACE.
//!
//! What that zero-access open still needs is to REACH the file: NT requires `FILE_TRAVERSE`
//! (`0x20`, the same bit as `FILE_EXECUTE`) on every intermediate directory in the path. By
//! default every token holds `SeChangeNotifyPrivilege` ("bypass traverse checking"), which skips
//! that check entirely — so a deny ACE on `locked` for `FILE_TRAVERSE` alone is ALSO not enough
//! while the privilege is held (this file's second version, which still failed on CI).
//! [`drop_bypass_privileges`] removes it from this process first, the same way
//! `identity::windows_fixture::drop_se_debug_privilege` removes `SeDebugPrivilege` for its own
//! DACL to be authoritative: an interactive session does not hold it enabled, which is why
//! neither gap would have shown up locally.
//!
//! Denying `FILE_TRAVERSE` still is not sufficient alone: on `ERROR_ACCESS_DENIED` (or
//! `ERROR_SHARING_VIOLATION`), `metadata`'s own fallback retries via `FindFirstFileExW` on the
//! same path — a directory-listing operation gated on `FILE_LIST_DIRECTORY` (`0x1`), a SEPARATE
//! bit from `FILE_TRAVERSE` despite the similar name, and one `SeChangeNotifyPrivilege` explicitly
//! does not cover ("This user right doesn't allow the user to list the contents of a folder.",
//! per Microsoft's own doc for it). So the deny ACE below denies both bits on `locked`, and
//! [`drop_bypass_privileges`] strips the one privilege that would otherwise blunt one of them —
//! between the two, neither of `metadata`'s two internal paths can complete.
//!
//! The precondition assertion in `an_undeterminable_windows_acl_fails_a_loadable_only_search_closed`
//! is what actually proves all of the above holds on THIS host, rather than resting on the
//! reasoning above: it calls `std::fs::metadata` directly and checks for raw code 5 BEFORE
//! asserting anything about [`resolve`]'s own behaviour.

use super::*;
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, LUID};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, SE_FILE_OBJECT, TRUSTEE_W,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenUser, ACL, DACL_SECURITY_INFORMATION,
    LUID_AND_ATTRIBUTES, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, SE_BACKUP_NAME, SE_CHANGE_NOTIFY_NAME,
    SE_PRIVILEGE_REMOVED, SE_RESTORE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{FILE_LIST_DIRECTORY, FILE_TRAVERSE};
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

/// Runs [`drop_bypass_privileges`] exactly once per test binary. Mirrors
/// `identity::windows_fixture`'s `SE_DEBUG_DROPPED` idiom.
static BYPASS_PRIVILEGES_DROPPED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Remove `SeChangeNotifyPrivilege` (see the module doc for why it matters here),
/// `SeBackupPrivilege` and their respective, less relevant twins from THIS process's token.
/// `SE_PRIVILEGE_REMOVED` is irreversible for the token, so this runs ONCE, before the first
/// deny ACE exists, exactly like `identity::windows_fixture::drop_se_debug_privilege`.
fn drop_bypass_privileges() {
    BYPASS_PRIVILEGES_DROPPED.get_or_init(|| {
        let mut token = HANDLE::default();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no close.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) }
            .expect("OpenProcessToken(TOKEN_ADJUST_PRIVILEGES)");
        for name in [SE_CHANGE_NOTIFY_NAME, SE_BACKUP_NAME, SE_RESTORE_NAME] {
            let mut luid = LUID::default();
            // SAFETY: `name` is one of the three static NUL-terminated wide strings named above.
            unsafe { LookupPrivilegeValueW(None, name, &mut luid) }.expect("LookupPrivilegeValueW");
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_REMOVED,
                }],
            };
            // Succeeds with ERROR_NOT_ALL_ASSIGNED when the token never held the privilege —
            // the normal local case, and exactly the state wanted either way.
            // SAFETY: `privileges` describes one LUID and `PrivilegeCount` matches.
            unsafe { AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None) }
                .expect("AdjustTokenPrivileges(SE_PRIVILEGE_REMOVED)");
        }
        // SAFETY: `token` is an owned handle this function is done with.
        unsafe { CloseHandle(token) }.expect("CloseHandle(process token)");
    });
}

/// Denies `FILE_TRAVERSE`/`FILE_LIST_DIRECTORY` on a single Windows DIRECTORY object for the
/// current user, via `SetNamedSecurityInfoW`, and restores the ORIGINAL DACL on drop (not a
/// guessed default) so `tempfile::TempDir`'s own `Drop` can subsequently delete the tree without
/// an access-denied error of its own.
struct DenyAclGuard {
    path: Vec<u16>,
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
        drop_bypass_privileges();
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

/// A `PATH` entry whose directory is denied at the Win32 ACL level, followed by one that holds
/// the name. `_guard` must outlive `_open`/`path`/`locked_tool` (it does: tuple bindings from
/// one `let` drop right-to-left) and, crucially, must drop before `root`'s own `TempDir` `Drop`
/// runs — true here for the same reason, since `root` is named first.
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

    // Denies the DIRECTORY, not `locked_tool` — see the module doc.
    let guard = DenyAclGuard::deny_traversal_and_listing(&locked);
    (root, open, path, locked_tool, guard)
}

/// Under `loadable_only`, a candidate a real Windows ACL denies fails the search closed: the
/// entry after it must not win because a check errored with `ERROR_ACCESS_DENIED`.
///
/// The precondition assertion is the point of this test over [`resolve_base_tests`]'s simulated
/// equivalent: it proves the ACL built above really does yield raw Windows code 5 on THIS host,
/// not merely a failure that happens to also map to `PermissionDenied` — see the module doc for
/// how easy that is to get wrong on Windows specifically.
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
