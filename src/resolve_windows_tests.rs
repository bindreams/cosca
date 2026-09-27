//! A REAL Windows ACL proof for [`resolve`]'s undeterminable-candidate disposition.
//!
//! `src/resolve_base_tests.rs` has a Unix-side test that simulates the Windows grammar
//! (`windows: true`) on a Unix HOST, using a directory this process is denied read access to —
//! useful for pinning the DISPOSITION (fail closed under `loadable_only`, skip and continue
//! otherwise), but not a real Windows `ERROR_ACCESS_DENIED` (raw code 5) from a real Windows
//! ACL, since it does not run on a Windows host. This file is that: it builds an actual deny ACE
//! with the Win32 Authorization APIs and checks the same two dispositions against it.
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
//! this process's own, so no other thread is affected. See
//! [`ImpersonationGuard::without_change_notify`]'s doc for why a process-wide strip is unsound
//! here.
//!
//! Only the combination above — both bits denied on the directory, `SeChangeNotifyPrivilege`
//! stripped for the probing thread — was actually measured to work, on GitHub's Windows CI
//! runners; there is no Windows host to develop this against directly.
//! [`locked_then_open`]'s own precondition assertion is what still proves it holds on whichever
//! host runs this test, rather than resting on the reasoning above.

use super::*;
use std::marker::PhantomData;
use std::os::windows::ffi::OsStrExt;

use windows::core::{Owned, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_NO_TOKEN, HANDLE, HLOCAL, LUID};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, SE_FILE_OBJECT, TRUSTEE_W,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, LookupPrivilegeValueW, SecurityImpersonation,
    TokenImpersonation, TokenPrivileges, TokenUser, ACL, DACL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES,
    NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{FILE_LIST_DIRECTORY, FILE_TRAVERSE};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
};

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
/// coarser kind.
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
/// `!Send` (via the `PhantomData<*const ()>` field): impersonation is a property of the OS
/// thread that called [`Self::without_change_notify`], not of this Rust value, so the guard must
/// not be movable to another thread, where `Drop` would revert impersonation nobody there set up
/// and leave THIS thread — the one that actually called `SetThreadToken` — impersonating forever.
///
/// Scoped to one thread's impersonation token rather than touching this process's own: the
/// alternative would be a process-wide, temporary DISABLE-then-RE-ENABLE of
/// `SeChangeNotifyPrivilege` on the process token (distinct from the `SE_PRIVILEGE_REMOVED` this
/// function applies to a DUPLICATE below, which is irreversible for whichever token it lands on
/// — re-enabling after THAT is not an option at all). That disable-then-re-enable alternative has
/// its own race: `cargo test` runs every test as a separate thread within ONE process (nextest,
/// which this repo's CI uses, instead gives each test its own process — see `d2b1c7bd`), so
/// under plain `cargo test` a concurrently running test on another thread of that same process
/// would observe the process token with the privilege missing too, for the whole disabled
/// window — a data race on shared, mutable process state. A thread's impersonation token is not
/// shared with any other thread, so touching only it, for only the calling thread's own
/// lifetime, has no such window.
struct ImpersonationGuard(PhantomData<*const ()>);

impl ImpersonationGuard {
    fn without_change_notify() -> Self {
        Self::assert_not_already_impersonating();

        // SAFETY: `TOKEN_DUPLICATE` is a real, valid `TOKEN_ACCESS_MASK` constant.
        let raw_token = unsafe { open_process_token(TOKEN_DUPLICATE) }.expect("OpenProcessToken(TOKEN_DUPLICATE)");
        // SAFETY: `raw_token` was just opened above and is owned by this function from here on —
        // wrapping it immediately means every exit path below, including a panic, closes it.
        let token = unsafe { Owned::new(raw_token) };

        let mut raw_dup = HANDLE::default();
        // SAFETY: `*token` is a live, owned handle with `TOKEN_DUPLICATE` access; `raw_dup` is a
        // valid `&mut` out-param.
        unsafe {
            DuplicateTokenEx(
                *token,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_QUERY,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw_dup,
            )
        }
        .expect("DuplicateTokenEx");
        // SAFETY: `raw_dup` was just created above and is owned by this function from here on —
        // same reasoning as `token`.
        let dup = unsafe { Owned::new(raw_dup) };
        drop(token); // the source token is no longer needed once the duplicate exists

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
        // `AdjustTokenPrivileges` reports success via its `BOOL` return (`Ok(())` here) even when
        // the token never held the privilege to remove — `GetLastError() == ERROR_NOT_ALL_ASSIGNED`
        // is the only signal of THAT, and it is not itself a failure (a token that never held the
        // privilege is a valid state, so this deliberately does not inspect `GetLastError()` at
        // all). Neither outcome proves `SeChangeNotifyPrivilege` is actually absent from `dup`
        // afterward, which is the one thing that matters here — so the assertion right below
        // reads the privilege list back via `GetTokenInformation` and checks that directly.
        // SAFETY: `privileges` describes one LUID and `PrivilegeCount` matches; `*dup` is this
        // function's own fresh, owned duplicate.
        unsafe { AdjustTokenPrivileges(*dup, false, Some(&privileges), 0, None, None) }
            .expect("AdjustTokenPrivileges(SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_REMOVED)");
        assert!(
            !token_has_privilege(*dup, luid),
            "AdjustTokenPrivileges(SE_PRIVILEGE_REMOVED) reported success, but \
             SeChangeNotifyPrivilege is still present on the duplicate token"
        );

        // Build the guard from `SetThreadToken`'s own result BEFORE dropping `dup` below: if
        // `SetThreadToken` succeeded, this thread is now impersonating, and `guard` — once
        // unwrapped — is the only thing whose `Drop` reverts that. Dropping `dup` cannot itself
        // fail (`Owned::drop` swallows `CloseHandle`'s own possible failure, matching every
        // other `HANDLE`'s `Free` impl), so there is no panic window between "impersonating" and
        // "guard exists" for it to open — but building `guard` first keeps that invariant true
        // even if a future edit here made freeing `dup` fallible.
        // SAFETY: `*dup` is a valid, owned impersonation-type token for this same process's own
        // identity, missing only the one privilege just removed.
        let guard = unsafe { SetThreadToken(None, Some(*dup)) }.map(|()| ImpersonationGuard(PhantomData));
        drop(dup);
        guard.expect("SetThreadToken")
    }

    /// `Drop` reverts to NO impersonation at all (`SetThreadToken(None, None)`), which would
    /// discard whatever impersonation the calling thread already had if this were nested inside
    /// it — a precondition worth asserting rather than silently violating.
    fn assert_not_already_impersonating() {
        let mut existing = HANDLE::default();
        // SAFETY: `GetCurrentThread` returns a pseudo-handle needing no close; `existing` is a
        // valid `&mut` out-param.
        match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &mut existing) } {
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_NO_TOKEN.0) => {} // expected: none yet
            Err(e) => panic!("OpenThreadToken: unexpected error probing for prior impersonation: {e}"),
            Ok(()) => {
                // SAFETY: `existing` is a handle this branch just opened, owned from here on —
                // wrapped so the `panic!` below still closes it.
                let _existing = unsafe { Owned::new(existing) };
                panic!(
                    "this thread is already impersonating — ImpersonationGuard::drop only knows \
                     how to revert to NO impersonation, so nesting would discard the caller's own"
                );
            }
        }
    }
}

/// Whether `token` currently holds the privilege named by `luid`, read back via
/// `GetTokenInformation(TokenPrivileges)` — see [`ImpersonationGuard::without_change_notify`]'s
/// call site for why this is checked directly rather than inferred from `AdjustTokenPrivileges`'s
/// own return value.
fn token_has_privilege(token: HANDLE, luid: LUID) -> bool {
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 is the documented size query; it fails with
    // ERROR_INSUFFICIENT_BUFFER and writes the required size.
    let _ = unsafe { GetTokenInformation(token, TokenPrivileges, None, 0, &mut needed) };
    // u32-backed so the `TOKEN_PRIVILEGES` cast below is 4-aligned, as it requires.
    let mut buf = vec![0u32; (needed as usize).div_ceil(4).max(1)];
    // SAFETY: `buf` is at least `needed` bytes.
    unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 4) as u32,
            &mut needed,
        )
    }
    .expect("GetTokenInformation(TokenPrivileges)");
    // SAFETY: the kernel wrote a `TOKEN_PRIVILEGES` — a `u32` count followed by that many
    // `LUID_AND_ATTRIBUTES`, both 4-byte types — at the head of a 4-aligned buffer.
    let count = unsafe { *buf.as_ptr().cast::<u32>() } as usize;
    // SAFETY: `count` is exactly how many `LUID_AND_ATTRIBUTES` the same call just wrote
    // immediately after the leading `u32` count, in the same buffer.
    let privileges = unsafe { std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<LUID_AND_ATTRIBUTES>(), count) };
    privileges.iter().any(|p| p.Luid == luid)
}

/// [`OpenProcessToken`] wrapped to return the handle by value instead of through an out-param,
/// so its caller can hand the result straight to [`Owned::new`] without an intermediate
/// `HANDLE::default()` binding of its own.
///
/// # Safety
/// Same as [`OpenProcessToken`]: `access` must be a valid `TOKEN_ACCESS_MASK` for the call.
unsafe fn open_process_token(access: windows::Win32::Security::TOKEN_ACCESS_MASK) -> windows::core::Result<HANDLE> {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no close; `token` is a valid
    // `&mut` out-param. The caller upholds `access`'s validity per this function's own contract.
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) }?;
    Ok(token)
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: reverts THIS thread's impersonation token to none, the exact counterpart to
        // `SetThreadToken(None, Some(*dup))` above.
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
    /// The whole security descriptor `GetNamedSecurityInfoW` allocated, as an `Owned<HLOCAL>`
    /// FIELD rather than a bare `PSECURITY_DESCRIPTOR` freed by hand: a struct's fields drop in
    /// DECLARATION order, but only after its own `Drop::drop` body has already returned — so
    /// this frees itself automatically, and always AFTER [`DenyAclGuard`]'s `Drop::drop` below
    /// has reapplied the DACL `original_dacl` (which points INTO this buffer) — with no manual
    /// `LocalFree` call needed on any path, `Drop::drop` included, and none of construction's own
    /// early-return panics able to leak it either, since it becomes an owned `Owned` value the
    /// moment `GetNamedSecurityInfoW` returns.
    // Never read after construction — kept alive purely for this `Drop`, which `-D warnings`
    // cannot tell from an accidentally-unused field.
    #[allow(dead_code)]
    original_sd: Owned<HLOCAL>,
    original_dacl: *mut ACL,
}

impl DenyAclGuard {
    /// `dir` is the directory object to deny — see the module doc for why this must be a
    /// directory in the path, not a file under it.
    fn deny_traversal_and_listing(dir: &Path) -> Self {
        let path = dir.to_path_buf();
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

        let mut original_dacl: *mut ACL = std::ptr::null_mut();
        let mut raw_sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated; `original_dacl` and `raw_sd` are valid `&mut`
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
                &mut raw_sd,
            )
        }
        .ok()
        .expect("GetNamedSecurityInfoW");
        // SAFETY: `raw_sd` was just allocated by `GetNamedSecurityInfoW` above and is owned by
        // this function from here on — wrapping it immediately means every exit path below,
        // including the two panics further down, frees it automatically (see the field's own
        // doc on `DenyAclGuard` for why that is also true of `DenyAclGuard`'s own `Drop`).
        let original_sd = unsafe { Owned::new(HLOCAL(raw_sd.0)) };

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
        // `original_sd` (an `Owned<HLOCAL>` local by now) frees itself when this function
        // unwinds past it, so this — unlike `new_dacl`'s own freeing just below — needs no
        // explicit cleanup before panicking.
        entries_set.ok().expect("SetEntriesInAclW");

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
        // `original_sd` again frees itself on unwind if this panics — see above.
        set.ok().expect("SetNamedSecurityInfoW");

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
        // `self.original_sd`'s buffer — `original_sd`'s own `Drop` (a struct FIELD, freed only
        // after this function body returns; see its doc) has not run yet, so the buffer is
        // still valid here regardless of which arm below this call takes.
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
/// The returned [`ImpersonationGuard`] and [`DenyAclGuard`] must be dropped, in that order
/// (impersonation reverted first), before the returned [`tempfile::TempDir`] is closed — each
/// caller below does so explicitly, rather than relying on the tuple's own drop order, so it can
/// also call `TempDir::close` and assert the tree actually got removed. Reverting impersonation
/// first is not merely cosmetic: with `SeChangeNotifyPrivilege` still stripped,
/// `SetNamedSecurityInfoW`'s own path resolution down to `locked` would need real
/// `FILE_TRAVERSE` on every ancestor of `locked` (`root` included) — nothing denies any of those
/// today, so restoring the ACL while still impersonating would in fact still work, but reverting
/// first removes the dependency on that staying true. Restoring the ACL before `TempDir::close`
/// tries to delete the tree IS unconditionally load-bearing, since deleting `locked` while it is
/// still denied would fail.
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
    let (root, _open, path, guard, impersonation) = locked_then_open();

    match search_tool(&path, true) {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
            assert_eq!(wrapped_raw_os_error(&e), Some(5), "{e}");
        }
        other => panic!("a loadable_only search must not skip an undeterminable candidate: {other:?}"),
    }

    // Explicit, in the order `locked_then_open`'s doc requires, so `root.close()` below sees a
    // `locked` that is actually deletable and a failure to remove it fails this test rather than
    // being swallowed by `TempDir`'s own `Drop`.
    drop(impersonation);
    drop(guard);
    root.close().expect("remove the tempdir");
}

/// An ordinary spawn skips the denied candidate and goes on, as before, so one ACL-denied `PATH`
/// directory does not break every unelevated spawn.
#[test]
fn an_undeterminable_windows_acl_is_skipped_by_an_ordinary_search() {
    let (root, open, path, guard, impersonation) = locked_then_open();
    assert_eq!(search_tool(&path, false).unwrap(), open.join("tool.exe"));

    // See the sibling test for why this order and the explicit `close()` matter.
    drop(impersonation);
    drop(guard);
    root.close().expect("remove the tempdir");
}
