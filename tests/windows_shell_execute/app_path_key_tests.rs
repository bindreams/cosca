//! The registry guard's own checks, on a scratch path of their own in HKCU (volatile, so a crash leaves nothing past
//! the logoff).

use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_VOLATILE,
};

use crate::app_path_key::{key_exists, AppPathKey};
use crate::test_groups::{shell_execute, Group};

fn scratch(tail: &str) -> String {
    format!(r"Software\cosca-probe-scratch-{}{tail}", std::process::id())
}

fn register(key: &str) -> AppPathKey {
    AppPathKey::register_at(HKEY_CURRENT_USER, REG_OPTION_VOLATILE, key, Path::new(r"C:\x.exe"))
        .unwrap_or_else(|e| panic!("register {key}: {e}"))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// Makes `child` under `key`, which keeps `key` from being deleted.
fn create_subkey(key: &str, child: &str) {
    let name = wide(&format!(r"{key}\{child}"));
    let mut hkey = HKEY::default();
    // SAFETY: `name` is NUL-terminated and outlives the call; `hkey` is a live local.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(name.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    assert_eq!(rc, ERROR_SUCCESS, "create the subkey");
    // SAFETY: `hkey` was opened above and is closed once.
    let _ = unsafe { RegCloseKey(hkey) };
}

fn delete_key(path: &str) {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let rc = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(name.as_ptr())) };
    assert_eq!(rc, ERROR_SUCCESS, "delete {path}");
}

/// Every parent the guard made is deleted with the key. Mutant: only the key itself.
#[skuld::test]
fn the_guard_deletes_the_parents_it_made(#[fixture(shell_execute)] _group: &Group) {
    let top = scratch("");
    let key = scratch(r"\App Paths\probe.exe");
    assert_eq!(
        key_exists(HKEY_CURRENT_USER, &top),
        Ok(false),
        "the scratch path is not free"
    );
    let guard = register(&key);
    assert_eq!(key_exists(HKEY_CURRENT_USER, &key), Ok(true));
    drop(guard);
    assert_eq!(
        key_exists(HKEY_CURRENT_USER, &top),
        Ok(false),
        "a parent the guard made was left behind"
    );
}

/// A parent that existed before is not the guard's to delete. Mutant: every parent is deleted.
#[skuld::test]
fn the_guard_keeps_the_parents_it_did_not_make(#[fixture(shell_execute)] _group: &Group) {
    let outer_key = scratch(r"\App Paths");
    let outer = register(&outer_key);
    let inner = register(&format!(r"{outer_key}\probe.exe"));
    drop(inner);
    assert_eq!(
        key_exists(HKEY_CURRENT_USER, &outer_key),
        Ok(true),
        "the guard deleted a parent it did not make"
    );
    drop(outer);
    assert_eq!(key_exists(HKEY_CURRENT_USER, &scratch("")), Ok(false));
}

/// A key that already exists is refused, not adopted. Mutant: the guard adopts it and deletes it on drop.
#[skuld::test]
fn the_guard_refuses_a_key_it_did_not_make(#[fixture(shell_execute)] _group: &Group) {
    let key = scratch(r"\App Paths\probe.exe");
    let guard = register(&key);
    let second = AppPathKey::register_at(HKEY_CURRENT_USER, REG_OPTION_VOLATILE, &key, Path::new(r"C:\y.exe"));
    assert!(second.is_err());
    assert_eq!(
        key_exists(HKEY_CURRENT_USER, &key),
        Ok(true),
        "the refused registration deleted the key"
    );
    drop(guard);
}

/// A delete that fails fails the test, and the guard keeps what it could not delete. Mutant: the failure is only
/// printed.
#[skuld::test]
fn a_failed_delete_fails_the_test(#[fixture(shell_execute)] _group: &Group) {
    let key = scratch(r"\App Paths\probe.exe");
    let mut guard = register(&key);
    create_subkey(&key, "child");

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| guard.finish()));
    assert!(outcome.is_err(), "a key with a subkey was left and the guard passed");

    delete_key(&format!(r"{key}\child"));
    guard.finish();
    assert_eq!(
        key_exists(HKEY_CURRENT_USER, &scratch("")),
        Ok(false),
        "the retry did not finish the job"
    );
}
