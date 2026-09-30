//! The `COSCA_TEST_SETUID` group: tests that need a real setuid-root helper. Depends only on std
//! and libc, so an integration test includes this file with `#[path]`.
//!
//! On unless `COSCA_TEST_SETUID=0`. An enabled group fails, rather than skips, unless
//! `COSCA_TEST_SETUID_CONSENT=1`: the helper is root, so run it in a sandbox or on CI.
//! `COSCA_TEST_SETUID_HELPER` names a copy of `cosca_testbin` that is owned by root with the
//! set-user-ID bit, on a filesystem not mounted `nosuid`.

use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

const GROUP: &str = "COSCA_TEST_SETUID";
const CONSENT: &str = "COSCA_TEST_SETUID_CONSENT";
const HELPER: &str = "COSCA_TEST_SETUID_HELPER";

/// Whether the group's tests run.
#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    Run,
    Disabled,
}

/// `Disabled` for an explicit `COSCA_TEST_SETUID=0`; otherwise `Run`.
///
/// # Panics
/// When enabled and `COSCA_TEST_SETUID_CONSENT` is not exactly `1`.
pub fn setuid_gate(var: impl Fn(&str) -> Option<String>) -> Gate {
    if var(GROUP).is_some_and(|v| v == "0") {
        return Gate::Disabled;
    }
    assert!(
        var(CONSENT).is_some_and(|v| v == "1"),
        "this test runs a setuid-root helper, which must never run on a developer host. Run it in a \
         container, VM or CI's setuid lane with {CONSENT}=1, or switch the group off with {GROUP}=0"
    );
    Gate::Run
}

/// The helper's path, or `None` when the group is disabled.
///
/// # Panics
/// When the gate panics, when `COSCA_TEST_SETUID_HELPER` is unset, when the file is not owned by
/// root with the set-user-ID bit, or when the caller is root (then nothing is unsignalable by it).
pub fn setuid_helper() -> Option<PathBuf> {
    if setuid_gate(|k| std::env::var(k).ok()) == Gate::Disabled {
        return None;
    }
    let helper = std::env::var_os(HELPER).unwrap_or_else(|| {
        panic!("{HELPER} is not set: point it at a root-owned, mode u+s copy of cosca_testbin (CI's \"Set up setuid-root helper\" step)")
    });
    let path = PathBuf::from(helper);
    let meta = std::fs::metadata(&path).unwrap_or_else(|e| panic!("{HELPER}={path:?} is unreadable: {e}"));
    assert!(
        meta.uid() == 0 && meta.mode() & 0o4000 != 0,
        "{HELPER}={path:?} must be owned by root with the set-user-ID bit (owner uid {}, mode {:o}): chown root and chmod u+s it",
        meta.uid(),
        meta.mode() & 0o7777
    );
    // SAFETY: `geteuid` has no preconditions.
    assert!(
        unsafe { libc::geteuid() } != 0,
        "the caller is root, so the setuid helper is signalable by it and the group tests nothing: run as an unprivileged user"
    );
    Some(path)
}
