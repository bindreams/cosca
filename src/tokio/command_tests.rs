//! Unit tests for the async builder mirror — assert the wrapped sync request records the
//! configured values (the integration suite only proves the spawn path).

use crate::containment::Nesting;
use crate::ContainMode;

#[test]
fn contain_with_and_nesting_recorded() {
    let mut cmd = super::Command::new();
    cmd.contain_with(ContainMode::TreeWalk).nesting(Nesting::Opaque);
    let req = cmd.inner.contain_request();
    assert_eq!(req.mode, Some(ContainMode::TreeWalk));
    assert_eq!(req.nesting, Nesting::Opaque);
}

#[test]
fn tokio_elevate_forwards_to_inner_request() {
    let mut c = super::Command::new();
    c.args(["id", "-u"]).elevation_backend(crate::elevation::Backend::Sudo);
    // command_tests is a child module of tokio::command, so it can read the private inner.
    let req = c.inner.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Sudo);
}

#[cfg(unix)]
#[tokio::test]
async fn tokio_child_elevation_is_none_without_elevate() {
    let mut c = super::Command::new();
    c.args(["true"]);
    let child = c.spawn().expect("spawn");
    assert!(child.elevation().is_none());
}

/// The async builder hand-mirrors the sync one and parity is not compiler-enforced (see this
/// module's own doc). `raw_executable` was missing for exactly that reason: the async raw backend
/// carried an `Exact` arm that no public async API could reach, so the "load exactly this file"
/// contract silently did not exist on the tokio side.
///
/// Asserted over the RECORDED spec rather than "a method was called", so it also pins that the
/// delegate forwards to `raw_executable` and not to `executable`.
#[test]
fn tokio_raw_executable_records_an_exact_spec() {
    use crate::command::ExecutableSpec;
    use std::path::Path;

    let mut c = super::Command::new();
    c.raw_executable("helper");
    assert!(
        matches!(c.inner.executable_spec(), Some(ExecutableSpec::Exact(p)) if p == Path::new("helper")),
        "raw_executable must record Exact, got {:?}",
        c.inner.executable_spec()
    );

    // And the sibling setter still records Search through the same wrapper, so the two are not
    // accidentally wired to the same inner method.
    let mut s = super::Command::new();
    s.executable("helper");
    assert!(matches!(s.inner.executable_spec(), Some(ExecutableSpec::Search(_))));
}
