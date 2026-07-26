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
