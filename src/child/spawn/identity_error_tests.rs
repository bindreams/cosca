//! A spawn whose child's identity cannot be read because the checked `/proc` view is
//! unavailable says so, and does not leak the child.

use super::spawn_tests::teardown_blocker;
use crate::error::Error;
use crate::identity::proc_view_fault::force_openat2_errno;

/// Mutant: "`spawn_identity_error` reports every `Unknown` as the OS refusing" - the
/// `Unassessable` that names no cause.
#[skuld::test]
fn a_spawn_where_openat2_is_unavailable_is_unsupported_naming_it() {
    for (errno, name) in [(rustix::io::Errno::NOSYS, "ENOSYS"), (rustix::io::Errno::PERM, "EPERM")] {
        let (mut cmd, teardown) = teardown_blocker();
        let forced = force_openat2_errno(errno);
        let err = cmd.spawn().err();
        drop(forced);

        match err.expect("a spawn without openat2 must fail") {
            Error::Unsupported { detail, platform, .. } => {
                assert_eq!(platform, "linux");
                assert_eq!(detail, crate::identity::openat2_refused_message(name), "{errno}");
            }
            other => panic!("{errno}: expected Unsupported, got {other:?}"),
        }
        teardown.assert_killed();
    }
}
