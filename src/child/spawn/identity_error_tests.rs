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

        let (err, fate) =
            crate::child::spawn::failure::expect_may_have_started_with(err.expect("a spawn without openat2 must fail"));
        assert_eq!(
            fate,
            crate::error::ChildFate::Reaped,
            "{errno}: the pidfd pins the child, so it is reaped"
        );
        match err {
            Error::Unsupported { detail, platform, .. } => {
                assert_eq!(platform, "linux");
                assert_eq!(detail, crate::identity::openat2_refused_message(name), "{errno}");
            }
            other => panic!("{errno}: expected Unsupported, got {other:?}"),
        }
        teardown.assert_killed();
    }
}

/// The error describes the read that failed, not a second look at a view that may have recovered:
/// the host's own view is fine here, yet the cause the read carried is named. Mutant:
/// "`spawn_identity_error` asks the view again".
#[skuld::test]
fn the_error_names_the_view_the_read_failed_on() {
    use crate::identity::{FakeKernel, HostKernel, ProcessId, UnknownCause};

    let kernel = FakeKernel::over(&HostKernel).open_proc_fails(rustix::io::Errno::NOSYS);
    let (read, cause) = ProcessId::of_with(&kernel, std::process::id());
    match crate::child::spawn::spawn_identity_error(read, cause) {
        Error::Unsupported { detail, .. } => {
            assert_eq!(detail, crate::identity::openat2_refused_message("ENOSYS"));
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }

    // A read that knows no cause is the OS's refusal, whatever the view is now.
    let err = crate::child::spawn::spawn_identity_error(crate::identity::Resolved::Unknown, UnknownCause::default());
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
}
