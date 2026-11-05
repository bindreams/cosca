//! A spawn whose child's identity cannot be read because the checked `/proc` view is
//! unavailable says so.

use crate::error::Error;

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
