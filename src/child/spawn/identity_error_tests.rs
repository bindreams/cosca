//! A spawn whose child's identity cannot be read because the checked `/proc` view is
//! unavailable says so, and does not leak the child. On pidfs the identity needs no view.

use super::spawn_tests::teardown_blocker;
use crate::error::Error;
use crate::test_groups::{pidfd_group_signal, Group};
use crate::test_seccomp::{deny_openat2_on_this_thread, OPENAT2_REFUSALS};

/// The kernel refuses `openat2` (a real seccomp filter): on pidfs the spawn identifies its child by
/// the pidfd it holds and needs no `/proc` view, so it succeeds. (Below Linux 6.9 it fails
/// `Unsupported` naming `openat2`; `the_error_names_the_view_the_read_failed_on` states that host.)
///
/// Mutant: the spawn reads its child's identity through the `/proc` view.
#[skuld::test]
fn a_spawn_where_openat2_is_refused_succeeds_on_pidfs(#[fixture(pidfd_group_signal)] _group: &Group) {
    for (errno, name) in OPENAT2_REFUSALS {
        // The hooks `teardown_blocker` arms are thread-local.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let (mut cmd, teardown) = teardown_blocker();
                    deny_openat2_on_this_thread(errno);
                    let child = cmd
                        .spawn()
                        .unwrap_or_else(|e| panic!("{name}: a pidfs spawn needs no openat2: {e}"));
                    child.kill().expect("kill the child");
                    child.wait().expect("reap the child");
                    drop(teardown);
                })
                .join()
                .expect("the filtered thread")
        });
    }
}

/// The error describes the read that failed, not a second look at a view that may have recovered:
/// the host's own view is fine here, yet the cause the read carried is named. Mutant:
/// "`spawn_identity_error` asks the view again".
#[skuld::test]
fn the_error_names_the_view_the_read_failed_on() {
    use crate::identity::{ProcessId, UnknownCause};

    // The `/proc` path: the view is only read where pidfds have no inode of their own.
    let kernel = crate::identity::ticks_host(std::process::id()).open_proc_fails(rustix::io::Errno::NOSYS);
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
