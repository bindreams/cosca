//! `open_verified` where the checked `/proc` cannot be opened for lack of `openat2` (kernel
//! before 5.6, or a seccomp filter): `Unsupported` naming the requirement, not `Unassessable`.

use crate::error::Error;
use crate::identity::proc_view_fault::force_openat2_errno;
use crate::identity::ProcessId;

use super::PidfdOp;

fn assert_names_openat2(result: Result<Option<rustix::fd::OwnedFd>, Error>, errno_name: &str) {
    match result {
        Err(Error::Unsupported { op, detail, platform }) => {
            assert_eq!(platform, "linux");
            assert_eq!(detail, crate::identity::openat2_refused_message(errno_name));
            // The caller's operation, not one shared string: owned children reach this path too.
            assert_eq!(op, "process terminate");
        }
        other => panic!(
            "expected Unsupported naming openat2, got {:?}",
            other.map(|fd| fd.is_some())
        ),
    }
}

/// `pidfd_open` succeeds, then the fdinfo check needs the `/proc` dirfd.
/// Mutant: "`verify_pidfd_target` reports an unopenable `/proc` as `Unassessable`".
#[test]
fn open_verified_is_unsupported_naming_openat2_when_it_is_unavailable() {
    for (errno, name) in [(rustix::io::Errno::NOSYS, "ENOSYS"), (rustix::io::Errno::PERM, "EPERM")] {
        let _forced = force_openat2_errno(errno);
        assert_names_openat2(super::open_verified(ProcessId::current(), PidfdOp::Terminate), name);
    }
}

/// The `pidfd_open`-refused arm asks [`proc_view`](crate::identity::proc_view).
/// Mutant: "`verify_without_pidfd` reports an unopenable `/proc` as `Unassessable`".
#[test]
fn open_verified_without_a_pidfd_is_unsupported_naming_openat2_when_it_is_unavailable() {
    let _errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL);
    let _forced = force_openat2_errno(rustix::io::Errno::NOSYS);
    assert_names_openat2(super::open_verified(ProcessId::current(), PidfdOp::Terminate), "ENOSYS");
}
