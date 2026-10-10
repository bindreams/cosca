use super::OwnerPidfdFailure::{CoscaGone, Unwatchable};

#[skuld::test]
fn owner_pidfd_errno_mapping() {
    let table = [
        (libc::ESRCH, CoscaGone, 123),
        (libc::EINVAL, CoscaGone, 123),
        (libc::EMFILE, Unwatchable, 116),
        (libc::ENFILE, Unwatchable, 116),
        (libc::ENOMEM, Unwatchable, 116),
        (libc::ENOSYS, Unwatchable, 116),
        (libc::EPERM, Unwatchable, 116),
    ];
    for (errno, failure, code) in table {
        let mapped = super::OwnerPidfdFailure::from_errno(errno);
        assert_eq!(mapped, failure, "errno {errno}");
        assert_eq!(mapped.exit_code(), code, "errno {errno}");
    }
}
