use std::os::fd::RawFd;

use crate::test_own_process::{own_process, test_path};
use crate::test_spawn::spawn;
use crate::test_stdio::RestoreStdio;

/// The (device, inode) of what `fd` refers to, or `None` if it is not open.
fn identity(fd: RawFd) -> Option<impl Eq + std::fmt::Debug + Copy> {
    // SAFETY: fstat on a descriptor number with a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == 0 {
        return Some((st.st_dev, st.st_ino));
    }
    let err = std::io::Error::last_os_error();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EBADF),
        "fstat({fd}) failed with {err}, not as a closed fd"
    );
    None
}

#[test]
fn close_frees_the_fd_and_drop_puts_the_same_file_back() {
    let Some(done) = own_process(test_path!(close_frees_the_fd_and_drop_puts_the_same_file_back), spawn) else {
        return;
    };
    let before = identity(2).expect("fd 2 is open");
    let restore = RestoreStdio::close(&done, &[2]);
    assert_eq!(identity(2), None, "close must free fd 2");
    drop(restore);
    assert_eq!(identity(2), Some(before), "drop must restore the same file");
}

#[test]
fn a_panic_partway_through_close_still_restores_the_fds_already_closed() {
    let Some(done) = own_process(
        test_path!(a_panic_partway_through_close_still_restores_the_fds_already_closed),
        spawn,
    ) else {
        return;
    };
    let before = identity(2).expect("fd 2 is open");
    // fd 2 is closed by the time the second fd fails, so the panic message itself goes nowhere.
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        RestoreStdio::close(&done, &[2, RawFd::MAX]);
    }))
    .expect_err("closing an fd that is not open must panic");
    assert_eq!(identity(2), Some(before), "the unwound guard must put fd 2 back");
    let message = panic
        .downcast_ref::<String>()
        .expect("a formatted panic message")
        .clone();
    let cause = std::io::Error::from_raw_os_error(libc::EBADF).to_string();
    assert!(
        message.contains(&cause),
        "{message:?} does not name the cause {cause:?}"
    );
}
