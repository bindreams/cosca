use std::os::fd::RawFd;

use crate::test_own_process::{own_process, test_path};
use crate::test_stdio::RestoreStdio;

/// The (device, inode) of what `fd` refers to, or `None` if it is not open.
fn identity(fd: RawFd) -> Option<(u64, u64)> {
    // SAFETY: fstat on a descriptor number with a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev as u64, st.st_ino as u64))
}

#[test]
fn close_frees_the_fd_and_drop_puts_the_same_file_back() {
    let Some(done) = own_process(test_path!(close_frees_the_fd_and_drop_puts_the_same_file_back)) else {
        return;
    };
    let before = identity(2).expect("fd 2 is open");
    let restore = RestoreStdio::close(&done, &[2]);
    assert_eq!(identity(2), None, "close must free fd 2");
    drop(restore);
    assert_eq!(identity(2), Some(before), "drop must restore the same file");
}
