use super::{wait_readable, POLL_FAILED};

#[skuld::test]
fn a_copy_whose_poll_fails_ends_with_its_own_code() {
    // `poll` of more descriptors than `RLIMIT_NOFILE` allows is `EINVAL`. The copy is a fork, as the
    // helper's are, and does only system calls.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` fills the two descriptors; the child below calls only system calls.
    let status = unsafe {
        assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC), 0);
        match libc::fork() {
            -1 => panic!("fork: {}", std::io::Error::last_os_error()),
            0 => {
                let none = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::setrlimit(libc::RLIMIT_NOFILE, &none);
                wait_readable(fds[0]);
                // A poll that did not fail would block: this code says it returned.
                libc::_exit(0)
            }
            child => {
                let mut status = 0;
                assert_eq!(libc::waitpid(child, &mut status, 0), child);
                status
            }
        }
    };
    assert!(libc::WIFEXITED(status), "{status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), POLL_FAILED);
}
