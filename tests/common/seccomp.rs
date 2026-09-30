//! A real seccomp filter on the calling thread, for tests of a syscall a sandbox refuses.

/// Make `pidfd_open` fail with `errno` (a positive `libc` constant) on the calling thread and
/// every process it forks, as a seccomp-filtered container does. A seccomp filter is per thread:
/// a test keeps its own `pidfd_open` by running the denied code on a thread of its own.
pub fn deny_pidfd_open_on_this_thread(errno: i32) {
    // `seccomp_data.nr`, the syscall number, is at offset 0.
    let filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_pidfd_open as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | errno as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: plain prctl calls; `program` and `filter` outlive the second, which copies them.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0, "no_new_privs");
        assert_eq!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
            0,
            "seccomp: {}",
            std::io::Error::last_os_error()
        );
        let pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0);
        assert_eq!(pidfd, -1, "pidfd_open must be denied");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(errno),
            "pidfd_open must answer the requested errno"
        );
    }
}
