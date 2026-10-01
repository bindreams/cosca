//! A real seccomp filter on the calling thread, for tests of a syscall a sandbox refuses.

/// Make `pidfd_open` fail with `errno` (a positive `libc` constant) on the calling thread and
/// every process it forks, as a seccomp-filtered container does. Run the denied code on its own
/// thread to keep the test's own `pidfd_open`.
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
    rustix::thread::set_no_new_privs(true).expect("no_new_privs");
    // SAFETY: `program` and `filter` outlive the call, and the kernel copies them. rustix wraps no
    // seccomp-filter `prctl`; musl reads every argument as `unsigned long`, hence the casts.
    unsafe {
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &program,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0,
            "seccomp: {}",
            std::io::Error::last_os_error()
        );
    }
    let denied = rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty());
    assert_eq!(
        denied.map(drop).map_err(|e| e.raw_os_error()),
        Err(errno),
        "pidfd_open must be denied with the requested errno"
    );
}
