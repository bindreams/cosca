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

/// [`deny_pidfd_open_on_this_thread`], and also make every fork of a new process fail with
/// `EAGAIN` on the calling thread: `fork`/`vfork` where they exist, `clone` without
/// `CLONE_THREAD`, and `clone3` with `ENOSYS` so libc falls back to `clone` (threads still start).
/// A spawn that reaches the fork under this filter fails with `Io`, not `Unsupported`, so it
/// proves a refusal was found BEFORE the fork.
pub fn deny_pidfd_open_and_forks_on_this_thread(errno: i32) {
    const CLONE_THREAD: u32 = 0x0001_0000;
    // `seccomp_data`: `nr` at offset 0, `args[0]` at offset 16.
    let load = |offset: u32| libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: offset,
    };
    let ret = |k: u32| libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k,
    };
    // Instruction indices, so each jump is the distance to its target minus one.
    let mut filter: Vec<libc::sock_filter> = vec![load(0)];
    let mut jumps: Vec<(usize, u32, u32, &'static str)> = Vec::new();
    let mut targets: std::collections::HashMap<&'static str, usize> = std::collections::HashMap::new();
    type Jumps = Vec<(usize, u32, u32, &'static str)>;
    fn cond(filter: &mut Vec<libc::sock_filter>, jumps: &mut Jumps, op: u32, k: u32, on_true: &'static str) {
        jumps.push((filter.len(), op, k, on_true));
        filter.push(libc::sock_filter {
            code: 0,
            jt: 0,
            jf: 0,
            k: 0,
        });
    }
    cond(
        &mut filter,
        &mut jumps,
        libc::BPF_JEQ,
        libc::SYS_pidfd_open as u32,
        "errno",
    );
    cond(
        &mut filter,
        &mut jumps,
        libc::BPF_JEQ,
        libc::SYS_clone3 as u32,
        "enosys",
    );
    cond(&mut filter, &mut jumps, libc::BPF_JEQ, libc::SYS_clone as u32, "clone");
    #[cfg(target_arch = "x86_64")]
    {
        cond(&mut filter, &mut jumps, libc::BPF_JEQ, libc::SYS_fork as u32, "eagain");
        cond(&mut filter, &mut jumps, libc::BPF_JEQ, libc::SYS_vfork as u32, "eagain");
    }
    // Nothing matched: allow.
    jumps.push((filter.len(), libc::BPF_JA, 0, "allow"));
    filter.push(libc::sock_filter {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    });
    targets.insert("errno", filter.len());
    filter.push(ret(libc::SECCOMP_RET_ERRNO | errno as u32));
    targets.insert("enosys", filter.len());
    filter.push(ret(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
    targets.insert("eagain", filter.len());
    filter.push(ret(libc::SECCOMP_RET_ERRNO | libc::EAGAIN as u32));
    // `clone` is allowed only as a thread.
    targets.insert("clone", filter.len());
    filter.push(load(16));
    cond(&mut filter, &mut jumps, libc::BPF_JSET, CLONE_THREAD, "allow");
    filter.push(ret(libc::SECCOMP_RET_ERRNO | libc::EAGAIN as u32));
    // Jumps only go forward, so the allow is last.
    targets.insert("allow", filter.len());
    filter.push(ret(libc::SECCOMP_RET_ALLOW));
    for (at, op, k, on_true) in jumps {
        let distance = targets[on_true] - at - 1;
        filter[at] = if op == libc::BPF_JA {
            libc::sock_filter {
                code: (libc::BPF_JMP | op) as u16,
                jt: 0,
                jf: 0,
                k: distance as u32,
            }
        } else {
            libc::sock_filter {
                code: (libc::BPF_JMP | op) as u16,
                jt: distance as u8,
                jf: 0,
                k,
            }
        };
    }
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
    }
}
