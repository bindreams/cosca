//! Test-only: run a closure on a thread that a seccomp filter makes answer `EPERM` for chosen
//! syscalls, standing in for the container profile or LSM that refuses a signal the kernel's own
//! permission rule would allow.

use std::collections::BTreeMap;

/// Run `body` on a fresh thread whose seccomp filter fails each of `syscalls` with `EPERM`, and
/// return its result; a panic in `body` resumes here.
///
/// The filter belongs to that thread alone (`apply_filter` is not `TSYNC`), so nothing else in the
/// test binary is affected, and it dies with the thread. Anything `body` forks inherits it.
pub(crate) fn with_denied<R: Send>(syscalls: &[i64], body: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = syscalls.iter().map(|&n| (n, vec![])).collect();
            let filter = seccompiler::SeccompFilter::new(
                rules,
                seccompiler::SeccompAction::Allow,
                seccompiler::SeccompAction::Errno(libc::EPERM as u32),
                std::env::consts::ARCH
                    .try_into()
                    .expect("a seccomp-supported architecture"),
            )
            .expect("build the filter");
            let program: seccompiler::BpfProgram = filter.try_into().expect("compile the filter");
            seccompiler::apply_filter(&program).expect("install the filter on this thread");
            body()
        });
        match worker.join() {
            Ok(r) => r,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}
