//! A signal the OS refuses, on a real Linux child: an already-exited child is `Ok` whatever
//! refuses the signal.

use crate::test_seccomp::with_denied;

fn wrapped() -> Option<crate::elevation::ElevationReport> {
    Some(crate::elevation::ElevationReport {
        via: crate::elevation::ElevatedVia::Wrapped(crate::elevation::Backend::Pkexec),
        stripped_env: Vec::new(),
        stdio: crate::elevation::ElevatedStdio::Passthrough,
    })
}

/// Every elevation report the refusal must not depend on.
fn reports() -> [Option<crate::elevation::ElevationReport>; 2] {
    [None, wrapped()]
}

fn blocker() -> (crate::Child, std::io::PipeWriter) {
    crate::test_child::held_contained_blocker(crate::Stdio::pipe())
}

// An exited child is Ok whatever refuses the signal =====

// A filter refuses both signal syscalls, yet an unreaped zombie is `Ok`: the kernel would have
// answered success for it, so the refusal is not about the child.
#[test]
fn an_exited_unreaped_child_is_ok_even_when_a_filter_refuses_the_signal() {
    for report in reports() {
        let (results, child) = with_denied(&[libc::SYS_pidfd_send_signal, libc::SYS_kill], move || {
            let (mut child, stdin) = blocker();
            child.set_elevation(report);
            drop(stdin);
            assert!(
                crate::wait::block_until_exit(child.id(), None).expect("watch the exit"),
                "exited"
            );
            let results = (child.terminate(), child.kill());
            (results, child)
        });
        results.0.expect("terminate of an exited child");
        results.1.expect("kill of an exited child");
        child.wait().expect("reap");
    }
}
