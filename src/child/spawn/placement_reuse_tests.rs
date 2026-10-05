//! A sync contained spawn whose child is reaped behind its back, and its pid reused, before the
//! attach takes the cgroup verdict, in a fresh pid namespace (see `test_child::pid_reuse`).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::fault;
use crate::command::Command;
use crate::test_child::pid_reuse::{in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_wait};
use crate::test_groups::{cgroup, namespaces};

/// Mutant: `attach` passes `pidfd_open(raw_pid)` for the held pidfd.
fn sync_attach_after_foreign_reap_and_reuse_waits_on_the_held_pidfd_body() {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain();

    let reuser = Rc::new(RefCell::new(None));
    let pid = Rc::new(Cell::new(None));
    let _at = fault::set_at(fault::SpawnPoint::BeforeAttach, {
        let (reuser, pid) = (Rc::clone(&reuser), Rc::clone(&pid));
        move || {
            let child = fault::spawn_pid();
            pid.set(Some(child));
            // The child exits on its stdin's EOF; the fixture reaps it and takes its pid.
            drop(writer);
            *reuser.borrow_mut() = Some(reap_behind_and_reuse(child));
        }
    });
    let _wait = crate::containment::cgroup::fault::set_on_wait({
        let pid = Rc::clone(&pid);
        move || {
            let fd = crate::containment::cgroup::fault::waited_pidfd().expect("the wait was given a pidfd");
            let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).expect("fdinfo");
            let child = pid.get().expect("the hook ran");
            assert!(
                !info.lines().any(|line| line == format!("Pid:\t{child}")),
                "the verdict must wait on the child's own pidfd, not one opened by the reused pid: {info}"
            );
        }
    });

    let child = cmd
        .spawn()
        .expect("a verdict from the held pidfd lets the spawn finish");
    let reuser = reuser.borrow_mut().take().expect("the hook ran");
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
    drop(child);
}
in_fresh_pid_ns!(
    cgroup_sync_attach_after_foreign_reap_and_reuse_waits_on_the_held_pidfd,
    fixture_sync_attach_reuse_driver,
    fixture_sync_attach_reuse_init,
    sync_attach_after_foreign_reap_and_reuse_waits_on_the_held_pidfd_body,
    cgroup
);
