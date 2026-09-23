use crate::containment::cgroup::test_support::{block_on, childs_copy, fork_running, reap};
use crate::containment::cgroup::PlacementReport;

/// The child's self-placement errno crosses `fork` into the parent. Deterministic and
/// cgroup-free: fd -1 is never writable, so the child's `write` always fails with `EBADF`,
/// and the parent must read back that exact errno rather than a guess.
#[cfg(target_os = "linux")]
#[test]
fn placement_report_crosses_fork_with_the_childs_errno() {
    use std::os::unix::process::CommandExt;

    let fresh = crate::containment::cgroup::ReportChannel::new().expect("open a report channel");
    assert_eq!(
        fresh.report_for_test(),
        PlacementReport::NotReported,
        "a fresh channel must report nothing, not a fabricated success"
    );

    let mut channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let slot = channel.slot();
    let mut cmd = std::process::Command::new("/bin/true");
    // SAFETY: the closure runs between fork and exec; it performs only the documented
    // async-signal-safe operations (two writes and a close).
    unsafe {
        cmd.pre_exec(move || {
            let _ = crate::containment::cgroup::place_self_in_cgroup_pre_exec(-1, slot);
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn");
    let report = channel.wait(child.id()).expect("open a pidfd");
    let status = child.wait().expect("wait");
    assert!(status.success(), "the failed placement must not abort the spawn");
    assert_eq!(
        report,
        PlacementReport::WriteFailed(libc::EBADF),
        "the child's own errno must reach the parent verbatim"
    );
}

/// A successful self-placement is reported too — the fact that separates "the write failed"
/// from "the write worked and the child then left the set".
#[cfg(target_os = "linux")]
#[test]
fn placement_report_records_a_successful_write() {
    use std::os::unix::process::CommandExt;

    let mut channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let slot = channel.slot();
    // /dev/null accepts any write, standing in for a writable cgroup.procs.
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    let fd = std::os::fd::IntoRawFd::into_raw_fd(sink);
    let mut cmd = std::process::Command::new("/bin/true");
    // SAFETY: as above; `fd` is a valid writable descriptor inherited by the fork, and the
    // closure closes only the child's copy.
    unsafe {
        cmd.pre_exec(move || {
            let _ = crate::containment::cgroup::place_self_in_cgroup_pre_exec(fd, slot);
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(channel.wait(child.id()).expect("open a pidfd"), PlacementReport::Placed);
    child.wait().expect("wait");
    // SAFETY: the parent's own copy of the descriptor, closed exactly once.
    unsafe { libc::close(fd) };
}

/// `wait` returns a report the child writes after the wait began, not what the channel held when
/// it was called: `spawn` can return before the child's `pre_exec` has run.
///
/// Ordered by a primitive, not by timing: the child is held on a gate, the wait signals just
/// before it blocks, and only then is the gate opened.
#[cfg(target_os = "linux")]
#[test]
fn report_channel_wait_returns_a_report_written_after_it_was_called() {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let mut channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let slot = channel.slot();
    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    let gate = gate_read.as_raw_fd();
    let pid = fork_running(move || {
        block_on(gate);
        // SAFETY: the channel's child end is this child's inherited copy; its parent holds
        // its own end.
        let _ = unsafe { slot.send_report(crate::containment::cgroup::REPORT_PLACED) };
    });
    let (polling_tx, polling_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        crate::containment::cgroup::fault::set_wait_polling_notifier(polling_tx);
        channel.wait(pid).expect("open a pidfd")
    });
    polling_rx.recv().expect("the wait reaches its poll with nothing sent");
    gate_write.write_all(b"x").expect("release the child");
    assert_eq!(waiter.join().expect("the waiting thread"), PlacementReport::Placed);
    reap(pid);
}

/// A child that exits without reporting reads as `NotReported` at once, even while another process
/// still holds the child's end: any process forked while the channel is open inherits it, and
/// one that never execs would otherwise hold off the channel's EOF for as long as it runs.
///
/// A regression hangs this test rather than failing it: the wait has no timeout by design.
#[cfg(target_os = "linux")]
#[test]
fn report_channel_wait_ends_at_the_childs_exit_while_another_process_holds_the_childs_end() {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let mut channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    let gate = gate_read.as_raw_fd();
    // Inherits the child's end, and keeps it until released through the gate.
    let holder = fork_running(move || block_on(gate));
    let child = fork_running(|| {});

    assert_eq!(channel.wait(child).expect("open a pidfd"), PlacementReport::NotReported);
    reap(child);
    gate_write.write_all(b"x").expect("release the holder");
    reap(holder);
}

/// Both ends of the report channel are close-on-exec, so no program this process starts inherits
/// either. (That they sit at fd 3 or above matters only with 0, 1 or 2 closed, which
/// `tests/spawn_io.rs` covers in a process of its own.)
#[cfg(target_os = "linux")]
#[test]
fn report_channel_is_close_on_exec() {
    use std::os::fd::AsRawFd;

    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    for (end, fd) in [("parent's", channel.read.as_raw_fd()), ("child's", channel.slot().fd)] {
        // SAFETY: `fd` is open for as long as `channel` lives.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags, -1, "F_GETFD: {}", std::io::Error::last_os_error());
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "the {end} end must be close-on-exec");
    }
}

/// Everything the child sent before the parent abandoned the exchange is still read, pidfd
/// included: the shut cuts off only what comes after.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_exchange_still_reads_what_was_sent_before_it() {
    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let (_end, slot) = childs_copy(&channel);
    // SAFETY: the channel is open.
    unsafe {
        assert_eq!(
            slot.send_intent().expect("send the intent"),
            crate::containment::cgroup::Delivery::Queued
        );
        assert_eq!(
            slot.send_report(crate::containment::cgroup::REPORT_PLACED)
                .expect("send the report"),
            crate::containment::cgroup::Delivery::Queued
        );
    }
    let received = channel.shut();
    assert_eq!(received.pid, Some(std::process::id()));
    assert!(received.pidfd.is_some(), "the intent carries a pidfd");
    assert_eq!(received.placement(), PlacementReport::Placed);
    // SAFETY: the child's end is still open in `slot`; the parent's end is shut for reading.
    assert_eq!(
        unsafe { slot.send_report(crate::containment::cgroup::REPORT_PLACED) }.expect("send"),
        crate::containment::cgroup::Delivery::Abandoned
    );
}

/// A send landing after the abandonment read what was queued, but before the channel closed, must
/// fail: a send that succeeded there would be discarded unread while its child went on to `exec`.
#[cfg(target_os = "linux")]
#[test]
fn a_send_after_the_abandonment_read_fails_rather_than_go_unread() {
    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let (end, slot) = childs_copy(&channel);
    let outcome = std::rc::Rc::new(std::cell::Cell::new(None));
    let seen = outcome.clone();
    crate::containment::cgroup::fault::set_after_shut_read(move || {
        // SAFETY: `end` keeps the child's end open for the call.
        let sent = unsafe { slot.send_report(crate::containment::cgroup::REPORT_PLACED) }.expect("send");
        seen.set(Some(sent));
        drop(end);
    });
    let received = channel.shut();
    assert_eq!(received.report, None, "nothing was queued before the read");
    assert_eq!(
        outcome.get(),
        Some(crate::containment::cgroup::Delivery::Abandoned),
        "a send in the window must see the abandonment"
    );
}
