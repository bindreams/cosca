use std::cell::RefCell;
use std::time::{Duration, Instant};

use super::{wait_warning, Due};

/// What `wait_warning` called, in order, and what the look and the warn were given.
#[derive(Default)]
struct Calls {
    steps: Vec<&'static str>,
    until: Option<Instant>,
    warned_after: Option<Duration>,
}

/// `wait_warning` with `ended_by` answering `ended`.
fn run(due: Option<Due>, ended: bool) -> (Calls, &'static str) {
    let calls = RefCell::new(Calls::default());
    let result = wait_warning(
        (),
        due,
        |(), until| {
            let mut calls = calls.borrow_mut();
            calls.steps.push("look");
            calls.until = Some(until);
            ended
        },
        |after| {
            let mut calls = calls.borrow_mut();
            calls.steps.push("warn");
            calls.warned_after = Some(after);
        },
        |()| {
            calls.borrow_mut().steps.push("wait");
            "waited"
        },
    );
    (calls.into_inner(), result)
}

fn due() -> Due {
    Due::in_(Some(Duration::from_secs(7))).expect("a threshold")
}

/// Without a threshold only the wait runs.
///
/// Mutant: the look or the warn runs without `due`.
#[skuld::test]
fn without_a_threshold_only_the_wait_runs() {
    let (calls, result) = run(None, false);
    assert_eq!(calls.steps, ["wait"]);
    assert_eq!(result, "waited");
}

/// A wait that ended within the threshold does not warn.
///
/// Mutant: the warn runs whatever the look found.
#[skuld::test]
fn a_wait_that_ended_in_time_does_not_warn() {
    let (calls, result) = run(Some(due()), true);
    assert_eq!(calls.steps, ["look", "wait"]);
    assert_eq!(result, "waited");
}

/// A wait still going at the threshold warns once, with the threshold's length, before it blocks;
/// the look is bounded by the threshold's instant, and the wait's answer is the result.
///
/// Mutants: the warn runs after the wait; it gets another length; the look gets another instant;
/// the result is the warn's.
#[skuld::test]
fn a_wait_still_going_at_the_threshold_warns_once_before_it_blocks() {
    let due = due();
    let (calls, result) = run(Some(due), false);
    assert_eq!(calls.steps, ["look", "warn", "wait"]);
    assert_eq!(calls.until, Some(due.until));
    assert_eq!(calls.warned_after, Some(due.after));
    assert_eq!(result, "waited");
}

#[cfg(target_os = "linux")]
mod exit_visible {
    use std::os::fd::AsFd as _;
    use std::time::Instant;

    use super::super::{exit_visible_by, ExitWatch};

    /// A child that only a kill or its closed stdin ends.
    fn running() -> std::process::Child {
        let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
        crate::test_spawn::spawn(&mut cmd).expect("spawn the child")
    }

    fn pidfd_of(child: &std::process::Child) -> std::os::fd::OwnedFd {
        crate::containment::cgroup::test_support::pidfd_of(child.id())
    }

    fn proc_dir(child: &std::process::Child) -> std::fs::File {
        std::fs::File::open(format!("/proc/{}", child.id())).expect("open the /proc directory")
    }

    fn pid(child: &std::process::Child) -> rustix::process::Pid {
        rustix::process::Pid::from_raw(child.id() as i32).expect("a positive pid")
    }

    /// Kills `child` and returns once it is a zombie, unreaped.
    fn exited(child: &mut std::process::Child) {
        child.kill().expect("kill");
        crate::test_child::wait_until_zombie(child.id());
    }

    fn by_now(watch: ExitWatch<'_>) -> bool {
        exit_visible_by(watch, Instant::now())
    }

    /// Mutant: the pidfd look answers `true` for a child that is running.
    #[skuld::test]
    fn a_running_child_named_by_its_pidfd_has_not_exited() {
        let mut child = running();
        let pidfd = pidfd_of(&child);
        assert!(!by_now(ExitWatch::PidFd(pidfd.as_fd())));
        exited(&mut child);
        child.wait().expect("reap");
    }

    /// Mutant: the pidfd look answers `false` for a child that has exited.
    #[skuld::test]
    fn an_exited_child_named_by_its_pidfd_has_exited() {
        let mut child = running();
        let pidfd = pidfd_of(&child);
        exited(&mut child);
        assert!(by_now(ExitWatch::PidFd(pidfd.as_fd())));
        child.wait().expect("reap");
    }

    /// Mutant: the look through the directory answers `true` for a running child.
    #[skuld::test]
    fn a_running_child_named_by_its_proc_directory_has_not_exited() {
        let mut child = running();
        let dir = proc_dir(&child);
        let pid = pid(&child);
        assert!(!by_now(ExitWatch::ProcDir { pid, dir: dir.as_fd() }));
        exited(&mut child);
        child.wait().expect("reap");
    }

    /// Mutant: the look through the directory answers `false` for a child that has exited.
    #[skuld::test]
    fn an_exited_child_named_by_its_proc_directory_has_exited() {
        let mut child = running();
        let dir = proc_dir(&child);
        let pid = pid(&child);
        exited(&mut child);
        assert!(by_now(ExitWatch::ProcDir { pid, dir: dir.as_fd() }));
        child.wait().expect("reap");
    }

    /// A directory that shows its child reaped answers `true` whatever process the number names by
    /// then: here a running one, which the look must not watch.
    ///
    /// Mutant: the look keeps the pidfd opened on the number without checking the directory.
    #[skuld::test]
    fn a_child_reaped_elsewhere_is_not_watched_through_its_number() {
        let mut gone = running();
        let dir = proc_dir(&gone);
        exited(&mut gone);
        gone.wait().expect("reap");
        let mut holder = running();
        assert!(by_now(ExitWatch::ProcDir {
            pid: pid(&holder),
            dir: dir.as_fd()
        }));
        exited(&mut holder);
        holder.wait().expect("reap");
    }

    /// A number no process can have (above `pid_max`) is a refused `pidfd_open`, which answers `true`
    /// for the wait to find.
    ///
    /// Mutant: a refused open answers `false`.
    #[skuld::test]
    fn a_refused_open_is_left_to_the_wait() {
        let mut child = running();
        let dir = proc_dir(&child);
        let pid = rustix::process::Pid::from_raw(i32::MAX).expect("a positive pid");
        assert!(by_now(ExitWatch::ProcDir { pid, dir: dir.as_fd() }));
        exited(&mut child);
        child.wait().expect("reap");
    }
}
