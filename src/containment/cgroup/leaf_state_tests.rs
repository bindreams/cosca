//! `proc_state` reads a child's state only through the checked `/proc` view.

use super::{proc_state, read_proc_state, StateUnknown};
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};
use crate::test_child::namespaces as ns;
use crate::test_child::{fixture_path, member_command};

#[skuld::test]
fn a_live_process_has_a_state_under_the_ordinary_view() {
    assert!(proc_state(std::process::id()).is_some());
}

/// Mutant: "the state is the field after the state" (`Z` becomes the next field).
#[skuld::test]
fn an_unreaped_exited_child_is_a_zombie() {
    let mut child = crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn true");
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: a well-formed `waitid`; `info` is an owned, zeroed `siginfo_t`. WNOWAIT leaves
        // the child unreaped.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EINTR), "waitid: {err}");
    }
    assert_eq!(proc_state(child.id()), Some('Z'));
    child.wait().expect("reap");
}

/// The highest pid the kernel allows is never handed out (`pid_max` is at most 2^22).
#[skuld::test]
fn a_nonexistent_pid_has_no_state_under_the_ordinary_view() {
    let pid = u32::MAX - 1;
    assert_eq!(proc_state(pid), None);
    let Err(StateUnknown::Unreadable(e)) = read_proc_state(pid) else {
        panic!("expected Unreadable");
    };
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
}

#[skuld::test]
fn an_unparsable_stat_is_named() {
    assert!(matches!(
        super::state_from_stat(String::from("garbage")),
        Err(StateUnknown::Unparsable(s)) if s == "garbage"
    ));
}

/// Mutant: "read `/proc/{pid}/stat` by path whatever the view", and "every non-Same view is
/// the same cause".
#[skuld::test]
fn no_state_is_read_when_the_view_is_diverged_or_unassessable() {
    for (view, wanted) in [
        (ForcedView::Diverged, "outer"),
        (ForcedView::Unassessable, "unassessable"),
    ] {
        let _forced = force_proc_view_once(view);
        let why = read_proc_state(std::process::id()).expect_err("no state");
        match (wanted, &why) {
            ("outer", StateUnknown::OuterProcfs) => {}
            ("unassessable", StateUnknown::ViewUnassessable(v)) => assert_eq!(v.reason, "forced by a test"),
            _ => panic!("{view:?}: {why:?}"),
        }
        let _forced = force_proc_view_once(view);
        assert_eq!(proc_state(std::process::id()), None, "{view:?}");
    }
}

/// pid 1 of a new pid namespace whose `/proc` is still the outer one: `/proc/1` is the outer
/// init, whose state says nothing about this process.
#[skuld::test]
fn namespaces_an_outer_procfs_gives_no_state() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_state_outer));
}

#[skuld::test]
fn fixture_state_outer() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_state_inner));
}

#[skuld::test]
fn fixture_state_inner() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    let outer = std::fs::read_to_string("/proc/1/stat").expect("the outer /proc/1/stat is readable by path");
    assert!(
        super::parse_proc_stat_state(&outer).is_some(),
        "control: read by path, pid 1 has a state: {outer:?}"
    );
    assert_eq!(proc_state(1), None);
}

/// A file mounted over a child's `stat` is not read.
#[skuld::test]
fn namespaces_a_stat_mounted_over_gives_no_state() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_state_overmount));
}

#[skuld::test]
fn fixture_state_overmount() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let mut child = KillOnDrop(Some(
        crate::test_spawn::spawn(&mut member_command(0)).expect("spawn the member"),
    ));
    crate::test_child::await_member_ready(child.0.as_mut().expect("child"));
    let pid = child.0.as_ref().expect("child").id();
    assert!(proc_state(pid).is_some(), "the member has a state before the mount");
    let scratch = tempfile::tempdir().expect("tempdir");
    let fake = scratch.path().join("stat");
    let zeros = ["0"; 16].join(" ");
    std::fs::write(&fake, format!("{pid} (fake) Z 1 1 {zeros} 1 0\n")).expect("write the fake stat");
    ns::bind_over(&fake, std::path::Path::new(&format!("/proc/{pid}/stat")));
    assert_eq!(proc_state(pid), None);
}

/// Kills and reaps the child when dropped, so a failing assertion cannot leak it.
struct KillOnDrop(Option<std::process::Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            _ = child.kill();
            _ = child.wait();
        }
    }
}
