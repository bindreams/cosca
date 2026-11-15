//! The root is reaped when its handle ends, not when a wait sees it exit: a waited root stays a
//! zombie that pins its number, and every end of the handle, armed or not, consumes it.

use crate::test_child::{
    assert_no_child_of_this_thread, has_not_exited, held_uncontained_blocker, is_unreaped_child, wait_until_zombie,
    Console,
};

/// After `wait` the root is a zombie of ours, which keeps its number out of circulation, and the
/// handle's end consumes it.
///
/// Mutant: a wait consumes the exit record.
#[skuld::test]
fn a_waited_root_stays_a_zombie_until_its_handle_drops() {
    let (child, writer) = held_uncontained_blocker(true);
    let pid = child.pid();
    drop(writer);
    child.wait().expect("wait");
    assert!(is_unreaped_child(pid), "the wait consumed the root's exit record");
    drop(child);
    assert!(!is_unreaped_child(pid), "the drop left the root a zombie");
}

/// Linux: a disarmed handle (`kill_on_drop(false)`) whose root has exited without the handle's wait
/// seeing it still reaps it at its end, since the consume names the child exactly: a drop that
/// kills and waits nothing leaves no zombie.
///
/// Mutant: the drop consumes only for an armed handle.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_disarmed_drop_of_an_exited_child_the_wait_never_saw_reaps_it() {
    let (child, writer) = held_uncontained_blocker(false);
    let pid = child.pid();
    drop(writer);
    wait_until_zombie(pid);
    assert!(is_unreaped_child(pid), "the test's own wait consumed the exit record");
    drop(child);
    assert!(
        !is_unreaped_child(pid),
        "the disarmed drop left the exited root a zombie"
    );
}

/// macOS: a disarmed handle whose root has exited without the handle's wait seeing it consumes
/// nothing, since the consume is by number and a check, not a pin: the zombie is the application's
/// to reap, as it was before the handle's end consumed anything.
///
/// Mutant: the drop consumes by number a root its wait never saw.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_disarmed_drop_of_an_exited_child_the_wait_never_saw_leaves_it_to_the_application() {
    let (child, writer) = held_uncontained_blocker(false);
    let pid = child.pid();
    drop(writer);
    wait_until_zombie(pid);
    assert!(is_unreaped_child(pid), "the test's own wait consumed the exit record");
    drop(child);
    assert!(is_unreaped_child(pid), "the drop consumed by number what no wait saw");
    crate::test_child::reaped_elsewhere::reap_behind(pid);
}

/// A disarmed handle's drop leaves a root that still runs alone: it is neither killed nor waited
/// for, and is the application's to reap.
///
/// Mutant: the drop kills a disarmed root.
#[skuld::test]
fn a_disarmed_drop_of_a_running_child_leaves_it_running() {
    let (child, writer) = held_uncontained_blocker(false);
    let pid = child.pid();
    drop(child);
    assert!(is_unreaped_child(pid), "the root is still ours");
    assert!(has_not_exited(pid), "the root was killed or waited for");
    drop(writer);
    crate::test_child::reaped_elsewhere::reap_behind(pid);
}

/// `Command::status` with `kill_on_drop(false)` ends with no zombie of its child: the drop of its
/// disarmed handle reaps it.
///
/// Mutant: the drop consumes only for an armed handle.
#[skuld::test]
fn status_with_kill_on_drop_false_leaves_no_zombie() {
    assert_no_child_of_this_thread("the test starts with no child");
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(["true"]);
    cmd.kill_on_drop(false);
    let status = cmd.status().expect("status");
    assert!(status.success(), "{status:?}");
    assert_no_child_of_this_thread("status left its child a zombie");
}
