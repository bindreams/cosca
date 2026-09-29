//! `CgroupLeaf::release_without_waiting`: bounded work only, whatever the leaf's state.
//!
//! Every test runs the release inside a [`bounded::Section`](crate::bounded::Section), so a wait
//! for the drain panics at once in debug builds instead of hanging.

use crate::containment::cgroup::fault;
use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
use crate::containment::cgroup::CgroupLeaf;

/// A [`FakeLeaf`] whose `rmdir` answers as cgroupfs does, and an entered leaf on it.
fn entered(name: &str, populated: bool) -> (FakeLeaf, CgroupLeaf) {
    crate::log_capture::install();
    let fake = FakeLeaf::new(name, populated);
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&path, &events));
    let leaf = entered_leaf_at(fake.leaf.clone());
    (fake, leaf)
}

/// Release `leaf` under the no-blocking contract; return the steps it took and the levels of the
/// records naming `name`.
fn release(leaf: CgroupLeaf, name: &str) -> (Vec<String>, Vec<log::Level>) {
    let mark = crate::log_capture::mark();
    fault::record_leaf_steps();
    {
        let _bounded = crate::bounded::Section::enter();
        leaf.release_without_waiting();
    }
    let steps = fault::take_leaf_steps();
    fault::take_rmdir_hook();
    (steps, crate::log_capture::levels_since(mark, name))
}

fn kill_file(fake: &FakeLeaf) -> Vec<u8> {
    std::fs::read(fake.leaf.join("cgroup.kill")).expect("read cgroup.kill")
}

/// A leaf that never drains, released while armed: the release returns. A release that ran the
/// blocking `Drop` would wait for the drain, which the debug contract turns into a panic.
#[test]
fn release_without_waiting_never_runs_the_blocking_drop() {
    let name = "cosca-release-never-blocks";
    let (_fake, leaf) = entered(name, true);
    let _ = release(leaf, name);
}

#[test]
fn an_armed_undrained_leaf_is_killed_left_behind_and_warned_about() {
    let name = "cosca-release-armed-undrained";
    let (fake, leaf) = entered(name, true);
    let mark = crate::log_capture::mark();
    let (steps, levels) = release(leaf, name);

    assert_eq!(steps, ["rmdir populated 1", "kill"]);
    assert_eq!(kill_file(&fake), crate::containment::cgroup::KILL_PAYLOAD);
    assert!(fake.leaf.exists(), "an undrained leaf is left behind");
    assert_eq!(levels, [log::Level::Warn]);
    let records = crate::log_capture::records_since(mark, name);
    assert!(
        records[0].contains("wait_tree"),
        "the warning must point at wait_tree().await, got {records:?}"
    );
}

#[test]
fn a_drained_leaf_is_removed_without_a_kill_and_without_a_warning() {
    let name = "cosca-release-drained";
    let (fake, leaf) = entered(name, false);
    let (steps, levels) = release(leaf, name);

    assert_eq!(steps, ["rmdir populated 0"]);
    assert!(!fake.leaf.exists(), "a drained leaf is removed");
    assert_eq!(levels, Vec::<log::Level>::new());
}

/// The kill lands before the release reads the drain: the leaf is swept and removed.
#[test]
fn a_leaf_that_drains_by_the_time_of_the_read_is_swept_and_removed() {
    crate::log_capture::install();
    let name = "cosca-release-drains-after-kill";
    let fake = FakeLeaf::new(name, true);
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    let first = std::cell::Cell::new(true);
    fault::set_rmdir_hook(move |_| {
        if first.replace(false) {
            // The members exit while the first rmdir is refused.
            FakeLeaf::set_populated(&events, false);
            return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
        }
        FakeLeaf::rmdir(&path, &events)
    });
    let leaf = entered_leaf_at(fake.leaf.clone());
    let (steps, levels) = release(leaf, name);

    assert_eq!(steps, ["rmdir populated 1", "kill", "rmdir populated 0"]);
    assert!(!fake.leaf.exists());
    assert_eq!(levels, Vec::<log::Level>::new());
}

/// Killed by this handle and disarmed after (`Child::detach`): the release fires the kill again,
/// and warns when the leaf has not drained. The armed twin, which `finish_elevated` leaves, is
/// `an_armed_undrained_leaf_is_killed_left_behind_and_warned_about`.
#[test]
fn a_disarmed_leaf_this_handle_killed_is_killed_again_and_warned_about() {
    let name = "cosca-release-disarmed-killed";
    let (fake, leaf) = entered(name, true);
    leaf.hard_kill().expect("kill the tree");
    leaf.disarm();
    let (steps, levels) = release(leaf, name);

    assert_eq!(steps, ["rmdir populated 1", "kill"]);
    assert!(fake.leaf.exists());
    assert_eq!(levels, [log::Level::Warn]);
}

/// A tree the caller asked to leave running is not killed and not a leak: `debug`.
#[test]
fn a_disarmed_never_killed_leaf_is_never_killed_and_logs_at_debug() {
    let name = "cosca-release-disarmed-never-killed";
    let (fake, leaf) = entered(name, true);
    leaf.disarm();
    let (steps, levels) = release(leaf, name);

    assert_eq!(steps, ["rmdir populated 1"]);
    assert_eq!(kill_file(&fake), b"", "nothing may write cgroup.kill");
    assert!(fake.leaf.exists());
    assert_eq!(levels, [log::Level::Debug]);
}

/// A kill the caller attempted and that failed is a mechanism failure, not a request to leave
/// the tree running.
#[test]
fn a_disarmed_leaf_whose_kill_attempt_failed_is_warned_about_and_not_killed_again() {
    let name = "cosca-release-disarmed-kill-failed";
    let (fake, leaf) = entered(name, true);
    std::fs::remove_file(fake.leaf.join("cgroup.kill")).expect("remove cgroup.kill");
    std::fs::create_dir(fake.leaf.join("cgroup.kill")).expect("make cgroup.kill unwritable");
    leaf.hard_kill().expect_err("the forced failure");
    leaf.disarm();
    let (steps, levels) = release(leaf, name);

    assert_eq!(steps, ["rmdir populated 1"]);
    assert_eq!(levels, [log::Level::Warn]);
}

/// A tree that exited on its own is swept and removed, though nobody killed it.
#[test]
fn a_disarmed_leaf_that_drained_on_its_own_is_swept_and_removed() {
    let name = "cosca-release-disarmed-self-drained";
    let fake = FakeLeaf::new(name, false);
    std::fs::create_dir(fake.leaf.join("leftover-child")).expect("leave an empty child cgroup");
    crate::log_capture::install();
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    fault::set_rmdir_hook(move |p| {
        if p.join("leftover-child").exists() {
            return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
        }
        FakeLeaf::rmdir(&path, &events)
    });
    let leaf = entered_leaf_at(fake.leaf.clone());
    leaf.disarm();
    let (steps, levels) = release(leaf, name);

    assert_eq!(steps, ["rmdir populated 0", "rmdir populated 0"], "no kill");
    assert!(!fake.leaf.exists());
    assert_eq!(levels, Vec::<log::Level>::new());
}

/// An armed leaf whose kill write fails is left behind and warned about, naming the kill.
#[test]
fn an_armed_leaf_whose_kill_write_fails_is_warned_about() {
    let name = "cosca-release-armed-kill-fails";
    let (fake, leaf) = entered(name, true);
    std::fs::remove_file(fake.leaf.join("cgroup.kill")).expect("remove cgroup.kill");
    std::fs::create_dir(fake.leaf.join("cgroup.kill")).expect("make cgroup.kill unwritable");
    let mark = crate::log_capture::mark();
    let (steps, levels) = release(leaf, name);

    assert_eq!(steps, ["rmdir populated 1"]);
    assert_eq!(levels, [log::Level::Warn]);
    assert!(crate::log_capture::records_since(mark, name)[0].contains("cgroup.kill failed"));
}

fn thread_ids() -> std::collections::BTreeSet<String> {
    std::fs::read_dir("/proc/self/task")
        .expect("list /proc/self/task")
        .map(|entry| entry.expect("a task entry").file_name().to_string_lossy().into_owned())
        .collect()
}

/// The pump a wait started is owned by the leaf, and the release ends it: nothing of the leaf
/// runs on after the release. Runs alone, so no other test's threads come and go between the
/// reads.
#[test]
fn release_stops_and_joins_the_leafs_pump() {
    use crate::containment::cgroup::test_support::alone;
    use crate::test_child::fixture_path;

    if !alone(fixture_path!(release_stops_and_joins_the_leafs_pump)) {
        return;
    }
    let name = "cosca-release-joins-pump";
    let (_fake, leaf) = entered(name, true);
    let before = thread_ids();
    // A wait that blocks starts the pump.
    let step = leaf.drain_step(Some(None)).expect("step the drain");
    assert!(matches!(step, crate::containment::cgroup::DrainStep::Block { .. }));
    assert_eq!(
        thread_ids().difference(&before).count(),
        1,
        "the wait must start the pump"
    );
    drop(step);

    let _ = release(leaf, name);
    assert_eq!(thread_ids(), before, "the release must stop and join the pump");
}
