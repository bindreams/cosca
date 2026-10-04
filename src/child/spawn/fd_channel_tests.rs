use std::os::fd::{AsRawFd, OwnedFd};

use super::{publish_ends, register};

fn pipe() -> (OwnedFd, OwnedFd) {
    let (r, w) = std::io::pipe().expect("pipe");
    (OwnedFd::from(r), OwnedFd::from(w))
}

fn is_cloexec(fd: &OwnedFd) -> bool {
    // SAFETY: `fcntl` on an fd the caller owns.
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC != 0 }
}

/// A command spawned again after its channel was withdrawn fails before the hook runs.
#[skuld::test]
fn a_command_spawned_again_after_withdraw_fails_before_the_hook_runs() {
    let mut cmd = std::process::Command::new("true");
    // SAFETY: the hook is trivially async-signal-safe.
    let shared = unsafe { register(&mut cmd, |_| Ok(())) };
    shared.publish(7, 8);
    let guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `guard`")]
    let first = cmd.spawn();
    drop(guard);
    first.expect("a live channel spawns").wait().expect("wait");
    shared.withdraw();
    let _guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard`")]
    let second = cmd.spawn();
    let err = second.expect_err("a withdrawn channel fails the spawn");
    assert_eq!(err.raw_os_error(), Some(libc::EBADF));
}

/// A channel that was never published fails the spawn, and the hook does not run.
///
/// Mutant: `register` does not gate on liveness.
#[skuld::test]
fn a_hook_run_before_publish_does_not_run() {
    let mut cmd = std::process::Command::new("true");
    // SAFETY: the hook is trivially async-signal-safe.
    let _shared = unsafe { register(&mut cmd, |_| Ok(())) };
    let _guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard`")]
    let spawned = cmd.spawn();
    assert_eq!(spawned.expect_err("not live yet").raw_os_error(), Some(libc::EBADF));
}

/// The hook reads the numbers `publish` stored.
///
/// Mutant: `publish` stores only the child's end.
#[skuld::test]
fn the_hook_sees_the_published_numbers() {
    let mut cmd = std::process::Command::new("true");
    // SAFETY: the hook is trivially async-signal-safe.
    let shared = unsafe {
        register(&mut cmd, |shared| {
            if shared.child_end() == 7 && shared.parent_end() == 8 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        })
    };
    shared.publish(7, 8);
    let _guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard`")]
    let spawned = cmd.spawn();
    spawned.expect("the hook saw 7 and 8").wait().expect("wait");
}

/// `publish_ends` returns `(child_end, parent_end)`, publishes those very numbers, keeps both
/// close-on-exec, and leaves the channel live.
///
/// Mutants: the tuple is returned swapped; the ends are published in the wrong slots.
#[skuld::test]
fn publish_ends_returns_and_publishes_the_ends_in_order() {
    let mut cmd = std::process::Command::new("true");
    // SAFETY: the hook is trivially async-signal-safe.
    let shared = unsafe { register(&mut cmd, |_| Ok(())) };
    let (child_in, parent_in) = pipe();
    let (child_raw, parent_raw) = (child_in.as_raw_fd(), parent_in.as_raw_fd());
    let (child_end, parent_end) = publish_ends(&shared, child_in, parent_in).expect("publish");
    assert!(
        child_raw >= 3 && parent_raw >= 3,
        "the test's own pipe sits above stdio"
    );
    assert_eq!((child_end.as_raw_fd(), parent_end.as_raw_fd()), (child_raw, parent_raw));
    assert_eq!((shared.child_end(), shared.parent_end()), (child_raw, parent_raw));
    assert!(is_cloexec(&child_end) && is_cloexec(&parent_end));
    let _guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard`")]
    let spawned = cmd.spawn();
    spawned.expect("a published channel spawns").wait().expect("wait");
}

/// With stdio closed, the lowest free numbers are 0 and 1. `publish_ends` moves both ends above
/// stdio, publishes the moved numbers, and keeps them close-on-exec. Runs in a re-exec'd child.
///
/// Mutants: `publish_ends` publishes the numbers it was given; it does not move the ends.
#[skuld::test]
fn publish_ends_moves_ends_out_of_closed_stdio_slots() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(fixture_publish_ends_with_stdio_closed));
}

#[skuld::test]
fn fixture_publish_ends_with_stdio_closed() {
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    let mut cmd = std::process::Command::new("true");
    // SAFETY: the hook is trivially async-signal-safe.
    let shared = unsafe { register(&mut cmd, |_| Ok(())) };
    let saved = crate::test_child::close_stdio_keeping_a_copy();
    let (child_in, parent_in) = pipe();
    let low = (child_in.as_raw_fd(), parent_in.as_raw_fd());
    let moved = publish_ends(&shared, child_in, parent_in);
    let published = (shared.child_end(), shared.parent_end());
    let cloexec = moved
        .as_ref()
        .map(|(c, p)| (is_cloexec(c), is_cloexec(p)))
        .map_err(ToString::to_string);
    let raws = moved
        .as_ref()
        .map(|(c, p)| (c.as_raw_fd(), p.as_raw_fd()))
        .map_err(ToString::to_string);
    drop(moved);
    drop(saved);
    assert!(
        low.0 < 3 && low.1 < 3,
        "the precondition: the pipe landed in stdio slots {low:?}"
    );
    let raws = raws.expect("publish");
    assert!(raws.0 >= 3 && raws.1 >= 3, "both ends are above stdio: {raws:?}");
    assert_eq!(published, raws, "the moved numbers are the published ones");
    assert_eq!(cloexec.expect("publish"), (true, true));
}
