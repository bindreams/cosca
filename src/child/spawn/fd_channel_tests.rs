use super::register;

/// Mutant: `register` does not gate on liveness, so the hook runs for a withdrawn channel (and the
/// second spawn succeeds), or `withdraw` leaves the channel live.
#[skuld::test]
fn a_command_spawned_again_after_withdraw_fails_before_the_hook_runs() {
    let mut cmd = std::process::Command::new("true");
    // SAFETY: the hook returns at once.
    let shared = unsafe { register(&mut cmd, |_| Ok(())) };
    shared.publish(7, -1);
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

/// The hook reads the numbers `publish` stored.
///
/// Mutant: `publish` stores only the child's end.
#[skuld::test]
fn the_hook_sees_the_published_numbers() {
    let mut cmd = std::process::Command::new("true");
    // SAFETY: the hook reads an atomic and returns.
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
