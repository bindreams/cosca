use super::{spawn_lock, spawn_lock_held_by_this_thread};

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic payload>")
}

/// The mutex is not reentrant: a nested `spawn_lock()` on the holding thread must be a named
/// panic, not a hang. Platform-independent: the guard lives in `acquire_spawn_lock`.
#[test]
fn a_nested_spawn_lock_panics_naming_the_reentry() {
    let outer = spawn_lock();
    let unwound = std::panic::catch_unwind(|| {
        let _inner = spawn_lock();
    });
    drop(outer);
    let payload = unwound.expect_err("a nested spawn_lock must panic");
    assert!(
        panic_message(&*payload).contains("spawn_lock re-entered"),
        "the panic must name the re-entry, got: {}",
        panic_message(&*payload)
    );
}

/// Dropping the guard clears the held flag, so the next acquire on this thread succeeds.
#[test]
fn dropping_the_guard_clears_the_held_flag() {
    assert!(!spawn_lock_held_by_this_thread());
    let guard = spawn_lock();
    assert!(spawn_lock_held_by_this_thread());
    drop(guard);
    assert!(!spawn_lock_held_by_this_thread());
    drop(spawn_lock());
}

/// The flag is per thread: another thread waits for the lock rather than tripping the guard.
#[test]
fn another_thread_blocks_rather_than_panics() {
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _guard = spawn_lock();
        held_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    held_rx.recv().unwrap();
    assert!(!spawn_lock_held_by_this_thread(), "another thread's hold is not ours");
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    drop(spawn_lock());
}

// `#[must_use]` lints -----

/// Discarding the guard releases the lock at once. `expect` makes clippy fail this file if either
/// lint stops firing, so the protection `MutexGuard` gave (rustc's `let_underscore_lock`) is kept.
#[test]
fn discarding_the_guard_is_linted() {
    #[expect(unused_must_use)]
    spawn_lock();
    #[expect(clippy::let_underscore_must_use)]
    let _ = spawn_lock();
    #[expect(clippy::let_underscore_must_use)]
    let _ = crate::test_spawn_lock();
}
