//! `cosca::test_spawn_lock()` is the same non-reentrant lock a cosca spawn takes itself. An
//! integration test that holds it across a `cosca::Command::spawn` must get a named panic, not a
//! hang. The check is compiled in only under `debug_assertions`, so this file is too; nothing in
//! CI runs the integration binaries in release.
#![cfg(debug_assertions)]

/// `#[expect]` fails the build if the guard stops being `#[must_use]`. The `let _ =` form is
/// covered by the lib crate's lint (`spawn_lock_tests`), which this crate does not enable.
#[test]
fn discarding_the_test_guard_is_linted() {
    #[expect(unused_must_use)]
    cosca::test_spawn_lock();
}

#[test]
fn a_spawn_under_an_outer_test_spawn_lock_panics_naming_the_reentry() {
    let outer = cosca::test_spawn_lock();
    let unwound = std::panic::catch_unwind(|| {
        let mut cmd = cosca::Command::new();
        // The panic is at lock acquisition, before the program is looked at.
        cmd.executable(std::env::current_exe().expect("this test binary's path"));
        let _ = cmd.spawn();
    });
    drop(outer);
    let payload = unwound.expect_err("a cosca spawn under an outer test_spawn_lock must panic");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic payload>");
    assert!(
        message.contains("spawn_lock re-entered"),
        "the panic must name the re-entry, got: {message}"
    );
}
