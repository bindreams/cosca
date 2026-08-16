//! Test-only child processes shared across the crate's unit tests.

/// A child that exits promptly and needs no external binary: this same test binary, run
/// with a filter that matches nothing, so libtest runs zero tests and exits 0.
///
/// The libtest filter is mandatory, and is why this lives in exactly one place: re-execing
/// the test binary with NO arguments runs the whole suite — including whichever test called
/// this — which then re-execs again, unboundedly.
///
/// Spawns under `spawn_lock()`: on macOS, a fork here that lands while another test's fd
/// marker write end happens to be open would transiently inherit it, and a concurrently
/// running sweep could then find and signal this bystander child. `spawn_lock()` is the same
/// lock every cosca-originated spawn in this test binary already takes.
pub(crate) fn spawn_a_process_that_exits() -> std::process::Child {
    let _guard = crate::child::spawn::spawn_lock();
    std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn")
}
