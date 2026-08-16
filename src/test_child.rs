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

/// The fully-qualified libtest path of [`fixture_survives_group_signal`], for callers that
/// re-exec this binary against it directly (`current_exe() --exact <this>`) rather than through
/// [`spawn_a_process_that_exits`]'s own filter.
#[cfg(windows)]
pub(crate) const FIXTURE_SURVIVES_GROUP_SIGNAL_TEST: &str = "test_child::fixture_survives_group_signal";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_survives_group_signal`] connects
/// back to and tags once the grandchild survivor exists in its own process group. Its mere
/// presence also tells the fixture it was re-exec'd deliberately rather than picked up by an
/// ordinary, unfiltered suite run — one var serves both roles, since the fixture needs the
/// address either way.
#[cfg(windows)]
pub(crate) const FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV: &str = "COSCA_FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR";

/// Windows-only fixture for the `root_exited`-on-`MembersRemain` regression (sync and async
/// twins): a no-op when picked up by an ordinary, unfiltered suite run —
/// [`FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV`] is unset there. Re-executed via `current_exe()
/// --exact` [`FIXTURE_SURVIVES_GROUP_SIGNAL_TEST`] with that var set, it instead spawns a
/// grandchild a group `CTRL_BREAK` can never reach — `CREATE_NEW_PROCESS_GROUP` puts it in its
/// own process group, the same isolation `graceful_shutdown_tree`'s own doc describes for a
/// nested contained descendant — then connects to the caller's listener at that address and
/// writes a single tag byte, proving the grandchild already exists (and is already in its own
/// group) before the caller proceeds to call `graceful_shutdown_tree`. The tag goes out over a
/// real TCP socket, not `print!`/`io::stdout()`: libtest captures the latter per-test and
/// discards it for a passing test, so a stdout-based readiness byte never reaches the caller's
/// piped reader at all — this is the same control-channel shape `tests/common`'s
/// `spawn_tree`/`spawn_tree_async` tag handshake already uses for exactly this reason, not a
/// Windows-specific mechanism. The job object still tracks the grandchild as a tree member
/// despite its own process group (job membership and process group are independent Win32
/// concepts), so it shows up as a `MembersRemain` survivor even though the signal itself never
/// reaches it. Mirrors [`spawn_a_process_that_exits`]'s filtered-re-exec idiom (see its own doc
/// for why the filter is mandatory) put to a second use.
#[cfg(windows)]
#[test]
fn fixture_survives_group_signal() {
    let Some(addr) = std::env::var_os(FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::Write;
    use std::os::windows::process::CommandExt;

    // CREATE_NEW_PROCESS_GROUP (winbase.h). A scalar flag, so a raw constant needs no
    // `windows`-crate import: `std::os::windows::process::CommandExt::creation_flags` takes it
    // as a plain `u32`.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    #[allow(clippy::zombie_processes)] // intentional: the grandchild must outlive us; containment kills it
    let _survivor = std::process::Command::new("ping")
        .args(["-n", "30", "127.0.0.1"])
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn a grandchild the group signal cannot reach");
    let mut sock = std::net::TcpStream::connect(addr.to_str().expect("utf8 addr")).expect("connect readiness socket");
    sock.write_all(b"R").expect("write readiness tag");
}
