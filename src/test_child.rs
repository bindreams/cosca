//! Test-only child processes shared across the crate's unit tests.

/// Runs the libtest fixture at fully-qualified path `fixture` (e.g.
/// `"resolve::resolve_tests::fixture_foo"`) in a FRESH re-exec of this test binary whose OS-level
/// cwd is `cwd` — proving whatever the fixture's body proves about a process's REAL cwd without
/// ever mutating THIS (shared, multithreaded) test binary's own cwd, which every other
/// concurrently running test in this binary would otherwise race. `Command::current_dir` sets the
/// CHILD's cwd before its own `exec`/`CreateProcessW`, so no window exists where this process's
/// cwd is anything other than what it always was.
///
/// `marker_env` is set to `cwd` itself in the child only, so the fixture can both (a) tell this
/// deliberate re-exec apart from being picked up by an ordinary, unfiltered suite run — where it
/// must no-op rather than assert against whatever the suite's own ambient cwd happens to be — and
/// (b) assert its OWN `std::env::current_dir()` against that same value, rather than trusting
/// that this function's `.current_dir(cwd)` call below actually took effect. Carrying the
/// directory in the marker, rather than a bare `"1"`, is what lets a fixture catch this helper's
/// OWN cwd-setting being silently dropped — a mutation that a caller checking only the fixture's
/// pass/fail outcome cannot otherwise see, since the fixture would still be asserting something
/// true about *some* directory, just not necessarily the one the parent prepared.
///
/// Spawns under `spawn_lock()`, matching every other raw `std::process::Command` re-exec of this
/// test binary (see [`spawn_a_process_that_exits`]'s doc for the macOS fd-marker hazard that
/// convention guards against).
///
/// Panics with the child's captured stdout/stderr on a non-zero exit, i.e. whenever the fixture's
/// own assertions failed — OR when the child's own libtest banner does not show that exactly the
/// one intended fixture ran. `--exact <fixture>` naming a test that does not exist (a typo, or a
/// rename on one side of the caller/fixture pair) makes libtest match ZERO tests and still exit
/// 0, which a bare `status.success()` check cannot tell apart from "the fixture ran and passed" —
/// build `fixture` with [`fixture_path!`] rather than a hand-typed string literal, so a mismatch
/// between a call site and its `#[test] fn` is a compile error instead of a silently-empty
/// filter; this stdout check is the remaining backstop for whatever that still lets through.
pub(crate) fn run_fixture_with_cwd(fixture: &str, cwd: &std::path::Path, marker_env: &str) {
    let _guard = crate::child::spawn::spawn_lock();
    // No `"cosca_unit_tests"` placeholder in slot 0: that convention belongs to [`fixture_argv`],
    // whose own doc says it is for `cosca::Command`'s `args`, which is the **full** argv because
    // `cosca::Command` never runs the platform's own arg0 convention. `std::process::Command`
    // below already supplies its own argv[0] from `Command::new`'s program path, so repeating a
    // placeholder here would only ride along as a harmless-but-stray extra positional filter.
    let output = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--test-threads=1", "--exact", fixture])
        .env(marker_env, cwd)
        .current_dir(cwd)
        .output()
        .expect("spawn fixture child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "fixture {fixture} failed (status {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status,
    );
    assert!(
        stdout.contains("running 1 test") && stdout.contains("test result: ok. 1 passed;"),
        "fixture {fixture} exited 0 but its libtest banner shows something other than exactly \
         one test run and passed — most likely `--exact {fixture}` matched ZERO tests (a stale \
         name on one side of a caller/fixture pair), which libtest also exits 0 for:\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// Reads `marker_env`'s value as the directory [`run_fixture_with_cwd`]'s caller prepared, and
/// returns `None` when it is unset — a fixture is picked up by an ordinary, unfiltered suite run
/// too, where it must no-op rather than assert against whatever the suite's own ambient cwd
/// happens to be.
///
/// When set, also asserts this fixture's OWN `std::env::current_dir()` actually IS that
/// directory: `run_fixture_with_cwd`'s `.current_dir(cwd)` call is what is supposed to guarantee
/// that, but a fixture that never checks it would keep passing even if that call were silently
/// dropped — an assertion the fixture's OWN body happened to still satisfy in whatever the
/// process's REAL ambient cwd was, for reasons that have nothing to do with the directory under
/// test. Every fixture in this file that takes a `marker_env` argument calls this instead of
/// reading `std::env::current_dir()` directly, so that check is never skippable by omission.
pub(crate) fn expected_cwd(marker_env: &str) -> Option<std::path::PathBuf> {
    let expected = std::path::PathBuf::from(std::env::var_os(marker_env)?);
    let actual = std::env::current_dir().expect("current_dir");
    assert_eq!(
        actual.canonicalize().expect("canonicalize actual cwd"),
        expected.canonicalize().expect("canonicalize expected cwd"),
        "this fixture's OS-level cwd must be the directory run_fixture_with_cwd's caller prepared",
    );
    Some(expected)
}

/// Builds the fully-qualified libtest `--exact` path of the `#[test] fn` named `$name`, for
/// [`run_fixture_with_cwd`]'s `fixture` argument. Two things tie the call site to the fixture
/// instead of letting them drift apart as two independently hand-typed strings:
///
/// - `let _: fn() = $name;` forces the compiler to resolve `$name` as an item in scope — a typo
///   or a stale name after a rename is a compile error here, not a filter that silently matches
///   zero tests at runtime (see [`run_fixture_with_cwd`]'s doc for why that is exactly the bug
///   this macro exists to rule out).
/// - `module_path!()` derives the module portion at compile time, so it can never fall out of
///   sync with a file move or a module rename; libtest's `--exact` filter never includes the
///   crate-name component `module_path!()` always carries as its own first segment, hence the
///   [`strip_crate_prefix`] call.
macro_rules! fixture_path {
    ($name:ident) => {{
        let _: fn() = $name;
        crate::test_child::strip_crate_prefix(concat!(module_path!(), "::", stringify!($name)))
    }};
}
pub(crate) use fixture_path;

/// Strips the crate-name segment `module_path!()` always carries as its own first component
/// (e.g. `"cosca::resolve::resolve_tests"`), since libtest's `--exact` filter never includes it
/// (e.g. `"resolve::resolve_tests"`). Panics if `path` does not start with that segment, which
/// would mean `module_path!()`'s documented contract no longer holds.
pub(crate) fn strip_crate_prefix(path: &'static str) -> &'static str {
    let prefix = concat!(env!("CARGO_PKG_NAME"), "::");
    path.strip_prefix(prefix)
        .unwrap_or_else(|| panic!("{path:?} does not start with {prefix:?} — module_path!()'s contract changed"))
}

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

/// The argv for re-executing this test binary against one fixture through `cosca::Command`,
/// whose `args` is the **full** argv — libtest drops slot 0 as the binary name, so a filter or
/// option placed there is silently eaten and `--exact` degrades to substring matching.
/// `--test-threads=1` keeps a future filter that matches more than one test from running them
/// concurrently inside a process the caller is about to signal.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) fn fixture_argv(test: &str) -> [&str; 4] {
    ["cosca_unit_tests", "--test-threads=1", "--exact", test]
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

/// The fully-qualified libtest path of [`fixture_registers_then_blocks`], for callers that
/// re-exec this binary against it directly (`current_exe() --exact <this>`).
// Gated with its consumers: the sync caller uses it only under `cfg(windows)`, the other two are
// behind the `tokio` feature, so a default-feature Unix build has none and `-D warnings` rejects it.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) const FIXTURE_REGISTERS_THEN_BLOCKS_TEST: &str = "test_child::fixture_registers_then_blocks";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_registers_then_blocks`] tags.
/// Its mere presence also tells the fixture it was re-exec'd deliberately rather than picked up
/// by an ordinary, unfiltered suite run.
pub(crate) const FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV: &str = "COSCA_FIXTURE_REGISTERS_THEN_BLOCKS_ADDR";

/// Bind a rendezvous listener for [`fixture_registers_then_blocks`]; returns it and its
/// `127.0.0.1:<port>` address.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) fn registration_rendezvous() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind rendezvous listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    (listener, addr)
}

/// Fixture supplying a happens-before edge on a live child: a no-op when picked up by an
/// ordinary, unfiltered suite run ([`FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV`] is unset there).
/// Re-executed via `current_exe() --exact` [`FIXTURE_REGISTERS_THEN_BLOCKS_TEST`] with that var
/// set, it connects to the caller's listener, writes one tag byte, then blocks on a 1-byte read
/// of that same socket. The caller unblocks it by writing a byte back, and it then exits 0 of
/// its own accord — an exit code no forced kill can produce.
///
/// The tag is the edge: the fixture cannot write it until it is executing its own code. On
/// Windows that is also after the console has registered it — a child signalled before that
/// point dies during loader init instead of to the console event, which is a different exit code
/// and a different thing under test.
///
/// It installs no console-control handler, so `CTRL_BREAK`'s default disposition terminates it.
/// Blocking on the socket rather than parking means a panicking or aborted caller closes the
/// socket and the fixture exits on EOF instead of orphaning.
#[test]
fn fixture_registers_then_blocks() {
    let Some(addr) = std::env::var_os(FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::{Read, Write};

    let mut sock = std::net::TcpStream::connect(addr.to_str().expect("utf8 addr")).expect("connect rendezvous socket");
    sock.write_all(b"R").expect("write registration tag");
    sock.flush().expect("flush registration tag");
    let mut sink = [0u8; 1];
    let _ = sock.read(&mut sink);
}

/// The fully-qualified libtest path of [`fixture_control_block`].
#[cfg(feature = "tokio")]
pub(crate) const FIXTURE_CONTROL_BLOCK_TEST: &str = "test_child::fixture_control_block";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_control_block`] tags. Its mere
/// presence also tells the fixture it was re-exec'd deliberately rather than picked up by an
/// ordinary, unfiltered suite run.
#[cfg(feature = "tokio")]
pub(crate) const FIXTURE_CONTROL_BLOCK_ADDR_ENV: &str = "COSCA_FIXTURE_CONTROL_BLOCK_ADDR";

/// A child that reports readiness and then blocks until the caller releases or kills it: a no-op
/// when picked up by an ordinary, unfiltered suite run ([`FIXTURE_CONTROL_BLOCK_ADDR_ENV`] is
/// unset there). Re-executed via `current_exe() --exact` [`FIXTURE_CONTROL_BLOCK_TEST`] with that
/// var set, it connects to the caller's listener, writes one tag byte, then blocks on a 1-byte
/// read of that same socket and RETURNS as soon as the read returns — so a caller that writes a
/// byte gets a clean voluntary exit, and a caller that kills it gets the socket's EOF.
///
/// Mirrors [`fixture_registers_then_blocks`]'s filtered-re-exec idiom (see
/// [`spawn_a_process_that_exits`] for why the filter is mandatory), and deliberately takes NO
/// `spawn_lock()`: see [`spawn_async_blocker`].
#[cfg(feature = "tokio")]
#[test]
fn fixture_control_block() {
    let Some(addr) = std::env::var_os(FIXTURE_CONTROL_BLOCK_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::{Read, Write};

    let mut sock = std::net::TcpStream::connect(addr.to_str().expect("utf8 addr")).expect("connect control socket");
    sock.write_all(b"R").expect("write readiness tag");
    sock.flush().expect("flush readiness tag");
    let mut sink = [0u8; 1];
    let _ = sock.read(&mut sink);
}

/// Spawn [`fixture_control_block`] through `cosca::tokio` and return its handle plus the control
/// socket, already past the readiness tag — so the child is provably executing its own code.
///
/// **Takes no `spawn_lock()`, deliberately.** That lock is a plain non-reentrant mutex and
/// cosca's own async spawn takes it internally, so a helper holding it across a cosca spawn
/// deadlocks on its own thread. Every existing helper that takes it spawns via
/// `std::process::Command`; the cosca-spawning helpers do not.
///
/// Uncontained (so the tree teardown is a verified no-op) and stdin INHERITED (so closing the
/// parent's stdio cannot make the child exit on its own). Spawned via `executable()`, which puts
/// Windows on the raw `CreateProcessW` backend.
#[cfg(feature = "tokio")]
pub(crate) fn spawn_async_blocker() -> (crate::tokio::Child, std::net::TcpStream) {
    use std::io::Read as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(&exe)
        .args(fixture_argv(FIXTURE_CONTROL_BLOCK_TEST))
        .env(FIXTURE_CONTROL_BLOCK_ADDR_ENV, &addr);
    // The child runs a full libtest harness, which writes its `running 1 test` / `test result:`
    // banner to fd 1 directly — libtest's capture wraps the Rust print machinery, not the
    // descriptor, so an inherited fd 1 lands that banner raw (and mid-line) in THIS binary's
    // output. Both are nulled; stdin stays inherited, per this helper's contract.
    cmd.stdout(crate::stdio::Stdio::null()).expect("stdout null");
    cmd.stderr(crate::stdio::Stdio::null()).expect("stderr null");
    let child = cmd.spawn().expect("spawn the control-block fixture");
    let (mut sock, _) = listener.accept().expect("accept the control socket");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the readiness tag");
    assert_eq!(&tag, b"R", "unexpected control tag");
    (child, sock)
}
