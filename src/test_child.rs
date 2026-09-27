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
    let mut cmd = fixture_command(fixture);
    cmd.env(marker_env, cwd).current_dir(cwd);
    run_fixture_command(fixture, cmd);
}

/// Runs the libtest fixture at fully-qualified path `fixture` in a FRESH re-exec of this test
/// binary, with no cwd or other data of its own to carry — for a fixture whose body needs
/// isolation for some OTHER process-wide, irreversible state, such as
/// [`crate::test_privilege::drop_dac_bypass`]'s credentials and capability sets, rather than for
/// the cwd `run_fixture_with_cwd` exists to isolate. [`is_fixture_reexec`] is what the fixture
/// checks, since there is no per-fixture marker here to carry it instead.
///
/// See [`run_fixture_with_cwd`]'s doc for the re-exec rationale, the panic conditions, and why
/// `fixture` should come from [`fixture_path!`].
///
/// `#[cfg(unix)]`: every current caller drops DAC-bypassing privilege, a unix-only concept: gate
/// this the same way rather than carry a cross-platform no-caller-on-Windows dead-code warning.
#[cfg(unix)]
pub(crate) fn run_fixture(fixture: &str) {
    run_fixture_command(fixture, fixture_command(fixture));
}

/// The `std::process::Command` common to every fixture re-exec: this binary, filtered to exactly
/// one test, single-threaded, with both stdio streams captured for [`run_fixture_command`],
/// [`FIXTURE_PARENT_PID_ENV`] set (see [`is_fixture_reexec`]), and — on unix — `TMPDIR` forced to
/// `/tmp`.
///
/// A fixture that builds its own tempdir cannot assume its ambient `TMPDIR`/`$TMPDIR` is writable
/// by whatever uid or capability set it ends up with after dropping privilege. On Linux, [`drop_dac_bypass`]
/// leaves this thread at uid 0 and drops the capabilities that would otherwise let it write
/// anywhere regardless of ownership — so a `TMPDIR` naming a directory some OTHER uid owns,
/// `0700`, genuinely refuses root once that drop has happened (measured: `TMPDIR` pointing at a
/// directory `chown`'d to a non-root uid, `chmod 0700`'d — the shape `pam_tmpdir` leaves behind
/// for a `sudo -E` invocation that preserved a non-root caller's own `TMPDIR` — fails a `tempdir()`
/// call made after the drop). `/tmp` itself is the one POSIX convention every one of this crate's
/// target platforms ships world-writable (`1777`) regardless of caller, so forcing it here — once,
/// for every fixture — is a structural fix rather than a per-fixture one to remember.
///
/// [`drop_dac_bypass`]: crate::test_privilege::drop_dac_bypass
///
/// No `"cosca_unit_tests"` placeholder in argv slot 0 (that's [`fixture_argv`]'s convention for
/// `cosca::Command`, see its doc): `std::process::Command` already supplies its own argv[0] from
/// `Command::new`'s program path.
///
/// `pub(crate)`, not just `run_fixture`/`run_fixture_with_cwd`'s private building block: a
/// bespoke launcher with its own stdio needs (`exact_posix_tests.rs`'s
/// `spawn_exact_tool_in_an_unreachable_cwd`, which pipes stdin for its own gate-byte protocol and
/// nulls stdout rather than piping it) can start from this and override just the stdio it needs
/// changed, rather than hand-rolling the argv/env/TMPDIR setup a third time.
pub(crate) fn fixture_command(fixture: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
    cmd.args(["--test-threads=1", "--exact", fixture])
        .env(FIXTURE_PARENT_PID_ENV, std::process::id().to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if cfg!(unix) {
        cmd.env("TMPDIR", "/tmp");
    }
    cmd
}

/// The env var every fixture re-exec ([`run_fixture`], [`run_fixture_with_cwd`]) sets, to its own
/// pid — see [`is_fixture_reexec`].
const FIXTURE_PARENT_PID_ENV: &str = "COSCA_FIXTURE_PARENT_PID";

/// Whether this process's real parent is the one that (deliberately) re-exec'd it via
/// [`run_fixture`]/[`run_fixture_with_cwd`] — not merely that [`FIXTURE_PARENT_PID_ENV`], or a
/// fixture-specific marker such as `run_fixture_with_cwd`'s `marker_env`, happens to be present
/// in whatever environment picked this process up.
///
/// Presence alone does not prove a deliberate re-exec: a marker env var can be inherited by the
/// shared, unfiltered suite process too — a stray shell `export`, a copy-pasted CI `env:` block —
/// which would then run a fixture's body, [`crate::test_privilege::drop_dac_bypass`] for one,
/// inside the process every other concurrently running test depends on. A real parent-pid match
/// is not spoofable by an inherited or coincidentally-named var.
///
/// On `true`, also writes [`FIXTURE_GATE_PASSED_LINE`] to this process's real stderr (see that
/// constant's doc for why): a mutant that makes this function always return `false` would
/// otherwise make every fixture silently no-op and every driver test still pass, since "the
/// fixture did nothing" and "the fixture ran and asserted nothing false" look identical from the
/// outside.
#[cfg(unix)]
pub(crate) fn is_fixture_reexec() -> bool {
    let reexec = std::env::var(FIXTURE_PARENT_PID_ENV)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .is_some_and(|pid| pid == std::os::unix::process::parent_id());
    if reexec {
        write_gate_passed();
    }
    reexec
}

/// The line a fixture's own re-exec gate ([`is_fixture_reexec`], or [`expected_cwd`] for a
/// `run_fixture_with_cwd` fixture) writes to this process's REAL stderr once it passes — bypassing
/// libtest's capture the same way `exact_posix_tests.rs`'s `report()` does, since a fixture that
/// gates out via an early `return` exits 0 with nothing further to distinguish it from one that
/// genuinely ran and passed. [`run_fixture_command`] asserts this line is present, so a mutant
/// that makes the gate always refuse is caught there instead of looking like a passing suite.
pub(crate) const FIXTURE_GATE_PASSED_LINE: &str = "COSCA_FIXTURE_GATE_PASSED";

fn write_gate_passed() {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{FIXTURE_GATE_PASSED_LINE}");
}

/// Spawns `cmd` (built from [`fixture_command`], possibly with more set on it) under
/// `spawn_lock()`, matching every other raw `std::process::Command` re-exec of this test binary
/// (see [`spawn_a_process_that_exits`]'s doc for the macOS fd-marker hazard that convention
/// guards against), and waits for it.
///
/// Panics with the child's captured stdout/stderr on a non-zero exit, i.e. whenever the fixture's
/// own assertions failed — OR when the child's own libtest banner does not show that exactly the
/// one intended fixture ran. `--exact <fixture>` naming a test that does not exist (a typo, or a
/// rename on one side of the caller/fixture pair) makes libtest match ZERO tests and still exit
/// 0, which a bare `status.success()` check cannot tell apart from "the fixture ran and passed" —
/// build `fixture` with [`fixture_path!`] rather than a hand-typed string literal, so a mismatch
/// between a call site and its `#[test] fn` is a compile error instead of a silently-empty
/// filter; this stdout check is the remaining backstop for whatever that still lets through.
fn run_fixture_command(fixture: &str, mut cmd: std::process::Command) {
    let child = {
        let _guard = crate::child::spawn::spawn_lock();
        cmd.spawn().expect("spawn fixture child")
    };
    let output = child.wait_with_output().expect("wait for fixture child");
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
    assert!(
        stderr.contains(FIXTURE_GATE_PASSED_LINE),
        "fixture {fixture} exited 0 and reported 1 test passed, but never wrote \
         {FIXTURE_GATE_PASSED_LINE:?} to its real stderr — its re-exec gate let it return early \
         without running its own body at all, which a passing libtest banner alone cannot tell \
         apart from a fixture that ran and found nothing wrong:\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// Reads `marker_env`'s value as the directory [`run_fixture_with_cwd`]'s caller prepared, and
/// returns `None` when it is unset, or (on unix) when [`is_fixture_reexec`] says this is not
/// really a deliberate re-exec — either way, a fixture is picked up by an ordinary, unfiltered
/// suite run too, where it must no-op rather than assert against whatever the suite's own ambient
/// cwd happens to be, or against a `marker_env` some unrelated process happened to leave behind.
///
/// When set, also asserts this fixture's OWN `std::env::current_dir()` actually IS that
/// directory: `run_fixture_with_cwd`'s `.current_dir(cwd)` call is what is supposed to guarantee
/// that, but a fixture that never checks it would keep passing even if that call were silently
/// dropped — an assertion the fixture's OWN body happened to still satisfy in whatever the
/// process's REAL ambient cwd was, for reasons that have nothing to do with the directory under
/// test. Every fixture in this file that takes a `marker_env` argument calls this instead of
/// reading `std::env::current_dir()` directly, so that check is never skippable by omission.
pub(crate) fn expected_cwd(marker_env: &str) -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    if !is_fixture_reexec() {
        return None;
    }
    let expected = std::path::PathBuf::from(std::env::var_os(marker_env)?);
    let actual = std::env::current_dir().expect("current_dir");
    assert_eq!(
        actual.canonicalize().expect("canonicalize actual cwd"),
        expected.canonicalize().expect("canonicalize expected cwd"),
        "this fixture's OS-level cwd must be the directory run_fixture_with_cwd's caller prepared",
    );
    // Windows has no `is_fixture_reexec` to have written this already (no `parent_id()` there);
    // unix already did, via that call above, so this second write is a harmless duplicate.
    write_gate_passed();
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

/// Exit code of the `tool` in [`cwd_and_path_tools`]'s first directory.
#[cfg(unix)]
pub(crate) const CWD_TOOL_EXIT: i32 = 11;
/// Exit code of the `tool` in [`cwd_and_path_tools`]'s second directory.
#[cfg(unix)]
pub(crate) const PATH_TOOL_EXIT: i32 = 22;

/// Two directories, each holding an executable script named `tool` that exits with its own code
/// ([`CWD_TOOL_EXIT`], [`PATH_TOOL_EXIT`]), so a child's exit status says which one was loaded.
/// Meant as the child's working directory and its `PATH`, respectively.
///
/// Each write is serialized against every other spawn's `fork` and the guard dropped before the
/// caller's spawn: a `fork` while a script's writable descriptor is open leaves the forked child
/// holding it until it execs, and `execve` of that script then fails with `ETXTBSY`. The lock is
/// not reentrant, so holding it across a `spawn()` would deadlock.
#[cfg(unix)]
pub(crate) fn cwd_and_path_tools() -> (tempfile::TempDir, tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt;
    let dirs = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    for (dir, code) in [(&dirs.0, CWD_TOOL_EXIT), (&dirs.1, PATH_TOOL_EXIT)] {
        let tool = dir.path().join("tool");
        let _guard = crate::child::spawn::spawn_lock();
        std::fs::write(&tool, format!("#!/bin/sh\nexit {code}\n")).expect("write tool");
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod tool");
    }
    dirs
}
