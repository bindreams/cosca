//! Issue #61's end-to-end reproduction: a REAL process group holding a mixed membership — one
//! member the caller may signal, one it genuinely may not (a real setuid-root process that has
//! called `setuid(0)` itself, so it is unsignalable IN FACT, not merely by a file mode bit) —
//! torn down through the crate's real public path, `Child::kill_tree` (which calls
//! `containment::unix::kill_group`, `SIGKILL`).
//!
//! Every OTHER real-process test in this suite (`tests/spawn_io.rs`'s `unix_kill_tree_reaps_the_
//! grandchild` and friends) spawns a group where every member is equally killable by the test's
//! own uid, so a regression that made `converge` silently drop a real refuser would still pass
//! them all. This is the one test that would fail if issue #61's fix were reverted — see the
//! module docs on `containment::unix::group` for the exact bug (`killpg`'s return value reports
//! only whether *at least one* member took the signal, never who it refused).
//!
//! # Platform scope
//! Linux only. The original bug was reproduced (and is reproduced here) via `/proc`-based group
//! membership and `kill(2)`'s real permission check (`kill_ok_by_cred`, `kernel/signal.c`),
//! which requires the target's REAL uid — not merely its effective/saved uid — to differ from
//! the caller's. macOS is deliberately excluded, not silently skipped there: SIP and the
//! hardened-runtime/notarization requirements on modern macOS make a locally-built setuid-root
//! binary unreliable to provision in CI (SIP can strip privileges from unsigned/ad-hoc-signed
//! binaries depending on where they live and how they were built), and there is no equivalent to
//! Linux's straightforward "chown root, chmod u+s, exec" contract to build an honest CI lane on.
//! Windows has no setuid concept at all. `containment::unix::group::members` itself is only
//! implemented for Linux and macOS (see that module), so this gap does not exist on Windows
//! regardless.
//!
//! # Running as root
//! Root may signal the setuid helper, so the scenario needs an unprivileged caller. Started as
//! root, the test re-executes this binary as uid 65534 (`nobody`), running only itself, and
//! requires that run to pass. Both this test binary (so every directory on its path, e.g. the
//! cargo target dir) and `COSCA_TEST_SETUID_HELPER` must be reachable by uid 65534: a `0700` home
//! directory on the path makes the re-run fail to start. The re-run identifies itself by
//! `COSCA_TEST_SETUID_RERUN` holding its parent's pid; a value inherited from elsewhere is an
//! error, not proof of a re-run. The CI "Run setuid-root process-group teardown test as root"
//! step exercises this path.
//!
//! # Gating
//! This test is `#[ignore]`d by default, so an ordinary `cargo nextest run` — locally, or in every
//! CI step that doesn't explicitly ask for it — counts it in the final `... skipped` tally, never
//! runs it to `... ok`. A vacuous pass that merely returned early (the shape this file used at
//! first) is indistinguishable in the log from a real one, which is exactly the failure this rule
//! exists to prevent: a test name reading "ok" must mean the scenario it describes was actually
//! exercised. Only the one CI step that has provisioned the helper runs it, via `cargo nextest run
//! --test group_teardown_setuid --run-ignored only` (see
//! `.github/workflows/ci.yaml`, the "Run setuid-root process-group teardown test" step, which
//! follows "Set up setuid-root helper").
//!
//! `COSCA_TEST_SETUID_HELPER` must hold the absolute path to a pre-provisioned COPY of
//! `cosca_testbin` that CI has `chown root:root` + `chmod u+s`'d (see the "Set up setuid-root
//! helper" step). Once a caller has explicitly opted in to running this ignored test, there is no
//! honest silent case left: the variable being unset there is a misconfiguration, not an
//! environment the test doesn't apply to, so it panics rather than no-op-returning. And with the
//! variable set, the test must fail LOUDLY if the helper does not actually achieve real uid 0 —
//! never silently pass. That check is performed by the spawned helper itself
//! (`setuid-control-block` in `testbin/main.rs`) and reported back over the same control socket
//! used for the readiness handshake, so a nosuid mount or a wrong owner/mode surfaces as a loud
//! panic here, not a false green.

// The whole file is Linux-only in purpose (see the module docs above) — gated here, once, rather
// than on every item, so the file compiles to nothing (no unused-code warnings) elsewhere.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};

fn testbin() -> &'static str {
    env!("CARGO_BIN_EXE_cosca_testbin")
}

/// Panics if unset: by the time this runs, the caller has already explicitly opted in (the test
/// is `#[ignore]`d, so it only executes given `--ignored`/`--include-ignored` or an exact-name
/// filter combined with one of those). An unset variable at that point is a misconfigured CI lane
/// or a developer who ran the wrong command, not a platform this test legitimately doesn't apply
/// to — see the module docs' "Gating" section.
fn gated() -> String {
    std::env::var("COSCA_TEST_SETUID_HELPER").unwrap_or_else(|_| {
        panic!(
            "this test was explicitly requested (it is #[ignore]d) but COSCA_TEST_SETUID_HELPER \
             is not set — see the module docs' \"Gating\" section for what it must point at"
        )
    })
}

/// `kill(pid, 0)` performs only the existence/permission check, sending nothing. `Ok(())` means
/// the pid is live and this caller may signal it. `EPERM` ALSO means alive — this is the exact
/// property under test: an unprivileged caller probing a genuinely-root-owned process gets
/// `EPERM` from the permission check itself, not `ESRCH`. Only `ESRCH` (or any other errno) means
/// the pid is actually gone. Independent of the crate's own code path — this is the same raw
/// syscall POSIX specifies `kill_group`'s underlying mechanism against, used here purely as an
/// oracle, not as a fixture of the code under test.
fn probe_kill0(pid: u32) -> Result<(), Option<i32>> {
    // Safety: signal 0 performs only the existence/permission check, sends nothing.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error().raw_os_error())
}

/// The uid this test re-executes itself as when started as root: `nobody`.
const UNPRIVILEGED: u32 = 65534;

/// Set by the parent to its own pid; the re-executed child accepts it only if it equals its
/// parent's pid (see [`rerun_role`]). The child then prints [`RERAN`] because libtest exits 0 when
/// the filter matches no test.
const RERUN_ENV: &str = "COSCA_TEST_SETUID_RERUN";
const RERAN: &str = "COSCA_TEST_SETUID_RERUN ran";

/// The libtest `--exact` name of `$name`; a rename that misses this call site fails to compile
/// instead of matching zero tests.
macro_rules! test_path {
    ($name:ident) => {{
        let _: fn() = $name;
        stringify!($name)
    }};
}

#[derive(Debug, PartialEq, Eq)]
enum Role {
    /// Started by a user or harness: no marker.
    Fresh,
    /// Re-executed by [`rerun_unprivileged`] in another process.
    Rerun,
}

/// Classifies this process from the inherited [`RERUN_ENV`] value and its parent's pid. A value
/// that is not the parent's pid was inherited from something else (a shell export, an outer
/// harness) and is an error, never proof that this is the re-run.
fn rerun_role(inherited: Option<&str>, parent_pid: u32) -> Result<Role, String> {
    match inherited {
        None => Ok(Role::Fresh),
        Some(v) if v == parent_pid.to_string() => Ok(Role::Rerun),
        Some(v) => Err(format!(
            "{RERUN_ENV}={v:?} is set in this process's environment but is not the pid of its parent ({parent_pid}), so it was inherited, not set by the re-run; unset it"
        )),
    }
}

/// The child inherits `COSCA_TEST_SETUID_HELPER`, so the helper (mode `u+s`, readable and
/// executable by anyone) and this binary must be reachable by [`UNPRIVILEGED`]; if not, the
/// child's failure says so.
fn rerun_unprivileged() {
    use std::os::unix::process::CommandExt as _;

    let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            test_path!(kill_tree_reports_refused_and_leaves_the_real_setuid_survivor_running),
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RERUN_ENV, std::process::id().to_string())
        .uid(UNPRIVILEGED)
        .gid(UNPRIVILEGED)
        .output()
        .expect("re-execute this test as an unprivileged user");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.lines().any(|line| line == RERAN),
        "the unprivileged re-run did not pass ({}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rerun_role_without_the_variable_is_fresh() {
    assert_eq!(rerun_role(None, 42), Ok(Role::Fresh));
}

#[test]
fn rerun_role_accepts_the_parents_pid() {
    assert_eq!(rerun_role(Some("42"), 42), Ok(Role::Rerun));
}

#[test]
fn rerun_role_rejects_an_inherited_value_naming_the_variable() {
    let err = rerun_role(Some("1"), 42).unwrap_err();
    assert!(err.contains(RERUN_ENV) && err.contains("inherited"), "{err}");
}

/// One accepted control connection, classified by its first line:
/// - `"R"` — the ordinary group leader, ready and blocked.
/// - `"P <pid>"` — the setuid-root helper, ready (fully real-uid-0) and blocked, reporting its
///   own pid so the harness can independently probe it.
/// - `"F <reason>"` — the setuid-root helper detected its OWN provisioning failed (wrong owner/
///   mode, nosuid mount, or `setuid(0)` itself failing) and is about to exit; never silently
///   treated as "ready".
enum Handshake {
    Root(BufReader<TcpStream>),
    Privileged { pid: u32, sock: BufReader<TcpStream> },
}

fn accept_one(listener: &TcpListener) -> Handshake {
    let (stream, _) = listener.accept().expect("accept control connection");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read control handshake line");
    let line = line.trim_end_matches('\n');
    if let Some(reason) = line.strip_prefix("F ") {
        panic!(
            "setuid helper provisioning failed: {reason}\n\
             (check that COSCA_TEST_SETUID_HELPER points at a copy of cosca_testbin that is \
             owned by root, mode u+s, on a filesystem NOT mounted nosuid)"
        );
    }
    if line == "R" {
        return Handshake::Root(reader);
    }
    if let Some(pid_str) = line.strip_prefix("P ") {
        let pid: u32 = pid_str.parse().expect("privileged helper reported a non-numeric pid");
        return Handshake::Privileged { pid, sock: reader };
    }
    panic!("unexpected control handshake line: {line:?}");
}

/// The one test that proves issue #61's fix actually works end to end, through the REAL public
/// `Child::kill_tree` path (not a pure helper, not a fault-injection seam) against a REAL mixed
/// process group.
///
/// `#[ignore]`d by default so an ordinary `cargo nextest run` counts it as `skipped`, not a
/// vacuous `ok` — see the module docs' "Gating" section for why, and for the one CI step that
/// runs it with `--run-ignored only` after provisioning `COSCA_TEST_SETUID_HELPER`.
#[test]
#[ignore = "requires COSCA_TEST_SETUID_HELPER (a real setuid-root helper); run with `cargo nextest \
            run --test group_teardown_setuid --run-ignored only` — see this file's module docs"]
fn kill_tree_reports_refused_and_leaves_the_real_setuid_survivor_running() {
    let helper = gated();
    let role = rerun_role(
        std::env::var(RERUN_ENV).ok().as_deref(),
        std::os::unix::process::parent_id(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    // Root may signal anything, so the setuid helper would not be unsignalable and this scenario
    // would not exist. Re-run as the unprivileged caller it is about.
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        // Without this a re-run that is still root would re-execute itself without end.
        assert_eq!(
            role,
            Role::Fresh,
            "the unprivileged re-run is still root: dropping to uid {UNPRIVILEGED} did not take effect"
        );
        return rerun_unprivileged();
    }
    if role == Role::Rerun {
        use std::io::Write as _;
        let mut out = std::io::stdout();
        writeln!(out, "\n{RERAN}")
            .and_then(|()| out.flush())
            .expect("announce the re-run");
    }
    assert!(
        std::path::Path::new(&helper).is_file(),
        "COSCA_TEST_SETUID_HELPER={helper:?} does not point at an existing file"
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();

    let mut cmd = cosca::Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "spawn-grandchild-setuid", &addr, &helper]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn contained root");

    // The pgid-based mechanism specifically — NOT cgroup v2 (whose `cgroup.kill` bypasses the
    // ordinary kill(2) permission check entirely and would not reproduce the bug at all) and NOT
    // Delegated/None. `.contain()`'s cgroup path only activates given a delegated cgroup v2
    // slice, which this lane's ordinary (unprivileged) `cargo nextest run` invocation does not have —
    // asserted, not assumed, exactly like this suite's existing `unix_kill_tree_reaps_the_
    // grandchild` (tests/spawn_io.rs).
    assert_eq!(
        child.containment(),
        cosca::Containment::ProcessGroup,
        "expected the pgid-based ProcessGroup mechanism, got {:?}",
        child.containment()
    );

    // Accept both connections; classify by content, not arrival order (real scheduling gives no
    // ordering guarantee between the root and the grandchild it spawns).
    let mut root_sock = None;
    let mut priv_pid = None;
    let mut priv_sock = None;
    for _ in 0..2 {
        match accept_one(&listener) {
            Handshake::Root(s) => root_sock = Some(s),
            Handshake::Privileged { pid, sock } => {
                priv_pid = Some(pid);
                priv_sock = Some(sock);
            }
        }
    }
    let mut root_sock = root_sock.expect("ordinary root connected");
    let priv_pid = priv_pid.expect("privileged helper connected and reported its pid");
    let priv_sock = priv_sock.expect("privileged helper connected");

    // Independent, pre-teardown confirmation that the helper is genuinely unsignalable by this
    // caller RIGHT NOW — not merely "we expect it will be later". If this is Ok(()), the helper
    // never actually became real-uid 0 and the whole scenario would not exercise the bug; fail
    // loudly rather than let the later assertion pass for the wrong reason.
    assert_eq!(
        probe_kill0(priv_pid),
        Err(Some(libc::EPERM)),
        "the setuid-root helper (pid {priv_pid}) must be confirmed unsignalable (EPERM) by this \
         caller BEFORE teardown — if it is not, provisioning did not achieve real uid 0"
    );

    // The real public path: SIGKILL via killpg, converge on delivering it to every reachable
    // member, and report the group's ACTUAL membership state — not killpg's own lying success.
    let result = child.kill_tree();

    // (1) The teardown reports Err(Containment), not Ok(()).
    match &result {
        Err(cosca::error::Error::Containment { detail }) => {
            assert!(
                detail.contains(&priv_pid.to_string()),
                "Containment error should name the refusing pid {priv_pid}, got: {detail}"
            );
        }
        other => panic!(
            "expected Err(Error::Containment{{..}}) naming the unsignalable pid {priv_pid}, got \
             {other:?} — issue #61's fix reverted: killpg's partial success is being reported as \
             a false Ok"
        ),
    }
    let _ = child.wait(); // reap the (actually dead) root

    // (2) The ordinary member is actually dead: its control socket EOFs (the kernel closed the
    // connection on the process's real exit — a real event, not a liveness poll).
    let mut buf = [0u8; 1];
    let n = root_sock.read(&mut buf).expect("read root control socket");
    assert_eq!(n, 0, "the ordinary group member must have been killed for real");

    // (3) The privileged member is actually STILL alive, and still genuinely unsignalable by
    // this caller — the one assertion no synthetic/pure-function test in this suite can make.
    assert_eq!(
        probe_kill0(priv_pid),
        Err(Some(libc::EPERM)),
        "the setuid-root helper (pid {priv_pid}) must still be alive AND unsignalable (EPERM) \
         after kill_tree() — issue #61's fix reverted: it was silently killed or dropped from \
         the verdict"
    );

    // Cleanup: dropping our end of the privileged helper's control socket closes the
    // connection; the helper (blocked reading it, per `setuid-control-block`) observes EOF and
    // exits on its own — the only way this test can end it, since it is genuinely unkillable by
    // this process. Its new parent (reparented off the killed root) reaps it in due course.
    drop(priv_sock);
}
