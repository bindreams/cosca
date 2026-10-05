//! Live elevation tier: the `ELEVATION` group (`src/test_groups.rs`, principle 10). It is on unless
//! `COSCA_TEST_ELEVATION=0`, it needs `COSCA_TEST_ELEVATION_CONSENT=1`, and `SKULD_LABELS=elevation`
//! selects it. Run where elevation cannot work, a test fails; none returns early.
//!
//! The ELEVATION lanes in `ci.yaml` set the machine up: `sudo` (passwords from
//! `COSCA_TEST_ELEVATION_PASSWORD`), `pkexec` and, on macOS, `osascript`, through
//! `.github/scripts/unattended-gui-elevation.py`, which approves the graphical tiers
//! (`gui_elevated_child_runs_as_root`, `pkexec_gui_auth_reaches_root`) without a person; `doas` on Linux; and
//! on Windows an unelevated administrator, with `COSCA_TEST_ELEVATION_MARKER_DIR` a directory only an
//! administrator can write. The pure tiers cover all logic unconditionally; only the privilege gain runs here.
//!
//! Outside the group: the controlling-terminal probes below, which need no elevation, and the `group` module,
//! whose tests carry no label, so the elevation lanes deselect them. They run in the main Test lanes, where
//! they re-exec this binary on one live test under chosen variables and never run its body.

use std::path::PathBuf;

#[path = "common/mod.rs"]
mod common;

use common::test_groups::{elevation, Group};

fn testbin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.push(if cfg!(windows) {
        "cosca_testbin.exe"
    } else {
        "cosca_testbin"
    });
    p
}

/// The precondition of every test that elevates: the test process itself is not. Run as root, elevation
/// short-circuits to "already elevated" and the test would pass without elevating anything.
fn require_unelevated() {
    assert!(
        !cosca::elevation::is_elevated(),
        "this test must run unelevated: as an already-elevated caller it would pass without elevating"
    );
}

#[cfg(unix)]
#[skuld::test]
fn posix_elevated_child_runs_as_root_and_captures_uid(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let mut c = cosca::Command::new();
    c.args(["id", "-u"])
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let out = c.output().expect("elevated output");
    assert!(out.status.success(), "elevated `id -u` failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "elevated child was not root"
    );
}

#[cfg(unix)]
#[skuld::test]
fn posix_child_self_detects_elevation(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let exe = testbin();
    let exe_str = exe.clone().into_os_string();
    let mut c = cosca::Command::new();
    // executable() set AND argv[0] == the exe path, so no distinct-argv0 rejection.
    c.executable(&exe)
        .args([exe_str, "is-elevated-report".into()])
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let s = c.read().expect("read");
    assert_eq!(s.trim(), "1", "elevated testbin did not self-detect elevation");
}

// Outside the group, `#[cfg(feature = "pty")]`: NON-VACUOUS proof that the probe consults the
// session's controlling terminal (/dev/tty), not isatty(STDIN). Under the test runner
// there is no controlling terminal, so we ALLOCATE a real pty and have the child acquire it
// as its controlling terminal (setsid + TIOCSCTTY on the inherited slave fd 3) WHILE its
// stdin is /dev/null. The probe must then report `1` — impossible for an isatty(STDIN) impl,
// since stdin is not a tty. Gated to the `pty` CI leg so it never ships a CI-vacuous assert.
#[cfg(all(target_os = "linux", feature = "pty"))]
#[skuld::test]
fn controlling_terminal_probe_consults_ctty_not_stdin() {
    use std::os::fd::{AsFd, OwnedFd};

    fn is_cloexec(fd: &impl AsFd) -> bool {
        let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).expect("F_GETFD failed");
        flags & libc::FD_CLOEXEC != 0
    }

    // A real pty pair, close-on-exec: tests run on parallel threads, and a child spawned by another
    // test must not inherit either end. Keep the master alive for the child's session lifetime.
    let master =
        nix::pty::posix_openpt(nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NOCTTY | nix::fcntl::OFlag::O_CLOEXEC)
            .expect("posix_openpt");
    nix::pty::grantpt(&master).expect("grantpt");
    nix::pty::unlockpt(&master).expect("unlockpt");
    let master: OwnedFd = master.into();
    // TIOCGPTPEER takes the slave from the master fd, not a devpts path lookup (ptsname + open):
    // a path can resolve to the wrong devpts instance in a mount namespace (Linux 4.13+).
    let slave: OwnedFd = rustix::pty::ioctl_tiocgptpeer(
        &master,
        rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY | rustix::pty::OpenptFlags::CLOEXEC,
    )
    .unwrap_or_else(|e| panic!("TIOCGPTPEER: {e}"));
    assert!(is_cloexec(&master));
    assert!(is_cloexec(&slave));
    let slave_file = std::fs::File::from(slave);

    let exe = testbin();
    let mut c = cosca::Command::new();
    c.args([exe.into_os_string(), "acquire-ctty-and-probe".into()]);
    // stdin = /dev/null: a buggy isatty(STDIN) probe would answer 0 here.
    c.stdin(cosca::Stdio::null()).unwrap();
    c.stdout(cosca::Stdio::pipe()).unwrap();
    // Pass the pty slave as fd 3; the child acquires it as its controlling terminal.
    c.fd(3, cosca::Stdio::from_file(slave_file)).unwrap();
    let mut ch = c.spawn().expect("spawn");
    let out = ch.communicate(None).expect("communicate");
    let _ = &master;
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "1",
        "probe must see the controlling terminal even with stdin=/dev/null",
    );
}

// Outside the group: setsid detaches the controlling terminal, so the probe must report 0.
// Linux-only (macOS ships no `setsid` binary; the probe itself is tested cross-platform
// in the unit suite).
#[cfg(target_os = "linux")]
#[skuld::test]
fn controlling_terminal_probe_is_false_after_setsid() {
    let exe = testbin();
    let mut c = cosca::Command::new();
    c.args(["setsid".into(), exe.into_os_string(), "controlling-terminal".into()]);
    let s = c.read().expect("read setsid child output");
    assert_eq!(
        s.trim(),
        "0",
        "controlling_terminal_present() must be false after setsid"
    );
}

// Auth::Stdin feeds the real password to `sudo -S`; the elevated child is root. It runs `whoami`, the one
// command the lane makes `sudo` ask a password for.
#[cfg(unix)]
#[skuld::test]
fn posix_stdin_auth_reaches_root(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let pw = std::env::var("COSCA_TEST_ELEVATION_PASSWORD")
        .expect("COSCA_TEST_ELEVATION_PASSWORD must hold the sudo password for the Auth::Stdin live test");
    let mut c = cosca::Command::new();
    c.args(["whoami"])
        .elevation_backend(cosca::elevation::Backend::Sudo)
        .elevation_auth(cosca::elevation::Auth::Stdin(cosca::elevation::Secret::new(pw)));
    let out = c.output().expect("stdin-auth elevated output");
    assert!(out.status.success(), "sudo -S whoami failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "root",
        "Auth::Stdin child was not root"
    );
}

// Auth::Askpass delivers the password via a trivial SUDO_ASKPASS helper script.
#[cfg(unix)]
#[skuld::test]
fn posix_askpass_auth_reaches_root(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let pw = std::env::var("COSCA_TEST_ELEVATION_PASSWORD")
        .expect("COSCA_TEST_ELEVATION_PASSWORD must hold the sudo password for the Auth::Askpass live test");
    // A minimal askpass script that echoes the password.
    let dir = std::env::temp_dir().join(format!("askpass-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("askpass.sh");
    std::fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' '{pw}'\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut c = cosca::Command::new();
    c.args(["whoami"])
        .elevation_backend(cosca::elevation::Backend::Sudo)
        .elevation_auth(cosca::elevation::Auth::Askpass(script.clone()));
    let out = c.output().expect("askpass elevated output");
    assert!(out.status.success(), "sudo -A whoami failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "root",
        "Auth::Askpass child was not root"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// (POSIX) kill() on a non-contained elevated long-lived child is the typed Unkillable, with
// the payload still alive, and dropping the child RETURNS (no hang).
//
// Waiting for the payload's readiness line means the program runs. Dropping the socket at the end
// releases the payload without needing a privileged kill.
#[cfg(unix)]
#[skuld::test]
fn posix_uncontained_elevated_child_is_unkillable_and_drop_does_not_hang(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let nonce = common::payload::fresh_nonce();
    let exe = testbin();
    let mut c = cosca::Command::new();
    c.executable(&exe)
        .args([
            exe.clone().into_os_string(),
            "block-on-socket".into(),
            addr.into(),
            nonce.clone().into(),
        ])
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let child = c.spawn().expect("elevated block-on-socket");
    // Watched by pid, not through `child`: this test owns the only `Child`, so the `drop` below
    // is the `Drop` under test and not a reference count going down.
    let mut payload =
        common::payload::accept_live_payload(listener, &nonce, common::payload::ExitWatch::Process(child.id().pid()));

    // sudo and doas leave this process tracking a front: sudo itself, which outlives the root
    // program it launched (a kill would orphan it), or, with direct exec, the root program, whose
    // kill is refused. Either way kill() sends nothing and answers the typed `Unkillable`; an `Ok`
    // here is a false kill. The payload is checked first, so a false `Ok` reads as one.
    let killed = child.kill();
    payload.assert_blocked();
    assert!(
        matches!(
            killed,
            Err(cosca::error::Error::Elevation {
                kind: cosca::error::ElevationErrorKind::Unkillable,
                ..
            })
        ),
        "kill() of an uncontained wrapper-elevated child must be the typed Unkillable, got {killed:?}"
    );
    // The payload is alive and `kill()` could not reap it, so a `Drop` that waited for the child
    // would block here until the test ended.
    drop(child);
    payload.release();
}

// The allowed (already-elevated) spawn path reports elevation() honestly. The spawn under test is made
// by an elevated testbin, so it holds whoever runs this test.
#[cfg(unix)]
#[skuld::test]
fn already_elevated_inherit_spawn_reports_already_elevated(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let exe = testbin();
    let mut c = cosca::Command::new();
    c.executable(&exe)
        .args([exe.clone().into_os_string(), "elevated-spawn-report".into()])
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let reported = c.read().expect("read the elevated testbin's report");
    assert_eq!(reported.trim(), "AlreadyElevated");
}

#[cfg(windows)]
#[skuld::test]
fn windows_elevated_child_writes_admin_marker(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let dir = std::env::var_os("COSCA_TEST_ELEVATION_MARKER_DIR")
        .map(PathBuf::from)
        .expect("COSCA_TEST_ELEVATION_MARKER_DIR must point at an admin-only writable dir");
    let marker = dir.join(format!("elev-{}.marker", std::process::id()));
    let exe = testbin();
    let mut c = cosca::Command::new();
    c.executable(&exe).args([
        exe.clone().into_os_string(),
        "write-marker".into(),
        marker.clone().into_os_string(),
    ]);
    c.elevate();
    let child = c.spawn().expect("runas spawn");
    // Honest report: WindowsUac + OwnConsole (never a faked shared stream).
    let report = child.elevation().unwrap();
    assert_eq!(report.via, cosca::elevation::ElevatedVia::WindowsUac);
    assert_eq!(report.stdio, cosca::elevation::ElevatedStdio::OwnConsole);
    let status = child.wait().expect("wait");
    assert!(status.success(), "elevated marker write failed: {status:?}");
    assert!(marker.exists(), "elevated child did not create the admin-only marker");
    let _ = std::fs::remove_file(&marker);
}

#[cfg(all(unix, feature = "tokio"))]
#[skuld::test]
async fn async_posix_elevated_child_runs_as_root(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let mut c = cosca::tokio::Command::new();
    c.args(["id", "-u"])
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let out = c.output().await.expect("async elevated output");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
}

// `Backend::Pkexec` with `Auth::Gui`: the lane's polkit rule authorizes the user, so no agent is needed.
#[cfg(target_os = "linux")]
#[skuld::test]
fn pkexec_gui_auth_reaches_root(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let mut c = cosca::Command::new();
    c.args(["/usr/bin/id", "-u"])
        .elevation_backend(cosca::elevation::Backend::Pkexec)
        .elevation_auth(cosca::elevation::Auth::Gui);
    let out = c.output().expect("pkexec elevated output");
    assert!(out.status.success(), "pkexec id -u failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "the pkexec child was not root"
    );
}

// `Backend::Doas`: the lane's `doas.conf` lets the user run anything as root without a password.
#[cfg(target_os = "linux")]
#[skuld::test]
fn doas_non_interactive_auth_reaches_root(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let mut c = cosca::Command::new();
    c.args(["id", "-u"])
        .elevation_backend(cosca::elevation::Backend::Doas)
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let out = c.output().expect("doas elevated output");
    assert!(out.status.success(), "doas id -u failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "the doas child was not root"
    );
}

/// A `runas` child's `kill()` against what happened to its payload. Where the caller may terminate the child (the
/// CI lane's account owns its elevated child; measured: `kill()` is `Ok` and the payload is gone), `Ok` is the truth and
/// the payload must be dead, seen as EOF or a reset on its socket. Where it may not, the answer is the typed
/// `Unkillable` and the payload is still alive. `Ok` with a live payload is a false kill. The 20 s is the failure bound
/// on the OS ending a process: shorter than nextest's 60 s bound on the whole test, so a false kill is this panic.
///
/// `COSCA_TEST_ELEVATION_EXPECT_KILL` pins the lane's outcome, `ok` or `unkillable`, so a regression to the other one
/// fails; without it either truthful outcome passes.
#[cfg(windows)]
fn assert_kill_matches_payload(killed: &Result<(), cosca::error::Error>, payload: &mut common::payload::Payload) {
    use std::io::Read as _;
    let expected = std::env::var("COSCA_TEST_ELEVATION_EXPECT_KILL").ok();
    match (killed, expected.as_deref()) {
        (
            Err(cosca::error::Error::Elevation {
                kind: cosca::error::ElevationErrorKind::Unkillable,
                ..
            }),
            None | Some("unkillable"),
        ) => payload.assert_blocked(),
        (Ok(()), None | Some("ok")) => {
            payload
                .sock
                .set_read_timeout(Some(std::time::Duration::from_secs(20)))
                .expect("set read timeout");
            let mut sink = [0u8; 1];
            match payload.sock.read(&mut sink) {
                Ok(0) => {}
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!(
                    "kill() returned Ok but the payload (pid {}) is still alive: {other:?}",
                    payload.pid
                ),
            }
        }
        (other, expected) => panic!(
            "kill() answered {other:?}, which COSCA_TEST_ELEVATION_EXPECT_KILL={expected:?} does not allow (unset: `Ok` with a dead payload, or the typed Unkillable)"
        ),
    }
}

// (Windows) `kill()` on a non-contained runas child reports what happened to it (see
// `assert_kill_matches_payload`), and Drop does not hang.
#[cfg(windows)]
#[skuld::test]
fn windows_kill_of_an_elevated_child_reports_what_happened(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let nonce = common::payload::fresh_nonce();
    let exe = testbin();
    let mut c = cosca::Command::new();
    c.executable(&exe)
        .args([
            exe.clone().into_os_string(),
            "block-on-socket".into(),
            addr.into(),
            nonce.clone().into(),
        ])
        .elevate();
    let child = c.spawn().expect("runas spawn");
    // A medium-integrity parent cannot open the UAC-elevated child by pid, and `Child` exposes no
    // handle to wait on, so its early exit cannot be watched; the `drop` below is the only owner.
    let mut payload = common::payload::accept_live_payload(listener, &nonce, common::payload::ExitWatch::Unobservable);
    let killed = child.kill();
    assert_kill_matches_payload(&killed, &mut payload);
    // On the lane `kill()` succeeded and the payload is gone. A child that cannot be terminated is covered at the
    // unit level: `runas_teardown_on_drop_never_blocks_on_an_unterminable_child` (windows_raw/proc_tests.rs).
    drop(child);
    payload.release();
}

// The async twin of the Windows marker test.
#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn async_windows_elevated_child_writes_admin_marker(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let dir = std::env::var_os("COSCA_TEST_ELEVATION_MARKER_DIR")
        .map(PathBuf::from)
        .expect("COSCA_TEST_ELEVATION_MARKER_DIR must point at an admin-only writable dir");
    let marker = dir.join(format!("elev-async-{}.marker", std::process::id()));
    let exe = testbin();
    let mut c = cosca::tokio::Command::new();
    c.executable(&exe).args([
        exe.clone().into_os_string(),
        "write-marker".into(),
        marker.clone().into_os_string(),
    ]);
    c.elevate();
    let mut child = c.spawn().expect("async runas spawn");
    let report = child.elevation().unwrap();
    assert_eq!(report.via, cosca::elevation::ElevatedVia::WindowsUac);
    assert_eq!(report.stdio, cosca::elevation::ElevatedStdio::OwnConsole);
    let status = child.wait().await.expect("wait");
    assert!(status.success(), "async elevated marker write failed: {status:?}");
    assert!(
        marker.exists(),
        "async elevated child did not create the admin-only marker"
    );
    let _ = std::fs::remove_file(&marker);
}

// (Windows, tokio) the async twin of the sync kill test: the same outcomes from kill(), and async Drop must
// not block, locking the sync/async parity of the runas-aware kill path.
#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn async_windows_kill_of_an_elevated_child_reports_what_happened(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let nonce = common::payload::fresh_nonce();
    let exe = testbin();
    let mut c = cosca::tokio::Command::new();
    c.executable(&exe)
        .args([
            exe.clone().into_os_string(),
            "block-on-socket".into(),
            addr.into(),
            nonce.clone().into(),
        ])
        .elevate();
    let mut child = c.spawn().expect("async runas spawn");

    // `Child::wait` is async and `&mut`, so the race is `select!` here and the helper's exit
    // arm just parks until this test stops watching.
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn({
        let nonce = nonce.clone();
        move || {
            let payload = common::payload::accept_live_payload(
                listener,
                &nonce,
                common::payload::ExitWatch::custom(move || {
                    let _ = stop_rx.recv();
                    "the test stopped watching".into()
                }),
            );
            let _ = done_tx.send(payload);
        }
    });
    let mut payload = tokio::select! {
        payload = done_rx => payload.expect("accept thread ended without a payload"),
        status = child.wait() => panic!("the client exited ({status:?}) before its payload reported ready"),
    };
    drop(stop_tx);
    let killed = child.kill();
    assert_kill_matches_payload(&killed, &mut payload);
    drop(child); // must return promptly; the unterminable case is a unit test (see the sync twin)
    payload.release();
}

// The graphical tier: the only test that raises the authentication dialog. It runs only where
// `.github/scripts/unattended-gui-elevation.py` has set the admin right to `allow`; elsewhere osascript
// hangs on the dialog (measured on a hosted runner). Like the others it fails without consent and lists
// as ignored under `COSCA_TEST_ELEVATION=0`.
#[cfg(target_os = "macos")]
#[skuld::test]
fn gui_elevated_child_runs_as_root(#[fixture(elevation)] _group: &Group) {
    require_unelevated();
    let mut c = cosca::Command::new();
    c.args(["/usr/bin/id", "-u"])
        .elevation_auth(cosca::elevation::Auth::Gui);
    c.stdin(cosca::Stdio::null()).unwrap();
    c.stdout(cosca::Stdio::pipe()).unwrap();
    let mut child = c.spawn().expect("gui-elevated spawn");
    let report = child.elevation().expect("an elevation report");
    assert_eq!(report.via, cosca::ElevatedVia::MacosOsascript);
    assert_eq!(report.stdio, cosca::ElevatedStdio::OsascriptRelay);
    // NOT dropped or killed before this returns: killing the front-end early would
    // leave the root payload running and its outcome unobservable.
    let out = child.communicate(None).expect("communicate");
    assert!(out.status.success(), "the elevated `id -u` failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "the relayed stdout must show the elevated child ran as root"
    );
}

// The group rules, as the live tests above see them: a re-exec of this binary on one live test,
// under chosen group variables. That test's body never runs in any of these, so they are safe on any
// host. They carry no label: the main Test lanes run them (the elevation lanes select by label and skip them).
mod group {
    use super::common::test_reexec::{command, suite_outcome, with_json_events, SuiteOutcome, NOCAPTURE};

    #[cfg(unix)]
    const LIVE_TEST: &str = "posix_elevated_child_runs_as_root_and_captures_uid";
    #[cfg(windows)]
    const LIVE_TEST: &str = "windows_elevated_child_writes_admin_marker";

    /// Re-execs this binary on exactly [`LIVE_TEST`] with the group's variables set as given (`None` removes them).
    fn run_live_test(
        extra: &[&str],
        group: Option<&str>,
        consent: Option<&str>,
        labels: Option<&str>,
    ) -> (SuiteOutcome, bool, String) {
        let mut cmd = command(std::env::current_exe().expect("current_exe"));
        cmd.args(["--test-threads=1", "--exact", LIVE_TEST, NOCAPTURE]);
        cmd.args(extra);
        with_json_events(&mut cmd);
        for (var, value) in [
            ("COSCA_TEST_ELEVATION", group),
            ("COSCA_TEST_ELEVATION_CONSENT", consent),
            ("SKULD_LABELS", labels),
        ] {
            match value {
                Some(value) => cmd.env(var, value),
                None => cmd.env_remove(var),
            };
        }
        let output = super::common::output_locked(&mut cmd).expect("re-exec this test binary");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let outcome = suite_outcome(&output.stdout).expect("the child reports its suite");
        (outcome, output.status.success(), stdout)
    }

    /// The `failed` event of [`LIVE_TEST`] itself: only it carries the fixture's refusal (the whole output
    /// cannot tell, as skuld prints the unavailable-test list after every run).
    fn failure_message(stdout: &str) -> String {
        let failure = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| event["type"] == "test" && event["event"] == "failed" && event["name"] == LIVE_TEST)
            .unwrap_or_else(|| panic!("no `failed` event for the test: {stdout}"));
        failure["stdout"].as_str().unwrap_or_default().to_owned()
    }

    /// Mutant: the group's `requires` never fails, so `=0` runs the test.
    #[skuld::test]
    fn group_zero_reports_ignored() {
        let (outcome, success, stdout) = run_live_test(&[], Some("0"), None, None);
        let expected = SuiteOutcome {
            test_count: 1,
            passed: 0,
            failed: 0,
            ignored: 1,
        };
        assert_eq!(outcome, expected, "{stdout}");
        assert!(success, "{stdout}");
    }

    /// Mutant: the live test returns early again, or the setup does not check consent.
    #[skuld::test]
    fn unset_consent_fails() {
        let (outcome, success, stdout) = run_live_test(&[], None, None, None);
        assert_eq!((outcome.test_count, outcome.failed), (1, 1), "{stdout}");
        assert_eq!(outcome.passed + outcome.ignored, 0, "{stdout}");
        assert!(!success, "{stdout}");
        assert!(
            failure_message(&stdout).contains("COSCA_TEST_ELEVATION_CONSENT=1"),
            "{stdout}"
        );
    }

    /// Mutant: any non-empty consent counts.
    #[skuld::test]
    fn consent_other_than_1_fails() {
        let (outcome, success, stdout) = run_live_test(&[], None, Some("yes"), None);
        assert_eq!((outcome.test_count, outcome.failed), (1, 1), "{stdout}");
        assert_eq!(outcome.passed + outcome.ignored, 0, "{stdout}");
        assert!(!success, "{stdout}");
        assert!(
            failure_message(&stdout).contains("COSCA_TEST_ELEVATION_CONSENT=1"),
            "{stdout}"
        );
    }

    /// Mutant: the setup grants a group that is off, so `--ignored` runs the body.
    #[skuld::test]
    fn group_zero_never_runs_the_body_under_run_ignored() {
        let (outcome, success, stdout) = run_live_test(&["--ignored"], Some("0"), None, None);
        assert_eq!((outcome.test_count, outcome.failed), (1, 1), "{stdout}");
        assert_eq!((outcome.passed, outcome.ignored), (0, 0), "{stdout}");
        assert!(!success, "{stdout}");
        // A body that ran would fail too (unprivileged, or not consented), so `failed` alone proves nothing.
        assert!(
            failure_message(&stdout).contains("setup failed: COSCA_TEST_ELEVATION=0"),
            "{stdout}"
        );
    }

    /// Mutant: the group's fixture carries no label, so `SKULD_LABELS=elevation` selects none of its tests.
    #[skuld::test]
    fn the_group_label_selects_its_tests() {
        let (outcome, _, stdout) = run_live_test(&[], Some("0"), None, Some("elevation"));
        assert_eq!(outcome.test_count, 1, "{stdout}");
        let (outcome, _, stdout) = run_live_test(&[], Some("0"), None, Some("!elevation"));
        assert_eq!(outcome.test_count, 0, "{stdout}");
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
