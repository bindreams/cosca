//! `COSCA_TEST_ELEVATION_GUI` gates the macOS graphical tier separately: unlike the
//! POSIX tier, it raises an interactive authentication dialog that no CI runner can
//! answer, so it is human-driven only. What CI DOES verify unattended lives in the
//! unit suite (`elevation::macos`), where the crate's own composer is in scope: the
//! two quoting layers driven through the real AppleScript parser and the real
//! /bin/sh with the privilege clause removed, plus an `osacompile` parse of the
//! unmodified elevated script.
//!
//! Live elevation tier — gated behind COSCA_TEST_ELEVATION (cgroup precedent):
//! a TRUE no-op when the var is absent, and FAILS LOUDLY when set but elevation is
//! unavailable. The pure tiers cover all logic unconditionally; only the privilege-gain
//! (and the cross-process controlling-terminal probes) run here.

use std::path::PathBuf;

#[path = "common/mod.rs"]
mod common;

fn gated() -> bool {
    std::env::var_os("COSCA_TEST_ELEVATION").is_some()
}

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

#[cfg(unix)]
#[skuld::test]
fn posix_elevated_child_runs_as_root_and_captures_uid() {
    if !gated() {
        return;
    }
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
fn posix_child_self_detects_elevation() {
    if !gated() {
        return;
    }
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

// UNGATED but `#[cfg(feature = "pty")]`: NON-VACUOUS proof that the probe consults the
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

// UNGATED: setsid detaches the controlling terminal, so the probe must report 0.
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

// GATED: run0 client -> transient-unit kill propagation. The payload holds a socket to this
// test, so its death is EOF on that socket. run0 authenticates via polkit;
// `--no-ask-password` (Auth::NonInteractive) suppresses the prompt.
#[cfg(target_os = "linux")]
#[skuld::test]
fn run0_client_kill_propagates_to_the_transient_unit() {
    use std::io::Read as _;
    use std::os::unix::process::ExitStatusExt as _;

    if !gated() || std::env::var_os("COSCA_TEST_ELEVATION_RUN0").is_none() {
        return; // requires run0 + a polkit-passwordless context that can spawn a transient unit.
    }
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
        .elevation_backend(cosca::elevation::Backend::Run0)
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let child = std::sync::Arc::new(c.spawn().expect("run0 spawn"));

    let mut payload = common::payload::accept_payload(
        listener,
        &nonce,
        common::payload::ExitWatch::custom({
            let child = std::sync::Arc::clone(&child);
            move || format!("{:?}", child.wait())
        }),
    );

    child.kill().expect("kill run0 client");
    let status = child.wait().expect("wait run0 client");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the client was not killed by our SIGKILL (it had already exited): {status:?}"
    );

    // The bound is on run0's own kill propagation, an external event; EOF is the payload dying.
    payload
        .sock
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .expect("set read timeout");
    let mut sink = [0u8; 1];
    match payload.sock.read(&mut sink) {
        Ok(0) => {}
        Ok(n) => panic!("the payload wrote {n} unexpected bytes"),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => panic!(
            "the payload (pid {}) is still alive 30s after the run0 client was killed: kill propagation is broken",
            payload.pid
        ),
        Err(e) => panic!("reading the payload socket failed: {e}"),
    }
}

// GATED: Auth::Stdin feeds the real password to `sudo -S`; the elevated child is root.
#[cfg(unix)]
#[skuld::test]
fn posix_stdin_auth_reaches_root() {
    if !gated() {
        return;
    }
    let pw = std::env::var("COSCA_TEST_ELEVATION_PASSWORD")
        .expect("COSCA_TEST_ELEVATION_PASSWORD must hold the sudo password for the Auth::Stdin live test");
    let mut c = cosca::Command::new();
    c.args(["id", "-u"])
        .elevation_backend(cosca::elevation::Backend::Sudo)
        .elevation_auth(cosca::elevation::Auth::Stdin(cosca::elevation::Secret::new(pw)));
    let out = c.output().expect("stdin-auth elevated output");
    assert!(out.status.success(), "sudo -S id failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "Auth::Stdin child was not root"
    );
}

// GATED: Auth::Askpass delivers the password via a trivial SUDO_ASKPASS helper script.
#[cfg(unix)]
#[skuld::test]
fn posix_askpass_auth_reaches_root() {
    if !gated() {
        return;
    }
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
    c.args(["id", "-u"])
        .elevation_backend(cosca::elevation::Backend::Sudo)
        .elevation_auth(cosca::elevation::Auth::Askpass(script.clone()));
    let out = c.output().expect("askpass elevated output");
    assert!(out.status.success(), "sudo -A id failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "Auth::Askpass child was not root"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// GATED (POSIX): kill() on a non-contained elevated long-lived child is the typed Unkillable, with
// the payload still alive, and dropping the child RETURNS (no hang).
//
// Waiting for the payload's readiness line means the program runs. Dropping the socket at the end
// releases the payload without needing a privileged kill.
#[cfg(unix)]
#[skuld::test]
fn posix_uncontained_elevated_child_is_unkillable_and_drop_does_not_hang() {
    if !gated() {
        return;
    }
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

// GATED: the allowed (already-elevated) spawn path reports elevation() honestly.
#[cfg(unix)]
#[skuld::test]
fn already_elevated_inherit_spawn_reports_already_elevated() {
    if !gated() || !cosca::elevation::is_elevated() {
        return; // deterministic only when the gated runner is itself elevated.
    }
    let mut c = cosca::Command::new();
    c.args(["true"]).elevation_auth(cosca::elevation::Auth::NonInteractive);
    let child = c.spawn().expect("spawn");
    assert_eq!(
        child.elevation().expect("elevation requested → Some").via,
        cosca::elevation::ElevatedVia::AlreadyElevated,
    );
    let _ = child.wait();
}

#[cfg(windows)]
#[skuld::test]
fn windows_elevated_child_writes_admin_marker() {
    if !gated() {
        return;
    }
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
async fn async_posix_elevated_child_runs_as_root() {
    if !gated() {
        return;
    }
    let mut c = cosca::tokio::Command::new();
    c.args(["id", "-u"])
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let out = c.output().await.expect("async elevated output");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
}

// GATED (Windows): a non-contained runas child a medium parent cannot
// PROCESS_TERMINATE returns the typed Unkillable, and Drop does not hang.
#[cfg(windows)]
#[skuld::test]
fn windows_elevated_child_is_unkillable_and_drop_does_not_hang() {
    if !gated() {
        return;
    }
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
    let payload = common::payload::accept_live_payload(listener, &nonce, common::payload::ExitWatch::Unobservable);
    match child.kill() {
        Err(cosca::error::Error::Elevation { kind, .. }) => {
            assert_eq!(kind, cosca::error::ElevationErrorKind::Unkillable);
        }
        // If the CI context runs the parent elevated too, the child is killable — accept Ok.
        Ok(()) => {}
        other => panic!("expected Unkillable or Ok, got {other:?}"),
    }
    // The payload is alive and `kill()` could not end it, so a `Drop` that waited for the child
    // would block here. Releasing afterwards ends a child that `kill()` could not.
    drop(child);
    payload.release();
}

// MANUAL-TIER async Windows elevation (4c785f26): mirrors the sync marker test. Runs only
// under the same gated, UAC-auto-approve manual tier documented in issue #9.
#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn async_windows_elevated_child_writes_admin_marker() {
    if !gated() {
        return;
    }
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

// GATED (Windows, tokio): the async twin of the sync unkillable/no-hang test. A runas child a
// medium-integrity parent cannot PROCESS_TERMINATE must surface the typed Unkillable from kill()
// (never a false Ok), and async Drop must not block — locking the sync/async parity of the
// runas-aware kill path.
#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn async_windows_elevated_child_is_unkillable_and_drop_does_not_hang() {
    if !gated() {
        return;
    }
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
    let payload = tokio::select! {
        payload = done_rx => payload.expect("accept thread ended without a payload"),
        status = child.wait() => panic!("the client exited ({status:?}) before its payload reported ready"),
    };
    drop(stop_tx);
    match child.kill() {
        Err(cosca::error::Error::Elevation { kind, .. }) => {
            assert_eq!(kind, cosca::error::ElevationErrorKind::Unkillable);
        }
        // If the manual runner is itself elevated, the child is killable — accept Ok.
        Ok(()) => {}
        other => panic!("expected Unkillable or Ok, got {other:?}"),
    }
    drop(child); // must return promptly (non-blocking async teardown)
    payload.release();
}

// GATED behind COSCA_TEST_ELEVATION_GUI: a TRUE no-op without it, and loud when set.
// This is the ONLY test that raises the authentication dialog, so it can never run
// unattended — a human must be at the keyboard to approve it. It is here so the path
// is verifiable at all, not so CI can verify it.
#[cfg(target_os = "macos")]
#[skuld::test]
fn gui_elevated_child_runs_as_root() {
    // Already root means the planner short-circuits to RunAsIs and reports
    // AlreadyElevated: osascript never runs, so the assertions below would fail on
    // a defect that does not exist. Same guard the POSIX gated tests use.
    if std::env::var_os("COSCA_TEST_ELEVATION_GUI").is_none() || cosca::elevation::is_elevated() {
        return;
    }
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

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
