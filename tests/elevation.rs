//! Live elevation tier — gated behind SUBPROCESS_TEST_ELEVATION (cgroup precedent):
//! a TRUE no-op when the var is absent, and FAILS LOUDLY when set but elevation is
//! unavailable. The pure tiers cover all logic unconditionally; only the privilege-gain
//! (and the cross-process controlling-terminal probes) run here.

use std::path::PathBuf;

fn gated() -> bool {
    std::env::var_os("SUBPROCESS_TEST_ELEVATION").is_some()
}

fn testbin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.push(if cfg!(windows) {
        "subprocess_testbin.exe"
    } else {
        "subprocess_testbin"
    });
    p
}

#[cfg(unix)]
#[test]
fn posix_elevated_child_runs_as_root_and_captures_uid() {
    if !gated() {
        return;
    }
    let mut c = subprocess::Command::new();
    c.args(["id", "-u"])
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let out = c.output().expect("elevated output");
    assert!(out.status.success(), "elevated `id -u` failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "elevated child was not root"
    );
}

#[cfg(unix)]
#[test]
fn posix_child_self_detects_elevation() {
    if !gated() {
        return;
    }
    let exe = testbin();
    let exe_str = exe.clone().into_os_string();
    let mut c = subprocess::Command::new();
    // executable() set AND argv[0] == the exe path, so no distinct-argv0 rejection.
    c.executable(&exe)
        .args([exe_str, "is-elevated-report".into()])
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let s = c.read().expect("read");
    assert_eq!(s.trim(), "1", "elevated testbin did not self-detect elevation");
}

// UNGATED but `#[cfg(feature = "pty")]`: NON-VACUOUS proof that the probe consults the
// session's controlling terminal (/dev/tty), not isatty(STDIN). Under a plain `cargo test`
// there is no controlling terminal, so we ALLOCATE a real pty and have the child acquire it
// as its controlling terminal (setsid + TIOCSCTTY on the inherited slave fd 3) WHILE its
// stdin is /dev/null. The probe must then report `1` — impossible for an isatty(STDIN) impl,
// since stdin is not a tty. Gated to the `pty` CI leg so it never ships a CI-vacuous assert.
#[cfg(all(target_os = "linux", feature = "pty"))]
#[test]
fn controlling_terminal_probe_consults_ctty_not_stdin() {
    use std::os::fd::{AsRawFd, OwnedFd};
    // A real pty pair. Keep the master alive for the child's session lifetime.
    let pty = nix::pty::openpty(None, None).expect("openpty");
    let master: OwnedFd = pty.master;
    let slave: OwnedFd = pty.slave;
    let slave_file = std::fs::File::from(slave);

    let exe = testbin();
    let mut c = subprocess::Command::new();
    c.args([exe.into_os_string(), "acquire-ctty-and-probe".into()]);
    // stdin = /dev/null: a buggy isatty(STDIN) probe would answer 0 here.
    c.stdin(subprocess::Stdio::null()).unwrap();
    c.stdout(subprocess::Stdio::pipe()).unwrap();
    // Pass the pty slave as fd 3; the child acquires it as its controlling terminal.
    c.fd(3, subprocess::Stdio::from_file(slave_file)).unwrap();
    let mut ch = c.spawn().expect("spawn");
    let out = ch.communicate(None).expect("communicate");
    let _ = master.as_raw_fd(); // keep master owned until here
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
#[test]
fn controlling_terminal_probe_is_false_after_setsid() {
    let exe = testbin();
    let mut c = subprocess::Command::new();
    c.args(["setsid".into(), exe.into_os_string(), "controlling-terminal".into()]);
    let s = c.read().expect("read setsid child output");
    assert_eq!(
        s.trim(),
        "0",
        "controlling_terminal_present() must be false after setsid"
    );
}

// GATED: run0 client -> transient-unit kill propagation. The client is ALWAYS reaped by
// wait(), so that proves nothing; instead the elevated PAYLOAD writes its own pid to a
// file, and after killing the client we assert THAT (the transient-unit process) is gone.
// run0 auths via polkit; --no-ask-password (Auth::NonInteractive) suppresses the prompt
// and fails loud without a polkit rule (verified: it does not silently hang), so an
// unattended run needs a passwordless polkit rule for the run0 action.
#[cfg(target_os = "linux")]
#[test]
fn run0_client_kill_propagates_to_the_transient_unit() {
    if !gated() || std::env::var_os("SUBPROCESS_TEST_ELEVATION_RUN0").is_none() {
        return; // requires run0 + a polkit-passwordless context that can spawn a transient unit.
    }
    let pidfile = std::env::temp_dir().join(format!("run0-payload-{}.pid", std::process::id()));
    let _ = std::fs::remove_file(&pidfile);
    let exe = testbin();
    let mut c = subprocess::Command::new();
    c.executable(&exe)
        .args([
            exe.clone().into_os_string(),
            "write-pid-then-sleep".into(),
            pidfile.clone().into_os_string(),
        ])
        .elevation_backend(subprocess::elevation::Backend::Run0)
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let child = c.spawn().expect("run0 spawn");

    // Wait for the payload to publish its pid on a real event (its file appears), not a timer.
    let payload_pid: u32 = loop {
        if let Ok(s) = std::fs::read_to_string(&pidfile) {
            if let Ok(pid) = s.trim().parse() {
                break pid;
            }
        }
        std::thread::yield_now();
    };
    assert!(pid_is_alive(payload_pid), "payload should be running before the kill");
    child.kill().expect("kill run0 client");
    child.wait().expect("wait run0 client");
    // The transient-unit payload must be gone — waitpid/kill(0) on its pid fails (ESRCH).
    // Poll on the real teardown event; if propagation is broken this loop exposes it.
    while pid_is_alive(payload_pid) {
        std::thread::yield_now();
    }
    let _ = std::fs::remove_file(&pidfile);
}

/// `kill(pid, 0)` performs only the existence/permission check, sending nothing. Success
/// means the pid is live (or a zombie we could signal). EPERM ALSO means alive: an
/// unprivileged parent probing a ROOT process gets EPERM from the permission check itself,
/// not ESRCH — so treating EPERM as "dead" would misreport a live root payload. Only ESRCH
/// (or any other errno) means the pid is actually gone.
#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    // SAFETY: signal 0 performs only the existence/permission check, sends nothing.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error().raw_os_error();
    err == Some(libc::EPERM) // ESRCH (or anything else) => not alive
}

// GATED: Auth::Stdin feeds the real password to `sudo -S`; the elevated child is root.
#[cfg(unix)]
#[test]
fn posix_stdin_auth_reaches_root() {
    if !gated() {
        return;
    }
    let pw = std::env::var("SUBPROCESS_TEST_ELEVATION_PASSWORD")
        .expect("SUBPROCESS_TEST_ELEVATION_PASSWORD must hold the sudo password for the Auth::Stdin live test");
    let mut c = subprocess::Command::new();
    c.args(["id", "-u"])
        .elevation_backend(subprocess::elevation::Backend::Sudo)
        .elevation_auth(subprocess::elevation::Auth::Stdin(subprocess::elevation::Secret::new(
            pw,
        )));
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
#[test]
fn posix_askpass_auth_reaches_root() {
    if !gated() {
        return;
    }
    let pw = std::env::var("SUBPROCESS_TEST_ELEVATION_PASSWORD")
        .expect("SUBPROCESS_TEST_ELEVATION_PASSWORD must hold the sudo password for the Auth::Askpass live test");
    // A minimal askpass script that echoes the password.
    let dir = std::env::temp_dir().join(format!("askpass-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("askpass.sh");
    std::fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' '{pw}'\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut c = subprocess::Command::new();
    c.args(["id", "-u"])
        .elevation_backend(subprocess::elevation::Backend::Sudo)
        .elevation_auth(subprocess::elevation::Auth::Askpass(script.clone()));
    let out = c.output().expect("askpass elevated output");
    assert!(out.status.success(), "sudo -A id failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "0",
        "Auth::Askpass child was not root"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// GATED (POSIX): dropping a non-contained elevated long-lived child must
// RETURN (no hang), and kill() on it must return the typed Unkillable error.
//
// Synchronized on a REAL event, not a timer: `sudo` is setuid, and its REAL uid stays the
// invoking user until it setresuid(2)s to root just before exec'ing the target. A kill()
// delivered in that window targets a process still owned (in the permission-check sense) by
// the invoking user, so it SUCCEEDS — racing sudo's internal privilege transition. Spawning
// the `write-pid-then-sleep` payload and polling for its pidfile (written only once the
// payload is running, i.e. strictly after the exec into a root-owned image) closes that
// window: the poll is on a filesystem event, never a sleep.
#[cfg(unix)]
#[test]
fn posix_uncontained_elevated_child_is_unkillable_and_drop_does_not_hang() {
    if !gated() {
        return;
    }
    let pidfile = std::env::temp_dir().join(format!("uncontained-payload-{}.pid", std::process::id()));
    let _ = std::fs::remove_file(&pidfile);
    let exe = testbin();
    let mut c = subprocess::Command::new();
    c.executable(&exe)
        .args([
            exe.clone().into_os_string(),
            "write-pid-then-sleep".into(),
            pidfile.clone().into_os_string(),
        ])
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let child = c.spawn().expect("elevated write-pid-then-sleep");

    // Wait for the payload to publish its pid on a real event (its file appears with parseable
    // content), not a timer — this is strictly after sudo's setresuid+exec into the payload.
    let payload_pid: u32 = loop {
        if let Ok(s) = std::fs::read_to_string(&pidfile) {
            if let Ok(pid) = s.trim().parse() {
                break pid;
            }
        }
        std::thread::yield_now();
    };
    assert!(pid_is_alive(payload_pid), "payload should be running before the kill");

    // kill() outcome depends on the backend's process topology:
    //  - direct-exec backends (doas, run0, sudo WITHOUT `Defaults use_pty`) make the tracked
    //    child the root process itself, so an unprivileged parent's signal is EPERM → the typed
    //    `Unkillable`.
    //  - sudo WITH `use_pty` (increasingly the distro default) keeps the tracked child as sudo's
    //    same-uid monitor and runs root under a pty grandchild, so kill() SUCCEEDS on the monitor.
    //    Tearing down that grandchild is the deferred "un-killable elevated child / sudo pty
    //    monitor" teardown contract (issue #14), out of this plan's scope.
    // Either way is contract-correct here; the load-bearing Decision-A guarantee this test exists
    // for is that neither kill() nor the Drop below BLOCKS. A raw untyped Io on the EPERM path
    // would be the real defect.
    match child.kill() {
        Ok(()) => {}
        Err(subprocess::error::Error::Elevation {
            kind: subprocess::error::ElevationErrorKind::Unkillable,
            ..
        }) => {}
        other => panic!("expected Ok (use_pty monitor) or typed Unkillable (direct exec), got {other:?}"),
    }
    // Dropping it must return (kill_on_drop is best-effort, non-blocking) — the test itself
    // completing is the assertion. Leave the child; the harness/OS reaps it.
    drop(child);
    let _ = std::fs::remove_file(&pidfile);
}

// GATED: the allowed (already-elevated) spawn path reports elevation() honestly.
#[cfg(unix)]
#[test]
fn already_elevated_inherit_spawn_reports_already_elevated() {
    if !gated() || !subprocess::elevation::is_elevated() {
        return; // deterministic only when the gated runner is itself elevated.
    }
    let mut c = subprocess::Command::new();
    c.args(["true"])
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let child = c.spawn().expect("spawn");
    assert_eq!(
        child.elevation().expect("elevation requested → Some").via,
        subprocess::elevation::ElevatedVia::AlreadyElevated,
    );
    let _ = child.wait();
}

#[cfg(windows)]
#[test]
fn windows_elevated_child_writes_admin_marker() {
    if !gated() {
        return;
    }
    let dir = std::env::var_os("SUBPROCESS_TEST_ELEVATION_MARKER_DIR")
        .map(PathBuf::from)
        .expect("SUBPROCESS_TEST_ELEVATION_MARKER_DIR must point at an admin-only writable dir");
    let marker = dir.join(format!("elev-{}.marker", std::process::id()));
    let exe = testbin();
    let mut c = subprocess::Command::new();
    c.executable(&exe).args([
        exe.clone().into_os_string(),
        "write-marker".into(),
        marker.clone().into_os_string(),
    ]);
    c.elevate();
    let child = c.spawn().expect("runas spawn");
    // Honest report: WindowsUac + OwnConsole (never a faked shared stream).
    let report = child.elevation().unwrap();
    assert_eq!(report.via, subprocess::elevation::ElevatedVia::WindowsUac);
    assert_eq!(report.stdio, subprocess::elevation::ElevatedStdio::OwnConsole);
    let status = child.wait().expect("wait");
    assert!(status.success(), "elevated marker write failed: {status:?}");
    assert!(marker.exists(), "elevated child did not create the admin-only marker");
    let _ = std::fs::remove_file(&marker);
}

#[cfg(all(unix, feature = "tokio"))]
#[tokio::test]
async fn async_posix_elevated_child_runs_as_root() {
    if !gated() {
        return;
    }
    let mut c = subprocess::tokio::Command::new();
    c.args(["id", "-u"])
        .elevation_auth(subprocess::elevation::Auth::NonInteractive);
    let out = c.output().await.expect("async elevated output");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
}

// GATED (Windows): a non-contained runas child a medium parent cannot
// PROCESS_TERMINATE returns the typed Unkillable, and Drop does not hang.
#[cfg(windows)]
#[test]
fn windows_elevated_child_is_unkillable_and_drop_does_not_hang() {
    if !gated() {
        return;
    }
    let exe = testbin();
    let mut c = subprocess::Command::new();
    // A long-lived elevated child (ping loops ~50s).
    c.executable(&exe)
        .args([exe.clone().into_os_string(), "sleep-marker".into()])
        .elevate();
    let child = c.spawn().expect("runas spawn");
    match child.kill() {
        Err(subprocess::error::Error::Elevation { kind, .. }) => {
            assert_eq!(kind, subprocess::error::ElevationErrorKind::Unkillable);
        }
        // If the CI context runs the parent elevated too, the child is killable — accept Ok.
        Ok(()) => {}
        other => panic!("expected Unkillable or Ok, got {other:?}"),
    }
    drop(child); // must return promptly (non-blocking teardown)
}

// MANUAL-TIER async Windows elevation (4c785f26): mirrors the sync marker test. Runs only
// under the same gated, UAC-auto-approve manual tier documented in issue #9.
#[cfg(all(windows, feature = "tokio"))]
#[tokio::test]
async fn async_windows_elevated_child_writes_admin_marker() {
    if !gated() {
        return;
    }
    let dir = std::env::var_os("SUBPROCESS_TEST_ELEVATION_MARKER_DIR")
        .map(PathBuf::from)
        .expect("SUBPROCESS_TEST_ELEVATION_MARKER_DIR must point at an admin-only writable dir");
    let marker = dir.join(format!("elev-async-{}.marker", std::process::id()));
    let exe = testbin();
    let mut c = subprocess::tokio::Command::new();
    c.executable(&exe).args([
        exe.clone().into_os_string(),
        "write-marker".into(),
        marker.clone().into_os_string(),
    ]);
    c.elevate();
    let mut child = c.spawn().expect("async runas spawn");
    let report = child.elevation().unwrap();
    assert_eq!(report.via, subprocess::elevation::ElevatedVia::WindowsUac);
    assert_eq!(report.stdio, subprocess::elevation::ElevatedStdio::OwnConsole);
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
#[tokio::test]
async fn async_windows_elevated_child_is_unkillable_and_drop_does_not_hang() {
    if !gated() {
        return;
    }
    let exe = testbin();
    let mut c = subprocess::tokio::Command::new();
    c.executable(&exe)
        .args([exe.clone().into_os_string(), "sleep-marker".into()])
        .elevate();
    let mut child = c.spawn().expect("async runas spawn");
    match child.kill() {
        Err(subprocess::error::Error::Elevation { kind, .. }) => {
            assert_eq!(kind, subprocess::error::ElevationErrorKind::Unkillable);
        }
        // If the manual runner is itself elevated, the child is killable — accept Ok.
        Ok(()) => {}
        other => panic!("expected Unkillable or Ok, got {other:?}"),
    }
    drop(child); // must return promptly (non-blocking async teardown)
}
