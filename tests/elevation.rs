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
#[test]
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
#[test]
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
#[test]
fn controlling_terminal_probe_consults_ctty_not_stdin() {
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

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
    let raw = unsafe {
        libc::ioctl(
            master.as_raw_fd(),
            libc::TIOCGPTPEER,
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    assert!(raw >= 0, "TIOCGPTPEER: {}", std::io::Error::last_os_error());
    // SAFETY: TIOCGPTPEER returned a fresh, owned descriptor above.
    let slave: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw) };
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
#[test]
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

// GATED: run0 client -> transient-unit kill propagation. The client is ALWAYS reaped by
// wait(), so that proves nothing; instead the elevated PAYLOAD reports its own pid over a
// loopback socket, and after killing the client we assert THAT (the transient-unit process) is
// gone. run0 auths via polkit; --no-ask-password (Auth::NonInteractive) suppresses the prompt.
// `run0` itself does exit (not hang) when auth fails without a polkit rule — but this test's OWN
// `listener.accept()` used to hang forever in exactly that case, since nothing would ever
// connect if the payload never started (measured with a fake failing run0: the earlier version
// of this test needed an external 60s kill). Racing the accept against the client's own exit,
// below, is what actually makes THIS TEST fail loud rather than hang — an unattended run still
// needs a passwordless polkit rule for the run0 action to reach the propagation check at all.
//
// The payload's own lifetime is tied to THIS TEST PROCESS's socket, never to the client: the
// client is what gets killed here, on purpose, to observe whether elevation's OWN kill
// propagation reaches the payload — tying the payload's death to the client's own exit (a
// stdin-EOF design, as the sibling Unkillable/drop test below uses) would make the payload die
// from the client's own teardown instead, masking a genuinely broken propagation path. Nextest
// gives this test its own process, so if propagation really is broken and the bounded wait
// below fails the test, THIS process's own exit still closes the listener/socket, releasing the
// payload — the same safety net `sleep-marker`'s own doc describes, not a substitute for the
// propagation check itself (nothing here closes the socket before that check completes).
#[cfg(target_os = "linux")]
#[test]
fn run0_client_kill_propagates_to_the_transient_unit() {
    use std::io::BufRead as _;

    if !gated() || std::env::var_os("COSCA_TEST_ELEVATION_RUN0").is_none() {
        return; // requires run0 + a polkit-passwordless context that can spawn a transient unit.
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let exe = testbin();
    let mut c = cosca::Command::new();
    c.executable(&exe)
        .args([
            exe.clone().into_os_string(),
            "write-pid-then-block-on-socket".into(),
            addr.into(),
        ])
        .elevation_backend(cosca::elevation::Backend::Run0)
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    let child = std::sync::Arc::new(c.spawn().expect("run0 spawn"));

    // Races the accept against the CLIENT's own exit — no timeout needed, since a run0 failure
    // before the payload ever starts (a denied polkit prompt, a missing rule, run0 itself
    // erroring out) is a real, already-existing event: the client process exiting. Without this,
    // `listener.accept()` alone would hang forever on exactly that failure, since nothing would
    // ever connect (measured: the reviewer confirmed this with a fake failing run0, killed only
    // by an external 60s bound). Both arms start racing concurrently, on their own threads, before
    // either result is awaited — `Child::wait()` takes `&self` (`SharedChild`-backed, safe to call
    // from a second thread while this one later calls `kill()`/`wait()` on the same `Arc` clone),
    // so the loser (usually the client-exit watch, since the client keeps running for the rest of
    // this test) is simply abandoned rather than joined: its result is sent but never read, and it
    // exits on its own once the client actually does.
    enum Raced {
        Connected(std::io::Result<(std::net::TcpStream, std::net::SocketAddr)>),
        ClientExited(Result<std::process::ExitStatus, cosca::error::Error>),
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Raced::Connected(listener.accept()));
        }
    });
    std::thread::spawn({
        let tx = tx.clone();
        let child = std::sync::Arc::clone(&child);
        move || {
            let _ = tx.send(Raced::ClientExited(child.wait()));
        }
    });
    let sock = match rx.recv().expect("neither race arm hung up") {
        Raced::Connected(r) => r.expect("accept payload connection").0,
        Raced::ClientExited(status) => panic!(
            "the run0 client exited ({status:?}) before its payload ever connected — \
             run0 failed before the payload started"
        ),
    };
    let mut reader = std::io::BufReader::new(sock);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read payload pid");
    let payload_pid: u32 = line.trim().parse().expect("parse payload pid");

    // Open the pidfd BEFORE killing the client: nothing has signalled the payload yet, so it
    // cannot have exited (and freed its pid for reuse) between reading it above and opening
    // this — opening it any later, after the kill, could race that reuse window instead.
    let rpid = rustix::process::Pid::from_raw(payload_pid as i32).expect("payload pid is positive");
    let pidfd =
        rustix::process::pidfd_open(rpid, rustix::process::PidfdFlags::empty()).expect("pidfd_open the payload");

    assert!(pid_is_alive(payload_pid), "payload should be running before the kill");
    child.kill().expect("kill run0 client");
    child.wait().expect("wait run0 client");

    // Block on the pidfd becoming readable (the payload exiting) — a real kernel event, not a
    // busy-spin — bounded at 30s as the FAILURE surface: the bound is on run0's own kill
    // propagation actually tearing down the transient unit, a genuinely external event this
    // test does not control, not a substitute for one.
    use std::os::fd::AsRawFd as _;
    let mut pfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // An absolute deadline, not a duration re-armed at 30s on every retry: an EINTR (e.g. a
    // signal this test process itself receives) must not extend the total bound past 30s.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let rc = loop {
        let remaining_ms = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .try_into()
            .unwrap_or(i32::MAX);
        // SAFETY: `pfd` is a single, correctly-initialized `pollfd`; `poll` writes only within
        // its bounds, and the `1` count matches the slice length passed.
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
        if rc >= 0 {
            break rc;
        }
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EINTR), "poll failed: {err}");
    };
    assert_eq!(
        rc, 1,
        "the transient unit's payload (pid {payload_pid}) is still alive 30s after the run0 \
         client was killed — run0's kill propagation to the transient unit appears broken"
    );
    // No `!pid_is_alive(payload_pid)` check here: `POLLIN` on the pidfd fires at the payload's
    // exit, before systemd reaps it, so `kill(pid, 0)` would still succeed against the zombie —
    // and once it IS reaped, the pid can be reused, making a post-hoc `kill(pid, 0)` meaningless
    // either way. Pidfd readiness is already the proof; a second, racy check on the bare pid adds
    // nothing but a false-failure risk.
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
#[test]
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

// GATED (POSIX): dropping a non-contained elevated long-lived child must
// RETURN (no hang), and kill() on it must return the typed Unkillable error.
//
// Synchronized on a REAL event, not a timer: `sudo` is setuid, and its REAL uid stays the
// invoking user until it setresuid(2)s to root just before exec'ing the target. A kill()
// delivered in that window targets a process still owned (in the permission-check sense) by
// the invoking user, so it SUCCEEDS — racing sudo's internal privilege transition. Spawning
// the `write-pid-then-block-on-stdin` payload and BLOCKING on its piped stdout (written only
// once the payload is running, i.e. strictly after the exec into a root-owned image) closes
// that window: the read is on a real pipe event, never a filesystem poll or a sleep.
//
// The payload's own lifetime is tied to THIS PROCESS, not a timer or a privileged kill: its
// stdin is a pipe whose write end this test holds. `sudo`/`doas`'s `closefrom` drops fds > 2 in
// the elevated child, so an extra marker fd would not survive it, but stdio does (see
// `write-pid-then-block-on-stdin`'s own doc) — and because the write end lives HERE, the OS
// closes it the moment this process exits for any reason (a clean return, a panic, or this
// process itself being killed), delivering EOF to the payload with no privileged kill needed.
// The un-killable case this test exists to prove (`kill()` returning `Unkillable`, decision A)
// is exactly the case where cleanup CANNOT be a privileged signal from here — the payload's own
// exit-on-EOF is the only cleanup this test can perform without privilege, matching that.
#[cfg(unix)]
#[test]
fn posix_uncontained_elevated_child_is_unkillable_and_drop_does_not_hang() {
    use std::io::BufRead as _;

    if !gated() {
        return;
    }
    let exe = testbin();
    let mut c = cosca::Command::new();
    c.executable(&exe)
        .args([exe.clone().into_os_string(), "write-pid-then-block-on-stdin".into()])
        .elevation_auth(cosca::elevation::Auth::NonInteractive);
    c.stdin(cosca::Stdio::pipe()).expect("set stdin pipe");
    c.stdout(cosca::Stdio::pipe()).expect("set stdout pipe");
    let mut child = c.spawn().expect("elevated write-pid-then-block-on-stdin");
    // Held for the rest of this function (and thus for the rest of this process's life): the
    // payload can only exit via EOF on this pipe, which the OS delivers unconditionally once
    // this handle — or the whole process holding it — goes away.
    let _stdin = child.stdin().expect("piped stdin");

    // Block reading the payload's pid off its piped stdout — a real pipe event, strictly after
    // sudo's setresuid+exec into the payload (it cannot write before then).
    let mut line = String::new();
    std::io::BufReader::new(child.stdout().expect("piped stdout"))
        .read_line(&mut line)
        .expect("read payload pid");
    let payload_pid: u32 = line.trim().parse().expect("parse payload pid");
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
        Err(cosca::error::Error::Elevation {
            kind: cosca::error::ElevationErrorKind::Unkillable,
            ..
        }) => {}
        other => panic!("expected Ok (use_pty monitor) or typed Unkillable (direct exec), got {other:?}"),
    }
    // Dropping it must return (kill_on_drop is best-effort, non-blocking) — the test itself
    // completing is the assertion.
    drop(child);
    // Only now: releases the payload for real, without needing any privilege — see this
    // function's own doc for why this is the cleanup this test uses instead of a privileged
    // kill (which the Unkillable case this test proves cannot always be relied on).
    drop(_stdin);
}

// GATED: the allowed (already-elevated) spawn path reports elevation() honestly.
#[cfg(unix)]
#[test]
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
#[test]
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
#[tokio::test]
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

/// Accepts one connection on `listener`, bounded at 30s as a FAILURE surface: an elevated
/// child that never connects (a crashed spawn, a dismissed UAC prompt, or the readiness tag
/// never arriving) would otherwise hang `TcpListener::accept()` forever. Runs the accept on a
/// background thread and races it against the bound via a channel — `accept()` itself has no
/// portable way to cancel, so a genuine hang there leaks that one thread in an already-failing,
/// soon-to-exit test process rather than hanging the whole CI job.
#[cfg(windows)]
fn accept_bounded(listener: std::net::TcpListener) -> std::net::TcpStream {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(listener.accept());
    });
    rx.recv_timeout(std::time::Duration::from_secs(30))
        .expect("accept() did not complete within its failure bound — the elevated child likely never connected")
        .expect("accept readiness connection")
        .0
}

// GATED (Windows): a non-contained runas child a medium parent cannot
// PROCESS_TERMINATE returns the typed Unkillable, and Drop does not hang.
#[cfg(windows)]
#[test]
fn windows_elevated_child_is_unkillable_and_drop_does_not_hang() {
    use std::io::Read;

    if !gated() {
        return;
    }
    // A loopback TCP address, not a pipe or any other inherited handle: an elevated `runas`
    // child gets its own console and inherits nothing from its caller (`spawn_elevated`'s
    // `ElevatedStdio::OwnConsole`), but it CAN still dial back out over loopback. This gives a
    // real readiness edge (the accepted connection + tag, proving the child is genuinely
    // running before `kill()` is attempted — never a chosen sleep duration) and, at the end, a
    // real way to end the child regardless of whether `kill()` itself succeeded.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let exe = testbin();
    let mut c = cosca::Command::new();
    c.executable(&exe)
        .args([exe.clone().into_os_string(), "sleep-marker".into(), addr.into()])
        .elevate();
    let child = c.spawn().expect("runas spawn");
    let mut sock = accept_bounded(listener);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("readiness tag");
    match child.kill() {
        Err(cosca::error::Error::Elevation { kind, .. }) => {
            assert_eq!(kind, cosca::error::ElevationErrorKind::Unkillable);
        }
        // If the CI context runs the parent elevated too, the child is killable — accept Ok.
        Ok(()) => {}
        other => panic!("expected Unkillable or Ok, got {other:?}"),
    }
    drop(child); // must return promptly (non-blocking teardown)
                 // Only now: on the (typical) Unkillable path the child is still running (that IS the
                 // property under test), so ending it for real is this test's own responsibility, not
                 // `kill()`'s — dropping the socket delivers EOF, which the child exits on.
    drop(sock);
}

// MANUAL-TIER async Windows elevation (4c785f26): mirrors the sync marker test. Runs only
// under the same gated, UAC-auto-approve manual tier documented in issue #9.
#[cfg(all(windows, feature = "tokio"))]
#[tokio::test]
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
#[tokio::test]
async fn async_windows_elevated_child_is_unkillable_and_drop_does_not_hang() {
    use std::io::Read;

    if !gated() {
        return;
    }
    // See the sync twin's doc for why a loopback TCP address, not a pipe, is what crosses the
    // elevation boundary here.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let exe = testbin();
    let mut c = cosca::tokio::Command::new();
    c.executable(&exe)
        .args([exe.clone().into_os_string(), "sleep-marker".into(), addr.into()])
        .elevate();
    let mut child = c.spawn().expect("async runas spawn");
    let mut sock = accept_bounded(listener);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("readiness tag");
    match child.kill() {
        Err(cosca::error::Error::Elevation { kind, .. }) => {
            assert_eq!(kind, cosca::error::ElevationErrorKind::Unkillable);
        }
        // If the manual runner is itself elevated, the child is killable — accept Ok.
        Ok(()) => {}
        other => panic!("expected Unkillable or Ok, got {other:?}"),
    }
    drop(child); // must return promptly (non-blocking async teardown)
                 // Only now: see the sync twin's doc for why ending the child is this test's own
                 // responsibility on the (typical) Unkillable path.
    drop(sock);
}

// GATED behind COSCA_TEST_ELEVATION_GUI: a TRUE no-op without it, and loud when set.
// This is the ONLY test that raises the authentication dialog, so it can never run
// unattended — a human must be at the keyboard to approve it. It is here so the path
// is verifiable at all, not so CI can verify it.
#[cfg(target_os = "macos")]
#[test]
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
