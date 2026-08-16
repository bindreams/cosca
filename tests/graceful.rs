//! Graceful-escalation trio integration tests (Child + Process). Death is proven only by a
//! real exit event — control-socket EOF/ConnectionReset or an inspected ExitStatus signal —
//! never by sleep, poll loop, or wall-clock. Escalation tests use a SIGTERM-ignoring child +
//! Duration::ZERO, so escalation is deterministic (the child is alive at the single poll).

#[path = "common/mod.rs"]
mod common;

#[cfg(unix)]
#[test]
fn child_terminate_sends_sigterm() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    let (child, mut sock) = common::spawn_blocker();
    child.terminate().expect("terminate sends SIGTERM");
    // Prove death by a real event: the control socket EOFs.
    let mut buf = [0u8; 1];
    match sock.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("expected EOF/ConnectionReset after SIGTERM, got {other:?}"),
    }
    // Reap and assert it died by SIGTERM (soft), NOT SIGKILL.
    let status = child.wait().expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "control-block must die by SIGTERM, got {status:?}"
    );
}

#[cfg(windows)]
#[test]
fn child_terminate_unsupported_on_windows() {
    let (child, _sock) = common::spawn_blocker();
    let err = child
        .terminate()
        .expect_err("lone graceful terminate has no Windows primitive");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    let _ = child.wait();
}

#[cfg(unix)]
#[test]
fn child_graceful_shutdown_graceful_path() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // control-block dies on default-disposition SIGTERM. The long grace is the safety bound on
    // a child that exits promptly — never the synchronization; correctness is the exit signal.
    let (child, mut sock) = common::spawn_blocker();
    let status = child
        .graceful_shutdown(Duration::from_secs(30))
        .expect("graceful_shutdown");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "graceful path must exit via SIGTERM, got {status:?}"
    );
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf); // dead — EOF
}

#[cfg(unix)]
#[test]
fn child_graceful_shutdown_escalates() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // This child installs SIG_IGN for SIGTERM, so it NEVER exits on the soft signal. With
    // Duration::ZERO the child is provably alive at the single poll → escalation to SIGKILL is
    // deterministic (no timing dependency at all). Because SIGTERM is ignored, SIGKILL is the
    // ONLY terminating signal the child can receive, so signal()==SIGKILL is unambiguous.
    let (child, mut sock) = common::spawn_control("control-block-ignore-term", &["R"], false);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .expect("graceful_shutdown escalates");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "SIGTERM-ignoring child must be force-killed, got {status:?}"
    );
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
}

#[cfg(windows)]
#[test]
fn child_graceful_shutdown_unsupported_on_windows() {
    use std::time::Duration;
    let (child, _sock) = common::spawn_blocker();
    let err = child
        .graceful_shutdown(Duration::from_secs(1))
        .expect_err("no Windows lone graceful");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    let _ = child.wait();
}

#[test]
fn child_graceful_shutdown_tree_tears_down_tree() {
    use std::io::Read;
    use std::time::Duration;
    // A contained 2-level tree (root R + grandchild G). The group's graceful signal
    // (SIGTERM / CTRL_BREAK) plus the hard sweep tear down BOTH; both sockets EOF. All OSes.
    let (child, mut socks) = common::spawn_grandchild(true);
    child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect("tree graceful");
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
}

#[cfg(unix)]
#[test]
fn child_graceful_shutdown_tree_graceful_root_sigterm() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // A contained control-block root that honors SIGTERM: the group signal makes it exit;
    // the root's reaped status is SIGTERM (15), not escalated.
    let (child, mut sock) = common::spawn_control("control-block", &["R"], true);
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect("tree graceful");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "root must exit via SIGTERM, got {status:?}"
    );
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
}

#[cfg(unix)]
#[test]
fn child_graceful_shutdown_tree_escalates() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // A contained SIGTERM-ignoring root: the group SIGTERM is ignored, so with Duration::ZERO
    // the root is provably alive at the poll and the hard sweep (kill_tree) SIGKILLs it. SIGKILL
    // is the only terminating signal it can receive (SIGTERM ignored), so the assertion is
    // unambiguous.
    let (child, mut sock) = common::spawn_control("control-block-ignore-term", &["R"], true);
    let status = child.graceful_shutdown_tree(Duration::ZERO).expect("tree escalates");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "ignored SIGTERM must escalate to SIGKILL, got {status:?}"
    );
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
}

#[cfg(unix)]
#[test]
fn child_graceful_shutdown_tree_sweeps_survivor_after_graceful_root_exit() {
    use std::io::Read;
    use std::time::Duration;
    // The exact case the sweep-before-reap invariant protects: the root honors the group
    // SIGTERM and exits within the grace, but the grandchild ignores it and survives — only
    // the post-grace hard sweep (running while the unreaped root still pins the group id)
    // can tear it down. The grandchild never exits, so on a drain-observable mechanism the
    // full grace is always spent watching the whole tree (not just the root) before the sweep
    // runs — 1s (not 30s) keeps this fast while staying a generous bound.
    //
    // This test asserts ONLY survivor teardown, deliberately not the root's reaped signal:
    // the handshake in `spawn_tree` proves the root is ready to RECEIVE the SIGTERM, not that
    // it finishes dying from it before the grace expires and the hard sweep's SIGKILL reaches
    // the same pid. If the root is still alive (not yet a zombie) at that instant, the sweep's
    // SIGKILL can pre-empt the SIGTERM's own kill, flipping the observed signal under load —
    // a genuine timing bet this test must not make. `child_graceful_shutdown_tree_graceful_root_sigterm`
    // covers the root's SIGTERM status instead, in a single-process tree where the drain
    // completes as soon as the root exits, so the sweep never runs concurrently with a still-alive
    // root at all.
    let (child, mut socks) = common::spawn_tree("spawn-grandchild-stubborn-child", true);
    child
        .graceful_shutdown_tree(Duration::from_secs(1))
        .expect("tree graceful with survivor");
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
}

#[cfg(unix)]
#[test]
fn process_terminate_sends_sigterm() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    let (child, mut sock) = common::spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.terminate().expect("foreign terminate");
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf); // dead — EOF
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(unix)]
#[test]
fn process_graceful_shutdown_graceful_path() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    let (child, mut sock) = common::spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.graceful_shutdown(Duration::from_secs(30)).expect("foreign graceful");
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
    let status = child.wait().expect("reap"); // owned handle reaps; confirm SIGTERM (graceful)
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(unix)]
#[test]
fn process_graceful_shutdown_escalates() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // SIGTERM is ignored → SIGKILL is the only terminating signal the child can receive, so the
    // reaped status is unambiguously SIGKILL.
    let (child, mut sock) = common::spawn_control("control-block-ignore-term", &["R"], false);
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.graceful_shutdown(Duration::ZERO).expect("foreign escalates");
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

#[cfg(windows)]
#[test]
fn process_lone_graceful_unsupported_on_windows() {
    use std::time::Duration;
    let (child, _sock) = common::spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    assert!(matches!(p.terminate(), Err(cosca::error::Error::Unsupported { .. })));
    assert!(matches!(
        p.graceful_shutdown(Duration::from_secs(1)),
        Err(cosca::error::Error::Unsupported { .. })
    ));
    child.kill().expect("cleanup");
    let _ = child.wait();
}

#[test]
fn process_kill_tree_tears_down_tree() {
    use std::io::Read;
    // An UNcontained 2-level tree (root R + grandchild G). Take the root foreign and kill_tree
    // it: the identity-walk (snapshot-then-kill) reaches both. Both sockets EOF. All OSes.
    let (child, mut socks) = common::spawn_grandchild(false);
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.kill_tree().expect("kill_tree");
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
    let _ = child.wait(); // reap the owned root (grandchild is reaped by init)
}

#[cfg(unix)]
#[test]
fn process_graceful_shutdown_tree_tears_down_tree() {
    use std::io::Read;
    use std::time::Duration;
    let (child, mut socks) = common::spawn_grandchild(false);
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.graceful_shutdown_tree(Duration::from_secs(30))
        .expect("foreign tree graceful");
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
    let _ = child.wait();
}

#[cfg(windows)]
#[test]
fn process_soft_tree_unsupported_on_windows() {
    use std::time::Duration;
    let (child, _sock) = common::spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    assert!(matches!(
        p.terminate_tree(),
        Err(cosca::error::Error::Unsupported { .. })
    ));
    assert!(matches!(
        p.graceful_shutdown_tree(Duration::from_secs(1)),
        Err(cosca::error::Error::Unsupported { .. })
    ));
    child.kill().expect("cleanup");
    let _ = child.wait();
}
