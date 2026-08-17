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
fn child_terminate_unsupported_for_an_uncontained_child_on_windows() {
    let (child, _sock) = common::spawn_blocker();
    assert_eq!(
        child.graceful_mechanism(),
        cosca::GracefulMechanism::None,
        "the refusal follows from the recorded fact, not from the platform"
    );
    let err = child
        .terminate()
        .expect_err("a child that leads no group cannot be addressed");
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
fn child_graceful_shutdown_unsupported_for_an_uncontained_child_on_windows() {
    use std::time::Duration;
    let (child, _sock) = common::spawn_blocker();
    assert_eq!(
        child.graceful_mechanism(),
        cosca::GracefulMechanism::None,
        "the refusal follows from the recorded fact, not from the platform"
    );
    let err = child
        .graceful_shutdown(Duration::from_secs(1))
        .expect_err("a child that leads no group cannot be addressed");
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

// GracefulMechanism =====

/// Unix is uniformly `Process`: every child cosca owns there can be sent an identity-bound
/// `SIGTERM`, whatever its containment. A `cfg`-confused implementation that reported the
/// contained child's group instead fails here.
#[cfg(unix)]
#[test]
fn graceful_mechanism_is_process_on_unix() {
    use cosca::GracefulMechanism;

    let (uncontained, _s1) = common::spawn_blocker();
    let (contained, _s2) = common::spawn_control("control-block", &["R"], true);
    assert_eq!(uncontained.graceful_mechanism(), GracefulMechanism::Process);
    assert_eq!(contained.graceful_mechanism(), GracefulMechanism::Process);
    for child in [uncontained, contained] {
        child.kill().expect("cleanup");
        let _ = child.wait();
    }
}

/// On Windows the two must DISAGREE: containment is what sets `CREATE_NEW_PROCESS_GROUP`, so an
/// uncontained child leads no group while a contained one does. A hardcoded return value fails
/// one of the two.
#[cfg(windows)]
#[test]
fn graceful_mechanism_distinguishes_contained_from_uncontained_on_windows() {
    use cosca::GracefulMechanism;

    let (uncontained, _s1) = common::spawn_blocker();
    let (contained, _s2) = common::spawn_control("control-block", &["R"], true);
    assert_eq!(uncontained.graceful_mechanism(), GracefulMechanism::None);
    assert_eq!(contained.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    for child in [uncontained, contained] {
        child.kill().expect("cleanup");
        let _ = child.wait();
    }
}

// The lone graceful ops on a console-group child =====

/// Delivery is proved by a byte the CHILD's own console-ctrl handler writes — never by the Win32
/// return value, which reports success for an event that reached nobody. The child survives its
/// break by design (its handler reports "handled"), so the read cannot race a teardown.
#[cfg(windows)]
#[test]
fn child_terminate_delivers_ctrl_break_to_a_contained_root() {
    use std::io::Read;

    use cosca::GracefulMechanism;

    let (child, mut sock) = common::spawn_control("control-block-ack-break", &["R"], true);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    // A MEASURED precondition, so the blocking read below cannot hang on a vacuous scenario.
    assert_eq!(
        common::in_our_console(child.id().pid()),
        Some(true),
        "the root must share our console for the event to be deliverable"
    );
    child.terminate().expect("terminate a console-group child");
    let mut ack = [0u8; 1];
    sock.read_exact(&mut ack).expect("the child must acknowledge the break");
    assert_eq!(&ack, b"B", "wrong ack byte");
    child.kill_tree().expect("cleanup");
    let _ = child.wait();
}

/// The graceful path end to end: no handler, so the default disposition applies and the child
/// dies to the console event. `0xC000013A` discriminates against `1` (this crate's escalation)
/// and `0xC0000142` (a signal that landed before the child could handle it).
#[cfg(windows)]
#[test]
fn child_graceful_shutdown_exits_via_ctrl_break_on_windows() {
    use std::time::Duration;

    // The long grace is a failure bound on the child's own exit, never the synchronization.
    let (child, _sock) = common::spawn_control("control-block", &["R"], true);
    let status = child
        .graceful_shutdown(Duration::from_secs(30))
        .expect("graceful_shutdown on a console-group child");
    assert_eq!(
        status.code(),
        Some(0xC000013A_u32 as i32),
        "the child must die to the console event, got {status:?}"
    );
}

/// `Duration::ZERO` makes the escalation deterministic — the break-ignoring child is provably
/// alive at the single poll — so code `1` is this crate's kill and nothing else.
#[cfg(windows)]
#[test]
fn child_graceful_shutdown_escalates_when_the_break_is_ignored() {
    use std::time::Duration;

    let (child, _sock) = common::spawn_control("control-block-ignore-break", &["R"], true);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .expect("graceful_shutdown escalates");
    assert_eq!(
        status.code(),
        Some(1),
        "a break-ignoring child must be force-killed, got {status:?}"
    );
}

/// The parity contract, deliberately not `cfg`-gated so it is one test rather than two: the
/// `Child` pins the pid for its whole life, so an already-exited child is `Ok` on every
/// platform.
#[test]
fn child_terminate_reports_ok_for_an_already_exited_child() {
    let (child, _sock) = common::spawn_control("control-block", &["R"], true);
    child.kill().expect("kill");
    let _status = child.wait().expect("reap");
    child.terminate().expect("already-dead must be Ok");
}

/// Pins a KNOWN LIMITATION, not desired behaviour. A child that shares no console with us is
/// signalled with a success Windows reports for an event that reached nobody, and nothing inside
/// this process can tell that case apart from a healthy one. Revisit when a route that reads the
/// TARGET's console exists — this test must then flip rather than the behaviour changing
/// silently.
#[cfg(windows)]
#[test]
fn child_graceful_ops_report_success_for_a_child_that_shares_no_console() {
    use std::io::Read;
    use std::time::Duration;

    use cosca::GracefulMechanism;

    let (child, mut sock) = common::spawn_gui_control(true);
    assert_eq!(
        child.graceful_mechanism(),
        GracefulMechanism::ConsoleGroup,
        "the flags do not exclude delivery — that is exactly what makes this a gap"
    );
    assert_eq!(
        common::in_our_console(child.id().pid()),
        Some(false),
        "a GUI-subsystem child is not in our console"
    );
    child.terminate().expect("the documented false success");
    // Neither shut down nor killed — this is also what catches an accidental auto-escalation
    // inside terminate.
    assert_eq!(
        child.is_alive(),
        cosca::identity::Liveness::Alive,
        "nothing was delivered, so the child must still be running"
    );
    // The FORCED half still works, so the op ends the child even though its cooperative half
    // reached nobody.
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .expect("the forced half needs no console");
    assert_eq!(status.code(), Some(1), "escalation's kill, got {status:?}");
    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
    let _ = child.wait();
}

/// The lone graceful shutdown's two halves have different radii on Windows: the cooperative
/// signal reaches the child's whole console group, the escalation reaches only the child. The
/// root here ignores the break (so only the escalation can have ended it) while its grandchild —
/// an ordinary spawn that stayed in the root's group — acks the break and survives.
#[cfg(windows)]
#[test]
fn child_graceful_shutdown_signals_the_group_but_only_kills_the_child() {
    use std::io::Read;
    use std::time::Duration;

    use cosca::containment::TreeDrain;

    let (child, mut socks) = common::spawn_tree("spawn-grandchild-ack-break", true);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .expect("graceful_shutdown on a console-group root");
    assert_eq!(
        status.code(),
        Some(1),
        "the root ignores the break, so only the escalation can have ended it, got {status:?}"
    );
    // Positive proof the cooperative half reached a descendant the forced half will not touch.
    // The grandchild's handler reports "handled", so this read cannot race its death.
    let mut ack = [0u8; 1];
    socks[1]
        .read_exact(&mut ack)
        .expect("the grandchild must acknowledge the break");
    assert_eq!(&ack, b"B", "wrong ack byte");
    // The job object's own live-member count: a kernel-authoritative, non-blocking verdict that
    // the grandchild is still running after a graceful_shutdown that returned Ok.
    assert_eq!(
        child.wait_tree_timeout(Duration::ZERO).expect("drain verdict"),
        TreeDrain::MembersRemain,
        "the escalation must not have reached the group"
    );
    child.kill_tree().expect("cleanup");
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

/// The case this capability exists for, end to end: a nested contained Windows child owns no
/// tree, leads a console process group of its own, and had no cooperative shutdown at all.
/// `break=1` is reachable only if that child's own handler acknowledged an event no tree op on
/// any handle in the system could have delivered to it; `tree=Unsupported` fails if the
/// containment gate was loosened, which this change must not do.
#[cfg(windows)]
#[test]
fn nested_delegated_child_can_be_gracefully_terminated() {
    use std::io::Read;
    use std::net::TcpListener;

    // Exact `key=value` matching, never `contains`: `mechanism=none` is a substring of
    // neighbouring text.
    fn field<'a>(report: &'a str, key: &str) -> &'a str {
        report
            .split_ascii_whitespace()
            .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("no field {key} in report: {report}"))
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    // Contained, so the reporter's own crate spawn is a real nested member.
    let mut cmd = cosca::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "report-nested-terminate", &addr])
        .contain();
    let child = cmd.spawn().expect("spawn reporter");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut r = String::new();
    sock.read_to_string(&mut r).expect("read report");

    assert_eq!(field(&r, "containment"), "delegated", "{r}");
    assert_eq!(field(&r, "mechanism"), "console-group", "{r}");
    assert_eq!(field(&r, "in_console"), "1", "{r}");
    assert_eq!(field(&r, "terminate"), "Ok", "{r}");
    assert_eq!(
        field(&r, "break"),
        "1",
        "the nested child's own handler must have acknowledged the event: {r}"
    );
    assert_eq!(
        field(&r, "tree"),
        "Unsupported",
        "a nested member still owns no tree teardown: {r}"
    );
    assert_eq!(field(&r, "cleanup"), "Ok", "{r}");
    let status = child.wait().expect("reap reporter");
    assert!(status.success(), "reporter failed: {status:?} — report: {r}");
}
