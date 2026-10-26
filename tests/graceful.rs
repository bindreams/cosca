//! Graceful-escalation trio integration tests (Child + Process). Death is proven only by a
//! real exit event — control-socket EOF/ConnectionReset or an inspected ExitStatus signal —
//! never by sleep, poll loop, or wall-clock. Escalation tests use a SIGTERM-ignoring child +
//! Duration::ZERO, so escalation is deterministic (the child is alive at the single poll).

#[path = "common/mod.rs"]
mod common;

#[cfg(unix)]
#[skuld::test]
fn child_terminate_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    let (child, sock) = common::spawn_blocker();
    child.terminate().expect("terminate sends SIGTERM");
    // Release the member after the signal. It leaves with 0 on the release, so a `terminate` that
    // sent nothing fails the signal assertion instead of leaving the reap waiting for a death.
    drop(sock);
    // Reap and assert it died by SIGTERM (soft), NOT SIGKILL.
    let status = child.wait().expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "control-block must die by SIGTERM, got {status:?}"
    );
}

#[cfg(windows)]
#[skuld::test]
fn child_terminate_unsupported_for_an_uncontained_child_on_windows() {
    let (child, sock) = common::spawn_blocker();
    assert_eq!(
        child.graceful_mechanism(),
        cosca::GracefulMechanism::None,
        "the refusal follows from the recorded fact, not from the platform"
    );
    let err = child
        .terminate()
        .expect_err("a child that leads no group cannot be addressed");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    common::kill_release_reap(&child, sock);
}

#[cfg(windows)]
#[skuld::test]
fn child_graceful_shutdown_unsupported_for_an_uncontained_child_on_windows() {
    use std::time::Duration;
    let (child, sock) = common::spawn_blocker();
    assert_eq!(
        child.graceful_mechanism(),
        cosca::GracefulMechanism::None,
        "the refusal follows from the recorded fact, not from the platform"
    );
    let err = child
        .graceful_shutdown(Duration::from_secs(1))
        .expect_err("a child that leads no group cannot be addressed");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    common::kill_release_reap(&child, sock);
}

#[cfg(unix)]
#[skuld::test]
fn process_terminate_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    let (child, sock) = common::spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.terminate().expect("foreign terminate");
    // Released after the signal: the member leaves with 0 on the release, so a `terminate` that
    // sent nothing fails the signal assertion, where an EOF read would never return.
    drop(sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(unix)]
#[skuld::test]
fn process_graceful_shutdown_graceful_path() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    let (child, sock) = common::spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.graceful_shutdown(Duration::from_secs(30)).expect("foreign graceful");
    // Released after the call, so a shutdown that signalled nothing fails the assertion below.
    drop(sock);
    let status = child.wait().expect("reap"); // owned handle reaps; confirm SIGTERM (graceful)
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(unix)]
#[skuld::test]
fn process_graceful_shutdown_escalates() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // SIGTERM is ignored → SIGKILL is the only terminating signal the child can receive, so the
    // reaped status is unambiguously SIGKILL.
    let (child, sock) = common::spawn_control("control-block-ignore-term", &["R"], false);
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.graceful_shutdown(Duration::ZERO).expect("foreign escalates");
    // Released after the call, so an escalation that sent nothing fails the assertion below.
    drop(sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

#[cfg(windows)]
#[skuld::test]
fn process_lone_graceful_unsupported_on_windows() {
    use std::time::Duration;
    let (child, sock) = common::spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    assert!(matches!(p.terminate(), Err(cosca::error::Error::Unsupported { .. })));
    assert!(matches!(
        p.graceful_shutdown(Duration::from_secs(1)),
        Err(cosca::error::Error::Unsupported { .. })
    ));
    common::kill_release_reap(&child, sock);
}

#[skuld::test]
fn process_kill_tree_tears_down_tree() {
    // An UNcontained 2-level tree (root R + grandchild G). Take the root foreign and kill_tree
    // it: the identity-walk (snapshot-then-kill) reaches both. All OSes.
    let (child, socks) = common::spawn_tree_with("spawn-grandchild", false, |cmd| {
        cmd.env(common::ECHO_HELD_ENV, "1");
    });
    let [root, grand]: [_; 2] = socks.try_into().expect("a root and a grandchild socket");
    let (root, grand) = (
        common::Member::new(root, child.id().pid()),
        common::Member::new(grand, common::last_reported_grandchild().expect("the grandchild's pid")),
    );
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.kill_tree().expect("kill_tree");
    // A kill that sent nothing fails here by assertion instead of hanging a read for an EOF.
    common::assert_members_killed(vec![(root, "the root"), (grand, "the grandchild")]);
    let _ = child.wait(); // reap the owned root (grandchild is reaped by init)
}

#[cfg(unix)]
#[skuld::test]
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
#[skuld::test]
fn process_soft_tree_unsupported_on_windows() {
    use std::time::Duration;
    let (child, sock) = common::spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    assert!(matches!(
        p.terminate_tree(),
        Err(cosca::error::Error::Unsupported { .. })
    ));
    assert!(matches!(
        p.graceful_shutdown_tree(Duration::from_secs(1)),
        Err(cosca::error::Error::Unsupported { .. })
    ));
    common::kill_release_reap(&child, sock);
}

// GracefulMechanism =====

/// Unix is uniformly `Process`: every child cosca owns there can be sent an identity-bound
/// `SIGTERM`, whatever its containment. A `cfg`-confused implementation that reported the
/// contained child's group instead fails here.
#[cfg(unix)]
#[skuld::test]
fn graceful_mechanism_is_process_on_unix() {
    use cosca::GracefulMechanism;

    let (uncontained, s1) = common::spawn_blocker();
    let (contained, s2) = common::spawn_control("control-block", &["R"], true);
    assert_eq!(uncontained.graceful_mechanism(), GracefulMechanism::Process);
    assert_eq!(contained.graceful_mechanism(), GracefulMechanism::Process);
    for (child, sock) in [(uncontained, s1), (contained, s2)] {
        common::kill_release_reap(&child, sock);
    }
}

/// On Windows the two must DISAGREE: containment is what sets `CREATE_NEW_PROCESS_GROUP`, so an
/// uncontained child leads no group while a contained one does. A hardcoded return value fails
/// one of the two.
#[cfg(windows)]
#[skuld::test]
fn graceful_mechanism_distinguishes_contained_from_uncontained_on_windows() {
    use cosca::GracefulMechanism;

    let (uncontained, s1) = common::spawn_blocker();
    let (contained, s2) = common::spawn_control("control-block", &["R"], true);
    assert_eq!(uncontained.graceful_mechanism(), GracefulMechanism::None);
    assert_eq!(contained.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    for (child, sock) in [(uncontained, s1), (contained, s2)] {
        common::kill_release_reap(&child, sock);
    }
}

// The lone graceful ops on a console-group child =====

/// The parity contract, deliberately not `cfg`-gated so it is one test rather than two: the
/// `Child` pins the pid for its whole life, so an already-exited child is `Ok` on every
/// platform.
#[skuld::test]
fn child_terminate_reports_ok_for_an_already_exited_child() {
    let (child, sock) = common::spawn_control("control-block", &["R"], true);
    common::kill_release_reap(&child, sock);
    child.terminate().expect("already-dead must be Ok");
}

/// The case this capability exists for, end to end: a nested contained Windows child owns no
/// tree, leads a console process group of its own, and had no cooperative shutdown at all.
/// `break=1` is reachable only if that child's own handler acknowledged an event no tree op on
/// any handle in the system could have delivered to it; `tree=Unsupported` fails if the
/// containment gate was loosened.
#[cfg(windows)]
#[skuld::test]
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
        .env(common::ACK_ENV, "1")
        .contain();
    let mut child = cmd.spawn().expect("spawn reporter");
    let mut sock = common::accept_or_die(&listener, &mut child);
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

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
