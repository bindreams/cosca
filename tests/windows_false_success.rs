//! Windows: a child whose console is not ours gets a **false success** from the cooperative
//! shutdown ops — they return `Ok` and deliver nothing.
//!
//! This is wrong-but-current behaviour, pinned deliberately. Nothing in cosca can tell a target
//! that has not registered with a console yet from one that is in another console, so nothing
//! here refuses such a child; what cosca reports honestly is the *route*, as
//! `graceful_mechanism() == OtherConsoleGroup`. The gap closes when a console-joining helper
//! exists, and this file is what makes that landing flip a test rather than change behaviour in
//! silence.
//!
//! The control leg is not optional: without a leg that measures a DELIVERED signal under the same
//! handshake, "still alive" is satisfied by any build that never signals anything.
//!
//! Console-list hygiene: each false-success leg signals an out-of-console pid, which leaves one
//! persistent dead entry in the caller's console process list. CI runners get a fresh console per
//! job; locally, run this suite from a fresh terminal. No test here asserts the absence of a pid
//! it did not just spawn.
#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use cosca::identity::Liveness;
use cosca::{ContainMode, Containment, GracefulMechanism};

#[path = "common/mod.rs"]
mod common;

use common::testbin;

/// Spawn a testbin control child with arbitrary builder configuration, and read its 1-byte tag
/// BEFORE returning — the real edge proving the child is running and has completed console
/// registration.
///
/// The handshake applies to every leg, not only the control. Without it every child sits in the
/// measured pre-registration window, where a console-group signal IS delivered and kills the
/// child at loader init — so "still alive" would be false for the wrong reason in the
/// false-success legs, and the control would fail too.
///
/// `common::spawn_control` cannot serve: it takes no extra configuration.
fn spawn_configured(mode: &str, configure: impl Fn(&mut cosca::Command)) -> (cosca::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = cosca::Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", mode, addr.as_str(), "R"]);
    configure(&mut cmd);
    let child = cmd.spawn().expect("spawn control child");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    assert_eq!(&tag, b"R", "wrong control tag");
    (child, sock)
}

#[cfg(feature = "tokio")]
fn spawn_configured_async(
    mode: &str,
    configure: impl Fn(&mut cosca::tokio::Command),
) -> (cosca::tokio::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", mode, addr.as_str(), "R"]);
    configure(&mut cmd);
    let child = cmd.spawn().expect("spawn async control child");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    assert_eq!(&tag, b"R", "wrong control tag");
    (child, sock)
}

/// THE CONTROL. A contained root with no flag methods really receives the break: its own console
/// ctrl handler writes `B` back over its socket, which is the only positive evidence of delivery
/// — the Win32 return value is evidence in neither direction.
///
/// Without this leg the three below pass against any build that never signals anything.
#[test]
fn a_plain_contained_root_really_receives_the_break() {
    let (child, mut sock) = spawn_configured("control-block-ack-break", |c| {
        c.contain();
    });
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    child.terminate_tree().expect("terminate_tree on a contained root");

    let mut ack = [0u8; 1];
    sock.read_exact(&mut ack)
        .expect("the child's ctrl handler must write its ack; EOF here means it died instead");
    assert_eq!(&ack, b"B", "the child acked something other than CTRL_BREAK");

    drop(sock);
    child.kill_tree().expect("kill_tree");
    child.wait().expect("reap");
}

/// A delivered `CTRL_BREAK` ends a handler-less child with `STATUS_CONTROL_C_EXIT`. Measured on
/// Windows 11 26100, 20 consecutive runs each way: a plain contained child exits with this, and a
/// suppressed or detached one exits `0` because nothing reached it and it was released by the
/// test's own byte.
const STATUS_CONTROL_C_EXIT: i32 = 0xC000_013Au32 as i32;

/// The shared body of the three false-success legs: a contained root whose creation flags put it
/// in a console of its own.
///
/// `control-block` installs NO break handler, so a delivered break kills it via the default
/// disposition — which is exactly what a plain contained child does under the same handshake.
///
/// **The subject is HOW the child died, so the assertion is on its termination status.** After
/// the cooperative op has reported success, the child is released through its own socket — a real
/// edge, not a duration — and must then exit `0`: it ended on the test's byte, having received
/// nothing. A delivered break would have ended it with `STATUS_CONTROL_C_EXIT` first. A
/// `Liveness` poll taken at the instant the op returns cannot serve here: measured, it reads
/// `Alive` for a plain contained child that is already dying, so it is the same value in both
/// worlds.
///
/// The second child is for the other half: the FORCED op still works on such a child even though
/// the cooperative one reached nobody. `graceful_shutdown_tree` waits out the exit before it
/// returns, so the `Dead` there is an edge and not a poll.
fn assert_false_success(expected_containment: Containment, configure: impl Fn(&mut cosca::Command)) {
    let (child, mut sock) = spawn_configured("control-block", &configure);
    assert_eq!(
        child.containment(),
        expected_containment,
        "this test is about the wrong thing if containment did not take"
    );
    assert_eq!(
        child.graceful_mechanism(),
        GracefulMechanism::OtherConsoleGroup,
        "cosca's honest report of the route; a derivation reading only the containment half of          the creation-flag word says ConsoleGroup here"
    );

    child
        .terminate_tree()
        .expect("the cooperative op reports success — that is the gap this pins");
    sock.write_all(b"x").expect("release the child through its own socket");
    let status = child.wait().expect("reap");
    assert_eq!(
        status.code(),
        Some(0),
        "the child exited on OUR release byte, so the cooperative op delivered nothing; a          delivered break would have ended it with STATUS_CONTROL_C_EXIT ({STATUS_CONTROL_C_EXIT})"
    );
    drop(sock);

    // A second child, because the first is already gone: the FORCED half of the graceful op
    // still tears such a tree down.
    let (child, sock) = spawn_configured("control-block", &configure);
    child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect("the forced half tears the tree down");
    assert_eq!(child.is_alive(), Liveness::Dead, "the forced half really ended it");
    drop(sock);
}

#[test]
fn a_no_window_contained_root_gets_a_false_success() {
    assert_false_success(Containment::JobObject, |c| {
        c.contain().no_window();
    });
}

#[test]
fn a_detached_contained_root_gets_a_false_success() {
    assert_false_success(Containment::JobObject, |c| {
        c.contain().detached();
    });
}

/// A distinct route into the same call site: on Windows `Attached::TreeWalk` reaches
/// `containment::windows::terminate` through `treewalk::terminate`, so a change made in one arm
/// only would miss it.
#[test]
fn a_treewalk_contained_root_gets_a_false_success_too() {
    assert_false_success(Containment::TreeWalk, |c| {
        c.contain_with(ContainMode::TreeWalk).no_window();
    });
}

// ===== async mirrors: parity is not compiler-enforced =====

#[cfg(feature = "tokio")]
#[tokio::test]
async fn an_async_plain_contained_root_really_receives_the_break() {
    let (mut child, mut sock) = spawn_configured_async("control-block-ack-break", |c| {
        c.contain();
    });
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    child.terminate_tree().expect("terminate_tree on a contained root");

    let mut ack = [0u8; 1];
    sock.read_exact(&mut ack)
        .expect("the child's ctrl handler must write its ack; EOF here means it died instead");
    assert_eq!(&ack, b"B");

    drop(sock);
    child.kill_tree().expect("kill_tree");
    child.wait().await.expect("reap");
}

#[cfg(feature = "tokio")]
async fn assert_false_success_async(expected_containment: Containment, configure: impl Fn(&mut cosca::tokio::Command)) {
    let (mut child, mut sock) = spawn_configured_async("control-block", &configure);
    assert_eq!(child.containment(), expected_containment);
    assert_eq!(
        child.graceful_mechanism(),
        GracefulMechanism::OtherConsoleGroup,
        "the async derivation must read the composed word too"
    );

    child.terminate_tree().expect("the cooperative op reports success");
    sock.write_all(b"x").expect("release the child through its own socket");
    let status = child.wait().await.expect("reap");
    assert_eq!(
        status.code(),
        Some(0),
        "the child exited on OUR release byte, so the cooperative op delivered nothing"
    );
    drop(sock);

    let (mut child, sock) = spawn_configured_async("control-block", &configure);
    child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("the forced half tears the tree down");
    assert_eq!(child.is_alive(), Liveness::Dead);
    drop(sock);
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn an_async_no_window_contained_root_gets_a_false_success() {
    assert_false_success_async(Containment::JobObject, |c| {
        c.contain().no_window();
    })
    .await;
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn an_async_detached_contained_root_gets_a_false_success() {
    assert_false_success_async(Containment::JobObject, |c| {
        c.contain().detached();
    })
    .await;
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn an_async_treewalk_contained_root_gets_a_false_success_too() {
    assert_false_success_async(Containment::TreeWalk, |c| {
        c.contain_with(ContainMode::TreeWalk).no_window();
    })
    .await;
}
