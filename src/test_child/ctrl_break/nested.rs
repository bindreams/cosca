//! The root of a nested contained child (Windows): a re-exec'd process that is itself a contained
//! member, so the child it spawns contained is a [`Delegated`](crate::Containment::Delegated)
//! member that owns no tree teardown yet leads a console process group of its own.
//!
//! The root makes the calls itself, so its `CTRL_BREAK` record is the one that `terminate` wrote.
//! It asserts that record before it waits for the nested child's ack, so a `terminate` that sends
//! nothing panics the root instead of leaving it blocked, and the caller sees the root fail.

use std::io::{Read, Write};

use super::{accept_root, assert_break_sent_to, in_our_console, member_argv, member_env, Handler};
use crate::test_child::{ack, fixture_argv, registration_rendezvous};
use crate::{Containment, GracefulMechanism};

/// The fully-qualified libtest path of [`fixture_nested_terminate_root`].
const ROOT_TEST: &str = "test_child::ctrl_break::nested::fixture_nested_terminate_root";

/// The `127.0.0.1:<port>` address the root reports to. Its presence also tells the fixture it was
/// re-exec'd deliberately rather than picked up by an ordinary suite run.
pub(crate) const ADDR_ENV: &str = "COSCA_FIXTURE_NESTED_TERMINATE_ADDR";

/// What the root writes after every assertion has held.
pub(crate) const DONE: &str = "done";

/// The argv of a re-exec'd [`fixture_nested_terminate_root`]; see [`fixture_argv`].
pub(crate) fn root_argv() -> [&'static str; 5] {
    fixture_argv(ROOT_TEST)
}

/// Runs the nested-terminate checks and writes [`DONE`] to the caller's socket.
#[skuld::test]
fn fixture_nested_terminate_root() {
    let Some(addr) = std::env::var_os(ADDR_ENV) else {
        return;
    };
    let mut report = ack::connect_control(addr.into_string().expect("utf8 addr")).expect("connect the report socket");

    let (listener, member_addr) = registration_rendezvous();
    let mut cmd = crate::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(member_argv());
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    for (key, value) in member_env(&member_addr, Handler::Ack, None) {
        cmd.env(key, value);
    }
    cmd.contain();
    let nested = cmd.spawn().expect("spawn the nested member");
    // The tag is written after the member's handler is installed and its console registered.
    let mut sock = accept_root(&listener, nested.id());
    let pid = nested.id().pid();

    assert_eq!(nested.containment(), Containment::Delegated);
    assert_eq!(nested.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_eq!(in_our_console(pid), Some(true), "the member must share our console");
    // A nested member owns no tree teardown. Asserted before `terminate`, so that a gate loosened
    // into sending would put a second entry in the record the assertion below requires.
    assert!(
        matches!(nested.terminate_tree(), Err(crate::error::Error::Unsupported { .. })),
        "a nested member still owns no tree teardown"
    );
    nested.terminate().expect("terminate a delegated console-group child");
    assert_break_sent_to(pid);
    let mut ack = [0u8; 1];
    sock.read_exact(&mut ack)
        .expect("the nested member's own handler must acknowledge the break");
    assert_eq!(&ack, b"B", "the member acked something other than CTRL_BREAK");

    nested.kill().expect("kill the nested member");
    drop(sock);
    // Released after the kill: the member leaves with 0 when released, so code 1 is the kill's.
    let status = nested.wait().expect("reap the nested member");
    assert_eq!(
        status.code(),
        Some(1),
        "kill must end the nested member, got {status:?}"
    );
    report.write_all(DONE.as_bytes()).expect("write the report");
    report.flush().expect("flush the report");
}
