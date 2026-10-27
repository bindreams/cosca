//! Windows: the console-group graceful signal (`CTRL_BREAK`) is delivered only within the
//! CALLING process's console. What the graceful ops do from a console-less caller is checked in
//! `src/child/ctrl_break_tests.rs`, which needs the sender's own record of the breaks; only this
//! crate's unit-test binary has it.
//!
//! The flag-matrix tests at the top measure what the creation-flag word does and does not
//! settle about console membership, and their discriminating power comes from the control legs
//! disagreeing with the exclusion legs — not from a before/after.

#[cfg(windows)]
use std::io::Read;
#[cfg(windows)]
use std::net::TcpListener;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;

#[cfg(windows)]
/// `DETACHED_PROCESS`: the new process gets NO console and does not inherit ours — the
/// GUI-app / service / detached-spawn caller these tests run against.
const DETACHED_PROCESS: u32 = 0x0000_0008;

#[cfg(windows)]
/// The three creation flags that keep a child out of the spawner's console, and the group flag
/// whose presence is what makes a child individually addressable at all. Raw constants because
/// `CommandExt::creation_flags` takes a plain `u32` (winbase.h).
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
#[cfg(windows)]
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
/// Spawn `exe` with exactly `flags`, block on its 1-byte tag, and hand back the child and its
/// socket. The tag is the load-bearing part: console registration is not synchronous with
/// `CreateProcess` returning, so a membership probe taken before it reads "absent" for every
/// flag word, including one with no detaching flag at all — and a matrix asserted at that
/// instant could never fail.
fn spawn_tagged_with_flags(exe: &str, args: &[&str], flags: u32) -> (std::process::Child, std::net::TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .arg(&addr)
        .env(common::ACK_ENV, "1")
        .creation_flags(flags);
    let mut child = common::spawn_locked(&mut cmd).expect("spawn flag-matrix child");
    let mut sock = common::accept_or_die(&listener, &mut child);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

#[cfg(windows)]
/// Kill and reap a flag-matrix child, dropping its socket first so a child blocked on the read
/// can also exit on EOF.
fn end(mut child: std::process::Child, sock: std::net::TcpStream) {
    drop(sock);
    let _ = child.kill();
    child.wait().expect("reap flag-matrix child");
}

#[cfg(windows)]
/// The control: membership does NOT come from `CREATE_NEW_PROCESS_GROUP`, and it does not come
/// from passing no flags either. Both legs must read present, which is what makes the exclusion
/// tests below discriminating rather than vacuous — and what fails if the tag handshake above
/// stopped being a real happens-before edge.
#[skuld::test]
fn console_group_flag_keeps_a_child_in_our_console() {
    for flags in [CREATE_NEW_PROCESS_GROUP, 0] {
        let (child, sock) = spawn_tagged_with_flags(env!("CARGO_BIN_EXE_cosca_testbin"), &["control-block"], flags);
        let seen = common::in_our_console(child.id());
        assert_eq!(
            seen,
            Some(true),
            "a console-subsystem child spawned with flags {flags:#x} must be in our console"
        );
        end(child, sock);
    }
}

#[cfg(windows)]
/// Each of the three detaching/suppressing flags excludes the child from our console, under the
/// same post-handshake timing the control above measures as present.
#[skuld::test]
fn console_detaching_flags_leave_a_child_outside_our_console() {
    for flag in [DETACHED_PROCESS, CREATE_NEW_CONSOLE, CREATE_NO_WINDOW] {
        let (child, sock) = spawn_tagged_with_flags(
            env!("CARGO_BIN_EXE_cosca_testbin"),
            &["control-block"],
            CREATE_NEW_PROCESS_GROUP | flag,
        );
        let seen = common::in_our_console(child.id());
        // `Some(false)`, never a bare falsy: a `None` probe result must fail this test, not
        // pass it.
        assert_eq!(
            seen,
            Some(false),
            "flag {flag:#x} must keep the child out of our console"
        );
        end(child, sock);
    }
}

#[cfg(windows)]
/// A GUI-subsystem image is outside our console under the exact flag word that keeps a
/// console-subsystem image inside it. This is why the creation-flag word is a sound negative
/// and an unsound positive: no flag can establish membership.
#[skuld::test]
fn a_gui_subsystem_child_is_outside_our_console_whatever_its_flags() {
    let (child, sock) = spawn_tagged_with_flags(env!("CARGO_BIN_EXE_cosca_testbin_gui"), &[], CREATE_NEW_PROCESS_GROUP);
    let seen = common::in_our_console(child.id());
    assert_eq!(
        seen,
        Some(false),
        "a GUI-subsystem child never attaches to the spawner's console"
    );
    end(child, sock);
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
