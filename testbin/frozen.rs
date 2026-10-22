//! The frozen-spawn helper modes. Both use the `cosca` crate: they are the callers whose behaviour
//! `tests/windows_suspended.rs` measures from outside.
//!
//! - `spawn-frozen-report <addr> <shape> <backend>`: spawn a frozen `control-block` child, report
//!   it, hold it frozen until the test says go, then block forever without ever dropping it. The
//!   test kills this process; whatever then happens to the frozen child is the guard's doing.
//! - `spawn-breakaway-report <addr> <how>`: be the child of a frozen spawn (or an ordinary one),
//!   spawn a grandchild with `CREATE_BREAKAWAY_FROM_JOB`, and report whether the OS allowed it.

use std::io::{Read, Write};

/// A windowless command for the `control-block` blocker, through the backend `backend` names.
fn blocker_command(backend: &str, addr: &str) -> cosca::Command {
    let exe = std::env::current_exe().expect("own path");
    let exe = exe.to_str().expect("UTF-8 path").to_owned();
    let mut cmd = cosca::Command::new();
    match backend {
        "argv" => {
            cmd.args([exe.as_str(), "control-block", addr, "G"]);
        }
        "executable" => {
            cmd.executable(exe.as_str())
                .args(["cosca_testbin", "control-block", addr, "G"]);
        }
        other => panic!("unknown backend {other}"),
    }
    cmd.env(crate::ack::ACK_ENV, "1");
    cmd.stdout(cosca::Stdio::null()).expect("null stdout");
    cmd.stderr(cosca::Stdio::null()).expect("null stderr");
    cmd.no_window();
    cmd
}

pub fn spawn_frozen_report(addr: &str, shape: &str, backend: &str) -> ! {
    let mut sock = crate::ack::connect_control(addr).expect("connect to the test");
    // Never connected to: this child is never resumed, so its own address is a dead end.
    let mut cmd = blocker_command(backend, "127.0.0.1:9");
    if shape == "contained" {
        cmd.contain();
    }
    let frozen = cmd.spawn_suspended().expect("spawn the frozen grandchild");
    let child_pid = frozen.id().pid();
    writeln!(
        sock,
        "frozen pid={child_pid} job={} guard={}",
        u8::from(frozen.test_job_handle_contains_self()),
        u8::from(frozen.test_guard_job_contains_self()),
    )
    .expect("report");
    sock.flush().expect("flush");
    // The test opens its handle on the frozen child now, while this process still holds it.
    let mut go = [0u8; 1];
    sock.read_exact(&mut go).expect("wait for the test's go");
    // Block until killed. `exit` runs no destructors, so the frozen child is never dropped here.
    let mut b = [0u8; 1];
    loop {
        if matches!(sock.read(&mut b), Ok(0) | Err(_)) {
            std::process::exit(0);
        }
    }
}

pub fn spawn_breakaway_report(addr: &str) -> ! {
    let mut sock = crate::ack::connect_control(addr).expect("connect to the test");
    let exe = std::env::current_exe().expect("own path");
    // A grandchild that exits at once: only the spawn's verdict is wanted.
    let mut cmd = cosca::Command::new();
    cmd.args([exe.to_str().expect("UTF-8 path"), "exit", "0"]);
    cmd.breakaway_from_job().no_window();
    let verdict = match cmd.spawn() {
        Ok(grandchild) => {
            grandchild.wait().expect("reap the grandchild");
            "ok".to_owned()
        }
        Err(e) => format!("err:{e}").replace(char::is_whitespace, "_"),
    };
    writeln!(sock, "breakaway:{verdict}").expect("report");
    sock.flush().expect("flush");
    let mut b = [0u8; 1];
    let _ = sock.read(&mut b);
    std::process::exit(0);
}
