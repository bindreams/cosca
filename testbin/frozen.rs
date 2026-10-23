//! The frozen-spawn helper modes. All use the `cosca` crate: they are the callers whose behaviour
//! `tests/windows_suspended.rs` measures from outside.
//!
//! - `spawn-frozen-report`: hold a contained frozen child and block, for the test to kill.
//! - `spawn-breakaway-report` and `spawn-breakaway-child`: whether a child's
//!   `CREATE_BREAKAWAY_FROM_JOB` grandchild is allowed.
//! - `spawn-measured-child`, `spawn-report-pid` and `report-pid`: a plain grandchild whose job
//!   membership the test checks.

use std::io::{Read, Write};

use windows::Win32::System::JobObjects::{JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_BREAKAWAY_OK};

/// A windowless command running `mode extra...` of this binary, through the backend `backend` names.
fn mode_command(backend: &str, mode: &str, extra: &[&str]) -> cosca::Command {
    let exe = std::env::current_exe().expect("own path");
    let exe = exe.to_str().expect("UTF-8 path").to_owned();
    let mut cmd = cosca::Command::new();
    match backend {
        "argv" => {
            cmd.args([exe.as_str(), mode]);
        }
        "executable" => {
            cmd.executable(exe.as_str()).args(["cosca_testbin", mode]);
        }
        other => panic!("unknown backend {other}"),
    }
    cmd.args(extra);
    cmd.env(crate::ack::ACK_ENV, "1");
    cmd.stdout(cosca::Stdio::null()).expect("null stdout");
    cmd.stderr(cosca::Stdio::null()).expect("null stderr");
    cmd.no_window();
    cmd
}

/// A windowless command for the `control-block` blocker, through the backend `backend` names.
fn blocker_command(backend: &str, addr: &str) -> cosca::Command {
    mode_command(backend, "control-block", &[addr, "G"])
}

pub fn spawn_frozen_report(addr: &str, backend: &str) -> ! {
    let mut sock = crate::ack::connect_control(addr).expect("connect to the test");
    // Never connected to: this child is never resumed, so its own address is a dead end.
    let mut cmd = blocker_command(backend, "127.0.0.1:9");
    cmd.contain();
    let frozen = cmd.spawn_suspended().expect("spawn the frozen grandchild");
    let child_pid = frozen.id().pid();
    writeln!(
        sock,
        "frozen pid={child_pid} containment={:?} job={}",
        frozen.test_containment(),
        u8::from(frozen.test_job_handle_contains_self()),
    )
    .expect("report");
    sock.flush().expect("flush");
    // The test opens its handle on the frozen child now, while this process still holds it.
    let mut go = [0u8; 1];
    sock.read_exact(&mut go).expect("wait for the test's go");
    // Block forever; never dropped, so the child's containment job alone must kill it.
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

/// Apply the shape a `spawn-measured-child` test names to `cmd`.
fn apply_shape(cmd: &mut cosca::Command, shape: &str) {
    match shape {
        "uncontained" => {}
        "contained" => {
            cmd.contain();
        }
        "treewalk" => {
            cmd.contain_with(cosca::ContainMode::TreeWalk);
        }
        other => panic!("unknown shape {other}"),
    }
}

/// Put this process into the ambient job `ambient` names: `j0`, a job of its own that forbids
/// breakaway; `jbreak`, one that permits breakaway; or `inherited`, the job the test spawned it
/// into, if any.
///
/// Returns the name the job can be opened by (the process keeps its handle, so the name lives as
/// long as the process), or `none` for `inherited`.
fn enter_ambient(ambient: &str) -> String {
    let limit = match ambient {
        "j0" => JOB_OBJECT_LIMIT(0),
        "jbreak" => JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        "inherited" => return "none".to_owned(),
        other => panic!("unknown ambient {other}"),
    };
    let name = format!("cosca-test-ambient-{}-{}", std::process::id(), ambient);
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    crate::breakaway::job_with_self_named(limit, windows::core::PCWSTR(wide.as_ptr()))
        .expect("put this process into the ambient job");
    name
}

/// Spawn the `spawn-report-pid` child as the test names, report its containment, tell it to
/// go, and hold until the test closes the socket.
///
/// `ambient` is as in [`enter_ambient`].
pub fn spawn_measured_child(addr: &str, backend: &str, shape: &str, how: &str, ambient: &str) -> ! {
    let ambient_job = enter_ambient(ambient);
    let mut sock = crate::ack::connect_control(addr).expect("connect to the test");
    let mut cmd = mode_command(backend, "spawn-report-pid", &[addr]);
    cmd.stdin(cosca::Stdio::pipe()).expect("stdin pipe");
    apply_shape(&mut cmd, shape);
    let mut child = match how {
        "frozen" => cmd
            .spawn_suspended()
            .expect("spawn the child frozen")
            .resume()
            .expect("resume the child"),
        "ordinary" => cmd.spawn().expect("spawn the child"),
        other => panic!("unknown how {other}"),
    };
    writeln!(
        sock,
        "helper containment={:?} ambient_job={ambient_job}",
        child.containment()
    )
    .expect("report");
    sock.flush().expect("flush");
    // Only now, with the frozen child resumed, may the child spawn.
    let mut stdin = child.stdin().expect("the child's stdin pipe");
    stdin.write_all(b"g").expect("send go");
    stdin.flush().expect("flush go");
    // Hold until the test closes the socket. The child holds until this process, and with it the
    // write end of its stdin, is gone.
    let mut b = [0u8; 1];
    while !matches!(sock.read(&mut b), Ok(0) | Err(_)) {}
    drop(stdin);
    child.wait().expect("reap the child");
    std::process::exit(0);
}

/// Spawn the `spawn-breakaway-report` child as the test names (the child reports, on its own
/// socket, whether its `CREATE_BREAKAWAY_FROM_JOB` grandchild was allowed), then hold until it exits,
/// which it does once the test closes that socket.
pub fn spawn_breakaway_child(addr: &str, backend: &str, shape: &str, how: &str, ambient: &str) -> ! {
    let _ = enter_ambient(ambient);
    let mut cmd = mode_command(backend, "spawn-breakaway-report", &[addr]);
    apply_shape(&mut cmd, shape);
    let child = match how {
        "frozen" => cmd
            .spawn_suspended()
            .expect("spawn the child frozen")
            .resume()
            .expect("resume the child"),
        "ordinary" => cmd.spawn().expect("spawn the child"),
        other => panic!("unknown how {other}"),
    };
    child.wait().expect("reap the child");
    std::process::exit(0);
}

/// Wait for go on stdin, spawn a plain grandchild (no containment, no breakaway flag) and keep its
/// handle, which keeps its pid naming it. Exits when stdin closes and the grandchild has gone.
pub fn spawn_report_pid(addr: &str) -> ! {
    let mut go = [0u8; 1];
    std::io::stdin().read_exact(&mut go).expect("wait for go");
    let exe = std::env::current_exe().expect("own path");
    let mut cmd = cosca::Command::new();
    cmd.args([exe.to_str().expect("UTF-8 path"), "report-pid", addr]);
    cmd.env(crate::ack::ACK_ENV, "1");
    cmd.stdout(cosca::Stdio::null()).expect("null stdout");
    cmd.stderr(cosca::Stdio::null()).expect("null stderr");
    cmd.no_window();
    let grandchild = cmd.spawn().expect("spawn the plain grandchild");
    let mut b = [0u8; 1];
    while !matches!(std::io::stdin().read(&mut b), Ok(0) | Err(_)) {}
    grandchild.wait().expect("reap the grandchild");
    std::process::exit(0);
}

/// Report this process's pid, then hold until the test closes the socket.
pub fn report_pid(addr: &str) -> ! {
    let mut sock = crate::ack::connect_control(addr).expect("connect to the test");
    writeln!(sock, "grandchild pid={}", std::process::id()).expect("report");
    sock.flush().expect("flush");
    let mut b = [0u8; 1];
    let _ = sock.read(&mut b);
    std::process::exit(0);
}
