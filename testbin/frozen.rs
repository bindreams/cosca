//! The frozen-spawn helper modes. All use the `cosca` crate: they are the callers whose behaviour
//! `tests/windows_suspended.rs` measures from outside.
//!
//! - `spawn-frozen-report <addr> <shape> <backend>`: spawn a frozen `control-block` child, report
//!   it, hold it frozen until the test says go, then block forever without ever dropping it. The
//!   test kills this process; whatever then happens to the frozen child is the guard's doing.
//! - `spawn-breakaway-report <addr> <how>`: be the child of a frozen spawn (or an ordinary one),
//!   spawn a grandchild with `CREATE_BREAKAWAY_FROM_JOB`, and report whether the OS allowed it.
//! - `spawn-measured-child <addr> <backend> <shape> <how> <ambient>`: spawn a child of the given
//!   shape, frozen and resumed or by an ordinary `spawn()`, and report its containment. The child
//!   (`spawn-report-job-flags`) spawns a plain grandchild (`report-job-flags`) once told to go, and
//!   the grandchild reports the limit flags of the job it sits in. The test compares the two `how`s.

use std::io::{Read, Write};

use windows::Win32::System::JobObjects::{
    JobObjectBasicLimitInformation, QueryInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
};

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
        "frozen pid={child_pid} containment={:?} job={} guard={}",
        frozen.test_containment(),
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

/// Spawn the `spawn-report-job-flags` child as the test names, report its containment, tell it to
/// go, and hold until the test closes the socket.
///
/// `ambient` is `j0` to first put this process into a job of its own, which forbids breakaway and
/// carries a flag no other job in the test has, or `inherited` to stay in the job the test spawned
/// it into.
pub fn spawn_measured_child(addr: &str, backend: &str, shape: &str, how: &str, ambient: &str) -> ! {
    match ambient {
        "j0" => {
            let limit = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            crate::breakaway::job_with_self(limit).expect("put this process into the ambient job");
        }
        "inherited" => {}
        other => panic!("unknown ambient {other}"),
    }
    let mut sock = crate::ack::connect_control(addr).expect("connect to the test");
    let mut cmd = mode_command(backend, "spawn-report-job-flags", &[addr]);
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
    writeln!(sock, "helper containment={:?}", child.containment()).expect("report");
    sock.flush().expect("flush");
    // Only now, with the frozen child resumed and its guard released, may the child spawn.
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

/// Wait for go on stdin, spawn a plain grandchild (no containment, no breakaway flag) and keep its
/// handle, which keeps its pid naming it. Exits when stdin closes and the grandchild has gone.
pub fn spawn_report_job_flags(addr: &str) -> ! {
    let mut go = [0u8; 1];
    std::io::stdin().read_exact(&mut go).expect("wait for go");
    let exe = std::env::current_exe().expect("own path");
    let mut cmd = cosca::Command::new();
    cmd.args([exe.to_str().expect("UTF-8 path"), "report-job-flags", addr]);
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

/// Report this process's pid and the limit flags of its innermost job, then hold until the test
/// closes the socket.
pub fn report_job_flags(addr: &str) -> ! {
    let mut sock = crate::ack::connect_control(addr).expect("connect to the test");
    let mut info = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
    // SAFETY: standard Win32; `info` is a valid, correctly sized out-parameter. `None` asks about
    // the calling process's own job.
    let queried = unsafe {
        QueryInformationJobObject(
            None,
            JobObjectBasicLimitInformation,
            std::ptr::addr_of_mut!(info).cast(),
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            None,
        )
    };
    let flags = match queried {
        Ok(()) => format!("{:#x}", info.LimitFlags.0),
        Err(_) => "not-in-a-job".to_owned(),
    };
    writeln!(sock, "grandchild pid={} job_flags={flags}", std::process::id()).expect("report");
    sock.flush().expect("flush");
    let mut b = [0u8; 1];
    let _ = sock.read(&mut b);
    std::process::exit(0);
}
