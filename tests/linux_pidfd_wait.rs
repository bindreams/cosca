//! Regression tests: a non-leader tid must not be reported as a live-and-exited process.
//! `pidfd_open` refuses such a tid (EINVAL < 6.16, ENOENT >= 6.16); see `open_verified`. A live
//! one is `NotThreadGroupLeader`; an exited-but-unreaped (ptraced) one is exited. The
//! reaped-leader sibling is in `src/wait/linux_tests.rs`.
#![cfg(target_os = "linux")]

use std::io::{BufRead, Write};

#[path = "common/mod.rs"]
mod common;
use common::testbin;

/// Spawn the testbin `mode`, returning the child, its stdin writer, and the listener its control
/// connection arrives on.
fn spawn_tid_reporter(mode: &str) -> (cosca::Child, std::io::PipeWriter, std::net::TcpListener) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();

    let mut cmd = cosca::Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", mode, &addr])
        .env(common::ACK_ENV, "1");
    cmd.stdin(cosca::Stdio::pipe()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn the tid reporter");
    let writer = child.stdin().expect("take the stdin pipe writer");
    (child, writer, listener)
}

fn accept_reader(
    listener: &std::net::TcpListener,
    child: &mut cosca::Child,
) -> std::io::BufReader<std::net::TcpStream> {
    std::io::BufReader::new(common::accept_or_die(listener, child))
}

fn read_tid(reader: &mut std::io::BufReader<std::net::TcpStream>) -> u32 {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read the reported tid");
    line.trim().parse().expect("the reported tid is a plain decimal number")
}

/// A live non-leader tid is `NotThreadGroupLeader`, on every kernel, with the pid and the
/// `pidfd_open` errno as data.
#[test]
fn block_until_exit_on_a_live_non_leader_tid_is_an_error() {
    let (mut child, writer, listener) = spawn_tid_reporter("report-tid-block-stdin");
    let mut reader = accept_reader(&listener, &mut child);
    let tid = read_tid(&mut reader);
    assert_ne!(
        tid,
        child.id().pid(),
        "the reported tid must be the WORKER thread's, not the process leader's"
    );

    let p = cosca::Process::from_pid(tid)
        .found()
        .expect("the live worker thread's tid resolves to an identity");
    match p.wait() {
        Err(cosca::error::Error::NotThreadGroupLeader { pid, source, .. }) => {
            assert_eq!(pid, tid);
            assert!(
                matches!(source.raw_os_error(), Some(libc::EINVAL | libc::ENOENT)),
                "pidfd_open's refusal is EINVAL (< 6.16) or ENOENT (>= 6.16), got {source:?}"
            );
        }
        other => panic!("block_until_exit on a live non-leader tid must be NotThreadGroupLeader, got {other:?}"),
    }

    // EOF the child's blocking stdin read, then reap it normally.
    drop(writer);
    let status = child.wait().expect("reap the tid reporter");
    assert!(
        status.success(),
        "the tid reporter must exit 0 on stdin EOF, got {status:?}"
    );
}

/// A ptraced non-leader thread that has exited stays a zombie, attached to its pid, until its
/// tracer waits for it: `pidfd_open` refuses it like a live one, `/proc` still lists it, but it is
/// exited. Waiting on it must report exited.
#[test]
fn block_until_exit_on_a_ptraced_zombie_thread_reports_exited() {
    let (mut child, writer, listener) = spawn_tid_reporter("traced-worker");
    let leader = child.id().pid() as libc::pid_t;
    let mut tracer = Tracer {
        leader,
        worker: None,
        writer: Some(writer),
    };

    // This thread is the tracer: it must attach, wait and resume.
    // SAFETY: PTRACE_SEIZE on this process's own child. `ptrace` is variadic and the kernel reads
    // `addr`/`data` at full width, so pass pointer-width values.
    let seized = unsafe {
        libc::ptrace(
            libc::PTRACE_SEIZE,
            leader,
            std::ptr::null_mut::<libc::c_void>(),
            libc::PTRACE_O_TRACECLONE as usize as *mut libc::c_void,
        )
    };
    assert_eq!(seized, 0, "PTRACE_SEIZE: {}", std::io::Error::last_os_error());
    tracer
        .writer()
        .write_all(b"g")
        .expect("tell the child to spawn its worker");

    // The leader stops at its clone event; the new thread starts stopped.
    let clone_event = wait_stop(leader);
    let mut new_tid: libc::c_ulong = 0;
    // SAFETY: PTRACE_GETEVENTMSG writes one `unsigned long` through the data pointer. `ptrace` is
    // variadic and the kernel reads `addr`/`data` at full width, so pass pointer-width values.
    let got = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            leader,
            std::ptr::null_mut::<libc::c_void>(),
            &raw mut new_tid,
        )
    };
    assert_eq!(got, 0, "PTRACE_GETEVENTMSG: {}", std::io::Error::last_os_error());
    let worker = new_tid as libc::pid_t;
    tracer.worker = Some(worker);
    assert_eq!(clone_event >> 16, libc::PTRACE_EVENT_CLONE, "status {clone_event:#x}");
    wait_stop(worker);
    resume(leader);
    resume(worker);

    let mut reader = accept_reader(&listener, &mut child);
    let tid = read_tid(&mut reader);
    assert_eq!(tid, worker as u32, "the reported tid is the traced worker's");
    let p = cosca::Process::from_pid(tid)
        .found()
        .expect("the live worker thread's tid resolves to an identity");

    tracer.writer().write_all(b"x").expect("tell the worker to exit");
    // Observe the worker's exit without reaping it: it stays a zombie until this thread waits.
    // SAFETY: `info` is a valid, zeroed out-param; WNOWAIT leaves the zombie in place.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            worker as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::__WALL,
        )
    };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());

    assert_eq!(
        p.wait().map_err(|e| format!("{e:?}")),
        Ok(()),
        "a zombie non-leader thread has exited"
    );

    // Reap the zombie thread, then let the leader exit on stdin EOF.
    // SAFETY: `worker` is a traced thread of our child; a null status pointer is allowed.
    let reaped = unsafe { libc::waitpid(worker, std::ptr::null_mut(), libc::__WALL) };
    assert_eq!(reaped, worker, "waitpid: {}", std::io::Error::last_os_error());
    drop(tracer.writer.take());
    let status = child.wait().expect("reap the traced child");
    assert!(status.success(), "the child must exit 0 on stdin EOF, got {status:?}");
}

/// The tracer's side of the ptrace test. If the test panics, kills the traced child and reaps its
/// worker thread: a thread group's leader cannot finish exiting while a traced thread is an
/// unreaped zombie, so without this a failed assertion would hang the child's own reap.
struct Tracer {
    leader: libc::pid_t,
    worker: Option<libc::pid_t>,
    writer: Option<std::io::PipeWriter>,
}

impl Tracer {
    fn writer(&mut self) -> &mut std::io::PipeWriter {
        self.writer
            .as_mut()
            .expect("the writer is open until the end of the test")
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        // SAFETY: `leader` is this process's own unreaped child, so its pid cannot be recycled.
        unsafe { libc::kill(self.leader, libc::SIGKILL) };
        if let Some(worker) = self.worker {
            // SAFETY: a null status pointer is allowed; ECHILD (already reaped) is expected.
            unsafe { libc::waitpid(worker, std::ptr::null_mut(), libc::__WALL) };
        }
    }
}

/// Block until `pid` (a tracee of this thread) reports a stop; returns the raw wait status.
fn wait_stop(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a valid out-param.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if r == pid {
            assert!(libc::WIFSTOPPED(status), "expected a ptrace stop, status {status:#x}");
            return status;
        }
        assert!(
            r == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted,
            "waitpid({pid}): {r} {}",
            std::io::Error::last_os_error()
        );
    }
}

fn resume(pid: libc::pid_t) {
    // SAFETY: PTRACE_CONT on a stopped tracee of this thread, delivering no signal. `ptrace` is
    // variadic and the kernel reads `addr`/`data` at full width, so pass pointer-width values.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    assert_eq!(rc, 0, "PTRACE_CONT({pid}): {}", std::io::Error::last_os_error());
}

/// A tid reporter that dies before connecting fails the helper naming the death, not hangs it.
#[test]
fn death_watch_accept_or_die_reader_panics_when_the_tid_reporter_dies_before_connecting() {
    let (mut child, _writer, listener) = spawn_tid_reporter("--not-a-real-mode");
    let pid = child.id().pid();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| accept_reader(&listener, &mut child)));
    let message = common::panic_message(result.expect_err("the accept must panic, not return or hang"));
    assert!(
        message.contains(&format!("the control target (pid {pid}) died before it connected")),
        "got: {message:?}"
    );
}
