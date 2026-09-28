//! Linux-only regression coverage for `crate::wait`'s foreign-process wait against a LIVE
//! non-leader thread id. `pidfd_open` requires the pid number it is given to resolve to a
//! THREAD-GROUP-LEADER task (`pid_has_task(pid, PIDTYPE_TGID)`, v6.15 kernel/fork.c:2114); a
//! live tid that is not its process's leader fails that check even though the task it names is
//! not gone — before Linux 6.16 with `EINVAL`, and from 6.16 (commit 8cf4b738) with `ENOENT`.
//! Reporting that as "exited" would be an early verdict on a still-running task.
//!
//! The sibling case — a process-group leader that HAS exited and been reaped while another
//! member of its group is still alive, which also hits `EINVAL`/`ENOENT` but must be reported
//! as exited — is `src/wait/linux_tests.rs`'s
//! `block_until_exit_reports_exited_for_a_reaped_pgid_leader`; that scenario needs a raw
//! `fork()` tree whose direct parent is the process that reaps the leader, which an
//! integration-test binary (not the leader's parent) cannot reproduce, so it lives as a
//! crate-internal unit test instead.
#![cfg(target_os = "linux")]

use std::io::BufRead;

#[path = "common/mod.rs"]
mod common;
use common::testbin;

/// Mutant: "treat EINVAL/ENOENT as gone without the exists() check". Without the `exists()`
/// fallback in `open_verified` (`src/wait/linux.rs`), `pidfd_open`'s `EINVAL`/`ENOENT` on this
/// live non-leader tid would be read as "already gone", and `Process::wait` would return `Ok(())`
/// for a task that is still running.
///
/// Asserts on the error's KIND and MESSAGE (`live_non_leader_error`'s cause text), not merely
/// that it is `Err`: the bare errno alone — `NotFound` from `ENOENT` on 6.16+ — reads as a
/// plain "gone" that a careless caller could misinterpret, which is exactly what this whole
/// bug was about at the other end of the same arm; `open_verified` deliberately does not
/// forward it as-is. Never asserts on which of `EINVAL`/`ENOENT` the kernel itself returned:
/// that depends on the kernel version (see this file's and `src/wait/linux.rs`'s module docs),
/// and both must map to the identical, kernel-independent cause below.
#[test]
fn block_until_exit_on_a_live_non_leader_tid_is_an_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();

    let mut cmd = cosca::Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "report-tid-block-stdin", &addr]);
    cmd.stdin(cosca::Stdio::pipe()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn the tid reporter");
    let writer = child.stdin().expect("take the stdin pipe writer");

    let (sock, _) = listener.accept().expect("accept the control connection");
    let mut reader = std::io::BufReader::new(sock);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read the reported tid");
    let tid: u32 = line.trim().parse().expect("the reported tid is a plain decimal number");
    assert_ne!(
        tid,
        child.id().pid(),
        "the reported tid must be the WORKER thread's, not the process leader's"
    );

    let p = cosca::Process::from_pid(tid)
        .found()
        .expect("the live worker thread's tid resolves to an identity");
    let result = p.wait();
    match result {
        Err(cosca::error::Error::Io(e)) => {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::InvalidInput,
                "wrong error kind for a live non-leader tid: {e}"
            );
            assert!(
                e.to_string().contains("not a thread-group leader"),
                "the error must name the real cause, got: {e}"
            );
        }
        other => panic!("block_until_exit on a live non-leader tid must be a descriptive Io error, got {other:?}"),
    }

    // Cleanup: EOF the child's blocking stdin read (a real event, not a signal to a group), then
    // reap it normally.
    drop(writer);
    let status = child.wait().expect("reap the tid reporter");
    assert!(
        status.success(),
        "the tid reporter must exit 0 on stdin EOF, got {status:?}"
    );
}
