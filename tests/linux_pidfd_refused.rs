//! `pidfd_open` refused by a real seccomp filter is `Unsupported` in the policy's message shape.
//! The unit tests force the errno through a seam; these tests make the kernel answer it.

#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use cosca::error::Error;

#[cfg(target_os = "linux")]
#[path = "common/mod.rs"]
mod common;

#[cfg(target_os = "linux")]
const REFUSALS: [(i32, &str); 4] = [
    (libc::EPERM, "EPERM"),
    (libc::EACCES, "EACCES"),
    (libc::ENODEV, "ENODEV"),
    (libc::ENOSYS, "ENOSYS"),
];

#[cfg(target_os = "linux")]
fn assert_refused(result: Result<impl std::fmt::Debug, Error>, op: &str, errno: &str) {
    match result {
        Err(e @ Error::Unsupported { .. }) => assert_eq!(
            e.to_string(),
            format!(
                "{op} is not supported on linux: cosca requires pidfd_open (Linux \u{2265} 5.3), \
                 refused here: pidfd_open answered {errno}"
            )
        ),
        other => panic!("{op} under a pidfd_open answering {errno} must be Unsupported, got {other:?}"),
    }
}

/// Mutants: an errno missing from the refusals; an op named as another; the message shape;
/// `Child::kill` routed through `pidfd_open`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_pidfd_open_is_unsupported_for_every_operation() {
    for (code, name) in REFUSALS {
        let (child, _control) = common::spawn_blocker();
        let process = cosca::Process::from_pid(child.id().pid())
            .found()
            .expect("resolve the child");
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    assert_refused(process.wait(), "process wait", name);
                    assert_refused(process.wait_timeout(Duration::ZERO), "process wait", name);
                    assert_refused(process.kill(), "process kill", name);
                    assert_refused(process.terminate(), "process terminate", name);
                    assert_refused(process.graceful_shutdown(Duration::ZERO), "process terminate", name);
                    assert_refused(child.terminate(), "process terminate", name);
                    assert_refused(child.graceful_shutdown(Duration::ZERO), "process terminate", name);
                    // An owned child is killed through its own handle: no pidfd, so no refusal.
                    child.kill().expect("Child::kill needs no pidfd_open");
                })
                .join()
                .expect("the filtered thread");
        });
        child.kill().expect("kill the child");
        child.wait().expect("reap the child");
    }
}

#[cfg(target_os = "linux")]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_seccomp_refused_pidfd_open_is_unsupported_for_every_async_operation() {
    for (code, name) in REFUSALS {
        let (child, _control) = common::spawn_blocker();
        let process = cosca::tokio::Process::from_pid(child.id().pid())
            .found()
            .expect("resolve the child");
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("runtime");
                    runtime.block_on(async {
                        assert_refused(process.wait().await, "process wait", name);
                        assert_refused(
                            process.wait_timeout(Duration::from_secs(60)).await,
                            "process wait",
                            name,
                        );
                        assert_refused(process.kill(), "process kill", name);
                        assert_refused(process.terminate(), "process terminate", name);
                        assert_refused(
                            process.graceful_shutdown(Duration::ZERO).await,
                            "process terminate",
                            name,
                        );
                    });
                })
                .join()
                .expect("the filtered thread");
        });
        child.kill().expect("kill the child");
        child.wait().expect("reap the child");
    }
}

/// `spawn` adopts its child through a pidfd; a refused `pidfd_open` fails the spawn with
/// `Unsupported` naming `spawn`, with no fallback.
///
/// Mutants: the op is another; an errno missing from the refusals.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_pidfd_open_fails_the_spawn_naming_spawn() {
    for (code, name) in REFUSALS {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap().to_string();
        let mut cmd = cosca::Command::new();
        cmd.executable(common::testbin())
            .args(["cosca_testbin", "control-block", addr.as_str(), "R"]);
        let result = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    cmd.spawn()
                })
                .join()
                .expect("the filtered thread")
        });
        assert_refused(result, "spawn", name);
    }
}

/// The refusal is found BEFORE the fork. The filter also makes any fork fail, so a spawn that got
/// as far as forking would fail `Io`, not `Unsupported`; and this thread ends with no child, live
/// or zombie, and the program never ran.
///
/// Mutant: the pre-fork probe is skipped.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_pidfd_open_is_found_before_any_fork() {
    use std::io::Read;

    for (code, name) in REFUSALS {
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let mut cmd = cosca::Command::new();
        cmd.args(["sh", "-c", "echo ran"]);
        cmd.stdout(cosca::Stdio::from_file(std::fs::File::from(
            std::os::fd::OwnedFd::from(writer),
        )))
        .expect("set stdout");
        let (result, waitid) = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_and_forks_on_this_thread(code);
                    let result = cmd.spawn();
                    // `__WNOTHREAD`: only this thread's children. ECHILD: it has none.
                    // SAFETY: a `waitid` with no output buffer, `WNOWAIT`: it consumes nothing.
                    let rc = unsafe {
                        libc::waitid(
                            libc::P_ALL,
                            0,
                            std::ptr::null_mut(),
                            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WNOTHREAD,
                        )
                    };
                    (result, (rc, std::io::Error::last_os_error().raw_os_error()))
                })
                .join()
                .expect("the filtered thread")
        });
        assert_refused(result, "spawn", name);
        assert_eq!(waitid, (-1, Some(libc::ECHILD)), "{name}: no child, not even a zombie");
        drop(cmd);
        let mut out = String::new();
        reader.read_to_string(&mut out).expect("read to EOF");
        assert_eq!(out, "", "{name}: the program must not have run");
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
