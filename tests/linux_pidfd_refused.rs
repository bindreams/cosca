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

/// The refusal fails the open, once, naming it, for every way of opening a process.
///
/// Mutants: an errno missing from the refusals; an op named as another; the message shape;
/// `Process::current` built without an open.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_pidfd_open_fails_the_open_naming_process_open() {
    for (code, name) in REFUSALS {
        let (child, control) = common::spawn_blocker();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    assert_refused(cosca::Process::open_pid(child.id().pid()), "process open", name);
                    assert_refused(cosca::Process::open(child.id()), "process open", name);
                    assert_refused(cosca::Process::current(), "process open", name);
                })
                .join()
                .expect("the filtered thread");
        });
        common::kill_release_reap(&child, control);
    }
}

/// An owned `Child` terminates through its own handle, so it needs no `pidfd_open` and meets no
/// refusal: the `SIGTERM` lands. The control socket is released only after `terminate` returns, so
/// a `terminate` that sent nothing leaves an exit 0.
///
/// Mutant: `Child::terminate` routed through `pidfd_open`, or sending nothing.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_child_terminates_through_its_own_handle_under_a_refused_pidfd_open() {
    for (code, _) in REFUSALS {
        let (child, control) = common::spawn_blocker();
        std::thread::scope(|scope| {
            let child = &child;
            scope
                .spawn(move || {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    child.terminate().expect("Child::terminate needs no pidfd_open");
                    drop(control);
                })
                .join()
                .expect("the filtered thread");
        });
        let status = child.wait().expect("reap the terminated child");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGTERM),
            "the child dies of the terminate sent through its own handle: {status:?}"
        );
    }
}

/// An owned `Child` shuts down gracefully and kills through its own handle under a refused
/// `pidfd_open`.
///
/// Mutant: `Child::graceful_shutdown` or `Child::kill` (or the grace wait) routed through
/// `pidfd_open`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_child_shuts_down_and_kills_through_its_own_handle_under_a_refused_pidfd_open() {
    for (code, _) in REFUSALS {
        let (child, control) = common::spawn_blocker();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    child
                        .graceful_shutdown(Duration::ZERO)
                        .expect("Child::graceful_shutdown needs no pidfd_open");
                    child.kill().expect("Child::kill needs no pidfd_open");
                })
                .join()
                .expect("the filtered thread");
        });
        drop(control);
        let status = child.wait().expect("reap the ended child");
        assert!(
            std::os::unix::process::ExitStatusExt::signal(&status).is_some(),
            "the child was ended by a signal: {status:?}"
        );
    }
}

/// An open made before the filter serves every act after it: no act opens a second pidfd.
///
/// Mutant: an act re-opens the process by its identity.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_held_process_needs_no_second_pidfd_open() {
    for (code, _) in REFUSALS {
        let (child, control) = common::spawn_blocker();
        let process = cosca::Process::open_pid(child.id().pid())
            .expect("open")
            .expect("running");
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    assert!(!process
                        .wait_timeout(Duration::ZERO)
                        .expect("a look needs no pidfd_open"));
                    process.kill().expect("a held kill needs no pidfd_open");
                    process.terminate().expect("a held terminate needs no pidfd_open");
                    process.wait().expect("a held wait needs no pidfd_open");
                })
                .join()
                .expect("the filtered thread");
        });
        common::kill_release_reap(&child, control);
    }
}

/// [`a_seccomp_refused_pidfd_open_fails_the_open_naming_process_open`] for the async `Process`.
#[cfg(target_os = "linux")]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_seccomp_refused_pidfd_open_fails_the_async_open_naming_process_open() {
    for (code, name) in REFUSALS {
        let (child, control) = common::spawn_blocker();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    assert_refused(cosca::tokio::Process::open_pid(child.id().pid()), "process open", name);
                    assert_refused(cosca::tokio::Process::open(child.id()), "process open", name);
                    assert_refused(cosca::tokio::Process::current(), "process open", name);
                })
                .join()
                .expect("the filtered thread");
        });
        common::kill_release_reap(&child, control);
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
    #[cfg(target_os = "linux")]
    common::install_log_capture();
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
