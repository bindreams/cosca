//! `pidfd_open` refused by a real seccomp filter is `Unsupported` in the policy's message shape.
//! The unit tests state the errno on a `FakeKernel`; these tests make the kernel answer it.

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
                    assert_refused(cosca::Process::open_pid(child.pid()), "process open", name);
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
        let process = cosca::Process::open_pid(child.pid()).expect("open").expect("running");
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

/// The root-only grace wait of a graceful shutdown looks through the handle the child holds: with
/// `pidfd_open` refused from before the `SIGTERM`, it still sees the exit. The child is contained
/// without a cgroup, so only its root is watched. The group's sweep after it lists the group, which
/// needs a pidfd for each member's identity, and says so: `Unsupported` naming the refusal. The
/// control socket is released only afterwards, so a shutdown that sent no `SIGTERM` ends in the
/// escalation's `SIGKILL`, not in the assertion's `SIGTERM`.
///
/// Mutant: the grace wait re-opens the child by its identity (the error then comes from the wait).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_root_only_graceful_shutdown_needs_no_pidfd_open_to_see_the_root_exit() {
    use std::os::unix::process::ExitStatusExt;

    for (code, name) in REFUSALS {
        let (child, control) = common::spawn_control("control-block", &["R"], true);
        assert!(
            !child.containment().can_observe_drain(),
            "{name}: the fixture must watch the root only, got {:?}",
            child.containment()
        );
        let result = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    child.graceful_shutdown_tree(Duration::from_secs(30))
                })
                .join()
                .expect("the filtered thread")
        });
        drop(control);
        match result {
            Err(Error::Unsupported { op, detail, .. }) => {
                assert!(op.starts_with("listing process group"), "{name}: {op}");
                assert!(
                    detail.contains(&format!("pidfd_open answered {name}")),
                    "{name}: the group sweep names the refusal: {detail}"
                );
            }
            other => panic!("{name}: expected the group sweep to be Unsupported, got {other:?}"),
        }
        let status = child.wait().expect("reap the root");
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{name}: {status:?}");
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
                    assert_refused(cosca::tokio::Process::open_pid(child.pid()), "process open", name);
                    assert_refused(cosca::tokio::Process::open(child.id()), "process open", name);
                    assert_refused(cosca::tokio::Process::current(), "process open", name);
                })
                .join()
                .expect("the filtered thread");
        });
        common::kill_release_reap(&child, control);
    }
}

/// Run `act` on a child of an async `control-block` fixture, on a current-thread runtime entered on
/// a thread whose `pidfd_open` is refused with `code`. The runtime is built and the child spawned
/// before the filter lands. The control socket is released only afterwards, so the returned status
/// is a clean exit unless `act` ended the child. Returns the result of `act` and the child's status.
#[cfg(target_os = "linux")]
#[cfg(feature = "tokio")]
fn async_act_under_refusal<T: std::fmt::Debug + Send>(
    code: i32,
    contain: bool,
    act: impl FnOnce(&tokio::runtime::Runtime, &mut cosca::tokio::Child) -> Result<T, Error> + Send,
) -> (Result<T, Error>, std::process::ExitStatus) {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a current-thread runtime");
                let _entered = runtime.enter();
                let (mut child, control) =
                    runtime.block_on(common::spawn_control_async("control-block", &["R"], contain));
                common::seccomp::deny_pidfd_open_on_this_thread(code);
                let result = act(&runtime, &mut child);
                drop(control);
                let status = runtime.block_on(child.wait()).expect("reap the child");
                (result, status)
            })
            .join()
            .expect("the filtered thread")
    })
}

/// The async `Child::terminate` signals through the pidfd the child holds, so a refused
/// `pidfd_open` changes nothing: the `SIGTERM` is sent. The control socket is released only
/// afterwards, so a `terminate` that sent nothing ends in a clean exit, not in the `SIGTERM`.
///
/// Mutant: `terminate` signals by the child's identity (the open then fails `Unsupported`).
#[cfg(target_os = "linux")]
#[cfg(feature = "tokio")]
#[skuld::test]
fn the_async_terminate_needs_no_pidfd_open() {
    use std::os::unix::process::ExitStatusExt;

    for (code, name) in REFUSALS {
        let (result, status) = async_act_under_refusal(code, false, |_, child| child.terminate());
        result.unwrap_or_else(|e| panic!("{name}: terminate needs no pidfd_open: {e}"));
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{name}: {status:?}");
    }
}

/// The async `graceful_shutdown` sends its `SIGTERM` and watches the exit through the pidfd the
/// child holds, so a refused `pidfd_open` changes nothing: the child ends of the `SIGTERM` within
/// the grace, and is not killed.
///
/// Mutants: the signal or the grace watch opens the child by its identity (the open then fails
/// `Unsupported`, or the watch ends in the escalation's `SIGKILL`).
#[cfg(target_os = "linux")]
#[cfg(feature = "tokio")]
#[skuld::test]
fn the_async_graceful_shutdown_needs_no_pidfd_open() {
    use std::os::unix::process::ExitStatusExt;

    for (code, name) in REFUSALS {
        let (result, status) = async_act_under_refusal(code, false, |runtime, child| {
            runtime.block_on(child.graceful_shutdown(Duration::from_secs(30)))
        });
        let shutdown = result.unwrap_or_else(|e| panic!("{name}: graceful_shutdown needs no pidfd_open: {e}"));
        assert_eq!(shutdown.signal(), Some(libc::SIGTERM), "{name}: {shutdown:?}");
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{name}: {status:?}");
    }
}

/// The async `graceful_shutdown_tree` of a child contained as a process group ends the child, then
/// cannot list the group, because a member's identity is made by opening its pidfd: with
/// `pidfd_open` refused it surfaces `Unsupported` naming the refusal, never "no member left".
///
/// Mutant: the sweep treats a group it could not list as empty (`Ok`).
#[cfg(target_os = "linux")]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_refused_pidfd_open_fails_the_async_graceful_shutdown_trees_group_sweep_naming_the_refusal() {
    for (code, name) in REFUSALS {
        let (result, _status) = async_act_under_refusal(code, true, |runtime, child| {
            assert!(
                !child.containment().can_observe_drain(),
                "{name}: the fixture must watch the root only, got {:?}",
                child.containment()
            );
            runtime.block_on(child.graceful_shutdown_tree(Duration::from_secs(30)))
        });
        match result {
            Err(Error::Unsupported { op, detail, .. }) => {
                assert!(op.starts_with("listing process group"), "{name}: {op}");
                assert!(
                    detail.contains(&format!("pidfd_open answered {name}")),
                    "{name}: the refusal is the cause: {detail}"
                );
            }
            other => panic!("{name}: expected Unsupported, got {other:?}"),
        }
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
        let mut cmd = common::command(common::Console::Hidden);
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

/// The refusal is found BEFORE the fork, whichever `Command` spawns. The filter also makes any fork
/// fail, so a spawn that got as far as forking would fail `Io`, not `Unsupported`; and this thread
/// ends with no child, live or zombie, and the program never ran. `build` makes the command that
/// writes `ran` to the file; `spawn` spawns it, on the filtered thread.
#[cfg(target_os = "linux")]
fn assert_refusal_found_before_any_fork<C: Send, T: std::fmt::Debug + Send>(
    code: i32,
    name: &str,
    build: impl FnOnce(std::fs::File) -> C,
    spawn: impl FnOnce(&mut C) -> Result<T, Error> + Send,
) {
    use std::io::Read;

    let (mut reader, writer) = std::io::pipe().expect("pipe");
    let mut cmd = build(std::fs::File::from(std::os::fd::OwnedFd::from(writer)));
    let (result, waitid) = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                common::seccomp::deny_pidfd_open_and_forks_on_this_thread(code);
                let result = spawn(&mut cmd);
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

/// Mutant: the pre-fork probe is skipped.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_pidfd_open_is_found_before_any_fork() {
    for (code, name) in REFUSALS {
        assert_refusal_found_before_any_fork(
            code,
            name,
            |stdout| {
                let mut cmd = common::command(common::Console::Hidden);
                cmd.args(["sh", "-c", "echo ran"]);
                cmd.stdout(cosca::Stdio::from_file(stdout)).expect("set stdout");
                cmd
            },
            |cmd| cmd.spawn(),
        );
    }
}

/// [`a_seccomp_refused_pidfd_open_is_found_before_any_fork`] for the async spawn, which makes its
/// own probe call. `tokio::Command::spawn` refuses outside a runtime, so the filtered thread enters
/// one.
///
/// Mutant: the async spawn skips the pre-fork probe.
#[cfg(target_os = "linux")]
#[cfg(feature = "tokio")]
#[skuld::test]
fn a_seccomp_refused_pidfd_open_is_found_before_any_async_fork() {
    for (code, name) in REFUSALS {
        assert_refusal_found_before_any_fork(
            code,
            name,
            |stdout| {
                let mut cmd = common::tokio_command(common::Console::Hidden);
                cmd.args(["sh", "-c", "echo ran"]);
                cmd.stdout(cosca::Stdio::from_file(stdout)).expect("set stdout");
                cmd
            },
            |cmd| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a current-thread runtime");
                let _entered = runtime.enter();
                cmd.spawn()
            },
        );
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
