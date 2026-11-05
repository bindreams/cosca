//! `openat2` refused by a real seccomp filter: `ProcessId::current` still works, and a by-pid read
//! is `Unknown`, or `Gone` for a pid no process can hold. The unit tests state the refusal through
//! a `Kernel` fake; these tests make the kernel answer it.

#[cfg(target_os = "linux")]
use cosca::identity::{Existence, Liveness, ProcessId, Resolved};

#[cfg(target_os = "linux")]
#[path = "common/mod.rs"]
mod common;

#[cfg(target_os = "linux")]
use common::seccomp::OPENAT2_REFUSALS as REFUSALS;

/// Above `PID_MAX_LIMIT` (2^22) yet a valid positive `kill` target, so `kill(pid, 0)` answers `ESRCH`.
#[cfg(target_os = "linux")]
const NO_PROCESS_CAN_HOLD: u32 = i32::MAX as u32;

/// Runs `f` on a thread with `openat2` refused with `errno`. A filter is per-thread and ends with
/// it, so the test's own thread keeps `openat2`.
#[cfg(target_os = "linux")]
fn with_openat2_refused<T: Send>(errno: i32, f: impl FnOnce() -> T + Send) -> T {
    on_a_thread(|| {
        common::seccomp::deny_openat2_on_this_thread(errno);
        f()
    })
}

/// Runs `f` on a thread of its own, for a test that lands the filter itself, after it has spawned.
#[cfg(target_os = "linux")]
fn on_a_thread<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| scope.spawn(f).join().expect("the filtered thread"))
}

/// A host where `openat2` is unavailable still has `/proc`, and `current()` reads `self/stat`
/// without it.
///
/// Mutant: `current_token` opens the checked `/proc` (it panics on the filtered thread).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_leaves_current_working() {
    let ordinary = ProcessId::current();
    for (errno, _) in REFUSALS {
        with_openat2_refused(errno, || assert_eq!(ProcessId::current(), ordinary, "{errno}"));
    }
}

/// Without `openat2` there is no view, so a by-pid read of a live pid is `Unknown`, and a pid no
/// process can hold is still `Gone`.
///
/// Mutants: an unavailable `openat2` hides an `ESRCH`; a live pid reads as `Gone`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_by_pid_reads_unknown_or_gone() {
    let id = ProcessId::current();
    for (errno, _) in REFUSALS {
        with_openat2_refused(errno, || {
            assert!(
                matches!(ProcessId::of(std::process::id()), Resolved::Unknown),
                "{errno}"
            );
            assert_eq!(id.exists(), Existence::Unknown, "{errno}");
            assert_eq!(id.is_alive(), Liveness::Unknown, "{errno}");
            assert!(matches!(ProcessId::of(NO_PROCESS_CAN_HOLD), Resolved::Gone), "{errno}");
        });
    }
}

/// An open under a refused `openat2` is `Unsupported` naming it, in the policy's message shape.
#[cfg(target_os = "linux")]
fn assert_names_openat2(result: Result<impl std::fmt::Debug, cosca::error::Error>, errno: &str) {
    match result {
        Err(e @ cosca::error::Error::Unsupported { .. }) => assert_eq!(
            e.to_string(),
            format!("process open is not supported on linux: {}", refused_detail(errno))
        ),
        other => panic!("an open under an openat2 answering {errno} must be Unsupported, got {other:?}"),
    }
}

/// `pidfd_open` succeeds, then the fdinfo check needs the `/proc` dirfd, which needs `openat2`.
///
/// Mutant: the success path reports an unopenable `/proc` as `Unassessable`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_open_unsupported_naming_openat2() {
    let id = ProcessId::current();
    for (errno, name) in REFUSALS {
        with_openat2_refused(errno, || assert_names_openat2(cosca::Process::open(id), name));
    }
}

/// A live worker thread's tid is no thread-group leader, so `pidfd_open` refuses it (`EINVAL`
/// before 6.16, `ENOENT` from 6.16) and the open decides by the `/proc` view, which needs
/// `openat2`.
///
/// Mutant: that arm reports an unopenable `/proc` as `Unassessable`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_open_of_a_live_non_leader_tid_unsupported_naming_openat2() {
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        // SAFETY: SYS_gettid takes no arguments and always succeeds.
        tid_tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as u32).unwrap();
        _ = stop_rx.recv();
    });
    let tid = tid_rx.recv().expect("the worker reports its tid");
    let id = ProcessId::of(tid).found().expect("the live worker's tid resolves");
    for (errno, name) in REFUSALS {
        with_openat2_refused(errno, || assert_names_openat2(cosca::Process::open(id), name));
    }
    drop(stop_tx);
    worker.join().expect("the worker ends");
}

// The scans, the walks and the teardowns =====

/// What an `Unsupported` that names the refusal says.
#[cfg(target_os = "linux")]
fn refused_detail(errno: &str) -> String {
    format!("cosca requires openat2 (Linux \u{2265} 5.6), refused here: openat2 answered {errno}")
}

/// `result` is `Unsupported` carrying exactly the refusal, for the call `what`.
#[cfg(target_os = "linux")]
fn assert_unsupported_naming(result: Result<(), cosca::error::Error>, errno: &str, what: &str) {
    match result {
        Err(cosca::error::Error::Unsupported { detail, .. }) => {
            assert_eq!(detail, refused_detail(errno), "{what} under {errno}")
        }
        other => panic!("{what} under an openat2 answering {errno} must be Unsupported, got {other:?}"),
    }
}

/// A child blocked on its control socket, walked by identity (`ContainMode::TreeWalk`).
#[cfg(target_os = "linux")]
fn spawn_treewalk_blocker() -> (cosca::Child, std::net::TcpStream) {
    let (child, control) = common::spawn_control_with("control-block", &["R"], false, |cmd| {
        cmd.contain_with(cosca::ContainMode::TreeWalk);
    });
    assert_eq!(child.containment(), cosca::Containment::TreeWalk);
    (child, control)
}

/// Every query that takes the process snapshot says the refusal, and warns of it: never "no
/// parent", never "no children".
///
/// Mutant: the snapshot reports an unopenable `/proc` as `Unassessable`, or maps it to `Ok(None)` or
/// `Ok(vec![])`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_parent_and_children_unsupported_naming_openat2_and_warned() {
    use cosca::identity::Recursive;

    let me = ProcessId::current();
    for (errno, name) in REFUSALS {
        let mark = common::log_mark();
        let results = with_openat2_refused(errno, || {
            [
                ("parent", me.parent().map(drop)),
                ("children(No)", me.children(Recursive::No).map(drop)),
                ("children(Yes)", me.children(Recursive::Yes).map(drop)),
            ]
        });
        for (call, result) in results {
            assert_unsupported_naming(result, name, call);
        }
        assert!(
            common::levels_since(mark, &refused_detail(name)).contains(&log::Level::Warn),
            "{name}: the snapshot's refusal is warned of"
        );
    }
}

/// Another refusal of `openat2` is not the requirement: it is `Unassessable`.
///
/// Mutant: every open failure is `Unsupported`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_with_another_errno_is_not_unsupported_for_the_snapshot() {
    let me = ProcessId::current();
    let result = with_openat2_refused(libc::ENOENT, || me.parent().map(drop));
    assert!(
        matches!(result, Err(cosca::error::Error::Unassessable { .. })),
        "{result:?}"
    );
}

/// A `Process` kills and terminates its tree by walking the snapshot, so both say the refusal and
/// signal nothing: the child leaves clean when its control socket is released.
///
/// Mutant: the walk maps the snapshot's error to `Unassessable`, or signals the root first.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_process_kill_tree_and_terminate_tree_unsupported_naming_openat2() {
    for (errno, name) in REFUSALS {
        let (child, control) = common::spawn_blocker();
        let process = cosca::Process::open(child.id())
            .expect("open")
            .expect("the child is running");
        let results = with_openat2_refused(errno, || {
            [
                ("kill_tree", process.kill_tree()),
                ("terminate_tree", process.terminate_tree()),
            ]
        });
        for (call, result) in results {
            assert_unsupported_naming(result, name, call);
        }
        drop(control);
        let status = child.wait().expect("reap the child");
        assert!(
            status.success(),
            "{name}: nothing was sent, yet the child ended {status:?}"
        );
    }
}

/// A `Session` child lists its group through `/proc`: `kill_tree` and `terminate_tree` say the
/// refusal, as a wait or a spawn does, and not `Unassessable` with the kind buried in `source`.
///
/// Mutant: `verify` maps an unlistable group to `Unassessable`, or `members` reports it as
/// `io::Error::other`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_kill_tree_and_terminate_tree_of_a_session_unsupported_naming_openat2() {
    for (errno, name) in REFUSALS {
        let (child, control) = common::spawn_control("control-block", &["R"], true);
        let results = with_openat2_refused(errno, || {
            [
                ("kill_tree", child.kill_tree()),
                ("terminate_tree", child.terminate_tree()),
            ]
        });
        for (call, result) in results {
            match result {
                Err(cosca::error::Error::Unsupported { detail, .. }) => {
                    assert!(detail.contains(&refused_detail(name)), "{call} under {name}: {detail}")
                }
                other => panic!("{call} under {name}: expected Unsupported, got {other:?}"),
            }
        }
        common::kill_tree_release_reap(&child, control);
    }
}

/// Another refusal is not the requirement: a group that cannot be listed keeps its own error and
/// does not claim `openat2` is missing.
///
/// Mutant: every `/proc` open failure is flagged as missing `openat2`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_with_another_errno_is_not_unsupported_for_a_group_listing() {
    let (child, control) = common::spawn_control("control-block", &["R"], true);
    let result = with_openat2_refused(libc::ENOENT, || child.kill_tree());
    match result {
        Err(cosca::error::Error::Unsupported { detail, .. }) => panic!("Unsupported: {detail}"),
        Err(e) => assert!(!e.to_string().contains("cosca requires openat2"), "{e}"),
        Ok(()) => panic!("a group that cannot be listed was reported as killed"),
    }
    common::kill_tree_release_reap(&child, control);
}

/// The walk could not find the descendants, and killing the root first would reparent them out of
/// any retry's reach: nothing is killed, the root included, and the error is returned.
///
/// Mutant: the handle backstop runs after a refused walk.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_leaves_a_treewalk_roots_kill_tree_an_error_and_the_root_alive() {
    for (errno, name) in REFUSALS {
        let (child, control) = spawn_treewalk_blocker();
        let result = with_openat2_refused(errno, || child.kill_tree());
        assert_unsupported_naming(result, name, "kill_tree");
        drop(control);
        let status = child.wait().expect("reap the root");
        assert!(
            status.success(),
            "{name}: the root must not have been killed: {status:?}"
        );
    }
}

/// A retry once `openat2` answers again finds the tree and kills it.
///
/// Mutant: `kill_tree` sends nothing from its second call on.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_then_recovered_lets_kill_tree_retry() {
    for (errno, _) in REFUSALS {
        let (child, control) = spawn_treewalk_blocker();
        with_openat2_refused(errno, || child.kill_tree()).expect_err("the first attempt fails");
        common::kill_tree_release_reap(&child, control);
    }
}

/// The async twin of the `kill_tree` row above. The runtime is built and the child spawned before
/// the filter lands.
///
/// Mutant: the async handle's own backstop runs after a refused walk.
#[cfg(all(target_os = "linux", feature = "tokio"))]
#[skuld::test]
fn a_seccomp_refused_openat2_leaves_an_async_treewalk_roots_kill_tree_an_error_and_the_root_alive() {
    for (errno, name) in REFUSALS {
        let (result, status) = on_a_thread(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a current-thread runtime");
            let _entered = runtime.enter();
            let (mut child, control) = runtime.block_on(common::spawn_control_async_with(
                "control-block",
                &["R"],
                false,
                |cmd| {
                    cmd.contain_with(cosca::ContainMode::TreeWalk);
                },
            ));
            assert_eq!(child.containment(), cosca::Containment::TreeWalk);
            common::seccomp::deny_openat2_on_this_thread(errno);
            let result = child.kill_tree();
            drop(control);
            let status = runtime.block_on(child.wait()).expect("reap the root");
            (result, status)
        });
        assert_unsupported_naming(result, name, "kill_tree");
        assert!(
            status.success(),
            "{name}: the root must not have been killed: {status:?}"
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
