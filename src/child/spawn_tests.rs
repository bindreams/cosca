//! Unit tests for the sync spawn path: error-path teardown (driven by the shared `fault` seam,
//! defined in `super` and also used by `src/tokio/spawn_tests.rs`), the elevation branch, and the
//! Windows backend router, and that a refused spawn refuses before it touches our handle
//! inheritance. In the library (not `tests/`) because the seam is `pub(crate)`/`#[cfg(test)]` and
//! only reachable from within the crate. The batch gate's tests are in `spawn/batch_gate_tests.rs`.

use super::fault;
use crate::command::Command;
use crate::error::Error;

// A long-lived child, so a teardown leak would show as an alive process at the assert rather than
// self-exiting.
fn blocker() -> Command {
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd
}

// A failed sync spawn must fully reap its child, not leak it. Each error arm is forced via the seam
// (which records the child's real identity); `fault::assert_child_reaped` then proves it was reaped.

#[test]
fn identity_failure_reaps_the_spawned_child() {
    fault::set_force_identity_vanished(true);
    let mut cmd = blocker();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    let err = err.expect("forced identity-vanish must make spawn return Err");
    assert!(
        matches!(err, Error::Io(_)),
        "identity-vanish surfaces as an Io error, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

#[test]
fn attach_failure_reaps_the_spawned_child() {
    fault::set_force_attach_failure(true);
    let mut cmd = blocker();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);

    let err = err.expect("forced attach failure must make spawn return Err");
    assert!(
        matches!(err, Error::Containment { .. }),
        "a real attach failure surfaces as Error::Containment, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// A reap that FAILS during teardown must leave a trace in a release build, where the
/// `debug_assert` beside it is compiled out: a `log::warn!` naming the error. Both teardown arms —
/// attach failure and unresolved identity — share the one teardown, and each is driven here.
///
/// Each leg's forced error carries its own marker, and records are scanned from a mark taken just
/// before, so a concurrent test's warning cannot satisfy this one.
#[test]
fn a_failed_teardown_reap_is_logged_on_both_arms() {
    a_failed_teardown_step_is_logged_on_both_arms(
        ["cosca-reap-fail-attach-7c1e", "cosca-reap-fail-identity-b93d"],
        fault::set_force_reap_failure,
        fault::take_force_reap_failure,
    );
}

/// Force one teardown step to fail with each marker, once per teardown arm, and check the failure
/// is consumed, logged, `debug_assert`ed in exactly the builds that keep it, and leaks no child.
fn a_failed_teardown_step_is_logged_on_both_arms(
    markers: [&'static str; 2],
    set_failure: fn(&'static str),
    take_failure: fn() -> Option<&'static str>,
) {
    crate::log_capture::install();
    let force_arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    for (marker, force_arm) in markers.into_iter().zip(force_arms) {
        let mark = crate::log_capture::mark();
        force_arm(true);
        set_failure(marker);
        let outcome = std::panic::catch_unwind(|| blocker().spawn().err());
        force_arm(false);
        assert_eq!(
            take_failure(),
            None,
            "{marker}: the teardown must consume the forced failure"
        );
        // Debug builds also trip the `debug_assert`; release builds must not panic at all.
        assert_eq!(
            outcome.is_err(),
            cfg!(debug_assertions),
            "{marker}: the debug_assert fires in exactly the builds that keep it"
        );
        if let Ok(err) = outcome {
            err.expect("the forced arm must fail the spawn");
        }
        assert!(
            crate::log_capture::contains_since(mark, marker),
            "{marker}: a failed teardown step must be logged"
        );
        fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    }
}

#[test]
fn spawn_unelevated_runs_a_plain_child() {
    let mut c = crate::command::Command::new();
    #[cfg(unix)]
    c.args(["true"]);
    #[cfg(windows)]
    c.args(["cmd", "/C", "exit 0"]);
    let kill_on_drop = c.kill_on_drop_flag();
    let child = super::spawn_unelevated(&mut c, kill_on_drop).expect("spawn");
    assert!(child.wait().expect("wait").success());
}

// A NON-elevated command must reach spawn_unelevated unchanged: the elevation branch
// is gated on `elevation_request().enabled`, so a plain command never routes through it.
#[test]
fn non_elevated_spawn_skips_the_elevation_branch() {
    let mut c = crate::command::Command::new();
    #[cfg(unix)]
    c.args(["true"]);
    #[cfg(windows)]
    c.args(["cmd", "/C", "exit 0"]);
    let child = super::spawn(&mut c).expect("non-elevated spawn");
    assert!(child.wait().expect("wait").success());
}

#[cfg(windows)]
#[test]
fn elevated_pipe_is_rejected_deterministically_regardless_of_privilege() {
    // DETERMINISTIC (no ambient-privilege branch): the honest config gate now runs BEFORE
    // the already-elevated short-circuit, so a piped elevated child is
    // Unsupported whether or not the runner is elevated — never a UAC prompt, never a hang.
    let mut c = crate::command::Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(crate::stdio::Stdio::pipe()).unwrap();
    assert!(matches!(
        super::spawn(&mut c),
        Err(crate::error::Error::Unsupported { .. })
    ));
}

// ===== Windows backend routing =====

/// The rule both Windows routers read, in both directions and for all four shapes.
///
/// `tests/windows_creation_flags.rs` names a backend in every test name; its `executable()` legs
/// carry their own behavioural proof (the child's `argv[0]`), but its argv legs have none — an
/// argv-only command would report the same `argv[0]` whichever backend spawned it. Their
/// std-path claim rests on this rule, which is now one function rather than two copies.
///
/// The **high-descriptor-only** shape is the branch with no coverage anywhere today: every
/// shipped Windows high-descriptor test also sets an explicit `executable()`, which
/// short-circuits the rule before the fd term is ever evaluated.
#[cfg(windows)]
#[test]
fn routes_to_raw_backend_answers_for_executables_and_high_descriptors() {
    use crate::stdio::Stdio;

    let mut argv_only = Command::new();
    argv_only.args(["cmd", "/C", "exit 0"]);
    assert!(
        !super::routes_to_raw_backend(&argv_only),
        "an argv-only command stays on the std path"
    );

    let mut exe_only = Command::new();
    exe_only.executable("cmd").args(["cmd", "/C", "exit 0"]);
    assert!(super::routes_to_raw_backend(&exe_only), "an executable() routes to raw");

    // BOTH setters must route here. The rule reads `executable_path()`, which is deliberately
    // variant-agnostic, so this holds today — the case exists to stop it being "tightened" to
    // `Search` only. That would send `raw_executable()` down the std path, where std resolves a
    // bare name itself, breaking the no-resolution contract at the one backend that honours it.
    let mut raw_exe_only = Command::new();
    raw_exe_only.raw_executable("cmd").args(["cmd", "/C", "exit 0"]);
    assert!(
        super::routes_to_raw_backend(&raw_exe_only),
        "a raw_executable() routes to raw too"
    );

    let mut high_fd_only = Command::new();
    high_fd_only.args(["cmd", "/C", "exit 0"]);
    high_fd_only.fd(3, Stdio::pipe_out()).unwrap();
    assert!(
        super::routes_to_raw_backend(&high_fd_only),
        "a descriptor >= 3 routes to raw even with no executable(): std cannot carry it, and the \
         std path's fd >= 3 collection is unix-only, so it would be dropped in silence"
    );

    let mut both = Command::new();
    both.executable("cmd").args(["cmd", "/C", "exit 0"]);
    both.fd(3, Stdio::pipe_out()).unwrap();
    assert!(super::routes_to_raw_backend(&both));
}
/// A sync spawn whose verdict fails closed while its child is still held at its hook — here one
/// that refuses the kill — writes nothing into the child's stdio. With fds 1 and 2 closed, `std`'s
/// error channel takes them, the child's stdio `dup2` closes its end, and `spawn` returns before the
/// hook runs; the child, released once its report has been read, finds the exchange shut and exits
/// with `ABANDONED_EXIT` rather than return an error `std` would write to that channel's fd number —
/// by now the child's stderr.
///
/// The sync path's only abandonment of a live child: `std` fails a spawn only once it has reaped
/// the child, and every later failure takes the verdict with the child in hand.
///
/// Runs in a copy of this test binary: closing 1 and 2 is process-wide.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_a_sync_spawn_failed_closed_writes_nothing_into_the_childs_stdio() {
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsRawFd;

    use crate::containment::cgroup::fault as cgroup_fault;

    const NAME: &str =
        "child::spawn::spawn_tests::cgroup_a_sync_spawn_failed_closed_writes_nothing_into_the_childs_stdio";
    const INNER: &str = "COSCA_TEST_FAILED_CLOSED_STDIO_INNER";
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    if std::env::var_os(INNER).is_none() {
        let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([NAME, "--exact", "--include-ignored", "--nocapture", "--test-threads=1"])
            .env(INNER, "1")
            .output()
            .expect("run the case");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let mut file = tempfile::tempfile().expect("tempfile");
    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    let mut release = gate_write.try_clone().expect("dup the gate");
    let mut cmd = blocker();
    for slot in [1, 2] {
        cmd.fd(
            slot,
            crate::stdio::Stdio::from_file(file.try_clone().expect("clone the file")),
        )
        .expect("wire the slot to the file");
    }
    cmd.contain();
    // The verdict cannot wait (no pidfd) and finds the leaf busy with something not the child, so
    // it fails closed; the child refuses its kill.
    cgroup_fault::set_force_pidfd_failure(true);
    cgroup_fault::set_force_leaf_busy(true);
    cgroup_fault::set_force_signal_denied(true);
    let status = std::rc::Rc::new(std::cell::Cell::new(None));
    let seen = status.clone();
    cgroup_fault::set_after_final_read(move |pid| {
        release.write_all(b"x").expect("release the child");
        // Its exit, not its reaping: the spawn's teardown reaps it.
        let pid = rustix::process::Pid::from_raw(pid as i32).expect("a positive pid");
        let exited = loop {
            match rustix::process::waitid(
                rustix::process::WaitId::Pid(pid),
                rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
            ) {
                Err(rustix::io::Errno::INTR) => continue,
                other => break other.expect("wait for the child").expect("it exited"),
            }
        };
        seen.set(Some(exited.exit_status()));
    });
    // SAFETY: this process's own std slots, closed only across the spawn and restored from copies
    // above 2 before anything else runs.
    let saved: Vec<(i32, i32)> = [1, 2]
        .into_iter()
        .map(|slot| unsafe { (slot, libc::fcntl(slot, libc::F_DUPFD_CLOEXEC, 3)) })
        .collect();
    for &(slot, _) in &saved {
        // SAFETY: as above.
        unsafe { libc::close(slot) };
    }
    // Inherited by the child, which waits on it at its hook; this thread's copy is cleared.
    cgroup_fault::set_hook_gate(gate_read.as_raw_fd());
    let spawned = cmd.spawn();
    let _ = cgroup_fault::take_hook_gate();
    for &(slot, saved) in &saved {
        // SAFETY: as above.
        unsafe {
            libc::dup2(saved, slot);
            libc::close(saved);
        }
    }
    // Released whatever happened, before any assert: a child held forever holds this process's
    // stdout, and would hang the outer run.
    gate_write.write_all(b"x").expect("release the child");
    let leftover = (
        cgroup_fault::take_force_leaf_busy(),
        cgroup_fault::take_force_signal_denied(),
    );

    let Err(err) = spawned else {
        panic!("a verdict failed closed must fail the spawn");
    };
    assert!(err.to_string().contains("could not be signalled"), "got {err}");
    assert_eq!(leftover, (false, false), "the verdict must take its seams");
    assert_eq!(
        status.get(),
        Some(Some(crate::containment::cgroup::ABANDONED_EXIT)),
        "the child must exit from its hook"
    );
    let mut written = Vec::new();
    file.rewind().expect("rewind the file");
    file.read_to_end(&mut written).expect("read the file");
    assert_eq!(written, b"", "nothing reached the child's stdio");
}

// ===== A refused spawn leaves our handle inheritance alone =====

/// A refused spawn must not have mutated this process first. `clear_std_handle_inheritance` is a
/// real, process-global, un-undone `SetHandleInformation` on our own std handles, so running it
/// before the refusal would leave a disposition-less side effect behind.
///
/// The two legs differ by one bit and are one `#[test]` so their order is guaranteed; `cargo
/// test` gives each test its own thread, so the thread-local seam starts clean. The positive leg
/// is what stops the negative one passing on a seam that was never wired.
///
/// The real handle flags are deliberately NOT measured instead: the mutation is process-global
/// and permanent, so any earlier contained spawn in this binary would already have made that
/// observation meaningless.
#[cfg(windows)]
#[test]
fn a_refused_raw_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.executable("cmd").args(["cmd", "/C", "exit 0"]).contain();
    let child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().expect("reap");
}

/// An environment key with an embedded NUL is refused before the process-global handle mutation
/// too. The seam's wiring is proven by the positive leg of the test above.
#[cfg(windows)]
#[test]
fn a_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .env("A\0B", "x");
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("an embedded NUL must be refused");
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput),
        "got {err:?}"
    );
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );
}

/// The std-path counterpart of the test above. The std backend reaches the same process-global
/// mutation through `containment::prepare`, which composes and validates the creation-flag word
/// at its top — a separate ordering the raw backends' tests cannot see.
///
/// Argv-only and no `executable()`, asserted through `routes_to_raw_backend` so a future routing
/// change cannot quietly turn this into a third raw-backend test.
#[cfg(windows)]
#[test]
fn a_refused_std_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    assert!(
        !crate::child::spawn::routes_to_raw_backend(&refused),
        "this leg is only a std-path proof while the command stays off the raw backend"
    );
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.args(["cmd", "/C", "exit 0"]).contain();
    let child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().expect("reap");
}

// kill_on_drop(false) commits only with the spawn -----
// The containment resource is disarmed when `spawn` hands the handle over, never before: a spawn
// that fails after its `Child` exists (the POSIX password write) still owns the tree it started.

/// An occupied temp leaf whose child entered it, attached to the next spawn on this thread.
#[cfg(target_os = "linux")]
fn attach_entered_leaf(leaf_path: &std::path::Path) {
    std::fs::create_dir(leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.to_path_buf(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
}

/// Until the spawn commits, a `kill_on_drop(false)` handle's leaf still kills on drop; once
/// committed, it does not.
#[cfg(target_os = "linux")]
#[test]
fn kill_on_drop_false_disarms_the_leaf_only_when_the_spawn_commits() {
    for commit in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-commit-leaf");
        attach_entered_leaf(&leaf_path);
        let mut cmd = blocker();
        cmd.kill_on_drop(false);
        let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
        if commit {
            child.commit_kill_on_drop();
        }
        child.kill().expect("end the stand-in root");
        let _ = child.wait();
        drop(child);

        let expected: &[u8] = if commit { b"" } else { b"1" };
        assert_eq!(
            std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
            expected,
            "committed: {commit}"
        );
    }
}

/// A failed password write tears the tree down through the leaf, even when the leaf's own `Drop`
/// would not: the root alone is not the tree.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_password_write_kills_the_contained_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-password-leaf");
    attach_entered_leaf(&leaf_path);
    let mut cmd = blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    // Rule out the leaf's `Drop`: only the failure path itself may kill.
    child.attached.disarm();

    let written = Err(Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "forced password-write failure".into(),
    });
    let err = super::finish_elevated(child, written).expect_err("a failed write fails the spawn");

    assert!(
        matches!(
            err,
            Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"1",
        "the failed spawn must kill its tree through the leaf"
    );
}

/// A failed password write whose child's one check comes back with ownership uncertain (a
/// genuine `ECHILD`: something else already reaped it) disarms what it retained, the same as a
/// leaked or already-uncertain-owned child's: the pid may already name another process, so this
/// spawn no longer treats itself as owning the tree to kill on drop.
///
/// `Containment::Delegated` here, not `CgroupV2`: this function's own tree-kill note at its top
/// fires whenever `can_teardown()` is true, which would write `cgroup.kill` before the Uncertain
/// arm is even reached, hiding the one write under test. `Delegated` skips that note, so the only
/// thing that can still touch `cgroup.kill` is the retained leaf's own `Drop` — armed or not.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_password_write_whose_check_is_uncertain_disarms_its_retained_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-uncertain-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::Delegated,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let mut cmd = blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-elevated-kill-eperm-uncertain-9e21",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_force_teardown_try_wait_echild();

    let err = super::elevated_write_failed(
        child,
        Error::Io(std::io::Error::other("cosca-password-write-fail-uncertain-11ab")),
    );

    assert!(err.to_string().contains("ownership is uncertain"), "got {err}");
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"",
        "an uncertain-ownership release must disarm its retained leaf, not kill through it"
    );
    // The real child is still alive: the kill above was faked. End it for real and reap it
    // ourselves, since cosca released it as ownership-uncertain without waiting.
    // SAFETY: `pid` is this process's own unreaped child.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: as above; a blocking reap of this process's own child.
    unsafe { libc::waitpid(pid as i32, &mut status, 0) };
}

/// Whether `pid`, a child of this process, has been reaped: `waitpid` no longer knows it.
#[cfg(target_os = "linux")]
fn reaped(pid: u32) -> bool {
    let mut status = 0;
    // SAFETY: a non-blocking query on a pid this process spawned; `status` is a valid int.
    let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

/// The error a failed password write returns.
#[cfg(target_os = "linux")]
fn failed_write() -> Result<(), Error> {
    Err(Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "forced password-write failure".into(),
    })
}

/// A `Delegated` spawn has no tree teardown of its own, but its root is still this spawn's child:
/// a failed password write kills and reaps it.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_password_write_kills_and_reaps_a_delegated_root() {
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::Delegated,
        attached: crate::containment::Attached::Delegated,
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let mut cmd = blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();

    let err = super::finish_elevated(child, failed_write()).expect_err("a failed write fails the spawn");

    let reaped = reaped(pid);
    if !reaped {
        // SAFETY: `pid` is this process's own unreaped child; do not leak it past the test.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    assert!(reaped, "the root must be killed and reaped, got {err:?}");
    assert!(err.to_string().contains("was terminated"), "got {err:?}");
}

/// A tree kill that fails does not stop the root's own kill and reap: the two are separate.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_password_write_reaps_the_root_when_the_tree_kill_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-unkillable-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    // A directory: writing `cgroup.kill` fails with EISDIR, as a refused kill would.
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill unwritable");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let mut cmd = blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();

    let err = super::finish_elevated(child, failed_write()).expect_err("a failed write fails the spawn");

    assert!(reaped(pid), "the root was killed, so it must be reaped, got {err:?}");
    let detail = err.to_string();
    assert!(detail.contains("was terminated"), "the root was killed, got {detail}");
    assert!(
        detail.contains("its contained tree could not be killed"),
        "the tree's failure is reported, got {detail}"
    );
}

/// A child the teardown could not kill is handed back in the error, on both teardown arms, and the
/// teardown does NOT go on to a blocking reap: a child it could not kill may still be running
/// (EPERM from a setuid child), and `wait()` would hang the spawn for as long as it runs. The reap
/// fault is armed as a tripwire — left unconsumed, it proves the reap step was never reached. The
/// error keeps why the spawn failed, and why the kill did; nothing panics, EPERM or not, since the
/// failure is the caller's to see. The child is left running, as a refused kill leaves it; the test
/// ends it, and the handed-back child reaps it.
#[test]
fn a_child_the_teardown_cannot_kill_is_handed_back_in_the_error_on_both_arms() {
    use std::io::ErrorKind;
    let force_arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    let cases = [
        ("cosca-kill-fail-attach-4e02", ErrorKind::Other),
        ("cosca-kill-eperm-attach-61c7", ErrorKind::PermissionDenied),
        ("cosca-kill-fail-identity-d51a", ErrorKind::Other),
        ("cosca-kill-eperm-identity-0a8b", ErrorKind::PermissionDenied),
    ];
    for (index, (marker, kind)) in cases.into_iter().enumerate() {
        let force_arm = force_arms[index / 2];
        force_arm(true);
        fault::set_force_kill_failure_leaving_child_alive_as(marker, kind);
        fault::set_force_reap_failure("cosca-reap-tripwire-9f31");
        let err = blocker().spawn().err();
        force_arm(false);
        assert_eq!(
            fault::take_force_kill_failure(),
            None,
            "{marker}: the kill failure must be consumed"
        );
        assert_eq!(
            fault::take_force_reap_failure(),
            Some("cosca-reap-tripwire-9f31"),
            "{marker}: a failed kill must not be followed by a blocking reap"
        );
        let Some(Error::Unreaped { error, kill, child }) = err else {
            panic!("{marker}: the unkillable child must be handed back, got {err:?}");
        };
        assert_eq!(kill.kind(), kind, "{marker}: the kill's own error");
        assert_eq!(kill.to_string(), marker, "{marker}: the kill's own error");
        if index / 2 == 0 {
            assert!(
                matches!(*error, Error::Containment { .. }),
                "{marker}: why the spawn failed, got {error:?}"
            );
        } else {
            assert!(
                matches!(*error, Error::Io(_)),
                "{marker}: why the spawn failed, got {error:?}"
            );
        }
        let captured = fault::take_captured().expect("seam captured the child's identity");
        let crate::identity::Resolved::Found(id) = captured else {
            panic!("{marker}: the seam must capture a resolved identity, got {captured:?}");
        };
        assert_eq!(
            child.pid(),
            id.pid(),
            "{marker}: the handed-back child is the spawned one"
        );
        crate::wait::kill(id).expect("end the child");
        child.wait().expect("wait for the handed-back child");
        fault::assert_child_reaped(captured);
    }
}

/// Dropping the error drops the handed-back child, which blocks until the child exits and reaps
/// it, so a caller that ignores it leaves no zombie. The child is left running, as a refused kill
/// leaves it — one that exited first would be reaped by the teardown's one check, and nothing
/// handed back — and the test ends it before dropping the error.
#[test]
fn dropping_the_error_reaps_the_handed_back_child_once_it_exits() {
    let mut cmd = blocker();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive("cosca-kill-fail-alive-3b7e");
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    assert!(
        matches!(err, Some(Error::Unreaped { .. })),
        "the unkillable child must be handed back, got {err:?}"
    );
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    crate::wait::kill(id).expect("end the child");
    drop(err);
    fault::assert_child_reaped(captured);
}

/// Block until the child `captured` names exits, an event outside this process. Windows only:
/// there a teardown that could not kill its child closes the handle without waiting, so a test
/// must wait for the exit itself before asserting it.
#[cfg(windows)]
fn await_exit(captured: &crate::identity::Resolved<crate::identity::ProcessId>) {
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    crate::wait::block_until_exit(*id, None).expect("watch the child's exit");
}

/// A child that exited before the teardown's kill, and whose kill still failed — a setuid zombie
/// keeps its credentials, so `kill(2)` refuses it with EPERM — is reaped by the teardown's one
/// check, and nothing is handed back: the spawn's own error is returned. The seam makes the child
/// exit before the teardown sees it, whatever the machine's speed.
#[test]
fn a_child_whose_kill_failed_after_it_exited_is_reaped_and_not_handed_back() {
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-eperm-exited-8e41",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_attach_failure_awaits_exit();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    assert!(
        matches!(err, Some(Error::Containment { .. })),
        "the spawn's own error, with no child handed back, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// A contained std-path root is created `CREATE_SUSPENDED` and resumed only by a successful
/// attach, so after a failed attach it cannot exit on its own and nothing may wait for it. When
/// its kill fails, the teardown terminates it again through the handle it holds, and reaps it.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_teardown_could_not_kill_is_terminated_through_its_handle() {
    crate::log_capture::install();
    let mut cmd = blocker();
    cmd.contain();
    let mark = crate::log_capture::mark();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive("cosca-kill-fail-suspended-71d0");
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    // The retry terminated it, so nothing is handed back: the spawn's own error.
    assert!(
        matches!(err, Some(Error::Containment { .. })),
        "the spawn's own error, got {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(mark, "cosca-kill-fail-suspended-71d0"),
        "the failed kill must be logged"
    );
    // Dead on return: the teardown reaped it, so no exit is awaited here.
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// When the retry fails too, the suspended child is leaked, and the teardown says so rather than
/// handing it to a wait that could never end. The test terminates it afterwards.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_teardown_cannot_terminate_is_reported_leaked() {
    crate::log_capture::install();
    let mut cmd = blocker();
    cmd.contain();
    let mark = crate::log_capture::mark();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-eperm-suspended-0c55",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_force_suspended_terminate_failure("cosca-terminate-fail-suspended-e3a9");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || cmd.spawn().err()));
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_suspended_terminate_failure(),
        None,
        "the retry must consume its forced failure"
    );
    // The leak is asserted even though EPERM on the kill is not.
    assert_eq!(outcome.is_err(), cfg!(debug_assertions));
    assert!(
        crate::log_capture::contains_since(mark, "cosca-terminate-fail-suspended-e3a9"),
        "the leaked suspended child must be reported"
    );
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    crate::wait::kill(id).expect("terminate the leaked child");
    await_exit(&captured);
    fault::assert_child_reaped(captured);
}

/// `blocker()` on the raw `CreateProcessW` backend, which an `executable()` routes to.
#[cfg(windows)]
fn raw_blocker() -> Command {
    let mut cmd = blocker();
    cmd.executable("ping");
    assert!(
        super::routes_to_raw_backend(&cmd),
        "this is only a raw-backend proof while executable() routes there"
    );
    cmd
}

/// The raw backend's counterpart of the std suspended-child test: after a failed attach its
/// contained root is still `CREATE_SUSPENDED`, so when the kill fails the teardown terminates it
/// again through the handle it holds, and waits for it.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_raw_teardown_could_not_kill_is_terminated_through_its_handle() {
    crate::log_capture::install();
    let marker = "cosca-raw-kill-fail-suspended-2b84";
    let mut cmd = raw_blocker();
    cmd.contain();
    let mark = crate::log_capture::mark();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive(marker);
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    err.expect("the forced arm must fail the spawn");
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    assert!(
        crate::log_capture::contains_since(mark, marker),
        "the failed kill must be logged"
    );
    // Dead on return: the teardown waited for the terminated child.
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// When the raw teardown's retry fails too, the suspended child is leaked, and it says so. The
/// test terminates it afterwards.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_raw_teardown_cannot_terminate_is_reported_leaked() {
    crate::log_capture::install();
    let marker = "cosca-raw-terminate-fail-suspended-8c1f";
    let mut cmd = raw_blocker();
    cmd.contain();
    let mark = crate::log_capture::mark();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive("cosca-raw-kill-fail-suspended-6e07");
    fault::set_force_suspended_terminate_failure(marker);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || cmd.spawn().err()));
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_suspended_terminate_failure(),
        None,
        "the retry must consume its forced failure"
    );
    assert_eq!(outcome.is_err(), cfg!(debug_assertions), "the leak is asserted");
    assert!(
        crate::log_capture::contains_since(mark, marker),
        "the leaked suspended child must be reported"
    );
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    crate::wait::kill(id).expect("terminate the leaked child");
    await_exit(&captured);
    fault::assert_child_reaped(captured);
}

/// The retry for a suspended child reads `ERROR_ACCESS_DENIED` as an exit already underway, as
/// `RawChild::kill` does, and waits for it instead of reporting a leak. The seam terminates the
/// child for real, so the exit the wait confirms is genuine.
#[cfg(windows)]
#[test]
fn a_suspended_child_whose_retry_finds_its_exit_underway_is_waited_for_not_reported_leaked() {
    crate::log_capture::install();
    let mut cmd = blocker();
    cmd.contain();
    let mark = crate::log_capture::mark();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-eperm-underway-5a0d",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_force_suspended_terminate_exit_underway();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    err.expect("the forced arm must fail the spawn");
    assert!(
        !fault::take_force_suspended_terminate_exit_underway(),
        "the retry must consume its forced outcome"
    );
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    // This child's own leak report, which names its pid: a sibling test's cannot match.
    assert!(
        !crate::log_capture::contains_since(mark, &format!("suspended pid {} either", id.pid())),
        "an exit already underway is not a leak"
    );
    // Dead on return: the teardown waited for the exit.
    fault::assert_child_reaped(captured);
}

/// A `try_wait` error after a failed kill — a genuine `ECHILD`, meaning something else already
/// reaped the child — means the pid may already name another process. The child is not handed
/// back, which would have its holder wait on that pid: it is released, the error logged, and the
/// spawn's own error returned.
#[cfg(unix)]
#[test]
fn a_child_whose_one_check_fails_with_echild_after_a_failed_kill_is_released_not_handed_back() {
    use crate::stdio::Stdio;
    crate::log_capture::install();
    let mut cmd = Command::new();
    cmd.args(["cat"]);
    cmd.stdin(Stdio::pipe_in()).unwrap().stdout(Stdio::null()).unwrap();
    let mark = crate::log_capture::mark();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-eperm-try-wait-echild-80d4",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_force_teardown_try_wait_echild();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    assert!(
        matches!(err, Some(Error::Containment { .. })),
        "the spawn's own error, with no child handed back, got {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(mark, "ownership is uncertain"),
        "the release must be logged"
    );
    // Released, never waited on: this test's own child, reaped by hand.
    let crate::identity::Resolved::Found(id) = fault::take_captured().expect("seam captured the child's identity")
    else {
        panic!("the seam must capture a resolved identity");
    };
    let pid = nix::unistd::Pid::from_raw(id.pid() as i32);
    nix::sys::wait::waitpid(pid, None).expect("reap the child");
}

/// A teardown whose one check comes back with ownership uncertain (a genuine `ECHILD`) disarms
/// what it retained, the same as a leaked or already-uncertain-owned child's: the pid may already
/// name another process, so this spawn no longer treats itself as owning the tree to kill on
/// drop.
///
/// Calls `teardown_unadopted` directly: it is private, reachable from this submodule, and driving
/// this exact arm through a full spawn would need attach failure, a real occupied leaf and the
/// ECHILD seam all armed together for one code path, proving nothing the direct call does not.
#[cfg(target_os = "linux")]
#[test]
fn a_teardown_whose_check_is_uncertain_disarms_its_retained_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-teardown-uncertain-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    let leaf = crate::containment::cgroup::test_support::entered_leaf_at(leaf_path.clone());
    let std_child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn a real child");
    let pid = std_child.id();
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-teardown-kill-eperm-uncertain-3f1a",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_force_teardown_try_wait_echild();

    let handed_back = super::teardown_unadopted(std_child, Some(crate::containment::Attached::Cgroup(leaf)));

    assert!(
        handed_back.is_none(),
        "an uncertain check releases the child, handing nothing back"
    );
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"",
        "an uncertain-ownership release must disarm its retained leaf, not kill through it"
    );
    // The real child is still alive: the kill above was faked. End it for real and reap it
    // ourselves, since the teardown released it as ownership-uncertain without waiting.
    // SAFETY: `pid` is this process's own unreaped child.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: as above; a blocking reap of this process's own child.
    unsafe { libc::waitpid(pid as i32, &mut status, 0) };
}

/// A `try_wait` error after a failed kill that is NOT `ECHILD` — a too-old kernel's `EINVAL` from
/// `waitid(P_PIDFD)`, or any other transient failure — says nothing about the child's ownership:
/// its pid is still pinned to this unreaped child, so it is handed back running, exactly as a
/// check that had not failed at all would hand it back.
#[cfg(unix)]
#[test]
fn a_child_whose_one_check_fails_with_a_non_echild_error_after_a_failed_kill_is_handed_back() {
    let marker = "cosca-teardown-try-wait-fail-non-echild-3c95";
    let mut cmd = blocker();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-eperm-try-wait-fail-non-echild-80d4",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_force_teardown_try_wait_error(marker);
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_teardown_try_wait_error(),
        None,
        "the teardown must consume it"
    );
    let Some(Error::Unreaped { child, .. }) = err else {
        panic!("a non-ECHILD check failure keeps the child, handed back running, got {err:?}");
    };
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    assert_eq!(
        child.pid(),
        id.pid(),
        "the handed-back child is the spawned one, still held"
    );
    crate::wait::kill(id).expect("end the child");
    child.wait().expect("wait for the handed-back child");
    fault::assert_child_reaped(captured);
}

/// A raw-backend child the teardown could not kill, and that is not suspended, is handed back in
/// the error, EPERM or not. The test ends it, and the handed-back child reaps it.
#[cfg(windows)]
#[test]
fn a_raw_teardown_hands_back_a_child_it_could_not_kill() {
    use std::io::ErrorKind;
    for (kind, marker) in [
        (ErrorKind::PermissionDenied, "cosca-raw-kill-eperm-uncontained-1f5b"),
        (ErrorKind::Other, "cosca-raw-kill-fail-uncontained-a92e"),
    ] {
        let mut cmd = raw_blocker();
        fault::set_force_attach_failure(true);
        fault::set_force_kill_failure_leaving_child_alive_as(marker, kind);
        let err = cmd.spawn().err();
        fault::set_force_attach_failure(false);
        assert_eq!(
            fault::take_force_kill_failure(),
            None,
            "{kind:?}: the kill failure must be consumed"
        );
        let Some(Error::Unreaped { kill, child, .. }) = err else {
            panic!("{kind:?}: the unkillable child must be handed back, got {err:?}");
        };
        assert_eq!(kill.kind(), kind);
        let captured = fault::take_captured().expect("seam captured the child's identity");
        let crate::identity::Resolved::Found(id) = captured else {
            panic!("the seam must capture a resolved identity, got {captured:?}");
        };
        assert_eq!(child.pid(), id.pid());
        crate::wait::kill(id).expect("terminate the child");
        child.wait().expect("wait for the handed-back child");
        fault::assert_child_reaped(captured);
    }
}

/// No thread outlives a failed spawn: cosca keeps none to reap with. After a spawn whose child is
/// handed back, no thread of the names cosca's reapers used — `cosca-reap`, `cosca-reap-<pid>`,
/// `cosca-unadopted-reaper` — exists. (`cosca-reaper` is the async `Child`'s kill-on-drop pool,
/// which a failed spawn never starts.)
#[cfg(target_os = "linux")]
#[test]
fn no_thread_outlives_a_failed_spawn_whose_child_is_handed_back() {
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-eperm-no-thread-5b8e",
        std::io::ErrorKind::PermissionDenied,
    );
    let err = blocker().spawn().err();
    fault::set_force_attach_failure(false);
    let Some(Error::Unreaped { child, .. }) = err else {
        panic!("the unkillable child must be handed back, got {err:?}");
    };
    let names: Vec<String> = std::fs::read_dir("/proc/self/task")
        .expect("list this process's threads")
        .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .map(|name| name.trim_end().to_owned())
        .collect();
    let reapers: Vec<&String> = names
        .iter()
        .filter(|name| *name == "cosca-reap" || name.starts_with("cosca-reap-") || name.starts_with("cosca-unadopted"))
        .collect();
    assert!(reapers.is_empty(), "a failed spawn left reaper threads: {reapers:?}");
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    crate::wait::kill(id).expect("end the child");
    child.wait().expect("wait for the handed-back child");
}

/// A failed reap of an elevated child the failed password write's teardown killed is not
/// discarded: it is logged at `warn`, which a release build keeps, and asserted in debug builds.
#[cfg(unix)]
#[test]
fn a_failed_reap_of_a_killed_elevated_child_is_logged() {
    crate::log_capture::install();
    let marker = "cosca-elevated-reap-fail-2a9c";
    let child = blocker().spawn().expect("spawn the stand-in for the elevated child");
    let id = child.id();
    let mark = crate::log_capture::mark();
    fault::set_force_reap_failure(marker);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::elevated_write_failed(
            child,
            Error::Io(std::io::Error::other("cosca-password-write-fail-5c01")),
        )
    }));
    assert_eq!(
        fault::take_force_reap_failure(),
        None,
        "the forced failure must be consumed"
    );
    assert_eq!(
        outcome.is_err(),
        cfg!(debug_assertions),
        "the debug_assert fires in exactly the builds that keep it"
    );
    assert!(
        crate::log_capture::contains_since(mark, marker),
        "a failed reap must be logged"
    );
    fault::assert_child_reaped(crate::identity::Resolved::Found(id));
}

/// When the deferred password write of a POSIX elevated spawn fails and its child refuses the kill
/// — a setuid `sudo` refuses ours with EPERM — the child is handed back in `Error::Unreaped`,
/// whose `error` is the elevation's own `AuthFailed`, rather than dropped unreaped.
#[cfg(unix)]
#[test]
fn an_elevated_child_a_failed_password_write_cannot_kill_is_handed_back() {
    let child = blocker().spawn().expect("spawn the stand-in for the elevated child");
    let pid = child.id().pid();
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-elevated-kill-eperm-4d1a",
        std::io::ErrorKind::PermissionDenied,
    );
    let err = super::elevated_write_failed(
        child,
        Error::Io(std::io::Error::other("cosca-password-write-fail-7e20")),
    );
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    let Error::Unreaped { error, kill, child } = err else {
        panic!("the unkillable elevated child must be handed back, got {err:?}");
    };
    assert_eq!(kill.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        matches!(&*error, Error::Elevation { kind: crate::error::ElevationErrorKind::AuthFailed, detail } if detail.contains("cosca-password-write-fail-7e20")),
        "why the spawn failed, got {error:?}"
    );
    assert_eq!(child.pid(), pid);
    let crate::identity::Resolved::Found(id) = crate::identity::ProcessId::of(pid) else {
        panic!("the handed-back child is unreaped, so its identity resolves");
    };
    crate::wait::kill(id).expect("end the child");
    child.wait().expect("wait for the handed-back child");
    fault::assert_child_reaped(crate::identity::Resolved::Found(id));
}

/// On Windows a held process handle pins its process, so a check that fails says nothing about
/// ownership: the teardown keeps the handle. A suspended child whose kill and check both failed is
/// still terminated through it, as one whose check succeeded is.
#[cfg(windows)]
#[test]
fn a_suspended_child_whose_check_fails_is_still_terminated_through_its_handle() {
    for raw in [false, true] {
        let mut cmd = if raw { raw_blocker() } else { blocker() };
        cmd.contain();
        fault::set_force_attach_failure(true);
        fault::set_force_kill_failure_leaving_child_alive("cosca-kill-fail-suspended-check-fail-8a0e");
        fault::set_force_teardown_try_wait_error("cosca-check-fail-suspended-2c47");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || cmd.spawn().err()));
        fault::set_force_attach_failure(false);
        assert_eq!(
            fault::take_force_teardown_try_wait_error(),
            None,
            "raw {raw}: the check failure must be consumed"
        );
        let err = outcome.expect("raw {raw}: the kill failure was recovered, so nothing panics");
        assert!(
            matches!(err, Some(Error::Containment { .. })),
            "raw {raw}: the retry terminated it, so the spawn's own error comes back, got {err:?}"
        );
        // Dead on return: the teardown terminated it through the handle it kept.
        fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    }
}

/// On Windows a running child whose kill and check both failed is handed back, not released: the
/// check's failure says nothing about ownership while the handle is held.
#[cfg(windows)]
#[test]
fn a_child_whose_check_fails_on_windows_is_handed_back() {
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive("cosca-kill-fail-check-fail-5e19");
    fault::set_force_teardown_try_wait_error("cosca-check-fail-handed-back-7b33");
    let err = blocker().spawn().err();
    fault::set_force_attach_failure(false);
    let Some(Error::Unreaped { child, .. }) = err else {
        panic!("the child must be handed back, got {err:?}");
    };
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    crate::wait::kill(id).expect("end the child");
    child.wait().expect("wait for the handed-back child");
    fault::assert_child_reaped(captured);
}
