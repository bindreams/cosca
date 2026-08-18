// Unit tests for dispatch root-detection and mechanism-selection logic.
// These test pure functions directly — no process-env mutation required.

use super::is_nested;

/// Without the marker the process is the root (not nested).
#[test]
fn is_nested_without_marker_is_false() {
    assert!(!is_nested(false));
}

/// With the marker the process is already inside a contained tree (nested).
#[test]
fn is_nested_with_marker_is_true() {
    assert!(is_nested(true));
}

// unix_setup_for mutual-exclusivity tests (S3) =====

/// `ContainMode::Session` must select `UnixSetup::Session` (setsid) — never
/// `ProcessGroup`. This is the critical S3 invariant: calling both setsid AND
/// setpgid/process_group(0) on the same Command would cause EPERM.
#[cfg(unix)]
#[test]
fn unix_setup_for_session_selects_setsid() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::Session)), UnixSetup::Session);
}

/// `ContainMode::Strongest` must select `UnixSetup::ProcessGroup` — never Session.
#[cfg(unix)]
#[test]
fn unix_setup_for_strongest_selects_process_group() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::Strongest)), UnixSetup::ProcessGroup);
}

/// `ContainMode::TreeWalk` must select `UnixSetup::None` — NO pre-spawn process
/// group. TreeWalk exists to catch children that escape a process group via
/// `setsid`/`setpgid`, so the root must not be put in a group; teardown is by
/// identity at kill time.
#[cfg(unix)]
#[test]
fn unix_setup_for_treewalk_selects_none() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::TreeWalk)), UnixSetup::None);
}

/// Uncontained (`None` mode) must select `UnixSetup::ProcessGroup` (the
/// prepare path gates on `mode.is_some()` before calling this, but the
/// default fallback is well-defined).
#[cfg(unix)]
#[test]
fn unix_setup_for_none_mode_selects_process_group() {
    use super::{unix_setup_for, UnixSetup};
    assert_eq!(unix_setup_for(None), UnixSetup::ProcessGroup);
}

// Attached actionability + nested delegation =====

#[test]
fn attached_is_actionable() {
    use super::Attached;
    // No teardown mechanism -> not actionable (the _tree guard rejects these).
    assert!(!Attached::None.is_actionable()); // uncontained / lone
    assert!(!Attached::Delegated.is_actionable());
    // Every real mechanism is actionable. Cheap variants are built inline; Cgroup/JobObject
    // need an OS handle, so a test-only constructor builds one (asserted on its own platform).
    assert!(Attached::TreeWalk(crate::identity::ProcessId::current()).is_actionable());
    #[cfg(unix)]
    assert!(Attached::ProcessGroup(0).is_actionable());
    #[cfg(target_os = "linux")]
    assert!(Attached::Cgroup(crate::containment::cgroup::CgroupLeaf::placeholder_for_test()).is_actionable());
    #[cfg(windows)]
    assert!(Attached::JobObject(crate::containment::windows::JobHandle::create_empty_for_test()).is_actionable());
}

/// `Child::kill_tree`/`terminate_tree`'s pgid-recycle precondition assert gates on this
/// predicate, not on `Attached::ProcessGroup` alone (`src/child.rs`, `src/tokio/child.rs`) —
/// a macOS `FdMarker` that carries a pgid must be covered too, since it fires `killpg`
/// unconditionally on pass 1 of every sweep, exactly the hazard this precondition guards.
#[cfg(unix)]
#[test]
fn attached_carries_recyclable_pgid() {
    use super::Attached;
    assert!(!Attached::None.carries_recyclable_pgid());
    assert!(!Attached::Delegated.carries_recyclable_pgid());
    assert!(!Attached::TreeWalk(crate::identity::ProcessId::current()).carries_recyclable_pgid());
    assert!(Attached::ProcessGroup(0).carries_recyclable_pgid());
    #[cfg(target_os = "linux")]
    assert!(
        !Attached::Cgroup(crate::containment::cgroup::CgroupLeaf::placeholder_for_test()).carries_recyclable_pgid()
    );
}

/// The macOS-specific half of `attached_carries_recyclable_pgid`: an `FdMarker` must track
/// its OWN `pgid`, not the mechanism's mere presence — `TreeWalk` mode creates no pgid at
/// all (`Marker::pgid: None`), so a marker built for it must read `false` here exactly like
/// `Attached::TreeWalk` itself, while a marker built for any grouped mode (`pgid: Some(_)`)
/// must read `true`, matching `Attached::ProcessGroup`.
#[cfg(target_os = "macos")]
#[test]
fn attached_fd_marker_carries_recyclable_pgid_tracks_its_own_pgid() {
    use std::os::fd::{AsFd, AsRawFd};

    use super::Attached;

    fn marker_with_pgid(pgid: Option<i32>) -> crate::containment::fdmarker::Marker {
        let (read, write) = std::io::pipe().expect("pipe");
        let handle = crate::containment::fdmarker::pipe_handle_of(write.as_fd()).expect("handle");
        let read_handle = crate::containment::fdmarker::pipe_handle_of(read.as_fd()).expect("read handle");
        let prepared = crate::containment::fdmarker::PreparedMarker {
            read: std::os::fd::OwnedFd::from(read),
            handle,
            read_handle,
            fd: write.as_fd().as_raw_fd(),
        };
        crate::containment::fdmarker::Marker::new(prepared, None, pgid, false)
    }

    assert!(Attached::FdMarker(marker_with_pgid(Some(1234))).carries_recyclable_pgid());
    assert!(!Attached::FdMarker(marker_with_pgid(None)).carries_recyclable_pgid());
}

/// Drives the real `attach()` nested arms (not a hand-built variant): a nested
/// (`!is_root`) contained spawn must yield BOTH halves of the delegated pair —
/// `Containment::Delegated` and `Attached::Delegated` — for a kernel mechanism
/// (Strongest) and TreeWalk, so `containment()` predicts the `_tree` error.
#[test]
fn nested_attach_is_delegated() {
    use super::{attach, Attached, Prepared};
    use crate::containment::{ContainMode, Containment};

    fn spawn_trivial() -> std::process::Child {
        // attach()'s nested arms don't touch the child, so an exited child is fine. Held for
        // the fork itself: a fork landing while a `fdmarker_tests.rs` test's marker write end
        // is transiently open would inherit it into this not-yet-`exec`'d process, and a
        // concurrent sweep could then find and SIGKILL it.
        let _guard = crate::child::spawn::spawn_lock();
        #[cfg(unix)]
        return std::process::Command::new("true").spawn().expect("spawn true");
        #[cfg(windows)]
        return std::process::Command::new("cmd")
            .args(["/C", "exit"])
            .spawn()
            .expect("spawn cmd");
    }

    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        let mut child = spawn_trivial();
        let prepared = Prepared {
            mode: Some(mode),
            is_root: false, // nested member
            #[cfg(target_os = "linux")]
            cgroup_leaf: None,
            #[cfg(target_os = "macos")]
            marker: None,
            #[cfg(windows)]
            graceful: crate::containment::windows::mechanism_from_flags(crate::containment::windows::group_flags()),
        };
        #[cfg(windows)]
        let proc_handle = {
            use std::os::windows::io::AsRawHandle;
            child.as_raw_handle()
        };
        let attachment = attach(
            child.id(),
            #[cfg(windows)]
            proc_handle,
            prepared,
        )
        .expect("attach nested");
        let (containment, attached) = (attachment.containment, attachment.attached);
        // Reap before asserting: `attached` is owned and independent of `child`, so a
        // failing assertion must not leak the helper (the nested arms don't touch it).
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            containment,
            Containment::Delegated,
            "nested member ({mode:?}) must report Containment::Delegated, got {containment:?}"
        );
        assert!(
            matches!(attached, Attached::Delegated),
            "nested member ({mode:?}) must be Attached::Delegated, got {attached:?}"
        );
    }
}

// kill_tree handle-backstop (treewalk / macOS fd-marker fault seam) =====

// A long-lived TreeWalk-contained child; no descendants, so with the root identity-kill
// seam-disabled the ONLY killer is kill_tree's handle backstop. Armed AFTER the fallible
// spawn so a spawn panic cannot leak the flag.
//
// On macOS, `ContainMode::TreeWalk` still attaches `Containment::FdMarker` (decision 2: the
// marker installs for every contained root regardless of requested mode) — its `sweep` calls
// `treewalk::kill_by_identity` directly, never `treewalk::hard_kill`, so `treewalk::fault`'s
// seam is never consumed there; `fdmarker::fault` provides the matching seam instead.
#[test]
fn sync_kill_tree_backstop_is_load_bearing() {
    #[cfg(not(target_os = "macos"))]
    use super::super::treewalk::fault;
    #[cfg(target_os = "macos")]
    use crate::containment::fdmarker::fault;
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn");
    fault::set_force_root_kill_noop(true);
    let result = child.kill_tree();
    assert!(
        !fault::armed(),
        "seam not consumed — hard_kill did not run on the arming thread"
    );
    result.expect("kill_tree via backstop");
    let status = child.wait().expect("reap");
    assert!(
        !status.success(),
        "the handle backstop must be what killed the root, got {status:?}"
    );
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_kill_tree_backstop_is_load_bearing() {
    #[cfg(not(target_os = "macos"))]
    use super::super::treewalk::fault;
    #[cfg(target_os = "macos")]
    use crate::containment::fdmarker::fault;
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    fault::set_force_root_kill_noop(true);
    let result = child.kill_tree();
    assert!(
        !fault::armed(),
        "seam not consumed — hard_kill did not run on the arming thread"
    );
    result.expect("kill_tree via backstop");
    let status = child.wait().await.expect("reap");
    assert!(
        !status.success(),
        "the handle backstop must be what killed the root, got {status:?}"
    );
}

// fd marker install policy (macOS) =====

/// The install policy, exhaustively: every mode installs a marker for a ROOT spawn, no
/// nested spawn ever does (it inherits the root's), no uncontained spawn does, and an
/// elevation-derived spawn does not (its `sudo` wrapper closes every descriptor >= 3).
#[cfg(target_os = "macos")]
#[test]
fn marker_wanted_installs_for_every_contained_root_and_nothing_else() {
    use crate::containment::fdmarker::marker_wanted;
    use crate::containment::ContainMode;
    for mode in [ContainMode::Strongest, ContainMode::Session, ContainMode::TreeWalk] {
        assert!(
            marker_wanted(Some(mode), true, false),
            "{mode:?} root installs a marker"
        );
        assert!(
            !marker_wanted(Some(mode), false, false),
            "{mode:?} nested inherits, never installs"
        );
        assert!(
            !marker_wanted(Some(mode), true, true),
            "{mode:?} elevated root must not install"
        );
    }
    assert!(
        !marker_wanted(None, true, false),
        "an uncontained spawn installs no marker"
    );
}

/// The marker mechanism is actionable: `kill_tree`/`terminate_tree` act on it.
#[cfg(target_os = "macos")]
#[test]
fn attached_fd_marker_is_actionable() {
    use std::os::fd::{AsFd, AsRawFd};

    use super::Attached;
    let (read, write) = std::io::pipe().expect("pipe");
    let handle = crate::containment::fdmarker::pipe_handle_of(write.as_fd()).expect("handle");
    let read_handle = crate::containment::fdmarker::pipe_handle_of(read.as_fd()).expect("read handle");
    let prepared = crate::containment::fdmarker::PreparedMarker {
        read: std::os::fd::OwnedFd::from(read),
        handle,
        read_handle,
        fd: write.as_fd().as_raw_fd(),
    };
    let marker = crate::containment::fdmarker::Marker::new(prepared, None, None, false);
    assert!(Attached::FdMarker(marker).is_actionable());
}

/// `prepare` must thread the caller's reserved child fds through to the placement, or a user
/// fd mapping would dup2 over the marker in the child.
#[cfg(target_os = "macos")]
#[test]
fn prepare_places_the_marker_above_the_callers_reserved_fds() {
    use crate::containment::{ContainMode, ContainRequest, Nesting};
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let prepared = super::prepare(
        &mut cmd,
        &ContainRequest {
            mode: Some(ContainMode::Strongest),
            nesting: Nesting::Mark,
        },
        &[3, 4, 5, 6, 7, 8, 9, 10],
        false,
    );
    let marker = prepared.marker.as_ref().expect("a contained macOS root gets a marker");
    assert!(
        marker.fd > 10,
        "prepare placed the marker on fd {}, which a user mapping would dup2 over",
        marker.fd
    );
}

/// A failed install degrades to the pre-existing mechanism rather than failing the spawn.
#[cfg(target_os = "macos")]
#[test]
fn a_failed_marker_install_leaves_prepare_without_one() {
    use crate::containment::fdmarker::fault::{lock_for_log_assertion, set_fault, Fault};
    use crate::containment::{ContainMode, ContainRequest, Nesting};
    // This test doesn't assert on log content itself, but triggering `Fault::Pipe` DOES emit
    // "fd marker: pipe() failed" into the shared `log_capture` buffer once any test has called
    // `log_capture::install()` — held for the whole body so it cannot land inside the sibling
    // fd-marker test module's fault-injection log-scanning test's scanned window on another
    // thread.
    let _serialize = lock_for_log_assertion();
    let mut cmd = std::process::Command::new("/usr/bin/true");
    set_fault(Some(Fault::Pipe));
    let prepared = super::prepare(
        &mut cmd,
        &ContainRequest {
            mode: Some(ContainMode::Strongest),
            nesting: Nesting::Mark,
        },
        &[],
        false,
    );
    assert!(prepared.marker.is_none(), "the forced failure must yield no marker");
}

/// An elevation-derived spawn must not install a marker: `sudo` closes every descriptor >= 3.
#[cfg(target_os = "macos")]
#[test]
fn prepare_installs_no_marker_for_an_elevation_derived_spawn() {
    use crate::containment::{ContainMode, ContainRequest, Nesting};
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let prepared = super::prepare(
        &mut cmd,
        &ContainRequest {
            mode: Some(ContainMode::Strongest),
            nesting: Nesting::Mark,
        },
        &[],
        true,
    );
    assert!(
        prepared.marker.is_none(),
        "an elevated spawn must not claim marker containment"
    );
}

#[cfg(windows)]
#[test]
fn resolve_root_id_distinguishes_a_denied_pid_from_a_vanished_one() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(PROCESS_SYNCHRONIZE.0);
    assert!(child.is_running(), "precondition: the subject must be live");

    let Err(crate::error::Error::Unassessable { detail, .. }) = super::resolve_root_id(child.pid()) else {
        panic!("a pid we may not query must not resolve to a root identity");
    };
    assert!(
        detail.contains("identity could not be read"),
        "denial must not read as vanishing: {detail}"
    );

    // Contrast: a pid no process holds.
    let Err(crate::error::Error::Containment { detail }) = super::resolve_root_id(0xFFFF_FFF0) else {
        panic!("a nonexistent pid must not resolve");
    };
    assert!(detail.contains("vanished"), "absence must not read as denial: {detail}");
}

#[cfg(target_os = "macos")]
#[test]
fn wait_drained_is_unsupported_without_a_marker() {
    // Mirrors `require_contained`: a mechanism that cannot answer says so, rather than
    // implying a guarantee it has not got.
    use super::Attached;
    for attached in [Attached::None, Attached::Delegated] {
        let err = attached
            .wait_drained(Some(Some(std::time::Instant::now())))
            .expect_err("a mechanism with no drain edge must be Unsupported");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn wait_drained_reports_members_remain_then_all_markers_closed() {
    use super::Attached;
    use crate::containment::fdmarker::{pipe_handle_of, Marker, PreparedMarker};
    use crate::containment::TreeDrain;
    use std::os::fd::{AsFd, OwnedFd};

    // A real holder in a separate process, mirroring marker_eof_tests.rs's
    // spawn_marker_holder: the marker's write end lives in the child, not in-process, so
    // wait_drained observes a genuinely open, then genuinely closed, write end.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "exec cat >/dev/null"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");

    // wait_drained now consults read_handle too (Marker::wait_drained calls
    // check_read_end_still_valid first, same as hard_kill/terminate) — so this uses the read
    // end's REAL current handle for both fields, standing in for install()'s full write-end
    // capture sequence without replicating it.
    let handle = pipe_handle_of(marker.as_fd()).expect("handle");
    let prepared = PreparedMarker {
        read: OwnedFd::from(marker),
        handle,
        read_handle: handle,
        fd: 3,
    };
    let attached = Attached::FdMarker(Marker::new(prepared, None, None, false));

    assert_eq!(
        attached
            .wait_drained(Some(Some(std::time::Instant::now())))
            .expect("bounded wait while the holder is alive"),
        TreeDrain::MembersRemain
    );

    drop(stdin); // cat's stdin EOFs, so cat exits, closing its inherited marker write end
    child.wait().expect("reap");

    assert_eq!(
        attached
            .wait_drained(None)
            .expect("unbounded wait after the holder exits"),
        TreeDrain::AllMarkersClosed
    );
}

/// The three shapes `windows_contain_setup` can produce must not all agree: an uncontained
/// spawn leads no group, while both contained shapes do. Lives here rather than in
/// `windows_tests.rs` because `windows_contain_setup` is defined in this module.
#[cfg(windows)]
#[test]
fn windows_contain_setup_records_the_mechanism_of_the_flags_it_chose() {
    use super::windows_contain_setup;
    use crate::containment::{ContainMode, ContainRequest, Nesting};
    use crate::graceful::GracefulMechanism;

    let uncontained = ContainRequest {
        mode: None,
        nesting: Nesting::Mark,
    };
    let contained = ContainRequest {
        mode: Some(ContainMode::Strongest),
        nesting: Nesting::Mark,
    };
    assert_eq!(
        windows_contain_setup(&uncontained, true).graceful,
        GracefulMechanism::None,
        "an uncontained spawn passes no flags, so it leads no group"
    );
    assert_eq!(
        windows_contain_setup(&contained, true).graceful,
        GracefulMechanism::ConsoleGroup,
        "a Strongest root spawns suspended into its own group"
    );
    assert_eq!(
        windows_contain_setup(&contained, false).graceful,
        GracefulMechanism::ConsoleGroup,
        "a nested spawn leads its own group too"
    );
}

/// The UAC-elevated attachment bypasses `mechanism_from_flags` entirely — nothing in the flag
/// matrix covers it — so its three fields are pinned here. `Unknown`, not the `None` a flagless
/// spawn yields nor the `OtherConsoleGroup` a suppressed one does: a copy-paste of either must
/// fail. What the dispatcher then does with the value is
/// `signal_refuses_a_child_cosca_did_not_create`, in `src/graceful_tests.rs`.
#[cfg(windows)]
#[test]
fn uac_elevated_attachment_has_no_in_process_route() {
    use super::{Attached, Attachment};
    use crate::containment::Containment;
    use crate::graceful::GracefulMechanism;

    let a = Attachment::uac_elevated();
    assert_eq!(a.containment, Containment::None);
    assert!(matches!(a.attached, Attached::None), "got {:?}", a.attached);
    assert_eq!(a.graceful, GracefulMechanism::Unknown);
}
