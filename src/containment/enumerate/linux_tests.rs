use super::process_parents;
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};

type Records = Vec<(log::Level, String)>;

fn snapshot_with(view: ForcedView) -> (Result<Vec<(u32, u32)>, crate::error::Error>, Records) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let forced = force_proc_view_once(view);
    let got = process_parents();
    drop(forced);
    (
        got,
        crate::log_capture::records_since_on_current_thread(mark, "enumerate::process_parents"),
    )
}

fn assert_unassessable_naming(got: Result<Vec<(u32, u32)>, crate::error::Error>, cause: &str) {
    match got {
        Err(crate::error::Error::Unassessable { detail, .. }) => {
            assert!(detail.contains(cause), "the error must name {cause:?}: {detail}")
        }
        other => panic!("expected Unassessable naming {cause:?}, got {other:?}"),
    }
}

/// An outer namespace's `/proc` lists processes whose pids mean nothing here, and the tree walk
/// signals by pid: the snapshot is `Unassessable` naming the view (and logged at `warn`), never
/// an empty list a walk would read as "no descendants". Mutants: "scan `/proc` by path whatever
/// the view"; "return an empty snapshot for a view that is not `Same`".
#[test]
fn a_diverged_view_is_unassessable_and_warned_about() {
    let (got, records) = snapshot_with(ForcedView::Diverged);
    assert_unassessable_naming(got, "outer pid namespace");
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("outer pid namespace")),
        "{records:?}"
    );
}

#[test]
fn an_unassessable_view_is_unassessable_and_warned_about_naming_the_cause() {
    let (got, records) = snapshot_with(ForcedView::Unassessable);
    assert_unassessable_naming(got, "forced by a test");
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("forced by a test")),
        "{records:?}"
    );
}

/// The ordinary snapshot lists this process under its real parent.
#[test]
fn the_ordinary_snapshot_lists_this_process_with_its_parent() {
    let me = std::process::id();
    let ppid = std::os::unix::process::parent_id();
    assert!(process_parents().expect("the snapshot").contains(&(me, ppid)));
}

/// Without `openat2` no view can be checked: the snapshot is `Unsupported`, naming the requirement
/// as a spawn does, and logged at `warn` with it. Mutant: "report every unreadable view as
/// `Unassessable`" - the requirement is missing from both the error and the warning.
#[test]
fn a_snapshot_without_openat2_is_unsupported_naming_it_and_warned_about() {
    for (errno, name) in [(rustix::io::Errno::NOSYS, "ENOSYS"), (rustix::io::Errno::PERM, "EPERM")] {
        crate::log_capture::install();
        let mark = crate::log_capture::mark();
        let forced = crate::identity::proc_view_fault::force_openat2_errno(errno);
        let got = process_parents();
        drop(forced);
        let records = crate::log_capture::records_since_on_current_thread(mark, "enumerate::process_parents");

        match got {
            Err(crate::error::Error::Unsupported { op, detail, platform }) => {
                assert_eq!(platform, "linux");
                assert_eq!(detail, crate::identity::openat2_refused_message(name), "{errno}");
                assert!(!op.contains("foreign"), "{op}");
            }
            other => panic!("{errno}: expected Unsupported, got {other:?}"),
        }
        assert!(
            records
                .iter()
                .any(|(level, m)| *level == log::Level::Warn
                    && m.contains(&crate::identity::openat2_refused_message(name))),
            "{errno}: {records:?}"
        );
    }
}

/// Another `/proc` open failure is not the requirement. Mutant: "every open failure is
/// `Unsupported`".
#[test]
fn a_snapshot_with_another_open_failure_is_not_unsupported() {
    let forced = crate::identity::proc_view_fault::force_openat2_errno(rustix::io::Errno::NOENT);
    let got = process_parents();
    drop(forced);
    assert!(matches!(got, Err(crate::error::Error::Unassessable { .. })), "{got:?}");
}

// Per-pid stat read failures =====

use crate::identity::pid_stat::fault::force_stat_read;

/// A pid that exited mid-scan (`ENOENT`, `ESRCH`) or that `hidepid` hides (`EACCES`, and `EPERM`
/// while the checked directory still answers) is absent, and the snapshot is still a snapshot.
/// Mutant: "fail the snapshot on every read error".
#[test]
fn a_pid_whose_stat_is_gone_or_hidden_is_skipped() {
    for errno in [libc::ENOENT, libc::ESRCH, libc::EACCES, libc::EPERM] {
        let _forced = force_stat_read(errno, None);
        let got = process_parents().unwrap_or_else(|e| panic!("errno {errno} is an absence: {e}"));
        assert!(got.is_empty(), "errno {errno}: {got:?}");
    }
}

/// Any other failure says nothing about the pid, and skipping it drops its whole subtree from a
/// walk: the snapshot is `Unassessable` naming `<pid>/stat` and the errno. Mutants: "skip every
/// read error" (an `EMFILE` from a full fd table hits every pid and yields `Ok(vec![])`); "a mount
/// crossing is skipped".
#[test]
fn any_other_stat_read_failure_is_unassessable_naming_pid_and_errno() {
    for errno in [
        libc::EXDEV,
        libc::ELOOP,
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOMEM,
        libc::EIO,
        libc::ENOSYS,
    ] {
        let _forced = force_stat_read(errno, None);
        let text = match process_parents() {
            Err(crate::error::Error::Unassessable { detail, source }) => {
                assert!(source.is_some(), "errno {errno}: the read's error is the source");
                detail
            }
            other => panic!("errno {errno}: expected Unassessable, got {other:?}"),
        };
        assert!(
            text.contains(&std::io::Error::from_raw_os_error(errno).to_string()),
            "{errno}: {text}"
        );
        if matches!(errno, libc::EXDEV | libc::ELOOP) {
            assert!(text.contains("lies beyond a mount in /proc"), "{errno}: {text}");
        }
        let pid = text.split("/stat").next().unwrap().rsplit(' ').next().unwrap();
        assert!(
            pid.parse::<u32>().is_ok(),
            "{errno}: the error must name the pid before `/stat`: {text}"
        );
    }
}

/// `EPERM` is `hidepid`'s answer and also a seccomp filter's for an `openat2` installed mid-scan;
/// only the checked directory still answering tells them apart. Mutant: "skip `EPERM` without the
/// re-check".
#[test]
fn eperm_is_unassessable_when_the_checked_directory_also_refuses() {
    for recheck in [libc::EPERM, libc::ENOSYS, libc::EMFILE] {
        let _forced = force_stat_read(libc::EPERM, Some(recheck));
        match process_parents() {
            Err(crate::error::Error::Unassessable { detail, .. }) => {
                assert!(detail.contains("self/stat"), "{recheck}: {detail}");
                assert!(
                    detail.contains(&std::io::Error::from_raw_os_error(recheck).to_string()),
                    "{recheck}: {detail}"
                );
            }
            other => panic!("{recheck}: expected Unassessable, got {other:?}"),
        }
    }
}

/// A failed `/proc` listing is `Unassessable` naming it and the errno, never an empty table.
/// Mutant: "an unlistable `/proc` is an empty snapshot".
#[test]
fn an_unlistable_proc_is_unassessable_naming_the_errno() {
    let _forced = crate::identity::proc_view_fault::force_pids_errno(libc::EIO);
    match process_parents() {
        Err(crate::error::Error::Unassessable { detail, source }) => {
            assert!(detail.contains("/proc could not be listed"), "{detail}");
            assert_eq!(source.and_then(|e| e.raw_os_error()), Some(libc::EIO));
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}

/// The kernel prints a parseable `stat` for every pid, so an unparsable one is a contract
/// violation, not an absence: the snapshot names the pid instead of dropping it. Mutant: "an
/// unparsable `stat` drops the pid".
#[test]
fn an_unparsable_stat_is_unassessable_naming_the_pid() {
    match super::ppid_of_stat(4242, b"4242 (no closing paren S 1") {
        Err(crate::error::Error::Unassessable { detail, .. }) => assert!(detail.contains("4242/stat"), "{detail}"),
        other => panic!("expected Unassessable, got {other:?}"),
    }
    assert_eq!(super::ppid_of_stat(4242, b"4242 (x) S 7 1 1").expect("parses"), 7);
}

/// The kernel prints a parseable `stat` for every pid, so an unparsable one reaching the snapshot
/// is a contract violation: asserted in debug. Mutant: "remove the assertion".
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "the kernel printed an unparseable stat")]
fn an_unparsable_stat_in_the_scan_is_asserted_in_debug() {
    let _forced = crate::identity::pid_stat::fault::force_stat_bytes(b"garbage");
    let _ = process_parents();
}

/// Without the assertion (release), the scan still refuses to drop the pid. Mutant: "an unparsable
/// `stat` drops the pid".
#[cfg(not(debug_assertions))]
#[test]
fn an_unparsable_stat_in_the_scan_is_unassessable_in_release() {
    let _forced = crate::identity::pid_stat::fault::force_stat_bytes(b"garbage");
    match process_parents() {
        Err(crate::error::Error::Unassessable { detail, .. }) => {
            assert!(detail.contains("/stat has no parseable"), "{detail}")
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}
