use super::process_parents_with;
use crate::identity::{FakeKernel, HostKernel, Kernel};

type Records = Vec<(log::Level, String)>;

/// The pid the stat rows list and read.
const PID: u32 = 4242;

fn snapshot_with(kernel: &dyn Kernel) -> (Result<Vec<(u32, u32)>, crate::error::Error>, Records) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let got = process_parents_with(kernel);
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
#[skuld::test]
fn a_diverged_view_is_unassessable_and_warned_about() {
    let (got, records) = snapshot_with(&FakeKernel::over(&HostKernel).diverged_view());
    assert_unassessable_naming(got, "outer pid namespace");
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("outer pid namespace")),
        "{records:?}"
    );
}

#[skuld::test]
fn an_unassessable_view_is_unassessable_and_warned_about_naming_the_cause() {
    let (got, records) = snapshot_with(&FakeKernel::over(&HostKernel).unreadable_view());
    assert_unassessable_naming(got, "self/status could not be read");
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("self/status could not be read")),
        "{records:?}"
    );
}

/// The ordinary snapshot lists this process under its real parent.
#[skuld::test]
fn the_ordinary_snapshot_lists_this_process_with_its_parent() {
    let me = std::process::id();
    let ppid = std::os::unix::process::parent_id();
    assert!(crate::containment::enumerate::process_parents()
        .expect("the snapshot")
        .contains(&(me, ppid)));
}

// Per-pid stat read failures =====

/// A kernel listing one pid, `PID`, whose `stat` read answers `errno`.
fn failing_stat(errno: i32) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .on_pids(Ok(&[PID]))
        .on_read(&format!("{PID}/stat"), Err(errno))
}

/// A pid that exited mid-scan (`ENOENT`, `ESRCH`) or that `hidepid` hides (`EACCES`, and `EPERM`
/// while the checked directory still answers) is absent, and the snapshot is still a snapshot.
/// Mutant: "fail the snapshot on every read error".
#[skuld::test]
fn a_pid_whose_stat_is_gone_or_hidden_is_skipped() {
    for errno in [libc::ENOENT, libc::ESRCH, libc::EACCES, libc::EPERM] {
        let got =
            process_parents_with(&failing_stat(errno)).unwrap_or_else(|e| panic!("errno {errno} is an absence: {e}"));
        assert!(got.is_empty(), "errno {errno}: {got:?}");
    }
}

/// Any other failure says nothing about the pid, and skipping it drops its whole subtree from a
/// walk: the snapshot is `Unassessable` naming `<pid>/stat` and the errno. Mutants: "skip every
/// read error" (an `EMFILE` from a full fd table hits every pid and yields `Ok(vec![])`); "a mount
/// crossing is skipped".
#[skuld::test]
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
        let text = match process_parents_with(&failing_stat(errno)) {
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
        assert_eq!(
            pid.parse::<u32>().ok(),
            Some(PID),
            "{errno}: the error must name the pid before `/stat`: {text}"
        );
    }
}

/// `EPERM` is `hidepid`'s answer and also a seccomp filter's for an `openat2` installed mid-scan;
/// only the checked directory still answering tells them apart. Mutant: "skip `EPERM` without the
/// re-check".
#[skuld::test]
fn eperm_is_unassessable_when_the_checked_directory_also_refuses() {
    for recheck in [libc::EPERM, libc::ENOSYS, libc::EMFILE] {
        let kernel = failing_stat(libc::EPERM).on_read("self/stat", Err(recheck));
        match process_parents_with(&kernel) {
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
#[skuld::test]
fn an_unlistable_proc_is_unassessable_naming_the_errno() {
    let kernel = FakeKernel::over(&HostKernel).on_pids(Err(libc::EIO));
    match process_parents_with(&kernel) {
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
#[skuld::test]
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
#[skuld::test]
#[should_panic(expected = "the kernel printed an unparseable stat")]
fn an_unparsable_stat_in_the_scan_is_asserted_in_debug() {
    let kernel = FakeKernel::over(&HostKernel)
        .on_pids(Ok(&[PID]))
        .on_read(&format!("{PID}/stat"), Ok(b"garbage"));
    drop(process_parents_with(&kernel));
}

/// Without the assertion (release), the scan still refuses to drop the pid. Mutant: "an unparsable
/// `stat` drops the pid".
#[cfg(not(debug_assertions))]
#[skuld::test]
fn an_unparsable_stat_in_the_scan_is_unassessable_in_release() {
    let kernel = FakeKernel::over(&HostKernel)
        .on_pids(Ok(&[PID]))
        .on_read(&format!("{PID}/stat"), Ok(b"garbage"));
    match process_parents_with(&kernel) {
        Err(crate::error::Error::Unassessable { detail, .. }) => {
            assert!(detail.contains("/stat has no parseable"), "{detail}")
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}
