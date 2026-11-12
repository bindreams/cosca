use super::process_parents;
use crate::identity::{FakeKernel, HostKernel, Kernel, UNREADABLE_STATUS_REASON};

type Records = Vec<(log::Level, String)>;

const PID: u32 = 4242;

fn snapshot_with(kernel: &dyn Kernel) -> (Result<Vec<(u32, u32)>, crate::error::Error>, Records) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let got = process_parents(kernel);
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
    // The read's error is the source, with its code, and the text names only the view.
    match &got {
        Err(err @ crate::error::Error::Unassessable { detail, .. }) => {
            assert_eq!(crate::error::first_os_code(err), Some(libc::EIO), "{err:?}");
            let os_error = std::io::Error::from_raw_os_error(libc::EIO).to_string();
            assert!(!detail.contains(&os_error), "{detail}");
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    assert_unassessable_naming(got, UNREADABLE_STATUS_REASON);
    let os_error = std::io::Error::from_raw_os_error(libc::EIO).to_string();
    assert!(
        records.iter().any(|(level, m)| *level == log::Level::Warn
            && m.contains(UNREADABLE_STATUS_REASON)
            && m.contains(&os_error)),
        "{records:?}"
    );
}

/// The ordinary snapshot lists this process under its real parent.
#[skuld::test]
fn the_ordinary_snapshot_lists_this_process_with_its_parent() {
    let me = std::process::id();
    let ppid = std::os::unix::process::parent_id();
    assert!(crate::containment::enumerate::process_parents(&HostKernel)
        .expect("the snapshot")
        .contains(&(me, ppid)));
}

// Per-pid stat read failures =====

/// A pid that exited mid-scan (`ENOENT`, `ESRCH`) or that `hidepid` hides (`EACCES`, and `EPERM`
/// while the checked directory still answers) is absent, and the snapshot is still a snapshot.
/// Mutant: "fail the snapshot on every read error".
#[skuld::test]
fn a_pid_whose_stat_is_gone_or_hidden_is_skipped() {
    for errno in [libc::ENOENT, libc::ESRCH, libc::EACCES, libc::EPERM] {
        let kernel = FakeKernel::listing_unreadable_pid(&HostKernel, PID, errno);
        let got = process_parents(&kernel).unwrap_or_else(|e| panic!("errno {errno} is an absence: {e}"));
        assert!(got.is_empty(), "errno {errno}: {got:?}");
    }
}

/// Any other failure says nothing about the pid, and skipping it drops its whole subtree from a
/// walk: the snapshot is `Unassessable`, its chain naming `<pid>/stat` in the `Unreadable` layer and
/// holding the errno below it. Mutants: "skip every read error" (an `EMFILE` from a full fd table
/// hits every pid and yields `Ok(vec![])`); "a mount crossing is skipped"; "the `Unreadable` layer
/// is folded into `detail`".
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
        let kernel = FakeKernel::listing_unreadable_pid(&HostKernel, PID, errno);
        let error = match process_parents(&kernel) {
            Err(error @ crate::error::Error::Unassessable { .. }) => error,
            other => panic!("errno {errno}: expected Unassessable, got {other:?}"),
        };
        let crate::error::Error::Unassessable { detail, source } = &error else {
            unreachable!()
        };
        assert!(
            !detail.contains("/stat") && !detail.contains(&std::io::Error::from_raw_os_error(errno).to_string()),
            "{errno}: the layer is not folded into the detail: {detail}"
        );
        assert_eq!(
            source.as_deref().and_then(|e| crate::error::first_os_code(e)),
            Some(errno),
            "errno {errno}: the read's error is below the layer"
        );
        let text = crate::error::Report(&error).to_string();
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

/// The warn of a snapshot a failed `stat` read ended carries the OS error.
#[skuld::test]
fn the_warn_of_a_failed_stat_read_says_the_os_error() {
    let kernel = FakeKernel::listing_unreadable_pid(&HostKernel, PID, libc::EIO);
    let (got, records) = snapshot_with(&kernel);
    assert!(got.is_err(), "{got:?}");
    let os_error = std::io::Error::from_raw_os_error(libc::EIO).to_string();
    assert!(
        records
            .iter()
            .any(|(level, line)| *level == log::Level::Warn && line.contains(&os_error)),
        "{records:?}"
    );
}

/// `EPERM` is `hidepid`'s answer and also a seccomp filter's for an `openat2` installed mid-scan;
/// only the checked directory still answering tells them apart. A re-check that refuses is
/// "refused self/stat too" over the pid's `EPERM`; one that fails otherwise says the re-check failed,
/// over its own errno. Mutant: "skip `EPERM` without the re-check"; "every failed re-check is a
/// refusal".
#[skuld::test]
fn eperm_is_unassessable_when_the_checked_directory_also_refuses() {
    for (recheck, refused, below) in [
        (libc::EPERM, true, libc::EPERM),
        (libc::ENOSYS, true, libc::EPERM),
        (libc::EMFILE, false, libc::EMFILE),
    ] {
        let kernel =
            FakeKernel::listing_unreadable_pid(&HostKernel, PID, libc::EPERM).on_read("self/stat", Err(recheck));
        match process_parents(&kernel) {
            Err(error @ crate::error::Error::Unassessable { .. }) => {
                let text = crate::error::Report(&error).to_string();
                assert_eq!(text.contains("refused self/stat too"), refused, "{recheck}: {text}");
                assert_eq!(
                    text.contains("re-check of self/stat failed"),
                    !refused,
                    "{recheck}: {text}"
                );
                assert_eq!(crate::error::first_os_code(&error), Some(below), "{recheck}: {text}");
            }
            other => panic!("{recheck}: expected Unassessable, got {other:?}"),
        }
    }
}

/// A failed `/proc` listing is `Unassessable` naming it and the errno, never an empty table.
/// Mutant: "an unlistable `/proc` is an empty snapshot".
#[skuld::test]
fn an_unlistable_proc_is_unassessable_naming_the_errno() {
    let kernel = FakeKernel::over(&HostKernel).same_view().on_pids(Err(libc::EIO));
    match process_parents(&kernel) {
        Err(crate::error::Error::Unassessable { detail, source }) => {
            assert!(detail.contains("/proc could not be listed"), "{detail}");
            assert_eq!(source.and_then(|e| crate::error::first_os_code(&*e)), Some(libc::EIO));
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
        .same_view()
        .on_pids(Ok(&[PID]))
        .on_read(&format!("{PID}/stat"), Ok(b"garbage"));
    drop(process_parents(&kernel));
}

/// Without the assertion (release), the scan still refuses to drop the pid. Mutant: "an unparsable
/// `stat` drops the pid".
#[cfg(not(debug_assertions))]
#[skuld::test]
fn an_unparsable_stat_in_the_scan_is_unassessable_in_release() {
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids(Ok(&[PID]))
        .on_read(&format!("{PID}/stat"), Ok(b"garbage"));
    match process_parents(&kernel) {
        Err(crate::error::Error::Unassessable { detail, .. }) => {
            assert!(detail.contains("/stat has no parseable"), "{detail}")
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}
