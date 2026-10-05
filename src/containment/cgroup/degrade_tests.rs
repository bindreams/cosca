// The diagnostic types are pure data, so their formatting is tested on every host.

use std::path::PathBuf;

use crate::containment::cgroup::{log_degrade, LeafError, NotEntered, NotPlaced, PlacementReport};

/// Every `LeafError` names the step, the path it touched, and the kernel's own reason.
/// Asserted per variant: a step whose message drops any of the three is the silence this
/// type exists to remove.
///
/// The reason is asserted as the source error's own rendering, not as `strerror` text: the same
/// raw code renders differently per host (13 is "Permission denied" on Linux and macOS, "The data
/// is invalid." on Windows), and "carried verbatim" is the claim.
#[skuld::test]
fn leaf_error_names_step_path_and_reason() {
    let reason = |code: i32| std::io::Error::from_raw_os_error(code).to_string();
    let cases: Vec<(LeafError, &[&str], Option<String>)> = vec![
        (
            LeafError::ReadProcSelfCgroup(std::io::Error::from_raw_os_error(13)),
            &["/proc/self/cgroup"],
            Some(reason(13)),
        ),
        (
            LeafError::NoUnifiedLine {
                line_count: 1,
                controllers: "9:memory".into(),
            },
            &["/proc/self/cgroup", "0::", "9:memory"],
            None,
        ),
        (
            LeafError::CreateLeafDir {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0"),
                source: std::io::Error::from_raw_os_error(13),
            },
            &["/sys/fs/cgroup/slice/cosca-7-0"],
            Some(reason(13)),
        ),
        (
            LeafError::KillUnsupported {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0"),
            },
            &["/sys/fs/cgroup/slice/cosca-7-0", "cgroup.kill"],
            None,
        ),
        (
            LeafError::CheckKill {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.kill"),
                source: std::io::Error::from_raw_os_error(13),
            },
            &["/sys/fs/cgroup/slice/cosca-7-0/cgroup.kill"],
            Some(reason(13)),
        ),
        (
            LeafError::OpenProcs {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.procs"),
                source: std::io::Error::from_raw_os_error(13),
            },
            &["cgroup.procs"],
            Some(reason(13)),
        ),
        (
            LeafError::OpenReportChannel(std::io::Error::from_raw_os_error(libc::EMFILE)),
            &["report"],
            Some(reason(libc::EMFILE)),
        ),
    ];
    for (err, needles, reason) in cases {
        let rendered = err.to_string();
        for needle in needles.iter().copied().chain(reason.as_deref()) {
            assert!(
                rendered.contains(needle),
                "{err:?} renders as {rendered:?}, which does not mention {needle:?}"
            );
        }
    }
}

/// The child's own self-placement outcome is reported verbatim, errno included — the one
/// step whose reason lives in the forked child and is otherwise unobservable to the parent.
#[skuld::test]
fn placement_report_renders_the_childs_errno() {
    assert!(PlacementReport::WriteFailed(16).to_string().contains("errno 16"));
    let busy = std::io::Error::from_raw_os_error(16).to_string();
    assert!(PlacementReport::WriteFailed(16).to_string().contains(&busy));
    assert!(PlacementReport::Placed.to_string().contains("succeeded"));
    assert!(PlacementReport::NotReported
        .to_string()
        .contains("exited before reporting"));
}

/// A child whose write failed renders the pid, the leaf path, the file's actual contents, its
/// errno and its state — and never claims a membership that never began.
#[skuld::test]
fn placement_absent_renders_every_observed_fact() {
    let absent = NotPlaced::Absent {
        pid: 4242,
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.procs"),
        procs: String::new(),
        report: NotEntered::WriteFailed(16),
        child_state: Some('Z'),
    };
    let rendered = absent.to_string();
    for needle in [
        "4242",
        "cosca-7-0/cgroup.procs",
        "empty",
        "errno 16",
        "is not in the leaf",
        "already exited",
    ] {
        assert!(
            rendered.contains(needle),
            "absent placement renders as {rendered:?}, which does not mention {needle:?}"
        );
    }
    assert!(
        !rendered.contains("membership ended"),
        "a child whose write failed was never a member: {rendered:?}"
    );
}

/// A child whose `pre_exec` closure never ran made no write at all, and is reported as such.
#[skuld::test]
fn placement_absent_renders_a_child_that_reported_nothing() {
    let rendered = NotPlaced::Absent {
        pid: 4242,
        path: PathBuf::from("/cg/cgroup.procs"),
        procs: String::new(),
        report: NotEntered::NotReported,
        child_state: Some('S'),
    }
    .to_string();
    assert!(rendered.contains("exited before reporting"), "got {rendered:?}");
    assert!(rendered.contains("is not in the leaf"), "got {rendered:?}");
}

/// A live child that is nonetheless not a member is a different diagnosis from a zombie one,
/// and must not be described as having exited.
#[skuld::test]
fn placement_absent_distinguishes_a_live_child() {
    let rendered = NotPlaced::Absent {
        pid: 4242,
        path: PathBuf::from("/cg/cgroup.procs"),
        procs: "99\n".into(),
        report: NotEntered::WriteFailed(16),
        child_state: Some('S'),
    }
    .to_string();
    assert!(rendered.contains("99"), "the file's real contents must be quoted");
    assert!(rendered.contains("errno 16"), "the child's errno must be carried");
    assert!(!rendered.contains("zombie"), "a live child must not be called a zombie");
}

/// An unreadable `cgroup.procs` is reported with its own error, not as an empty file.
#[skuld::test]
fn placement_unreadable_names_the_io_error() {
    let rendered = NotPlaced::Unreadable {
        pid: 4242,
        path: PathBuf::from("/cg/cgroup.procs"),
        source: std::io::Error::from_raw_os_error(13),
        report: NotEntered::WriteFailed(16),
    }
    .to_string();
    assert!(rendered.contains("/cg/cgroup.procs"));
    assert!(rendered.contains(&std::io::Error::from_raw_os_error(13).to_string()));
}

/// The degrade is logged at `warn` with the reason attached — the single line a human reading
/// CI output needs to tell WHICH step failed from the bare fact that containment degraded.
#[skuld::test]
fn degrade_logs_the_reason_at_warn() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    log_degrade(&LeafError::KillUnsupported {
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-degrade-probe-a41f"),
    });
    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-degrade-probe-a41f"),
        vec![log::Level::Warn],
        "a spawn that did not get the containment it asked for is worth a warning"
    );
    let records = crate::log_capture::records_since(mark, "cosca-degrade-probe-a41f");
    assert!(
        records.iter().all(|record| record.contains("process group")),
        "the degrade log must say what containment degraded TO: {records:?}"
    );
}

/// A repeated reason warns each time; nothing remembers earlier reports.
#[skuld::test]
fn a_repeated_degrade_reason_warns_every_time() {
    crate::log_capture::install();
    let reason = || LeafError::KillUnsupported {
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-repeat-probe-7c13"),
    };

    let mark = crate::log_capture::mark();
    for _ in 0..3 {
        log_degrade(&reason());
    }

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-repeat-probe-7c13"),
        vec![log::Level::Warn, log::Level::Warn, log::Level::Warn],
    );
}

// /proc/self/cgroup summary -----
// `/proc/self/cgroup` is a whole-system dump of every hierarchy the caller is in, read to look
// up one `0::` line. When there is no such line, none of its paths is one cosca touched, and
// none of them separates a v1-only host from an unmounted unified hierarchy from an empty
// file — so only the line count and controllers come back. The sibling variants keep their
// paths for the opposite reason, pinned by `leaf_error_names_step_path_and_reason` and by
// `the_leaf_path_reaches_the_record_verbatim` below.

/// The summary keeps every fact that separates a v1-only host from an unmounted unified
/// hierarchy from an empty file, and drops every path.
#[skuld::test]
fn no_unified_line_reports_the_shape_of_the_file_not_its_paths() {
    let real = concat!(
        "12:freezer:/kubepods/burstable/pod4f8c1e2a-9d3b-11ee-b9d1-0242ac120002/\
         3dc1f9a06b8e4a1c9f2b7d5e8a0c6413\n",
        "11:memory:/user.slice/user-1000.slice\n",
        "1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n",
    );
    let (line_count, controllers) = crate::containment::cgroup::summarize_cgroup_controllers(real);
    assert_eq!(line_count, 3);
    assert_eq!(controllers, "12:freezer, 11:memory, 1:name=systemd");

    let rendered = LeafError::NoUnifiedLine {
        line_count,
        controllers,
    }
    .to_string();
    for identifier in [
        "user-1000",
        "session-3",
        "pod4f8c1e2a",
        "3dc1f9a06b8e4a1c9f2b7d5e8a0c6413",
        "kubepods",
    ] {
        assert!(
            !rendered.contains(identifier),
            "{identifier:?} identifies the caller and must not reach an arbitrary sink; got \
             {rendered:?}"
        );
    }
    assert!(!rendered.contains('\n'), "one record, one line: {rendered:?}");
    for kept in ["0::", "freezer", "memory", "name=systemd", "3"] {
        assert!(rendered.contains(kept), "{kept:?} is the diagnosis; got {rendered:?}");
    }
}

/// An empty `/proc/self/cgroup` is its own diagnosis and must still read as one.
#[skuld::test]
fn no_unified_line_summarizes_an_empty_file() {
    let (line_count, controllers) = crate::containment::cgroup::summarize_cgroup_controllers("");
    assert_eq!(line_count, 0);
    let rendered = LeafError::NoUnifiedLine {
        line_count,
        controllers,
    }
    .to_string();
    assert!(rendered.contains('0'), "the line count is the fact here: {rendered:?}");
}

/// The asymmetry is deliberate, not an oversight in the summary's reach: a step that FAILED on
/// a path reports that path in full, identifiers and all. It is the one path the syscall
/// touched, it is the diagnosis, and a record without it says only that some mkdir somewhere
/// was refused.
#[skuld::test]
fn the_leaf_path_reaches_the_record_verbatim() {
    let leaf = "/sys/fs/cgroup/kubepods/pod4f8c1e2a-9d3b-11ee-b9d1-0242ac120002/cosca-7-0";
    let rendered = LeafError::CreateLeafDir {
        path: PathBuf::from(leaf),
        source: std::io::Error::from_raw_os_error(13),
    }
    .to_string();
    assert!(
        rendered.contains(leaf),
        "the failing mkdir's own path is the diagnosis and must not be summarized away: got \
         {rendered:?}"
    );
}

/// A line the kernel format does not explain is reported as unparseable, never quoted: an
/// unrecognized line is exactly the case where cosca cannot know which part is a path.
#[skuld::test]
fn no_unified_line_never_quotes_a_line_it_could_not_parse() {
    let (line_count, controllers) =
        crate::containment::cgroup::summarize_cgroup_controllers("nonsense-with-no-colons\n");
    assert_eq!(line_count, 1);
    assert!(
        !controllers.contains("nonsense"),
        "an unparsed line's content must not be echoed: {controllers:?}"
    );
}
