use std::cell::Cell;
use std::io;

use super::{kill_gate, terminate_gate, Front, Gate};
use crate::elevation::elevation_tests::report;
use crate::elevation::{Backend, ElevatedVia, ElevationReport};
use crate::error::{ElevationErrorKind, Error};

const PID: u32 = 4242;

/// The fronts a report names, and no other: pkexec execs the program, and UAC and an already-elevated
/// parent track it. Mutant: a backend's arm of `ElevationReport::front` answers another's.
#[skuld::test]
fn a_report_names_the_front_its_via_leaves_tracked() {
    for (via, name) in FRONTS {
        assert_eq!(report(via.clone()).front().map(Front::name), Some(name), "{via:?}");
    }
    for via in NOT_FRONTS.iter().flatten() {
        assert_eq!(report(via.clone()).front(), None, "{via:?}");
    }
}

/// Sudo, doas, pkexec and UAC may run the tracked process as another user; osascript's front runs
/// as this user, and an already-elevated child is the caller's own. Mutant: an arm of
/// `ElevationReport::may_run_as_another_user` flips.
#[skuld::test]
fn a_report_says_whether_the_tracked_process_may_run_as_another_user() {
    let runs_as_another_user = |via: ElevatedVia| report(via).may_run_as_another_user();
    for backend in [Backend::Sudo, Backend::Doas, Backend::Pkexec] {
        assert!(runs_as_another_user(ElevatedVia::Wrapped(backend)), "{backend:?}");
    }
    assert!(runs_as_another_user(ElevatedVia::WindowsUac));
    assert!(!runs_as_another_user(ElevatedVia::MacosOsascript));
    assert!(!runs_as_another_user(ElevatedVia::AlreadyElevated));
}

const FRONTS: [(ElevatedVia, &str); 3] = [
    (ElevatedVia::Wrapped(Backend::Sudo), "sudo"),
    (ElevatedVia::Wrapped(Backend::Doas), "doas"),
    (ElevatedVia::MacosOsascript, "osascript"),
];

const NOT_FRONTS: [Option<ElevatedVia>; 4] = [
    None,
    Some(ElevatedVia::Wrapped(Backend::Pkexec)),
    Some(ElevatedVia::WindowsUac),
    Some(ElevatedVia::AlreadyElevated),
];

/// `answers` in turn, one per call; the last is repeated once they run out.
fn in_turn(answers: Vec<io::Result<bool>>) -> impl Fn() -> io::Result<bool> {
    let answers: Vec<_> = answers
        .into_iter()
        .map(|a| a.map_err(|e| (e.kind(), e.to_string())))
        .collect();
    let next = Cell::new(0);
    move || {
        let i = next.get().min(answers.len() - 1);
        next.set(next.get() + 1);
        answers[i].clone().map_err(|(kind, text)| io::Error::new(kind, text))
    }
}

/// What a gate asked, in order: `r` for `running`, `c` for `in_cgroup`.
fn kill_gate_asking(
    report: Option<ElevationReport>,
    running: io::Result<bool>,
    in_cgroup: io::Result<bool>,
) -> (Gate, String) {
    kill_gate_asking_in_turn(report, vec![running], in_cgroup)
}

/// [`kill_gate_asking`], with `running` answering in turn.
fn kill_gate_asking_in_turn(
    report: Option<ElevationReport>,
    running: Vec<io::Result<bool>>,
    in_cgroup: io::Result<bool>,
) -> (Gate, String) {
    let asked = Cell::new(String::new());
    let note = |c: char| {
        let mut s = asked.take();
        s.push(c);
        asked.set(s);
    };
    let running = in_turn(running);
    let g = kill_gate(
        report.and_then(|report| report.front()),
        PID,
        || {
            note('r');
            running()
        },
        || {
            note('c');
            in_cgroup
        },
    );
    (g, asked.take())
}

fn refusal_detail(g: Gate) -> String {
    match g {
        Gate::Closed(Error::Elevation {
            kind: ElevationErrorKind::Unkillable,
            detail,
            ..
        }) => detail,
        other => panic!("expected a closed gate with Unkillable, got {other:?}"),
    }
}

#[skuld::test]
fn a_live_front_outside_a_cgroup_is_closed_with_unkillable_naming_it() {
    for (via, name) in FRONTS {
        let (g, asked) = kill_gate_asking(Some(report(via.clone())), Ok(true), Ok(false));
        assert_eq!(asked, "rcr", "{via:?}");
        let detail = refusal_detail(g);
        assert!(detail.contains(&format!("pid {PID} is")), "{detail}");
        assert!(detail.contains(name), "{detail}");
        assert!(detail.contains("no kill was sent"), "{detail}");
        assert_eq!(
            detail.contains("direct exec"),
            name != "osascript",
            "only a wrapper may track the program itself: {detail}"
        );
    }
}

/// A front that has left its cgroup (pam_systemd moving sudo into a session scope) is outside it.
#[skuld::test]
fn a_live_front_that_left_its_cgroup_is_closed() {
    let (g, _) = kill_gate_asking(Some(report(ElevatedVia::Wrapped(Backend::Sudo))), Ok(true), Ok(false));
    refusal_detail(g);
}

/// An exited front has nothing left to orphan, and its cgroup is not asked about.
#[skuld::test]
fn an_exited_front_is_exited() {
    for (via, _) in FRONTS {
        let (g, asked) = kill_gate_asking(Some(report(via.clone())), Ok(false), Ok(true));
        assert_eq!(asked, "r", "{via:?}");
        assert!(matches!(g, Gate::Exited), "{via:?}: {g:?}");
    }
}

/// A cgroup kill reaches a member whatever its credentials, so a live front in one, or one whose
/// state cannot be read, is killed through it.
#[skuld::test]
fn a_live_front_in_its_cgroup_is_killed_through_the_cgroup_only() {
    for (via, _) in FRONTS {
        for running in [Ok(true), Err(io::Error::other("peek refused"))] {
            let (g, asked) = kill_gate_asking(Some(report(via.clone())), running, Ok(true));
            assert_eq!(asked, "rc", "{via:?}");
            assert!(
                matches!(&g, Gate::CgroupOnly(f) if Some(*f) == report(via.clone()).front()),
                "{via:?}: {g:?}"
            );
        }
    }
}

const CODE: i32 = 5;

fn os_error() -> io::Error {
    io::Error::from_raw_os_error(CODE)
}

fn refusal(g: Gate) -> Error {
    match g {
        Gate::Closed(error) => error,
        other => panic!("expected a closed gate, got {other:?}"),
    }
}

#[track_caller]
fn assert_refused_by_one_read(error: &Error, words: &str) {
    let Error::Elevation {
        kind: ElevationErrorKind::Unkillable,
        detail,
        ..
    } = error
    else {
        panic!("expected Unkillable, got {error:?}");
    };
    assert!(detail.contains(words), "{detail}");
    assert!(
        !detail.contains(&os_error().to_string()),
        "the cause is in the detail: {detail}"
    );
    assert_eq!(crate::error::first_os_code(error), Some(CODE), "{error:?}");
}

#[skuld::test]
fn a_front_whose_state_cannot_be_read_is_closed_and_says_why() {
    let g = kill_gate(Some(Front::Sudo), PID, || Err(os_error()), || Ok(false));
    assert_refused_by_one_read(&refusal(g), "whether it had exited could not be read");
    let g = kill_gate(Some(Front::Sudo), PID, || Ok(true), || Err(os_error()));
    assert_refused_by_one_read(&refusal(g), "whether its cgroup kill reaches it could not be read");
}

#[skuld::test]
fn a_front_whose_place_cannot_be_read_after_the_kill_has_the_read_as_its_cause() {
    let (r, _) = reached_asking(Ok(false), Err(os_error()));
    assert_refused_by_one_read(&r.expect_err("not shown reached"), "its cgroup could not be read");
}

#[skuld::test]
fn a_front_whose_cgroup_kill_failed_has_the_failure_as_its_cause() {
    let e = super::cgroup_kill_failed(Front::Sudo, PID, Error::Io(os_error()));
    assert_refused_by_one_read(&e, "its cgroup kill failed");
}

/// A refusal of a front whose cgroup was not killed says so and carries no failure: the tree's
/// failure stands before it in a failed spawn's `cleanup`, so a `Report` of the spawn prints each
/// failure once, the tree's first.
///
/// Mutant: the refusal repeats the tree's failure in its words.
#[skuld::test]
fn a_front_whose_cgroup_was_not_killed_says_so_and_the_report_prints_each_failure_once() {
    use std::sync::Arc;

    use crate::error::{ChildFate, Failures};

    let refusal = super::cgroup_not_killed(Front::Sudo, PID);
    assert!(std::error::Error::source(&refusal).is_none(), "{refusal:?}");
    let refusal_words = refusal.to_string();
    assert!(
        refusal_words.contains(&format!("pid {PID} is what sudo left"))
            && refusal_words.ends_with(" (its cgroup was not killed)"),
        "{refusal_words}"
    );

    let tree = Error::Containment {
        detail: "the kernel refused the write of leaf/cgroup.kill".into(),
        source: Some(Arc::new(Error::Io(io::Error::from_raw_os_error(libc::EISDIR)))),
    };
    let started = Error::MayHaveStarted {
        fate: ChildFate::Running { id: None },
        wrapper_elevated: true,
        detail: None,
        source: Arc::new(Error::Io(io::Error::from_raw_os_error(libc::EPIPE))),
        unreaped: None,
        cleanup: Failures::collect([Arc::new(tree), Arc::new(refusal)]),
    };
    let epipe = io::Error::from_raw_os_error(libc::EPIPE).to_string();
    let eisdir = io::Error::from_raw_os_error(libc::EISDIR).to_string();
    assert_eq!(
        crate::error::said(&started),
        format!(
            "the program may have started, and its child may still be running; its teardown failed too (2 failures, \
             in `cleanup`): {}; cleanup: [(1) process containment failed: the kernel \
             refused the write of leaf/cgroup.kill: {}; (2) {refusal_words}]",
            crate::error::io_said(&epipe),
            crate::error::io_said(&eisdir)
        )
    );
}

/// The tracked process is the program itself, or there is no elevation: signalled like any child,
/// with nothing read.
#[skuld::test]
fn a_child_that_is_not_a_front_is_open_whatever_its_containment() {
    for via in &NOT_FRONTS {
        for in_cgroup in [false, true] {
            let reported = via.clone().map(report);
            let (g, asked) = kill_gate_asking(reported.clone(), Ok(true), Ok(in_cgroup));
            assert_eq!(asked, "", "{via:?}");
            assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
            let g = terminate_gate(reported.and_then(|reported| reported.front()), PID, || {
                panic!("not asked")
            });
            assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
        }
    }
}

/// sudo and doas relay `SIGTERM` to the program: never gated.
#[skuld::test]
fn a_sigterm_to_a_relaying_front_is_open() {
    for via in [ElevatedVia::Wrapped(Backend::Sudo), ElevatedVia::Wrapped(Backend::Doas)] {
        let g = terminate_gate(report(via.clone()).front(), PID, || panic!("not asked"));
        assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
    }
}

/// A `SIGTERM` would end osascript and orphan the program: refused while osascript runs, sent once
/// it has exited.
#[skuld::test]
fn a_sigterm_to_a_live_osascript_is_closed() {
    let osascript = report(ElevatedVia::MacosOsascript).front();
    let detail = refusal_detail(terminate_gate(osascript, PID, || Ok(true)));
    assert!(detail.contains(&format!("pid {PID} is osascript")), "{detail}");
    assert!(detail.contains("no SIGTERM was sent"), "{detail}");
    let error = refusal(terminate_gate(osascript, PID, || Err(os_error())));
    assert_refused_by_one_read(&error, "whether it had exited could not be read");
    assert!(matches!(terminate_gate(osascript, PID, || Ok(false)), Gate::Open));
}

/// What `cgroup_kill_reached` asked, in order (`e`xited, `u`nder the leaf), and its answer.
fn reached_asking(exited: io::Result<bool>, under_leaf: io::Result<bool>) -> (Result<(), Error>, String) {
    reached_asking_in_turn(vec![exited], under_leaf)
}

/// [`reached_asking`], with `exited` answering in turn.
fn reached_asking_in_turn(exited: Vec<io::Result<bool>>, under_leaf: io::Result<bool>) -> (Result<(), Error>, String) {
    let asked = Cell::new(String::new());
    let note = |c: char| {
        let mut s = asked.take();
        s.push(c);
        asked.set(s);
    };
    let exited = in_turn(exited);
    let r = super::cgroup_kill_reached(
        Front::Sudo,
        PID,
        || {
            note('e');
            exited()
        },
        || {
            note('u');
            under_leaf
        },
    );
    (r, asked.take())
}

/// A front exited, or in its leaf after the write, was there for the kill.
#[skuld::test]
fn a_front_in_its_leaf_after_the_kill_was_reached() {
    let (r, asked) = reached_asking(Ok(true), Ok(false));
    assert!(r.is_ok() && asked == "e", "{r:?} {asked}");
    let (r, asked) = reached_asking(Ok(false), Ok(true));
    assert!(r.is_ok() && asked == "eu", "{r:?} {asked}");
}

/// A front neither exited nor in its leaf left it before the kill: refused, and named.
#[skuld::test]
fn a_front_outside_its_leaf_after_the_kill_was_not_reached() {
    let (r, _) = reached_asking(Ok(false), Ok(false));
    let detail = refusal_detail(Gate::Closed(r.expect_err("not reached")));
    assert!(detail.contains("left the cgroup before its kill"), "{detail}");
}

/// The two failed reads of a refusal, as its cause: both are the `source` (a `Several`, the first
/// read first), and neither is in the detail, which says only what was done.
#[track_caller]
fn assert_refused_by_two_reads(error: &Error, words: &[&str], reads: [&str; 2]) {
    let Error::Elevation {
        kind: ElevationErrorKind::Unkillable,
        detail,
        source: Some(source),
    } = error
    else {
        panic!("expected Unkillable with a source, got {error:?}");
    };
    for word in words {
        assert!(detail.contains(word), "{detail}");
    }
    for read in reads {
        assert!(!detail.contains(read), "a cause is in the detail: {detail}");
    }
    let Error::Several(failures) = &**source else {
        panic!("expected the two reads as a Several, got {source:?}");
    };
    let texts: Vec<_> = failures.iter().map(|failure| crate::error::said(&**failure)).collect();
    assert_eq!(texts, reads.map(crate::error::io_said), "{error:?}");
}

/// A front whose place cannot be read is not shown reached: refused, with every read that failed
/// as its cause.
///
/// Mutants: only the first read is the cause; the reads are in the detail's text.
#[skuld::test]
fn a_front_whose_place_after_the_kill_cannot_be_read_is_refused() {
    let (r, _) = reached_asking(Err(io::Error::other("peek refused")), Err(io::Error::other("hidepid")));
    let error = r.expect_err("not shown reached");
    assert_refused_by_two_reads(
        &error,
        &[
            "nothing shows the cgroup kill reached it",
            "whether it had exited could not be read",
            "its cgroup could not be read",
        ],
        ["peek refused", "hidepid"],
    );
}

/// The gate before a kill, when both of its reads fail: closed, with both as the cause.
///
/// Mutant: the second failed read replaces the first, or is only in the detail.
#[skuld::test]
fn a_front_whose_two_gate_reads_fail_is_closed_with_both_as_its_cause() {
    let g = kill_gate(
        Some(Front::Sudo),
        PID,
        || Err(io::Error::other("peek refused")),
        || Err(io::Error::other("hidepid")),
    );
    assert_refused_by_two_reads(
        &refusal(g),
        &[
            "whether it had exited could not be read",
            "whether its cgroup kill reaches it could not be read",
        ],
        ["peek refused", "hidepid"],
    );
}

/// A front that exits, and is reaped by another thread's `wait`, between the gate's two reads has
/// no cgroup left to read: the gate reads it again, finds it exited, and kills nothing.
#[skuld::test]
fn a_front_reaped_between_the_gates_reads_has_exited() {
    let sudo = ElevatedVia::Wrapped(Backend::Sudo);
    let reaped = || Err(io::Error::other("ESRCH: reaped"));
    let (g, asked) = kill_gate_asking_in_turn(Some(report(sudo.clone())), vec![Ok(true), Ok(false)], reaped());
    assert!(matches!(g, Gate::Exited), "{g:?}");
    assert_eq!(asked, "rcr");
    let (g, _) = kill_gate_asking_in_turn(Some(report(sudo)), vec![Ok(true), Ok(true)], reaped());
    refusal_detail(g);
}

/// A front its cgroup kill ended, reaped by another thread's `wait` before its cgroup is read,
/// was reached: the check reads its exit again.
#[skuld::test]
fn a_front_reaped_before_its_cgroup_is_read_was_reached() {
    let reaped = || Err(io::Error::other("ESRCH: reaped"));
    let (r, asked) = reached_asking_in_turn(vec![Ok(false), Ok(true)], reaped());
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(asked, "eue");
    let (r, _) = reached_asking_in_turn(vec![Ok(false), Ok(false)], reaped());
    r.expect_err("still running, unplaced");
}
