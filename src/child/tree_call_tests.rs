//! The shared decisions of [`super::tree_call`], driven directly: [`PidfdShutdown`]'s outcomes
//! (Linux), and [`root_number`] over every input it reads.
//!
//! [`PidfdShutdown`]: crate::child::PidfdShutdown

use super::{root_number, RootNumber};
use crate::containment::Attached;
use crate::identity::{ProcessId, Resolved};
use crate::signal::RootState;

/// A pgid no test process holds: the decisions only name it in their text.
const PGID: i32 = 999_999;

// PidfdShutdown -----

#[cfg(target_os = "linux")]
mod pidfd_shutdown {
    use std::cell::RefCell;

    use super::PGID;
    use crate::child::{PidfdShutdown, TreeCall};
    use crate::containment::dispatch::TreeSignal;
    use crate::containment::{Attached, TreeKilled};
    use crate::elevation::front::Gate;
    use crate::error::Error;
    use crate::signal::Sent;
    use crate::test_child::reaped_elsewhere::{warns_since, ROOT_KILLED_BY_PIDFD, ROOT_TERMED_BY_PIDFD};

    const WHY: &str = "the root's own handle could not say";

    fn graceful_call<'a>(attached: &'a Attached, killed: &'a TreeKilled) -> TreeCall<'a> {
        TreeCall {
            attached,
            pid: PGID as u32,
            signal: TreeSignal::Term,
            op: "graceful_shutdown_tree",
            earlier: None,
            killed,
        }
    }

    fn unkillable(what: &str) -> Error {
        Error::Elevation {
            kind: crate::error::ElevationErrorKind::Unkillable,
            detail: what.into(),
        }
    }

    /// One run: `term` answers the `SIGTERM`, `exited` the grace (`None`: the grace is not asked),
    /// `kill_gate` and `kill` the escalation. Returns the error, what was sent, and the warns.
    fn run(
        gate: Gate,
        term: Result<Sent, Error>,
        exited: Option<Result<bool, &'static str>>,
        kill_gate: Gate,
        kill: Result<Sent, Error>,
    ) -> (Error, Vec<&'static str>, Vec<String>) {
        crate::log_capture::install();
        let attached = Attached::ProcessGroup(PGID);
        let killed = TreeKilled::default();
        let call = graceful_call(&attached, &killed);
        let sent = RefCell::new(Vec::new());
        let mark = crate::log_capture::mark();
        let shutdown = match PidfdShutdown::start(gate, || {
            sent.borrow_mut().push("term");
            term
        }) {
            Ok(shutdown) => shutdown,
            Err(e) => return (e, sent.into_inner(), warns_since(mark)),
        };
        // A grace the row does not answer reads as an exit, so a wrongly waited one shows in `sent`.
        let waited = shutdown.needs_grace().then(|| {
            sent.borrow_mut().push("grace");
            exited.unwrap_or(Ok(true))
        });
        let err = shutdown.finish(
            &call,
            WHY,
            waited,
            || kill_gate,
            || {
                sent.borrow_mut().push("kill");
                kill
            },
        );
        (err, sent.into_inner(), warns_since(mark))
    }

    /// Mutant: `start` ignores a closed gate.
    #[skuld::test]
    fn a_front_the_sigterm_may_not_reach_is_refused_with_nothing_sent() {
        let (err, sent, warns) = run(
            Gate::Closed(unkillable("osascript")),
            Ok(Sent::Delivered),
            Some(Ok(true)),
            Gate::Open,
            Ok(Sent::Delivered),
        );
        assert!(
            matches!(&err, Error::Elevation { detail, .. } if detail == "osascript"),
            "{err:?}"
        );
        assert_eq!(sent, Vec::<&str>::new());
        assert_eq!(warns, Vec::<String>::new());
    }

    /// Mutant: a failed grace wait read as an exit (no kill).
    #[skuld::test]
    fn a_failed_grace_wait_kills_the_root_at_once() {
        crate::log_capture::install();
        let mark = crate::log_capture::mark();
        let (err, sent, warns) = run(
            Gate::Open,
            Ok(Sent::Delivered),
            Some(Err("forced wait failure")),
            Gate::Open,
            Ok(Sent::Delivered),
        );
        assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
        assert_eq!(sent, ["term", "grace", "kill"]);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
        let debug = crate::log_capture::records_since_on_current_thread(mark, "grace wait failed");
        assert_eq!(debug.len(), 1, "{debug:?}");
        assert_eq!(debug[0].0, log::Level::Debug, "{debug:?}");
        assert!(debug[0].1.contains("forced wait failure"), "{debug:?}");
    }

    /// Mutant: the escalation ignores a closed kill gate.
    #[skuld::test]
    fn a_front_the_kill_may_not_reach_is_refused_after_the_grace() {
        let (err, sent, warns) = run(
            Gate::Open,
            Ok(Sent::Delivered),
            Some(Ok(false)),
            Gate::Closed(unkillable("sudo")),
            Ok(Sent::Delivered),
        );
        assert!(
            matches!(&err, Error::Elevation { detail, .. } if detail == "sudo"),
            "{err:?}"
        );
        assert_eq!(sent, ["term", "grace"]);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("then the kill of the root through its pidfd failed"),
            "{warns:?}"
        );
    }

    /// Mutant: the grace waited, or the kill sent, after a failed `SIGTERM`.
    #[skuld::test]
    fn a_failed_sigterm_waits_no_grace_and_is_the_error() {
        let (err, sent, warns) = run(
            Gate::Open,
            Err(Error::Io(std::io::Error::other("forced term failure"))),
            None,
            Gate::Open,
            Ok(Sent::Delivered),
        );
        assert!(
            matches!(&err, Error::Io(e) if e.to_string() == "forced term failure"),
            "{err:?}"
        );
        assert_eq!(sent, ["term"]);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("sent nothing: the SIGTERM to the root through its pidfd failed (forced term failure)"),
            "{warns:?}"
        );
    }

    /// A `SIGTERM` that finds the root gone, or a handle that no longer reaches it (a tokio backend
    /// forgotten unproven holds no pidfd), waits no grace and sends no kill.
    ///
    /// Mutant: the grace waited for anything but a delivered `SIGTERM`.
    #[skuld::test]
    fn a_sigterm_that_reached_nothing_waits_no_grace() {
        for (term, says) in [
            (Sent::Gone, "sent nothing: the root's pidfd shows it is gone"),
            (Sent::Unverified, "sent nothing: the root's handle no longer reaches it"),
        ] {
            let (err, sent, warns) = run(Gate::Open, Ok(term), None, Gate::Open, Ok(Sent::Delivered));
            assert!(matches!(err, Error::Unassessable { .. }), "{says}: {err:?}");
            assert_eq!(sent, ["term"], "{says}");
            assert_eq!(warns.len(), 1, "{says}: {warns:?}");
            assert!(warns[0].contains(says), "{warns:?}");
            assert!(!warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
        }
    }

    /// Mutant: a kill that found the root gone reported as a kill.
    #[skuld::test]
    fn a_kill_that_finds_the_root_gone_says_so() {
        let (err, sent, warns) = run(
            Gate::Open,
            Ok(Sent::Delivered),
            Some(Ok(false)),
            Gate::Open,
            Ok(Sent::Gone),
        );
        assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
        assert_eq!(sent, ["term", "grace", "kill"]);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("its pidfd showed it gone after the grace"),
            "{warns:?}"
        );
        assert!(!warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    }
}

// root_number -----

/// What `root_number` answered, in a comparable shape.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Trusted,
    Empty,
    #[cfg(target_os = "macos")]
    Untrusted,
    #[cfg(target_os = "macos")]
    NoWalk,
    /// `MayNameAnother`, with `exact_root` and a phrase its `why` contains.
    MayNameAnother(bool, &'static str),
}

/// The state a row hands `root_number`, built fresh per call (`RootState` holds an `io::Error`).
#[derive(Debug, Clone, Copy)]
enum State {
    Unreaped,
    Reaped,
    Unknown,
}

fn answer(attached: &Attached, state: State, own: bool, read: Resolved<ProcessId>) -> (Answer, bool) {
    let _read = crate::child::fault::force_root_reads(read);
    let looked = std::cell::Cell::new(false);
    let number = root_number(attached, PGID as u32, || {
        looked.set(true);
        let state = match state {
            State::Unreaped => RootState::Unreaped,
            State::Reaped => RootState::Reaped,
            State::Unknown => RootState::Unknown(std::io::Error::other("forced")),
        };
        (state, own)
    });
    let answer = match number {
        RootNumber::Trusted => Answer::Trusted,
        RootNumber::Empty => Answer::Empty,
        #[cfg(target_os = "macos")]
        RootNumber::Untrusted(_) => Answer::Untrusted,
        #[cfg(target_os = "macos")]
        RootNumber::NoWalk => Answer::NoWalk,
        RootNumber::MayNameAnother { why, exact_root } => {
            let phrase = ["could not be read", "was reaped elsewhere", "could not say whether it"]
                .into_iter()
                .find(|phrase| why.contains(phrase))
                .unwrap_or_else(|| panic!("an unexpected reason: {why}"));
            Answer::MayNameAnother(exact_root, phrase)
        }
    };
    (answer, looked.get())
}

/// `root_number` over every state, own-reap flag and identity read, for a process group (which
/// reaches its tree through the root's number) and a `TreeWalk` (which checks for itself). The
/// identity read matters only after this handle's own reap.
///
/// Mutants: any one arm of `root_number` answering another row's value; the look taken for a
/// mechanism that does not need it (off macOS).
#[skuld::test]
fn root_number_answers_each_state_own_reap_and_identity_read() {
    let other = || ProcessId::from_parts_for_test(PGID as u32, 1);
    let reads = || [Resolved::Gone, Resolved::Found(other()), Resolved::Unknown];
    let group = Attached::ProcessGroup(PGID);
    let exact = cfg!(target_os = "linux");
    for own in [false, true] {
        for (i, read) in reads().into_iter().enumerate() {
            let case = format!("own: {own}, read #{i}");
            assert_eq!(
                answer(&group, State::Unreaped, own, read),
                (Answer::Trusted, true),
                "unreaped, {case}"
            );
        }
        for (i, read) in reads().into_iter().enumerate() {
            let case = format!("own: {own}, read #{i}");
            assert_eq!(
                answer(&group, State::Unknown, own, read).0,
                Answer::MayNameAnother(exact, "could not say whether it"),
                "unknown, {case}"
            );
        }
    }
    for read in reads() {
        assert_eq!(
            answer(&group, State::Reaped, false, read).0,
            Answer::MayNameAnother(false, "was reaped elsewhere"),
            "reaped elsewhere"
        );
    }
    // This handle's own reap: the pid names nothing (the group's id while a member survives), names
    // another process (so the group is empty), or cannot be read.
    let [gone, found, unknown] = reads();
    assert_eq!(
        answer(&group, State::Reaped, true, gone).0,
        Answer::Trusted,
        "own reap, gone"
    );
    assert_eq!(
        answer(&group, State::Reaped, true, found).0,
        Answer::Empty,
        "own reap, found"
    );
    assert_eq!(
        answer(&group, State::Reaped, true, unknown).0,
        Answer::MayNameAnother(false, "could not be read"),
        "own reap, unreadable"
    );

    // A `TreeWalk` checks for itself.
    let walk = Attached::TreeWalk(other());
    for state in [State::Unreaped, State::Reaped, State::Unknown] {
        for own in [false, true] {
            for read in reads() {
                let (answer, looked) = answer(&walk, state, own, read);
                #[cfg(not(target_os = "macos"))]
                assert_eq!((answer, looked), (Answer::Trusted, false), "{state:?}, own: {own}");
                #[cfg(target_os = "macos")]
                {
                    let expected = match state {
                        State::Unknown => Answer::Untrusted,
                        _ => Answer::Trusted,
                    };
                    assert_eq!((answer, looked), (expected, true), "{state:?}, own: {own}");
                }
            }
        }
    }
}
