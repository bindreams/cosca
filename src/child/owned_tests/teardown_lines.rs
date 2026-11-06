//! Every line a teardown can log, in one table.
//!
//! A teardown ends in one of sixteen ways: what its kill answered (delivered, found nothing to
//! signal, refused) times what the wait or look after it found. [`rows`] states, once, the clause
//! each way is said as, for a caller that leaves the child and for one that hands it back. Each
//! caller then says it as one line, led by its own name: `<label>: <clause>`, at the clause's level.
//!
//! The rule of the table: no line says two contradictory things (never both where the child goes
//! and that something else happens to it), every line names its caller, and one fate has one
//! wording, whoever says it. The rows run the real [`OwnedChild`] teardown over a `FakeProcess`,
//! and the real callers' logging over its outcome.

use std::io;

use super::teardown::{child_with_an_unreadable_exit, exit, fake, id};
use crate::child::owned::teardown::{Disposition, TeardownOutcome};
use crate::child::owned::OwnedChild;
use crate::error::Error;
use crate::os_process::child::Foreign;
use crate::os_process::fake::ReapAnswer;
use crate::signal::Sent;

/// The pid of the child every row tears down.
pub(crate) const PID: u32 = super::teardown::PID;

/// Where a child goes that a caller leaves: a zombie once it exits on Unix, and on Windows, which
/// has none, nothing that waits for it.
pub(crate) const LEFT: &str = if cfg!(unix) {
    "; left unreaped"
} else {
    "; nothing waits for it"
};

/// Where a child goes that a caller hands back.
pub(crate) const HANDED_BACK: &str = "; handed back to the caller in the error";

/// What the refused kill's error says.
const REFUSED: &str = "cosca-refused-5b0e";

/// What the failed wait's error says.
pub(crate) fn wait_error() -> String {
    io::Error::from(io::ErrorKind::Other).to_string()
}

/// What the refused kill says of itself in the clause: the error the teardown holds.
pub(crate) fn refusal() -> String {
    Error::Io(io::Error::other(REFUSED)).to_string()
}

/// What the teardown's kill answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kill {
    /// A signal reached the child.
    Delivered,
    /// The child was already gone: nothing to signal, and none reached it.
    Nothing,
    /// The signal was refused, so the teardown looks once and never waits.
    Refused,
}

/// What the wait (after a kill) or the look (after a refused one) found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Found {
    Exited,
    /// The reap took the zombie and could not read its exit record.
    Unreadable,
    /// Someone else reaped it.
    ReapedElsewhere,
    /// Launchd holds its zombie.
    Orphaned,
    /// The wait failed.
    WaitFailed,
    /// The look found it running. Only a look: a wait never answers it.
    Running,
}

/// One way a teardown ends, and the clause it is said as under each disposition.
pub(crate) struct Row {
    pub(crate) kill: Kill,
    pub(crate) found: Found,
    pub(crate) level: log::Level,
    /// Whether the teardown left the child uncollected: still this process's, so a caller that hands
    /// children back has one to hand back.
    pub(crate) uncollected: bool,
    /// The clause of a caller that leaves the child.
    pub(crate) leave: String,
    /// The clause of a caller that hands the child back.
    pub(crate) hand_back: String,
}

impl Row {
    pub(crate) fn clause(&self, disposition: Disposition) -> &str {
        match disposition {
            Disposition::Leave => &self.leave,
            Disposition::HandBack => &self.hand_back,
        }
    }
}

/// The table.
pub(crate) fn rows() -> Vec<Row> {
    use log::Level::{Debug, Warn};
    // What a clause says of a child: the teardown's, after a kill; the look's, after a refused one.
    let after_a_kill = format!("teardown of child {PID}");
    let after_a_refusal = format!("child {PID} could not be terminated ({})", refusal());
    let unreadable = "the child's exit record was unreadable (si_code 7)";
    let orphaned = "not ours to reap (launchd holds its zombie, because its tracer died)";
    let failed = format!("the wait failed: {}", wait_error());
    let same = |kill, found, level, clause: String| Row {
        kill,
        found,
        level,
        uncollected: false,
        leave: clause.clone(),
        hand_back: clause,
    };
    let by_disposition = |kill, found, clause: String| Row {
        kill,
        found,
        level: Warn,
        uncollected: true,
        leave: format!("{clause}{LEFT}"),
        hand_back: format!("{clause}{HANDED_BACK}"),
    };
    vec![
        // The kill reached the child: the wait that follows is the reap.
        same(
            Kill::Delivered,
            Found::Exited,
            Debug,
            format!("{after_a_kill}: reaped it after the kill"),
        ),
        same(
            Kill::Delivered,
            Found::Unreadable,
            Warn,
            format!("{after_a_kill}: reaped it after the kill; {unreadable}"),
        ),
        same(
            Kill::Delivered,
            Found::ReapedElsewhere,
            Debug,
            format!("{after_a_kill}: reaped by someone else"),
        ),
        same(
            Kill::Delivered,
            Found::Orphaned,
            Warn,
            format!("{after_a_kill}: {orphaned}"),
        ),
        by_disposition(Kill::Delivered, Found::WaitFailed, format!("{after_a_kill}: {failed}")),
        // The child was already gone: no kill reached it, so the line does not say "after the kill".
        same(
            Kill::Nothing,
            Found::Exited,
            Debug,
            format!("{after_a_kill}: reaped it"),
        ),
        same(
            Kill::Nothing,
            Found::Unreadable,
            Warn,
            format!("{after_a_kill}: reaped it; {unreadable}"),
        ),
        same(
            Kill::Nothing,
            Found::ReapedElsewhere,
            Debug,
            format!("{after_a_kill}: reaped by someone else"),
        ),
        same(
            Kill::Nothing,
            Found::Orphaned,
            Warn,
            format!("{after_a_kill}: {orphaned}"),
        ),
        by_disposition(Kill::Nothing, Found::WaitFailed, format!("{after_a_kill}: {failed}")),
        // The kill was refused: one look, named by the refusal, and no kill reached the child.
        same(
            Kill::Refused,
            Found::Exited,
            Debug,
            format!("{after_a_refusal}: reaped it"),
        ),
        same(
            Kill::Refused,
            Found::Unreadable,
            Warn,
            format!("{after_a_refusal}: reaped it; {unreadable}"),
        ),
        same(
            Kill::Refused,
            Found::ReapedElsewhere,
            Debug,
            format!("{after_a_refusal}: reaped by someone else"),
        ),
        same(
            Kill::Refused,
            Found::Orphaned,
            Warn,
            format!("{after_a_refusal}: {orphaned}"),
        ),
        by_disposition(Kill::Refused, Found::WaitFailed, format!("{after_a_refusal}: {failed}")),
        // Still running: a caller that leaves it says it keeps running, and one that hands it back
        // says so.
        Row {
            kill: Kill::Refused,
            found: Found::Running,
            level: Warn,
            uncollected: true,
            leave: format!("{after_a_refusal}; leaving it running"),
            hand_back: format!("{after_a_refusal}{HANDED_BACK}"),
        },
    ]
}

/// What `torn` said of the child, and at what level.
pub(crate) fn said_of(torn: &TeardownOutcome) -> Option<(log::Level, String)> {
    torn.said().map(|said| (said.level(), said.text().to_owned()))
}

/// The outcome of the real teardown `row` states, for a caller that does `disposition`.
pub(crate) fn outcome(row: &Row, disposition: Disposition) -> TeardownOutcome {
    let kill = crate::child::owned::teardown::Kill {
        disposition,
        tree: None,
    };
    // A kill is refused for want of permission: the only refusal a teardown over its own handle expects.
    let refused = || io::Error::new(io::ErrorKind::PermissionDenied, REFUSED);
    if row.found == Found::Unreadable {
        // A child whose reap read no exit record answers every wait so, and its handle, having reaped
        // it, sends every kill nothing: `Kill::Nothing` is the only one `tear_down` can be given for
        // it, so the other two rows enter below `tear_down`, where the kill's answer is the input.
        let child = child_with_an_unreadable_exit();
        return match row.kill {
            // A kill sent elsewhere reached it: the reap that follows.
            Kill::Delivered => child.reap_after_tree_kill(disposition),
            Kill::Nothing => child.tear_down(Some(id()), kill, None),
            Kill::Refused => child.look_after_refused_kill(Some(id()), Error::Io(refused()), disposition),
        };
    }
    let signal = match row.kill {
        Kill::Delivered => Ok(Sent::Delivered),
        Kill::Nothing => Ok(Sent::Gone),
        Kill::Refused => Err(refused()),
    };
    OwnedChild::new(Box::new(fake().reaps([reap_answer(row.found)]).signals([signal]))).tear_down(
        Some(id()),
        kill,
        None,
    )
}

/// What the wait or look of `found` answers.
fn reap_answer(found: Found) -> ReapAnswer {
    match found {
        Found::Exited => ReapAnswer::Reaped(exit()),
        Found::ReapedElsewhere => ReapAnswer::Foreign(Foreign::Gone),
        Found::Orphaned => ReapAnswer::Foreign(Foreign::Orphaned),
        Found::WaitFailed => ReapAnswer::Err(io::ErrorKind::Other),
        Found::Running => ReapAnswer::Running,
        Found::Unreadable => unreachable!("the unreadable rows build their own child"),
    }
}

/// The outcome of the reap of a child a tree kill has just ended ([`OwnedChild::reap_after_tree_kill`]),
/// for the row whose kill was delivered, for a caller that does `disposition`. It sends the child
/// nothing: the kill was sent elsewhere.
pub(crate) fn outcome_after_a_tree_kill(row: &Row, disposition: Disposition) -> TeardownOutcome {
    assert_eq!(row.kill, Kill::Delivered, "a tree kill reached the child");
    let child = match row.found {
        Found::Unreadable => child_with_an_unreadable_exit(),
        found => OwnedChild::new(Box::new(fake().reaps([reap_answer(found)]))),
    };
    child.reap_after_tree_kill(disposition)
}

/// What no clause says, whoever says it.
const NEVER_SAID: [&str; 3] = ["not waited on", "torn down through", "left uncollected"];

/// What a clause says of where the child goes, or what is done to it: it says at most one.
fn fates() -> [&'static str; 3] {
    [HANDED_BACK, LEFT, "; leaving it running"]
}

/// The clause says one thing of the child's fate, in the one wording, and no wording of an earlier
/// round.
#[track_caller]
fn assert_one_wording(clause: &str) {
    let said: Vec<_> = fates().into_iter().filter(|fate| clause.contains(fate)).collect();
    assert!(said.len() <= 1, "{clause:?} says {said:?}");
    for old in NEVER_SAID {
        assert!(!clause.contains(old), "{clause:?} says {old:?}");
    }
    if cfg!(windows) {
        assert!(!clause.contains("unreaped"), "{clause:?}: Windows has no zombies");
    }
}

/// The table's own rows state one wording per fate, and the real teardown says each row's clause at
/// its level, and leaves the child uncollected as the row says.
///
/// Mutants: a clause is worded apart from `Disposition::suffix`; "after the kill" is said of a kill
/// that reached nothing; the leave wording is the hand-back one; a failed wait or a look that finds
/// the child running leaves it collected, or a reaped one uncollected.
#[skuld::test]
fn the_teardown_says_every_row_as_the_table_states_it() {
    for row in rows() {
        for disposition in [Disposition::Leave, Disposition::HandBack] {
            let torn = outcome(&row, disposition);
            let wanted = row.clause(disposition);
            assert_one_wording(wanted);
            assert_eq!(torn.uncollected(), row.uncollected, "{:?} {:?}", row.kill, row.found);
            assert_eq!(
                disposition.hands_back(&torn.remains()),
                row.uncollected && disposition == Disposition::HandBack
            );
            assert_eq!(
                said_of(&torn),
                Some((row.level, wanted.to_owned())),
                "{:?} {:?} {disposition:?}",
                row.kill,
                row.found
            );
        }
    }
}

/// The reap of a child a tree kill ended says each delivered-kill row as the table states it, under
/// both dispositions, a failed reap included: it is `uncollected` and handed back or left, as the
/// row says.
///
/// Mutants: the tree-kill reap drops a failed wait, or says it as the other disposition.
#[skuld::test]
fn the_reap_after_a_tree_kill_says_every_delivered_row_as_the_table_states_it() {
    for row in rows().into_iter().filter(|row| row.kill == Kill::Delivered) {
        for disposition in [Disposition::Leave, Disposition::HandBack] {
            let torn = outcome_after_a_tree_kill(&row, disposition);
            assert_eq!(torn.uncollected(), row.uncollected, "{:?} {disposition:?}", row.found);
            assert_eq!(
                said_of(&torn),
                Some((row.level, row.clause(disposition).to_owned())),
                "{:?} {disposition:?}",
                row.found
            );
        }
    }
}

/// Every caller says every row as one line: its own name, a colon, the clause, at the clause's
/// level. A line at warn is the one warn of the event; a lower one is logged on its own.
///
/// Mutants: a caller words the clause itself or drops its own name; a line is logged at the wrong
/// level; a clause is logged twice.
#[skuld::test]
fn every_caller_says_every_row_as_one_line_under_its_own_name() {
    crate::log_capture::install();
    for row in rows() {
        for disposition in [Disposition::Leave, Disposition::HandBack] {
            for (label, say) in callers() {
                // The teardown logs nothing of its own but the OS layer's: the callers log the clause.
                let torn = outcome(&row, disposition);
                let mark = crate::log_capture::mark();
                say(torn);
                assert_eq!(
                    crate::log_capture::records_since_on_current_thread(mark, ""),
                    [(row.level, format!("{label}: {}", row.clause(disposition)))],
                    "{label} {:?} {:?} {disposition:?}",
                    row.kill,
                    row.found
                );
            }
        }
    }
}

type Say = fn(TeardownOutcome);

/// Each caller's name, and what it logs of an outcome.
fn callers() -> Vec<(&'static str, Say)> {
    use crate::containment::dispatch::TeardownCaller;
    let mut callers: Vec<(&'static str, Say)> = Vec::new();
    #[cfg(unix)]
    {
        callers.push((TeardownCaller::Drop.label(), |torn| {
            say_in_a_report(TeardownCaller::Drop, torn)
        }));
        callers.push((TeardownCaller::FailedRun.label(), |torn| {
            say_in_a_report(TeardownCaller::FailedRun, torn);
        }));
        callers.push((TeardownCaller::FinishElevated.label(), |torn| {
            say_in_a_report(TeardownCaller::FinishElevated, torn);
        }));
    }
    #[cfg(any(target_os = "linux", windows))]
    callers.push((TeardownCaller::FailedSpawn.label(), |torn| {
        use crate::child::owned::teardown::{Expect, HandleTeardown};
        HandleTeardown::new(torn, Expect::Anything).say_as_failed_spawn(&mut crate::child::spawn::Diagnosis::default());
    }));
    callers
}

/// What a `Child`'s drop, a failed run's teardown and `finish_elevated` do with an outcome: fold its
/// clause into the event's one report and emit it.
#[cfg(unix)]
fn say_in_a_report(caller: crate::containment::dispatch::TeardownCaller, torn: TeardownOutcome) {
    use crate::containment::dispatch::{DropView, RootView};

    let view = DropView {
        caller,
        root_pid: PID,
        root: RootView::Trusted,
        tree_killed: false,
    };
    let mut report = crate::child::drop_report::DropReport::new(&view);
    report.fold_clause(torn);
    report.emit(&[]);
}
