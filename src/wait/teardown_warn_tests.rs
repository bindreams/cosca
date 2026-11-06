use std::cell::RefCell;
use std::time::{Duration, Instant};

use super::{wait_warning, Due};

/// What `wait_warning` called, in order, and what the look and the warn were given.
#[derive(Default)]
struct Calls {
    steps: Vec<&'static str>,
    until: Option<Instant>,
    warned_after: Option<Duration>,
}

/// `wait_warning` with `ended_by` answering `ended`.
fn run(due: Option<Due>, ended: bool) -> (Calls, &'static str) {
    let calls = RefCell::new(Calls::default());
    let result = wait_warning(
        (),
        due,
        |(), until| {
            let mut calls = calls.borrow_mut();
            calls.steps.push("look");
            calls.until = Some(until);
            ended
        },
        |after| {
            let mut calls = calls.borrow_mut();
            calls.steps.push("warn");
            calls.warned_after = Some(after);
        },
        |()| {
            calls.borrow_mut().steps.push("wait");
            "waited"
        },
    );
    (calls.into_inner(), result)
}

fn due() -> Due {
    Due::in_(Some(Duration::from_secs(7))).expect("a threshold")
}

/// Without a threshold only the wait runs.
///
/// Mutant: the look or the warn runs without `due`.
#[skuld::test]
fn without_a_threshold_only_the_wait_runs() {
    let (calls, result) = run(None, false);
    assert_eq!(calls.steps, ["wait"]);
    assert_eq!(result, "waited");
}

/// A wait that ended within the threshold does not warn.
///
/// Mutant: the warn runs whatever the look found.
#[skuld::test]
fn a_wait_that_ended_in_time_does_not_warn() {
    let (calls, result) = run(Some(due()), true);
    assert_eq!(calls.steps, ["look", "wait"]);
    assert_eq!(result, "waited");
}

/// A wait still going at the threshold warns once, with the threshold's length, before it blocks;
/// the look is bounded by the threshold's instant, and the wait's answer is the result.
///
/// Mutants: the warn runs after the wait; it gets another length; the look gets another instant;
/// the result is the warn's.
#[skuld::test]
fn a_wait_still_going_at_the_threshold_warns_once_before_it_blocks() {
    let due = due();
    let (calls, result) = run(Some(due), false);
    assert_eq!(calls.steps, ["look", "warn", "wait"]);
    assert_eq!(calls.until, Some(due.until));
    assert_eq!(calls.warned_after, Some(due.after));
    assert_eq!(result, "waited");
}
