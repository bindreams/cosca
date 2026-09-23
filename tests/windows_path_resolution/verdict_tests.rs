//! Tests for `verdict.rs`, run on every host by `windows_path_logic`.

use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};

use super::verdict::*;

/// Run `conclude`, returning whether it marked the canary passed and its panic message, if any.
fn verdict(failures: &[String], facts: &Disagreements) -> (bool, Option<String>) {
    let marked = Cell::new(false);
    let outcome = catch_unwind(AssertUnwindSafe(|| conclude(failures, facts, || marked.set(true))));
    let message = outcome.err().map(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    });
    (marked.get(), message)
}

#[test]
fn a_passing_canary_is_marked() {
    let mut facts = Disagreements::about("Windows");
    facts.check(true, "fact", "ok");
    facts.require(true, "unused".into());
    assert_eq!(verdict(&[], &facts), (true, None));
}

#[test]
fn a_measurement_failure_is_reported_and_not_marked() {
    let mut facts = Disagreements::about("Windows");
    facts.check(false, "fact", "other");
    let (marked, message) = verdict(&["probe broke".into()], &facts);
    assert!(!marked);
    assert!(message.unwrap().contains("could not be taken: probe broke"));
}

#[test]
fn a_canary_that_checked_nothing_is_not_marked() {
    let (marked, message) = verdict(&[], &Disagreements::about("Windows"));
    assert!(!marked);
    assert!(message.unwrap().contains("checked no fact"));
}

#[test]
fn a_broken_fact_is_reported_before_a_coverage_shortfall_and_not_marked() {
    let mut facts = Disagreements::about("Windows");
    facts.check(false, "x resolves to y", "z");
    facts.require(false, "planted 4 of 5".into());
    let (marked, message) = verdict(&[], &facts);
    assert!(!marked);
    let message = message.unwrap();
    assert!(
        message.contains("The measured behaviour of Windows has changed"),
        "{message}"
    );
    assert!(message.contains("x resolves to y — measured z"), "{message}");
    assert!(!message.contains("planted"), "{message}");
}

#[test]
fn an_unmet_requirement_is_reported_and_not_marked() {
    let mut facts = Disagreements::about("Windows");
    facts.check(true, "fact", "ok");
    facts.require(false, "planted 4 of 5".into());
    let (marked, message) = verdict(&[], &facts);
    assert!(!marked);
    assert!(message.unwrap().contains("could not be taken: planted 4 of 5"));
}
