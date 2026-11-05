//! `ChildSlot`: the child comes out once, and a slot that gave it up answers nothing.

use super::teardown::{fake, PID};
use crate::child::owned::slot::ChildSlot;
use crate::child::owned::OwnedChild;

fn slot() -> ChildSlot {
    ChildSlot::new(OwnedChild::new(Box::new(fake())))
}

/// Mutant: `take` clones or keeps the child.
#[skuld::test]
fn the_child_comes_out_once() {
    let mut slot = slot();
    assert_eq!(slot.pid(), Some(PID));
    assert!(slot.take().is_some());
    assert!(slot.take().is_none());
}

/// Mutant: a slot that gave its child up answers from a stale one.
#[skuld::test]
#[should_panic(expected = "taken out of its slot")]
fn a_slot_that_gave_its_child_up_panics_on_use() {
    let mut slot = slot();
    drop(slot.take());
    _ = slot.pid();
}
