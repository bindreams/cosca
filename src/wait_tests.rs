use super::remaining;
use std::time::{Duration, Instant};

#[test]
fn remaining_unbounded_and_overflow_are_none() {
    assert_eq!(remaining(None), None);
    assert_eq!(remaining(Some(None)), None);
}

#[test]
fn remaining_past_deadline_saturates_to_zero() {
    let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    assert_eq!(remaining(Some(Some(past))), Some(Duration::ZERO));
}
