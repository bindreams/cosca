use super::{Existence, Liveness, Resolved};

#[test]
fn unknown_is_distinct_from_the_negative_state() {
    assert_ne!(Existence::Unknown, Existence::Gone);
    assert_ne!(Liveness::Unknown, Liveness::Dead);
    assert_ne!(Resolved::<u8>::Unknown, Resolved::<u8>::Gone);
}

#[test]
fn is_unknown_reports_only_the_unknown_variant() {
    assert!(Existence::Unknown.is_unknown());
    assert!(!Existence::Present.is_unknown());
    assert!(!Existence::Gone.is_unknown());
    assert!(Liveness::Unknown.is_unknown());
    assert!(!Liveness::Alive.is_unknown());
    assert!(!Liveness::Dead.is_unknown());
    assert!(Resolved::<u8>::Unknown.is_unknown());
    assert!(!Resolved::Found(1u8).is_unknown());
}

#[test]
fn found_yields_the_value_only_for_found() {
    assert_eq!(Resolved::Found(7u8).found(), Some(7));
    assert_eq!(Resolved::<u8>::Gone.found(), None);
    assert_eq!(Resolved::<u8>::Unknown.found(), None);
}

#[test]
fn map_preserves_the_non_found_variants() {
    assert_eq!(Resolved::Found(2u8).map(|v| v + 1), Resolved::Found(3u8));
    assert_eq!(Resolved::<u8>::Gone.map(|v| v + 1), Resolved::<u8>::Gone);
    assert_eq!(Resolved::<u8>::Unknown.map(|v| v + 1), Resolved::<u8>::Unknown);
}
