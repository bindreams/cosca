// Exercises the ACTUAL shared classifier both Drop impls call (crate::child::
// is_teardown_mechanism_failure), not a hand-copied duplicate — a future edit to the real
// condition is caught here automatically. Cannot force a REAL Containment through a live
// Drop without root (same constraint as the rest of this plan), so this drives the
// classifier directly with constructed Error values. Both Unassessable shapes are exercised
// because they classify oppositely: `source: None` (an ordinary "member unconfirmed" outcome
// from group::decide) is NOT a mechanism failure; `source: Some(_)` (group::state's listing
// itself failed) IS one.
#[test]
fn teardown_mechanism_failure_excludes_containment_and_per_member_unassessable() {
    use crate::child::is_teardown_mechanism_failure;
    assert!(!is_teardown_mechanism_failure(&crate::error::Error::Containment {
        detail: "refused".into()
    }));
    assert!(!is_teardown_mechanism_failure(&crate::error::Error::Unassessable {
        detail: "unknown".into(),
        source: None
    }));
    assert!(is_teardown_mechanism_failure(&crate::error::Error::Io(
        std::io::Error::other("mechanism failure")
    )));
}

#[test]
fn teardown_mechanism_failure_includes_listing_failure_unassessable() {
    use crate::child::is_teardown_mechanism_failure;
    assert!(is_teardown_mechanism_failure(&crate::error::Error::Unassessable {
        detail: "process group 372 could not be listed after SIGKILL".into(),
        source: Some(std::io::Error::other("sysctl KERN_PROC_PGRP failed"))
    }));
}
