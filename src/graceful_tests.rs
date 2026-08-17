//! Unit tests for the graceful-mechanism vocabulary and its dispatch.

use super::GracefulMechanism;

// The four strings are a stable, distinct vocabulary. Exact, not `contains`: a refactor that
// collapsed two variants onto one string would still satisfy a substring check.
#[test]
fn graceful_mechanism_display_is_stable_and_distinct() {
    let all = [
        (GracefulMechanism::Process, "process"),
        (GracefulMechanism::ConsoleGroup, "own console group"),
        (
            GracefulMechanism::OtherConsoleGroup,
            "own console group in another console",
        ),
        (GracefulMechanism::Unknown, "unknown"),
        (GracefulMechanism::None, "none"),
    ];
    for (mechanism, expected) in all {
        assert_eq!(mechanism.to_string(), expected, "Display for {mechanism:?}");
    }
    for (i, (_, a)) in all.iter().enumerate() {
        for (_, b) in all.iter().skip(i + 1) {
            assert_ne!(a, b, "two variants share a Display string");
        }
    }
}

// `None` is the one mechanism the crate refuses up front, and it refuses with the remedy: a
// wildcard arm that fell through to the console call would return something else entirely.
#[test]
fn signal_refuses_a_child_with_no_mechanism() {
    let id = crate::identity::ProcessId::current();
    let err = super::signal(GracefulMechanism::None, id).expect_err("no group to address");
    let crate::error::Error::Unsupported { detail, .. } = &err else {
        panic!("expected Unsupported, got {err:?}");
    };
    assert!(detail.contains("contain"), "the refusal must name the remedy: {detail}");
}

// The dispatcher's half of `uac_elevated_attachment_has_no_in_process_route`, which pins only
// the recorded constant. The subject is a live contained child of OUR own, whose group a
// wrongly-routed event really would reach: a dispatcher that fired at it returns `Ok` (or the
// OS's `Io` if the event finds no group), never this typed refusal, so the variant-and-detail
// assertion below is what separates the two worlds — and the misfire lands on a child this test
// already owns rather than a stranger.
#[cfg(windows)]
#[test]
fn signal_refuses_a_child_cosca_did_not_create() {
    let mut cmd = crate::Command::new();
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let mechanism = crate::containment::Attachment::uac_elevated().graceful;
    let err = super::signal(mechanism, child.id()).expect_err("a child cosca did not create must not be signalled");
    let crate::error::Error::Unsupported { detail, .. } = &err else {
        panic!("expected Unsupported, got {err:?}");
    };
    assert!(
        detail.contains("did not create this child"),
        "the refusal must say whose child this is not: {detail}"
    );
    assert!(detail.contains("kill()"), "the refusal must name the remedy: {detail}");
    let _ = child.kill_tree();
    let _ = child.wait();
}
