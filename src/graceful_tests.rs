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

// `OtherConsoleGroup` shares `ConsoleGroup`'s arm — the flag word says the child's group lives
// in another console, but a child may re-attach to ours after it starts, so the signal is
// attempted rather than refused. No spawn through the public containment API can carry this
// mechanism (the flag words emitted never produce it), so the dispatcher is the only place the
// routing can be pinned at all. `Ok` is what separates the two worlds: the `Unsupported` arms
// refuse, and `wait::terminate` — the only other path out of `signal` — is itself `Unsupported`
// on Windows.
#[cfg(windows)]
#[test]
fn signal_attempts_a_child_whose_group_may_be_in_another_console() {
    let mut cmd = crate::Command::new();
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let other = super::signal(GracefulMechanism::OtherConsoleGroup, child.id());
    let group = super::signal(GracefulMechanism::ConsoleGroup, child.id());
    assert!(
        other.is_ok(),
        "OtherConsoleGroup must be attempted, not refused: {other:?}"
    );
    assert_eq!(
        other.is_ok(),
        group.is_ok(),
        "the two console mechanisms must take one path: {other:?} vs {group:?}"
    );
    let _ = child.kill_tree();
    let _ = child.wait();
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
