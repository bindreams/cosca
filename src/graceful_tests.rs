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
