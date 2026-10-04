//! Group enablement for integration tests: the lib's `check_group` (`src/test_groups.rs`), included
//! by `#[path]` because an integration test cannot name a `#[cfg(test)]` item of the library.
//!
//! A group whose environment support varies by host declares `COSCA_TEST_<GROUP>`, on by default:
//! only the literal `0` disables it. A group that changes system state also needs
//! `COSCA_TEST_<GROUP>_CONSENT=1`. An enabled group without consent fails; it never skips.
//! See `docs/principles.md`, principles 9 and 10.

#[path = "../../src/test_groups.rs"]
pub mod test_groups;

/// Whether the tests of `group` run on this host. Returns `false` only when the caller set
/// `COSCA_TEST_<GROUP>=0`; the test then returns early, as an opted-out test does. Otherwise it
/// asserts consent and returns `true`.
///
/// # Panics
///
/// When the group is enabled and `COSCA_TEST_<GROUP>_CONSENT` is not exactly `1`.
pub fn require_group(group: &str) -> bool {
    test_groups::check_group(&format!("COSCA_TEST_{group}"), |name| std::env::var(name).ok())
        .unwrap_or_else(|why| panic!("{why}"))
}
