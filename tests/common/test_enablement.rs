//! Group enablement for integration tests, the twin of the library's
//! `test_support::require_group` (an integration test cannot name a `#[cfg(test)]` item of the
//! library). Keep the two messages identical.
//!
//! A group whose environment support varies by host declares `COSCA_TEST_<GROUP>`, on by default:
//! only the literal `0` disables it. A group that changes system state also needs
//! `COSCA_TEST_<GROUP>_CONSENT=1`. An enabled group without consent fails; it never skips.
//! See `docs/principles.md`, principles 9 and 10.

/// Whether the tests of `group` run on this host. Returns `false` only when the caller set
/// `COSCA_TEST_<GROUP>=0`; the test then returns early, as an opted-out test does. Otherwise it
/// asserts consent and returns `true`.
///
/// # Panics
///
/// When the group is enabled and `COSCA_TEST_<GROUP>_CONSENT` is not exactly `1`.
pub fn require_group(group: &str) -> bool {
    require_group_in(group, |name| std::env::var(name).ok())
}

/// [`require_group`] over an explicit environment, so its cases are testable without touching this
/// process's own.
pub fn require_group_in(group: &str, env: impl Fn(&str) -> Option<String>) -> bool {
    let enabled = format!("COSCA_TEST_{group}");
    if env(&enabled).is_some_and(|v| v == "0") {
        return false;
    }
    let consent = format!("COSCA_TEST_{group}_CONSENT");
    assert!(
        env(&consent).is_some_and(|v| v == "1"),
        "{group} tests touch real system state and run only in a sandbox (a container, VM or \
         CI); set {consent}=1 there to consent, or {enabled}=0 to turn the group off"
    );
    true
}
