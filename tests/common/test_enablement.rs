//! Group enablement for integration tests. The lib's `check_group` is included by `#[path]` because
//! an integration test cannot name a `#[cfg(test)]` item of the library. See `docs/principles.md`,
//! principles 9 and 10.

#[path = "../../src/test_groups.rs"]
pub mod test_groups;

/// `false` when `COSCA_TEST_<GROUP>=0`; the caller then returns early. Otherwise `true`.
///
/// # Panics
///
/// When the group is enabled and `COSCA_TEST_<GROUP>_CONSENT` is not exactly `1`.
pub fn require_group(group: &str) -> bool {
    test_groups::check_group(&format!("COSCA_TEST_{group}"), |name| std::env::var(name).ok())
        .unwrap_or_else(|why| panic!("{why}"))
}
