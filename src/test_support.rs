//! Test-only support shared across the crate's unit tests.

// The debugger stand-in is `ptrace` on macOS.
#[cfg(target_os = "macos")]
pub(crate) mod tracer;

/// Whether test group `group` (for example `"TRACER"`) runs. `COSCA_TEST_<group>=0` turns it
/// off, and the caller returns early. Otherwise it runs, and fails here unless
/// `COSCA_TEST_<group>_CONSENT` is exactly `1`.
pub(crate) fn require_group(group: &str) -> bool {
    require_group_in(group, |name| std::env::var(name).ok())
}

/// [`require_group`] over an environment lookup.
fn require_group_in(group: &str, var: impl Fn(&str) -> Option<String>) -> bool {
    crate::test_groups::check_group(&format!("COSCA_TEST_{group}"), var).unwrap_or_else(|why| panic!("{why}"))
}

#[cfg(test)]
#[path = "test_support_group_tests.rs"]
mod test_support_group_tests;
