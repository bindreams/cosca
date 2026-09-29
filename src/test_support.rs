//! Test-only support shared across the crate's unit tests.

// The debugger stand-in is `ptrace` on macOS; Linux uses only `require_group`.
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
    check_group(group, var).unwrap_or_else(|why| panic!("{why}"))
}

/// [`require_group`]'s rule: `Ok(false)` for a group turned off, `Err` naming the consent
/// variable for an enabled group without consent.
fn check_group(group: &str, var: impl Fn(&str) -> Option<String>) -> Result<bool, String> {
    let enabled = format!("COSCA_TEST_{group}");
    let consent = format!("COSCA_TEST_{group}_CONSENT");
    if var(&enabled).as_deref() == Some("0") {
        return Ok(false);
    }
    if var(&consent).as_deref() != Some("1") {
        return Err(format!(
            "{group} tests touch real system state and run only in a sandbox (a container, VM or \
             CI); set {consent}=1 there to consent, or {enabled}=0 to turn the group off"
        ));
    }
    Ok(true)
}

#[cfg(test)]
#[path = "test_support_group_tests.rs"]
mod test_support_group_tests;
