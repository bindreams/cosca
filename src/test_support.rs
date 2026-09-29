//! Test-only support shared across the crate's unit tests.

#[cfg(target_os = "macos")]
pub(crate) mod tracer;

/// Fails the calling test unless test group `group` (for example `"TRACER"`) may run
/// (docs/principles.md, principles 9 and 10): `COSCA_TEST_<group>` is not the literal `0`, and
/// `COSCA_TEST_<group>_CONSENT` is exactly `1`. It never returns early as a pass.
///
/// Principle 9 reports `=0` as `ignored`, which libtest cannot do at run time. Until the skuld
/// migration a lane honours `=0` with a nextest filter, and a test it still reaches
/// fails naming that filter.
#[cfg(unix)]
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "the first Linux caller is US's tracer test")
)]
pub(crate) fn require_group(group: &str) {
    if let Err(why) = check_group(group, |name| std::env::var(name).ok()) {
        panic!("{why}");
    }
}

/// [`require_group`]'s rule over an environment lookup.
#[cfg(unix)]
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "the first Linux caller is US's tracer test")
)]
fn check_group(group: &str, var: impl Fn(&str) -> Option<String>) -> Result<(), String> {
    let enabled = format!("COSCA_TEST_{group}");
    let consent = format!("COSCA_TEST_{group}_CONSENT");
    if var(&enabled).as_deref() == Some("0") {
        return Err(format!(
            "{enabled}=0 disables this group, but this test was still run: exclude it with a \
             nextest filter such as -E 'not test(/{}/)'",
            group.to_lowercase()
        ));
    }
    if var(&consent).as_deref() != Some("1") {
        return Err(format!(
            "{group} tests touch real system state and run only in a sandbox (a container, VM or \
             CI); set {consent}=1 there to consent, or opt out with {enabled}=0 and the nextest \
             filter -E 'not test(/{}/)'",
            group.to_lowercase()
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "test_support_group_tests.rs"]
mod test_support_group_tests;
