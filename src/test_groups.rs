//! Test groups: one declaration each (`docs/principles.md` §10).
//!
//! A group is a skuld fixture carrying three things: `requires` (the off-switch: `Err` only for
//! `<env>=0`, so an opted-out test is ignored, at list time too), a setup that fails the test
//! unless `<env>_CONSENT` is exactly `1` (system-affecting groups only), and the group's label
//! (lane selection, `SKULD_LABELS=<label>`).

/// Proof that the group is enabled (and consented to, where asked).
pub(crate) struct Group;

/// The rule behind every group: `Ok(false)` for `enabled_var=0`; `Err` naming the consent
/// variable for an enabled group without exactly `<enabled_var>_CONSENT=1`.
pub(crate) fn check_group(enabled_var: &str, var: impl Fn(&str) -> Option<String>) -> Result<bool, String> {
    let consent = format!("{enabled_var}_CONSENT");
    if require_enabled(enabled_var, &var).is_err() {
        return Ok(false);
    }
    if var(&consent).as_deref() != Some("1") {
        return Err(format!(
            "tests under {enabled_var} touch real system state and run only in a sandbox (a container, VM or \
             CI); set {consent}=1 there to consent, or {enabled_var}=0 to turn the group off"
        ));
    }
    Ok(true)
}

/// A group's `requires`: `Err` only when `enabled_var` is `0`.
pub(crate) fn require_enabled(enabled_var: &str, var: impl Fn(&str) -> Option<String>) -> Result<(), String> {
    if var(enabled_var).as_deref() == Some("0") {
        return Err(format!("{enabled_var}=0"));
    }
    Ok(())
}

/// A consent-asking group's setup: [`check_group`]'s rule, where `what` says what the group does.
pub(crate) fn require_consent(
    enabled_var: &str,
    what: &str,
    var: impl Fn(&str) -> Option<String>,
) -> Result<Group, String> {
    match check_group(enabled_var, var) {
        Ok(true) => Ok(Group),
        // skuld runs the body of a test whose `requires` failed when ignored tests are included
        // (`--run-ignored only`), so a group that is off refuses here as well.
        Ok(false) => Err(format!("{enabled_var}=0")),
        Err(why) => Err(format!("the group {what}: {why}")),
    }
}

/// Declares a test group: the fixture `$fixture`, labelled `$label` (declared in
/// `test_harness.rs`), switched off by `env = "<NAME>"` set to `0`. With `consent = "<what the
/// group does>"` its setup also fails the test unless `<NAME>_CONSENT` is exactly `1`.
///
/// A test file brings the fixture into scope with `use crate::test_groups::{$fixture, Group};`.
macro_rules! test_group {
    ($label:ident => $fixture:ident, env = $env:literal, consent = $what:literal) => {
        test_group!(@declare $label, $fixture, $env, require_consent($env, $what, |name| std::env::var(name).ok()));
    };
    ($label:ident => $fixture:ident, env = $env:literal) => {
        test_group!(@declare $label, $fixture, $env, require_enabled($env, |name| std::env::var(name).ok()).map(|()| Group));
    };
    (@declare $label:ident, $fixture:ident, $env:literal, $setup:expr) => {
        mod $fixture {
            #[allow(dead_code, reason = "a root that includes this file may have no test in the group")]
            pub(super) fn enabled() -> Result<(), String> {
                super::require_enabled($env, |name| std::env::var(name).ok())
            }
        }

        #[allow(dead_code, reason = "a root that includes this file may have no test in the group")]
        #[skuld::fixture(requires = [$fixture::enabled], labels = [crate::test_harness::$label])]
        pub(crate) fn $fixture() -> Result<Group, String> {
            $setup
        }
    };
}

test_group!(ROOT => root, env = "COSCA_TEST_ROOT", consent = "runs as root, for a DAC bypass");
test_group!(NAMESPACES => namespaces, env = "COSCA_TEST_NAMESPACES", consent = "unshares namespaces and mounts");
test_group!(DRIVE_MAPPING => drive_mapping, env = "COSCA_TEST_DRIVE_MAPPING", consent = "maps a drive letter for the whole logon session");
test_group!(SETUID => setuid, env = "COSCA_TEST_SETUID", consent = "runs a setuid-root copy of cosca_testbin");
test_group!(PATH_PROBES => path_probes, env = "COSCA_TEST_PATH_PROBES", consent = "launches copies of cosca_testbin_image and creates a suspended process");
test_group!(SHELL_EXECUTE => shell_execute, env = "COSCA_TEST_SHELL_EXECUTE", consent = "elevates through ShellExecuteEx and registers volatile App Paths keys");
test_group!(SHELL_PROBES => shell_probes, env = "COSCA_TEST_SHELL_PROBES", consent = "plants and executes batch files through ShellExecuteEx and launches copies of cosca_testbin_image");
test_group!(ELEVATION_ROUTES => elevation_routes, env = "COSCA_TEST_ELEVATION_ROUTES", consent = "derives tokens, creates accounts and a scheduled task, launches copies of this test binary under derived tokens and scratch accounts, and plants a batch file that CreateProcessW may run");
test_group!(CGROUP => cgroup, env = "COSCA_TEST_CGROUP", consent = "creates, kills and removes cgroup v2 leaves, runs process trees in them, and unshares file tables and mount namespaces to mount over them");
test_group!(TRACER => tracer_group, env = "COSCA_TEST_TRACER", consent = "attaches a tracer with ptrace to its own children as a debugger would, re-executes the test binary as that tracer (on macOS an ad-hoc signed copy with the debugger entitlement), and on Linux allows any process to trace its tracee");
test_group!(UID_SWITCH => uid_switch, env = "COSCA_TEST_UID_SWITCH", consent = "runs as real root and switches to other real uids, spawning and signalling processes under them");
test_group!(ELEVATION => elevation, env = "COSCA_TEST_ELEVATION", consent = "runs commands with real administrator or root privileges");
