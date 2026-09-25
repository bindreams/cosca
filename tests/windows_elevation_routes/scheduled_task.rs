//! Question 3's Task Scheduler arm, reduced to its gating question.

use windows::Win32::Security::TOKEN_QUERY;

use crate::harness::{
    elevation_type_name, integrity_name, open_own_token, require_gate, schtasks_registration_report,
    token_elevation_type, token_integrity_rid,
};
use crate::windows_probe::mark_test_passed;

/// Can a caller REGISTER a task that runs with `RunLevel=Highest`? If registration needs
/// elevation the route is dead for an unelevated caller regardless of what a registered task
/// could do.
///
/// Deliberately does NOT run the task. Observing the resulting process's integrity would mean
/// waiting on the Task Scheduler service with no handle to wait on, and the registration answer is
/// the one that decides the route.
#[test]
#[ignore = "registers and deletes a scheduled task; opt in with --ignored on a throwaway host"]
fn can_this_caller_register_a_runlevel_highest_task() {
    require_gate("COSCA_PROBE_ALLOW_STATE", "registers and deletes a scheduled task");
    let etype_str = open_own_token(TOKEN_QUERY)
        .and_then(|t| token_elevation_type(t.0))
        .map_or_else(
            |e| format!("<error: {e}>"),
            |v| format!("{v} {}", elevation_type_name(v)),
        );
    let rid_str = open_own_token(TOKEN_QUERY)
        .and_then(|t| token_integrity_rid(t.0))
        .map_or_else(
            |e| format!("<error: {e}>"),
            |v| format!("0x{v:04x} {}", integrity_name(v)),
        );
    println!("PROBE schtasks-highest: measured at integrity {rid_str} (elevation_type {etype_str})");
    let (lines, any_create_exited) = schtasks_registration_report();
    for line in lines {
        println!("PROBE schtasks-highest: {line}");
    }
    assert!(
        any_create_exited,
        "not one schtasks /create call exited with a status, so nothing was measured — schtasks \
         itself could not be launched"
    );
    mark_test_passed("COSCA_PROBE_MARKERS");
}
