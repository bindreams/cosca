//! Windows: what a job object's breakaway limits do to a child that asks to escape, and how
//! cosca classifies the refusal.
//!
//! The first six tests characterize the OS through a raw `std::process::Command`, with no cosca
//! involved, because two classifier arms depend on facts Win32 does not document: what a
//! silent-breakaway job does with the flag, and where a child lands under job nesting. Only then
//! do the cosca legs assert cosca's own behaviour.
//!
//! Every job shape is CONSTRUCTED by a short-lived helper that assigns itself to it — assigning a
//! process to a job is irreversible, so this cannot happen in the test binary — which makes each
//! assertion deterministic whatever ambient job a CI runner holds. The helper reports its own
//! independent reading of the job's limits, so a shape that was not built the way the test names
//! it fails loudly instead of measuring something else.
#![cfg(windows)]

use std::net::TcpListener;

#[path = "common/mod.rs"]
mod common;

use common::{read_report_line, report_field, testbin};

/// Run the `report-breakaway` helper for one job shape and one spawn vehicle, and return its
/// report line. The helper blocks on the report socket until this function drops it, so every
/// field describes a live measurement.
fn breakaway_report(shape: &str, vehicle: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind report listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = std::process::Command::new(testbin());
    cmd.args(["report-breakaway", addr.as_str(), shape, vehicle]);
    let mut helper = {
        let _guard = cosca::test_spawn_lock();
        cmd.spawn().expect("spawn breakaway helper")
    };
    let (sock, _) = listener.accept().expect("accept report socket");
    let report = read_report_line(&sock);
    drop(sock);
    helper.wait().expect("reap breakaway helper");
    report
}

/// `ERROR_ACCESS_DENIED`, as the helper encodes a raw `io::Error`.
const RAW_ACCESS_DENIED: &str = "Io-5";

#[test]
fn a_permitting_job_lets_a_raw_flag_child_break_away() {
    let r = breakaway_report("permit", "raw");
    assert_eq!(report_field(&r, "limits"), "breakaway-ok", "wrong job shape: {r}");
    assert_eq!(report_field(&r, "spawn"), "Ok", "{r}");
    assert_eq!(
        report_field(&r, "in_inner"),
        "0",
        "the child must have left the job: {r}"
    );
}

/// The negative control for the row above: without the flag, the same child in the same job
/// STAYS. Without it, `in_inner == 0` there could hold for a reason unrelated to the request.
#[test]
fn a_child_without_the_raw_flag_stays_in_the_permitting_job() {
    let r = breakaway_report("permit-no-request", "raw");
    assert_eq!(report_field(&r, "limits"), "breakaway-ok", "wrong job shape: {r}");
    assert_eq!(report_field(&r, "in_inner"), "1", "{r}");
    assert_eq!(report_field(&r, "in_any"), "1", "{r}");
}

/// The fact the typed containment error rests on.
#[test]
fn a_forbidding_job_denies_the_raw_flag() {
    let r = breakaway_report("forbid", "raw");
    assert_eq!(report_field(&r, "limits"), "none", "wrong job shape: {r}");
    assert_eq!(
        report_field(&r, "spawn"),
        RAW_ACCESS_DENIED,
        "a forbidding job denies the flag with ACCESS_DENIED: {r}"
    );
}

/// Breakaway leaves the immediate job and climbs the parent chain until a job forbids it, so a
/// successful breakaway under nesting can still leave the child inside an ancestor.
///
/// The nesting is CONSTRUCTED, not observed, so `in_outer == 1` is deterministic — and it is the
/// half a partial breakaway can fail. Asserting only `in_inner == 0` would pass under any
/// breakaway at all.
#[test]
fn nested_breakaway_climbs_to_the_first_forbidding_job() {
    let r = breakaway_report("nested", "raw");
    assert_eq!(report_field(&r, "limits"), "breakaway-ok", "wrong inner job shape: {r}");
    assert_eq!(report_field(&r, "spawn"), "Ok", "{r}");
    assert_eq!(
        report_field(&r, "in_inner"),
        "0",
        "the child left the permitting job: {r}"
    );
    assert_eq!(
        report_field(&r, "in_outer"),
        "1",
        "and stopped at the forbidding one above it: {r}"
    );
    assert_eq!(report_field(&r, "in_any"), "1", "{r}");
}

/// A silent-breakaway job keeps new children out ON ITS OWN, without the child requesting
/// anything. Paired with `a_child_without_the_raw_flag_stays_in_the_permitting_job`'s
/// `in_inner == 1`, this is a discriminating measurement: the same no-request child lands inside
/// one job and outside the other, so the difference is attributable to the limit.
#[test]
fn a_child_without_the_raw_flag_already_leaves_a_silent_breakaway_job() {
    let r = breakaway_report("silent-no-request", "raw");
    assert_eq!(
        report_field(&r, "limits"),
        "silent-breakaway-ok",
        "wrong job shape: {r}"
    );
    assert_eq!(report_field(&r, "spawn"), "Ok", "{r}");
    assert_eq!(report_field(&r, "in_inner"), "0", "{r}");
}

/// Whether a silent-breakaway job also refuses the explicit FLAG is undocumented, and the spawn
/// outcome is the only thing this shape can measure about the request: `in_inner == 0` holds here
/// with or without the flag (the control above measures exactly that), so asserting it would be a
/// test that cannot fail.
///
/// Measured on Windows 11 26100, 2026-08-18: the spawn **succeeds**. That selects the classifier
/// arm for `SilentBreakaway` — it keeps the raw error, because no breakaway request can reach the
/// classifier from such a job at all. The verdict exists solely to stop a silent-breakaway job
/// being misread as one that forbids breakaway, whose message would be wrong about the world.
#[test]
fn a_silent_breakaway_job_accepts_the_raw_flag() {
    let r = breakaway_report("silent", "raw");
    assert_eq!(
        report_field(&r, "limits"),
        "silent-breakaway-ok",
        "wrong job shape: {r}"
    );
    assert_eq!(
        report_field(&r, "spawn"),
        "Ok",
        "a silent-breakaway job does not refuse the flag: {r}"
    );
}

// ===== the same shapes through cosca =====
//
// The `argv` legs are the point of this section: the routing rule sends an `executable()` to the
// raw backend, so a helper written in the existing testbin style would exercise only that one —
// and the std path is the one most spawns take. What makes each leg's NAME true is
// `child::spawn::spawn_tests::routes_to_raw_backend_answers_for_executables_and_high_descriptors`
// for these exact two builder shapes; the `control-block` child reports no backend evidence of
// its own, so no assertion here restates the routing rule.

#[test]
fn cosca_breaks_a_child_away_via_the_std_backend() {
    let r = breakaway_report("permit", "argv");
    assert_eq!(report_field(&r, "limits"), "breakaway-ok", "wrong job shape: {r}");
    assert_eq!(report_field(&r, "spawn"), "Ok", "{r}");
    assert_eq!(report_field(&r, "in_inner"), "0", "{r}");
}

#[test]
fn cosca_breaks_a_child_away_via_the_raw_backend() {
    let r = breakaway_report("permit", "exec");
    assert_eq!(report_field(&r, "limits"), "breakaway-ok", "wrong job shape: {r}");
    assert_eq!(report_field(&r, "spawn"), "Ok", "{r}");
    assert_eq!(report_field(&r, "in_inner"), "0", "{r}");
}

/// The raw vehicle gets `Io-5` for this shape (`a_forbidding_job_denies_the_raw_flag`); cosca
/// turns the same refusal into a typed error naming the job's limit and the remedy.
#[test]
fn a_forbidding_job_yields_a_typed_containment_error_via_the_std_backend() {
    let r = breakaway_report("forbid", "argv");
    assert_eq!(report_field(&r, "limits"), "none", "wrong job shape: {r}");
    assert_eq!(report_field(&r, "spawn"), "Containment", "{r}");
}

#[test]
fn a_forbidding_job_yields_a_typed_containment_error_via_the_raw_backend() {
    let r = breakaway_report("forbid", "exec");
    assert_eq!(report_field(&r, "limits"), "none", "wrong job shape: {r}");
    assert_eq!(report_field(&r, "spawn"), "Containment", "{r}");
}
