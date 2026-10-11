//! The harness's own cleanup checks: they must tell "gone" from "could not tell", and pick a profile by SID.

use crate::harness::{profile_removal_script, require_gate, task_lookup_outcome, ScheduledTask};
use crate::test_groups::{elevation_routes, Group};
use windows::core::HRESULT;

fn failure(code: u32) -> windows::core::Result<()> {
    Err(windows::core::Error::from(HRESULT(code as i32)))
}

/// Only `ERROR_FILE_NOT_FOUND` means the task is gone. Mutant: any failure counts as "gone".
#[skuld::test]
fn a_task_lookup_is_gone_only_for_file_not_found() {
    assert_eq!(task_lookup_outcome("t", Ok(())), Ok(true));
    assert_eq!(task_lookup_outcome("t", failure(0x8007_0002)), Ok(false));
    for other in [0x8007_0005_u32, 0x8007_0003, 0x8000_4005] {
        let outcome = task_lookup_outcome("t", failure(other));
        assert!(outcome.is_err(), "{other:#x} was taken for an answer: {outcome:?}");
    }
}

/// The real Task Scheduler says "no such task" for a name nothing registered. Mutant: the query fails.
#[skuld::test]
fn the_task_scheduler_reports_an_unregistered_task_as_gone() {
    let task = ScheduledTask::new(format!("cosca-never-registered-{}", std::process::id()));
    assert_eq!(task.is_registered(), Ok(false));
}

/// A task `schtasks` registered is seen as registered, and as gone once deleted. Mutant: `is_registered` is
/// always `Ok(false)`.
#[skuld::test]
fn the_task_scheduler_sees_a_registered_task(#[fixture(elevation_routes)] _group: &Group) {
    require_gate("COSCA_PROBE_ALLOW_STATE", "registers and deletes a scheduled task");
    let mut task = ScheduledTask::new(format!("cosca-probe-seen-{}", std::process::id()));
    let created = crate::common::output_locked(std::process::Command::new("schtasks").args([
        "/create",
        "/tn",
        &task.name,
        "/tr",
        "cmd.exe /c exit 0",
        "/sc",
        "ONCE",
        "/st",
        "23:59",
        "/f",
    ]))
    .expect("run schtasks /create");
    assert!(created.status.success(), "schtasks /create failed: {created:?}");
    assert_eq!(task.is_registered(), Ok(true));
    task.delete();
    assert_eq!(task.is_registered(), Ok(false));
}

/// The profile is picked by the account's SID. Mutant: by its path.
#[skuld::test]
fn the_profile_is_removed_by_the_accounts_sid() {
    let script = profile_removal_script("coscaprobestd");
    assert!(
        script.contains("SecurityIdentifier") && script.contains("$_.SID -eq $sid"),
        "{script}"
    );
    assert!(!script.contains("LocalPath"), "{script}");
}
