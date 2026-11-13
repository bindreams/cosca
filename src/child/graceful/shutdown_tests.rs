//! `run_ready`, the sync driver's one poll, and `graceful_status_of_reap`, the one answer of both cores for the reap.

use super::run_ready;
use crate::child::owned::ChildWaitOutcome;

/// Mutant: a future that is ready is polled again or its value dropped.
#[skuld::test]
fn a_ready_future_gives_its_output_through_every_await() {
    async fn ready(n: u32) -> u32 {
        n
    }
    assert_eq!(run_ready(async { ready(1).await + ready(2).await }), 3);
}

/// Mutant: a pending future is waited for instead of refused.
#[skuld::test]
#[should_panic(expected = "run_ready: the future is pending, but a blocking driver's waits are all ready")]
fn a_pending_future_is_a_broken_contract() {
    run_ready(std::future::pending::<()>());
}

/// A root reaped elsewhere, or whose pid names another process now, leaves no exit status: the answer is
/// `Unassessable` naming the call, with the `ECHILD` every wait answers as its `source()`, so a caller can
/// tell it from any other refusal. The same for both calls.
///
/// Mutant: the foreign verdict is folded into an `Io`, or its `ECHILD` is dropped.
#[cfg(unix)]
#[skuld::test]
fn a_root_reaped_elsewhere_answers_unassessable_with_its_echild_as_the_source() {
    use crate::error::Error;
    use crate::os_process::child::Foreign;

    for foreign in [Foreign::Gone, Foreign::Other] {
        for op in ["graceful_shutdown", "graceful_shutdown_tree"] {
            let answer = super::graceful_status_of_reap(4242, op, Ok(ChildWaitOutcome::Foreign(foreign)))
                .expect_err("no exit status was collected");

            let Error::Unassessable { detail, .. } = &answer else {
                panic!("{answer:?}");
            };
            assert!(
                detail.starts_with(&format!("pid 4242: {op} sent its signals")),
                "{detail}"
            );
            assert!(
                detail.ends_with("exit status cannot be collected: the root was reaped elsewhere"),
                "{detail}"
            );
            assert_eq!(crate::error::first_os_code(&answer), Some(libc::ECHILD), "{answer:?}");
        }
    }
}

/// A reap that failed is the answer as it is, even with an `ECHILD` in it: only the reap's own foreign
/// verdict says the root was reaped elsewhere.
///
/// Mutant: any `ECHILD` below the failure counts.
#[cfg(unix)]
#[skuld::test]
fn a_failed_reap_stays_the_answer_whatever_it_holds() {
    use crate::error::Error;

    let failed = Error::Io(std::io::Error::from_raw_os_error(libc::ECHILD));
    let words = failed.to_string();

    let answer = super::graceful_status_of_reap(4242, "graceful_shutdown", Err(failed)).expect_err("the reap failed");

    assert!(matches!(answer, Error::Io(_)), "{answer:?}");
    assert_eq!(answer.to_string(), words);
}

/// An exit record is the status, and an unreadable one is the `InvalidData` every wait answers.
///
/// Mutant: an unreadable record is answered as a status or as a foreign reap.
#[skuld::test]
fn an_exit_record_is_the_status_and_an_unreadable_one_invalid_data() {
    use crate::error::Error;
    use crate::os_process::child::ExitRecord;

    let status = std::process::ExitStatus::default();
    let answered = super::graceful_status_of_reap(
        4242,
        "graceful_shutdown",
        Ok(ChildWaitOutcome::Exited(ExitRecord::Status(status))),
    );
    assert_eq!(answered.expect("an exit"), status);

    let answer = super::graceful_status_of_reap(
        4242,
        "graceful_shutdown",
        Ok(ChildWaitOutcome::Exited(ExitRecord::Unreadable { si_code: 7 })),
    )
    .expect_err("an unreadable record");
    assert!(
        matches!(&answer, Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidData),
        "{answer:?}"
    );
}

/// A zombie launchd holds has no status to collect: the macOS refusal, for both calls, with no source
/// and no warn.
///
/// Mutant: it is answered as a root reaped elsewhere.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_zombie_launchd_holds_answers_the_unpinned_refusal_quietly() {
    use crate::error::Error;
    use crate::os_process::child::Foreign;

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    for op in ["graceful_shutdown", "graceful_shutdown_tree"] {
        let answer = super::graceful_status_of_reap(4242, op, Ok(ChildWaitOutcome::Foreign(Foreign::Orphaned)))
            .expect_err("no exit status");

        let Error::Unassessable { detail, source: None } = &answer else {
            panic!("{answer:?}");
        };
        assert!(
            detail.starts_with(&format!("pid 4242: {op} sent its signals")),
            "{detail}"
        );
        assert!(detail.contains("launchd"), "{detail}");
    }
    assert_eq!(crate::log_capture::warns_since(mark, ""), Vec::<String>::new());
}
