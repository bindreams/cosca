//! What the end of an `OwnedChild` asks of the OS: the consume of the exit record, over a
//! `FakeProcess` that states what each consume answers and whether it names the child exactly.

use std::process::ExitStatus;

use super::fixtures::status;
use crate::child::owned::OwnedChild;
use crate::os_process::child::{ExitRecord, Foreign};
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::wait::exit_only::Reap;

fn exit() -> ExitRecord {
    ExitRecord::Status(ExitStatus::default())
}

/// A child that was never waited on asks to consume at its end where its consume names it exactly.
///
/// Mutant: the drop consumes only after a wait.
#[skuld::test]
fn a_handle_never_waited_on_consumes_at_its_end_where_the_consume_is_exact() {
    let fake = FakeProcess::new([]).with_exact_consume(true);
    drop(OwnedChild::new(Box::new(fake.clone())));
    assert_eq!(fake.reap_calls(), 1);
}

/// Where the consume is by the child's number (macOS), a handle whose wait never saw the exit
/// consumes nothing: a by-number consume is a check, not a pin, and it could take another process's
/// record.
///
/// Mutant: the drop consumes in every state on every platform.
#[skuld::test]
fn a_handle_never_waited_on_consumes_nothing_where_the_consume_is_by_number() {
    let fake = FakeProcess::new([]).with_exact_consume(false);
    drop(OwnedChild::new(Box::new(fake.clone())));
    assert_eq!(fake.reap_calls(), 0);
}

/// A handle whose wait saw the exit consumes it at its end whichever way the consume names the
/// child: it is the consume a wait made before the end of the handle took it over.
///
/// Mutant: the drop skips the consume for a by-number child whatever the state.
#[skuld::test]
fn a_handle_whose_wait_saw_the_exit_consumes_it_at_its_end_either_way() {
    for exact in [true, false] {
        let fake = FakeProcess::new([])
            .reaps([ReapAnswer::Exited(exit())])
            .with_exact_consume(exact);
        let child = OwnedChild::new(Box::new(fake.clone()));
        status(child.wait(None));
        assert_eq!(fake.reap_calls(), 0, "a wait consumed (exact: {exact})");
        drop(child);
        assert_eq!(fake.reap_calls(), 1, "the end did not consume (exact: {exact})");
    }
}

/// A handle whose wait found the child gone, or only running, never saw an exit: where the consume
/// is by number, the end consumes nothing.
///
/// Mutant: any wait that ran counts as seeing the exit.
#[skuld::test]
fn a_wait_that_saw_no_exit_leaves_a_by_number_consume_unasked() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Foreign(Foreign::Gone)])
        .with_exact_consume(false);
    let child = OwnedChild::new(Box::new(fake.clone()));
    assert!(matches!(
        child.wait(None),
        Ok(crate::child::owned::ChildWaitOutcome::Foreign(Foreign::Gone))
    ));
    drop(child);
    assert_eq!(fake.reap_calls(), 0);
}

/// What a consume's answer is logged as at the end of the handle, and that none of them panics:
/// a taken record says nothing, a zombie only a tracer holds says nothing, a child someone else
/// reaped is a `debug`, and a consume that failed is a `warn` that says a zombie may be left.
///
/// Mutant: any answer is dropped silently, or is logged above its level.
#[skuld::test]
fn the_end_of_the_handle_logs_what_its_consume_found() {
    crate::log_capture::install();
    type Row = (Result<Reap, std::io::Error>, Option<(log::Level, &'static str)>);
    let rows: [Row; 5] = [
        (Ok(Reap::Reaped(exit())), None),
        (Ok(Reap::Running), None),
        (
            Ok(Reap::Foreign(Foreign::Gone)),
            Some((log::Level::Debug, "nothing left to reap")),
        ),
        (
            Ok(Reap::Foreign(Foreign::Orphaned)),
            Some((log::Level::Debug, "nothing left to reap")),
        ),
        (
            Err(std::io::Error::other("forced consume failure")),
            Some((log::Level::Warn, "a zombie may be left")),
        ),
    ];
    for (answer, logged) in rows {
        let fake = FakeProcess::new([]).consumes([answer]);
        let child = OwnedChild::new(Box::new(fake.clone()));
        let mark = crate::log_capture::mark();
        drop(child);
        let records = crate::log_capture::records_since_on_current_thread(mark, "");
        match logged {
            None => assert_eq!(records, [], "a quiet answer logged"),
            Some((level, text)) => {
                let [(seen, said)] = &records[..] else {
                    panic!("one record expected: {records:?}");
                };
                assert_eq!(*seen, level, "{said}");
                assert!(said.contains(text), "{said}");
            }
        }
    }
}

/// A consume that hands back a record that is not an exit is a contract breach: the drop warns,
/// and asserts in a debug build, except while the thread unwinds, where an assert would abort.
///
/// Mutant: the warn is lost, or the assert fires mid-unwind.
#[skuld::test]
fn an_unreadable_record_at_the_end_of_the_handle_warns_and_asserts_but_never_mid_unwind() {
    crate::log_capture::install();
    let unreadable = ExitRecord::Unreadable { si_code: 99 };
    let child = || OwnedChild::new(Box::new(FakeProcess::new([]).consumes([Ok(Reap::Reaped(unreadable))])));

    let mark = crate::log_capture::mark();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _child = child();
        panic!("a test unwinding past its child");
    }));
    assert!(unwound.is_err());
    let warns = crate::log_capture::warns_since(mark, "not an exit record");
    assert_eq!(warns.len(), 1, "{warns:?}");

    let mark = crate::log_capture::mark();
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(child())));
    assert_eq!(
        dropped.is_err(),
        cfg!(debug_assertions),
        "a debug build asserts the contract; a release build returns"
    );
    let warns = crate::log_capture::warns_since(mark, "not an exit record");
    assert_eq!(warns.len(), 1, "{warns:?}");
}
