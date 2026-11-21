//! A tree walk over a failed macOS process listing errors and signals nothing. macOS only: the
//! failures are `FakeKernel` rows.

use crate::error::Error;
use crate::identity::{FakeKernel, HostKernel, ProcessId};
use crate::test_child::{live_exiting_member as live_member, release_unsignalled as release};

use super::treewalk_walks_tests::{children_queries, walks};

fn assert_unassessable_naming(result: Result<(), Error>, cause: &str) {
    match result {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(detail.contains(cause), "the error must name {cause:?}: {detail}")
        }
        other => panic!("expected Unassessable naming {cause:?}, got {other:?}"),
    }
}

/// Mutants: "the walk reads an empty snapshot for a failed listing" (`Ok`, nothing found); "signal
/// the root, then return the error"; "the walk lists through the host's kernel" (the row is left).
#[skuld::test]
fn every_walk_over_a_failed_listing_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        let (child, id) = live_member();
        let kernel = FakeKernel::over(&HostKernel).on_pids(Err(libc::EIO));
        let result = walk(&kernel, id);
        assert!(
            matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains("proc_listallpids")),
            "{name}: {result:?}"
        );
        assert!(kernel.all_rows_taken(), "{name}: the failed listing was not read");
        release(child);
    }
}

/// The walker's cooperative signal over a failed listing sent nothing: `NotSent`, with the listing's
/// error, so `graceful_shutdown_tree` ends the call. Mutant: the failure is a `Sent { result: Err(..) }`.
#[skuld::test]
fn a_walkers_terminate_over_a_failed_listing_says_nothing_was_sent() {
    let (child, id) = live_member();
    let kernel = FakeKernel::over(&HostKernel).on_pids(Err(libc::EIO));
    let (outcome, _) = super::terminate_tree(&kernel, id, None, crate::containment::TreeStop::default());
    match outcome {
        crate::containment::TerminateOutcome::NotSent(Error::Unassessable { detail, .. })
            if detail.contains("proc_listallpids") => {}
        other => panic!("expected NotSent(Unassessable), got {other:?}"),
    }
    release(child);
}

/// Mutant: "`children` maps the snapshot's error to `Ok(vec![])`".
#[skuld::test]
fn children_over_a_failed_listing_are_unassessable() {
    let me = ProcessId::current();
    for (name, query) in children_queries() {
        let result = query(&me, &FakeKernel::over(&HostKernel).on_pids(Err(libc::EIO)));
        assert!(
            matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains("proc_listallpids")),
            "{name}: {result:?}"
        );
    }
}

/// A pid denied its ppid read leaves its subtree out of any walk, so the snapshot is
/// `Unassessable` naming the count and the pid, and no walk signals. Mutant: "`denied > 0` still
/// returns `Ok`".
#[skuld::test]
fn every_walk_over_a_snapshot_with_a_denied_ppid_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        let (child, id) = live_member();
        let kernel = FakeKernel::over(&HostKernel).on_record_refused(id.pid());
        let result = walk(&kernel, id);
        assert!(
            matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains(&format!("sample: [{}]", id.pid()))),
            "{name}: {result:?}"
        );
        release(child);
    }
}

/// Mutant: "`children` ignores a denied ppid elsewhere in the table".
#[skuld::test]
fn children_over_a_snapshot_with_a_denied_ppid_are_unassessable() {
    let (child, id) = live_member();
    let me = ProcessId::current();
    for (_, query) in children_queries() {
        let result = query(&me, &FakeKernel::over(&HostKernel).on_record_refused(id.pid()));
        assert_unassessable_naming(result, &format!("sample: [{}]", id.pid()));
    }
    release(child);
}

/// A root that no longer holds its pid has no descendants: its pid's new owner's children are not
/// its own, and are never signalled. `terminate` sends nothing (`RootExited`); `hard_kill` killed
/// nothing, and is `Unassessable`. Mutants: "walk without an anchor"; "a kill that found no root is `Ok`". A stale
/// identity cannot be opened, so only the identity-level walks run.
#[skuld::test]
fn every_walk_from_a_root_that_lost_its_pid_signals_nothing_and_a_kill_is_unassessable() {
    let me = ProcessId::current();
    let stale = me.with_other_value();

    let (child, _) = live_member();
    let kernel = crate::identity::HostKernel;
    let result = super::hard_kill(&kernel, stale, &super::ByIdentity::new(&kernel, stale))
        .outcome()
        .into_result()
        .map_err(crate::containment::dispatch::Unkilled::into_error);
    assert_unassessable_naming(result, "no walk ran");
    release(child);

    let (child, _) = live_member();
    let result = super::terminate(
        &kernel,
        stale,
        &super::ByIdentity::new(&kernel, stale),
        crate::containment::TreeStop::default(),
    );
    assert!(
        matches!(result, (super::SendAnswer::RootExited(_), None)),
        "terminate sends nothing: {result:?}"
    );
    release(child);
}
