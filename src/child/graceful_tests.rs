//! Unit tests for the graceful trio's watch-failure ordering (the fault seam is pub(crate),
//! unreachable from tests/).

use std::time::Duration;

use super::fault as term_fault;
use crate::wait::fault;

// A watch failure must not strand the tree between the soft signal and the hard sweep: the
// sweep and reap still run, then the watch error surfaces. The reap is proven by identity on
// all Unix — procfs and `sysctl KERN_PROC` are both zombie-inclusive, so a swept-but-unreaped
// root would still be exists()-visible. (Windows runs the same body but skips that assert:
// exists() stays true there while `child` still holds the process handle.)
#[test]
fn graceful_tree_watch_error_still_sweeps_and_reaps() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect_err("the watch error must surface");
    assert!(
        crate::log_capture::contains_since(mark, &format!("graceful_shutdown_tree({pid})", pid = id.pid())),
        "the subsumption trace must fire on the forced watch error"
    );
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the watch error (a zombie would still exist)"
    );
    #[cfg(windows)]
    let _ = id;
    let status = child.wait().expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

// The LONE-path twin of the same invariant (Unix-gated: graceful_shutdown is Unsupported on
// Windows before the watch runs). With the old `wait_timeout(grace)?` shape the child would
// die by our SIGTERM but stay a zombie — `exists()` catches exactly that on all Unix
// (procfs / `sysctl KERN_PROC` are both zombie-inclusive).
#[cfg(unix)]
#[test]
fn graceful_lone_watch_error_still_escalates_and_reaps() {
    let mut cmd = crate::Command::new();
    cmd.args(["sleep", "30"]);
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
        .expect_err("the watch error must surface");
    assert!(
        crate::log_capture::contains_since(mark, &format!("graceful_shutdown({pid})", pid = id.pid())),
        "the subsumption trace must fire on the forced watch error"
    );
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "child must be killed AND reaped despite the watch error (a zombie would still exist)"
    );
    let status = child.wait().expect("cached status — already reaped by the graceful op");
    assert!(
        !status.success(),
        "escalated child cannot report success, got {status:?}"
    );
}

// A term_group refusal must not strand the tree between the soft signal and the hard sweep:
// the sweep and reap still run, then the refusal surfaces. Mirrors
// `graceful_tree_watch_error_still_sweeps_and_reaps` above, for the terminate seam instead
// of the watch seam. Uses `Duration::ZERO`, not a nonzero grace: the watch-error test's
// `from_secs(30)` was safe there because that seam fires BEFORE the watch ever runs, so the
// grace is never actually waited. This seam replaces `terminate_tree` itself, so with a
// nonzero grace the watch WOULD really block for the full window — racing the "sleep 30"
// fixture's own natural exit and violating the no-timed-synchronization rule. `ZERO` is
// documented (`graceful_shutdown`'s own rustdoc) as "signals, polls once, then escalates",
// which is exactly the ordering this test needs and nothing more.
#[test]
fn graceful_tree_terminate_refusal_still_sweeps_and_reaps() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::Containment);
    // A successful sweep is fresher, positive proof the group cleared, superseding the held
    // refusal — the call must report `Ok`, not resurface the disproved `Containment` error.
    let status = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect("a successful sweep must supersede the forced terminate refusal");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
    // Matches the TERMINATE trace specifically, not the pre-existing watch-error trace (both
    // share the same "graceful_shutdown_tree({pid})" prefix, so a bare prefix match would
    // pass even if the wrong log line fired). No `armed()` check here: `take_force_terminate`
    // runs unconditionally at the very top of `graceful_shutdown_tree`, so by the time any
    // assertion after calling it runs, the seam is ALWAYS already consumed — asserting that
    // would be tautologically true and catch nothing.
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!("graceful_shutdown_tree({pid}): terminate_tree refused", pid = id.pid())
        ),
        "the terminate-refusal trace specifically must fire"
    );
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!(
                "graceful_shutdown_tree({pid}): tree confirmed clear; discarding the superseded terminate_tree refusal",
                pid = id.pid()
            )
        ),
        "the refusal must be logged as discarded, not silently dropped"
    );
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the forced terminate refusal"
    );
    #[cfg(windows)]
    let _ = id;
}

// Same hold-and-continue contract as the `Containment` test above, but for the OTHER
// ordinary #61 outcome: `Error::Unassessable { source: None, .. }` (group::decide's
// per-member-unconfirmed shape). Mirrors the test above almost exactly; kept as a fully
// separate test (not parameterized) matching this file's existing convention of one test
// per forced-error shape.
#[test]
fn graceful_tree_unassessable_per_member_still_sweeps_and_reaps() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::UnassessablePerMember);
    // Same supersession as the `Containment` test above: the sweep's success disproves the
    // held per-member-unconfirmed state, so the call must report `Ok`.
    let status = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect("a successful sweep must supersede the forced unassessable state");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!("graceful_shutdown_tree({pid}): terminate_tree refused", pid = id.pid())
        ),
        "the terminate-refusal trace specifically must fire"
    );
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!(
                "graceful_shutdown_tree({pid}): tree confirmed clear; discarding the superseded terminate_tree refusal",
                pid = id.pid()
            )
        ),
        "the refusal must be logged as discarded, not silently dropped"
    );
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the forced unassessable state"
    );
    #[cfg(windows)]
    let _ = id;
}

// `Error::Unassessable { source: Some(_), .. }` — group::state's OWN listing failed, no
// signal was ever attempted — must fail fast, the SAME disposition
// `crate::child::is_teardown_mechanism_failure` gives the identical error shape reaching
// `Child::drop`. Regression test: folding this shape into the same hold-and-continue arm as
// the ordinary per-member case would silently disagree with the classifier for the same
// underlying error.
#[test]
fn graceful_tree_unassessable_mechanism_failure_fails_fast() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    term_fault::set_force_terminate(term_fault::Forced::UnassessableMechanism);
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("the forced listing-mechanism failure must surface immediately");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: Some(_), .. }),
        "got {err:?}"
    );
    // Fails fast: no grace was waited, no sweep ran, so the child is STILL ALIVE — same
    // assertion shape as the pre-existing NoConsole/Unsupported fail-fast test below.
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "a listing-mechanism failure must return before any grace wait or sweep"
    );
    // Clean up: the child is still running by design (no sweep happened above).
    let _ = child.kill_tree();
    let _ = child.wait();
}

// The core #62 property: on a drain-observable mechanism, a tree that drains on its own within
// `grace` must skip the hard sweep entirely — not merely run a sweep that no-ops on an empty
// group. Proven by forcing `kill_tree` to fail: the call only comes back `Ok` if that branch
// was never entered. On a mechanism with no kernel drain edge (no `ProcessGroup`/`Session`
// fallback host in CI, but asserted either way rather than assumed), the sweep stays
// unconditional by design, so the forced failure must surface instead — both arms are real,
// exercised assertions, not a skip.
#[test]
fn graceful_tree_drained_skips_sweep_when_mechanism_allows() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]); // dies to the default-disposition SIGTERM well within grace
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let drainable = child.containment().can_observe_drain();
    term_fault::set_force_kill_tree_error(true);
    let result = child.graceful_shutdown_tree(Duration::from_secs(30));
    if drainable {
        let status = result.expect("a fully-drained tree must not invoke the sweep at all");
        assert!(
            term_fault::kill_tree_armed(),
            "the forced kill_tree failure must still be armed — the sweep was never entered"
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(libc::SIGTERM),
                "graceful root exit, got {status:?}"
            );
        }
        #[cfg(windows)]
        let _ = status;
    } else {
        // No kernel drain edge on this mechanism: the sweep is unconditional by design (see
        // graceful_shutdown_tree's own doc), so the forced failure must surface — proving the
        // sweep WAS entered, the opposite of the branch above.
        let err = result.expect_err("a non-drainable mechanism must always run the sweep");
        assert!(
            !term_fault::kill_tree_armed(),
            "the sweep must have consumed the forced-failure seam"
        );
        assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
        let _ = child.kill_tree(); // cleanup: the forced failure means the real sweep never ran
        let _ = child.wait();
    }
}

// A NON-containment terminate_tree error (modelling NoConsole/Unsupported) must NOT be held
// -- this is the pre-existing, still-documented "no signal sent, no grace waited, tree left
// running" contract from #46, unrelated to #61, and this task's scoping must not silently
// rewrite it (see this task's "Scope correction" note above). `Duration::ZERO` here too: the
// point is that the function returns before ever reaching the watch, at all, regardless of
// the requested grace, so there is nothing to synchronize on.
#[test]
fn graceful_tree_non_containment_terminate_error_fails_fast() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    term_fault::set_force_terminate(term_fault::Forced::Unsupported);
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("the forced Unsupported error must surface immediately");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    // Fails fast: no grace was waited, no sweep ran, so the child is STILL ALIVE.
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "a non-containment terminate error must return before any grace wait or sweep"
    );
    // Clean up: the child is still running by design (no sweep happened above).
    let _ = child.kill_tree();
    let _ = child.wait();
}
