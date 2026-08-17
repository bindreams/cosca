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

// The invariant under test: only an AUTHORITATIVE drain-observable mechanism (cgroup v2, Windows
// job object — kernel-owned membership a live process cannot leave without exiting) may skip
// the hard sweep when a tree drains on its own within `grace`. macOS's fd marker IS
// drain-observable (`can_observe_drain()` is true) but its EOF is advisory — see `TreeDrain`'s
// own doc — so it must land in the same "sweep always runs" bucket as a mechanism with no drain
// edge at all, not the "skip the sweep" bucket. Proven by forcing `kill_tree` to fail: the call
// only comes back `Ok` if that branch was never entered. Both arms are real, exercised
// assertions on every platform, not a skip.
//
// Both arms block on a readiness edge from the child's own code before signalling. Without it
// the child has not registered with the console (Windows) or installed its disposition (Unix)
// when the signal arrives, and what the test measures is an abrupt death during startup rather
// than the cooperative path it is named for.
#[test]
fn graceful_tree_drained_skips_sweep_only_when_the_mechanism_is_authoritative() {
    use std::io::Read;

    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    {
        // `exec` keeps the signalled root process `sleep` itself, so the SIGTERM assertion below
        // still means what it means. It dies to the default disposition well within grace.
        cmd.args(["sh", "-c", "echo r; exec sleep 30"]);
        cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    }
    #[cfg(windows)]
    let (listener, addr) = crate::test_child::registration_rendezvous();
    #[cfg(windows)]
    {
        cmd.executable(std::env::current_exe().expect("current_exe"))
            .args(["--exact", crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_TEST]);
        cmd.env(crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, addr);
    }
    cmd.contain();
    #[allow(unused_mut)]
    let mut child = cmd.spawn().expect("spawn");
    #[cfg(unix)]
    {
        let mut readiness = [0u8; 1];
        child
            .stdout()
            .expect("piped stdout")
            .read_exact(&mut readiness)
            .expect("readiness byte");
    }
    #[cfg(windows)]
    let _sock = {
        let (mut sock, _) = listener.accept().expect("accept rendezvous connection");
        let mut tag = [0u8; 1];
        sock.read_exact(&mut tag).expect("registration tag");
        sock
    };
    let authoritative = matches!(
        child.containment(),
        crate::containment::Containment::CgroupV2 | crate::containment::Containment::JobObject
    );
    let armed = term_fault::ArmedKillTreeError::arm();
    let result = child.graceful_shutdown_tree(Duration::from_secs(30));
    if authoritative {
        let status = result.expect("an authoritatively-drained tree must not invoke the sweep at all");
        assert!(
            term_fault::kill_tree_armed(),
            "the forced kill_tree failure must still be armed — the sweep was never entered"
        );
        drop(armed); // disarm now that this branch's own assertion above has run
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
        assert_eq!(
            status.code(),
            Some(0xC000013A_u32 as i32),
            "the root must die to the console event, not to a loader-init kill or the sweep, got {status:?}"
        );
    } else {
        // Either the marker is advisory (macOS, drain-observable but not authoritative) or
        // there is no kernel drain edge at all: either way the sweep is unconditional by design
        // (see graceful_shutdown_tree's own doc), so the forced failure must surface — proving
        // the sweep WAS entered, the opposite of the branch above.
        let err = result.expect_err("a non-authoritative mechanism must always run the sweep");
        assert!(
            !term_fault::kill_tree_armed(),
            "the sweep must have consumed the forced-failure seam"
        );
        drop(armed); // already disarmed by the sweep above; this is a no-op, kept for symmetry
        assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
        let _ = child.kill_tree(); // cleanup: the forced failure means the real sweep never ran
        let _ = child.wait();
    }
}

// Regression test: on the `MembersRemain` branch — a drain-observable
// mechanism whose tree does NOT fully drain within `grace` — `root_exited` must be freshly
// computed by its own zero-duration probe of the root, not hardcoded `false`. Otherwise an
// already-exited-but-unreaped root is stranded as a zombie when the subsequent hard sweep
// also fails, because the best-effort reap below is gated on `root_exited`.
//
// Fixture: the root shell installs `trap '' TERM`, backgrounds `sleep 30` (which vastly
// outlives `grace`, keeping the tree from fully draining and forcing `MembersRemain`
// specifically), writes a single readiness byte, then exits on its own. The test blocks on
// that byte before ever calling `graceful_shutdown_tree` — a genuine happens-before edge from a
// real pipe event, not a sleep or a bet that the runner is fast: the root's own `trap`
// installation has nothing else synchronizing it against `spawn()` returning, and the byte
// cannot be written until both the trap and the background job are already in place.
// On a mechanism with no kernel drain edge, this same fixture still exercises the pre-existing
// root-only watch, which already computes `root_exited` correctly — asserted separately below
// rather than skipped, per this crate's "never silently skip" testing convention.
#[cfg(unix)]
#[test]
fn graceful_tree_members_remain_still_reaps_an_already_exited_root() {
    use std::io::Read;

    let mut cmd = crate::Command::new();
    cmd.args(["sh", "-c", "trap '' TERM; sleep 30 & echo r; exit 0"]);
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .expect("readiness byte");
    let id = child.id();
    let drainable = child.containment().can_observe_drain();
    term_fault::set_force_kill_tree_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(2))
        .expect_err("the forced sweep failure must surface");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    assert!(
        !term_fault::kill_tree_armed(),
        "the sweep must have consumed the forced-failure seam"
    );
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "an already-exited root must be best-effort reaped even when the sweep fails ({})",
        if drainable {
            "MembersRemain branch"
        } else {
            "non-drain-observable fallback branch — pre-existing, unaffected behavior"
        }
    );
    // Cleanup: the forced sweep failure was a stub, so the SIGTERM-ignoring descendant is
    // still alive — a real sweep now (the seam is already consumed) actually kills it.
    let _ = child.kill_tree();
}

// Windows twin of `graceful_tree_members_remain_still_reaps_an_already_exited_root` above,
// reached via a job object instead of cgroup/process-group — but NOT a check on the same
// postcondition, because that postcondition does not translate. The Unix test proves an
// already-exited root is best-effort REAPED (`waitpid`-collected) even when the sweep also
// fails, so it never strands a zombie. Windows has no reap concept to strand: per the
// `shared_child` crate's own comment on its Windows backend, "there's no such thing as reaping
// child processes on Windows — instead, you close the child handle when you're done with it,
// like a file", and `Child::wait()` never closes that handle on any Windows backend (raw or
// std) — only `Child`'s own `Drop` does. A Windows process object stays resolvable exactly as
// long as ANY handle referencing it is open, including this very `Child`'s own handle, held for
// this whole test — so `id.exists()` reports `Present` here whether or not the best-effort
// `self.wait()` call inside `graceful_shutdown_tree` ran, on both the fixed code and the bug it
// was meant to catch. There is no Windows-observable difference to assert here; asserting `Gone`
// would be tautologically false regardless of correctness (as CI's `left: Present, right: Gone`
// failure demonstrated) rather than evidence of anything. What IS Windows-observable, and
// exercised below, is that a drain-observable-but-not-fully-drained mechanism (`MembersRemain`)
// still runs the hard sweep and surfaces its failure — the same control flow this branch is
// otherwise built to protect.
//
// Fixture: `test_child::fixture_survives_group_signal` (see its own doc) plays the Unix root
// shell's role — it spawns a `CREATE_NEW_PROCESS_GROUP` grandchild the group `CTRL_BREAK` can
// never reach (forcing `MembersRemain` on the drain-observable job object, exactly like the Unix
// fixture's backgrounded, TERM-immune `sleep`), THEN connects back and tags over the TCP
// listener below, proving the grandchild already exists in its own group before this test
// proceeds — the same happens-before edge the Unix fixture's readiness-byte read supplies, over
// the same control-channel shape `tests/common::spawn_tree` uses (a stdout byte would not work
// here: libtest captures a passing test's own `print!` output and discards it, so it would never
// reach a piped reader — see the fixture's own doc).
#[cfg(windows)]
#[test]
fn windows_graceful_tree_members_remain_surfaces_the_forced_sweep_failure() {
    use std::io::Read;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();

    let mut cmd = crate::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(["--exact", crate::test_child::FIXTURE_SURVIVES_GROUP_SIGNAL_TEST]);
    cmd.env(crate::test_child::FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV, addr);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    // Blocks until the fixture has connected — which it does only after the grandchild survivor
    // already exists in its own process group (see the fixture's own doc).
    let (mut sock, _) = listener.accept().expect("accept readiness connection");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("readiness tag");
    term_fault::set_force_kill_tree_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(2))
        .expect_err("the forced sweep failure must surface");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    assert!(
        !term_fault::kill_tree_armed(),
        "the sweep must have consumed the forced-failure seam"
    );
    // Cleanup: the forced sweep failure was a stub, so the group-signal-immune descendant is
    // still alive — a real sweep now (the seam is already consumed) actually kills it.
    let _ = child.kill_tree();
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
