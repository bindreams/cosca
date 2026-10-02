//! Unit tests for the graceful trio's watch-failure ordering (the fault seam is pub(crate),
//! unreachable from tests/).

use std::time::Duration;

use super::fault as term_fault;
use crate::wait::fault;

/// A contained [`crate::test_child::BLOCKER_ARGV`] child with piped stdin and stdout, plus its
/// stdin writer, which the caller must keep for exactly as long as the child must stay running.
/// `Existence::Present` is not proof of life — it is zombie-inclusive on every platform — so a
/// liveness claim goes through [`assert_still_running`].
fn blocker() -> (crate::Child, std::io::PipeWriter) {
    crate::test_child::held_contained_blocker(crate::Stdio::pipe())
}

/// A [`blocker`] for a test whose only end is a real kill: on Unix it ignores `SIGTERM`, on Windows
/// it is `more.com` (see [`crate::test_child::windows_more`]).
fn kill_only_blocker() -> (crate::Child, std::io::PipeWriter) {
    #[cfg(unix)]
    {
        crate::test_child::term_ignoring_blocker()
    }
    #[cfg(windows)]
    {
        crate::test_child::windows_blocker()
    }
}

/// Proves a [`blocker`] is genuinely still running, not merely resolvable. On Unix, round-trips
/// a byte through `cat`'s piped stdout over the stdin writer the caller holds; a killed-but-unreaped
/// `cat` cannot echo.
///
/// On Windows, `findstr` does not echo and `is_alive()` races the asynchronous `TerminateProcess`.
/// Instead, write a line containing `x`, close stdin, and require both a clean exit (`findstr`'s
/// "a match was found" code) and the echoed match on stdout; a killed process produces neither.
/// This consumes `stdin` and reaps the child.
fn assert_still_running(child: &mut crate::Child, mut stdin: std::io::PipeWriter) {
    #[cfg(unix)]
    {
        let mut stdout = child.stdout().expect("piped stdout");
        crate::test_child::assert_echoes(&mut stdin, &mut stdout);
    }
    #[cfg(windows)]
    {
        use std::io::{Read as _, Write as _};
        stdin.write_all(b"x\r\n").expect("write to the blocker");
        drop(stdin); // EOF: findstr can now finish reading and exit
        let mut output = Vec::new();
        child
            .stdout()
            .expect("piped stdout")
            .read_to_end(&mut output)
            .expect("read stdout to EOF");
        let status = child.wait().expect("the blocker must exit after stdin closes");
        assert!(
            status.success(),
            "the blocker must exit 0 (findstr's own 'a match was found' code), got {status:?}"
        );
        assert!(
            output.windows(1).any(|w| w == b"x"),
            "the blocker's stdout must contain the echoed match, got {output:?}"
        );
    }
}

/// Sweeps the tree and reaps the child. Windows discards errors: `assert_still_running` already
/// reaped the child there, so a second kill or wait has nothing to act on.
fn cleanup(child: &mut crate::Child) {
    #[cfg(unix)]
    {
        child.kill_tree().expect("cleanup sweep");
        child.wait().expect("reap");
    }
    #[cfg(windows)]
    {
        _ = child.kill_tree();
        _ = child.wait();
    }
}

// A watch failure must not strand the tree between the soft signal and the hard sweep: the
// sweep and reap still run, then the watch error surfaces. The reap is proven by identity on
// all Unix — procfs and `sysctl KERN_PROC` are both zombie-inclusive, so a swept-but-unreaped
// root would still be exists()-visible. (Windows runs the same body but skips that assert:
// exists() stays true there while `child` still holds the process handle.)
#[test]
fn graceful_tree_watch_error_still_sweeps_and_reaps() {
    let (child, stdin) = kill_only_blocker();
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    // Released between the sweep and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
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
    crate::test_child::assert_killed("the swept root", status);
}

// The LONE-path twin of the same invariant (Unix-gated: graceful_shutdown is Unsupported on
// Windows before the watch runs). With the old `wait_timeout(grace)?` shape the child would
// die by our SIGTERM but stay a zombie — `exists()` catches exactly that on all Unix
// (procfs / `sysctl KERN_PROC` are both zombie-inclusive).
#[cfg(unix)]
#[test]
fn graceful_lone_watch_error_still_escalates_and_reaps() {
    let (child, stdin) = kill_only_blocker();
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    // Released between the kill and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
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
    crate::test_child::assert_killed("the escalated child", status);
}

// A term_group refusal must not strand the tree between the soft signal and the hard sweep:
// the sweep and reap still run, then the refusal surfaces. Mirrors
// `graceful_tree_watch_error_still_sweeps_and_reaps` above, for the terminate seam instead
// of the watch seam. Uses `Duration::ZERO`, not a nonzero grace: the watch-error test's
// `from_secs(30)` was safe there because that seam fires BEFORE the watch ever runs, so the
// grace is never actually waited. This seam replaces `terminate_tree` itself, so with a
// nonzero grace the watch WOULD really block for the full window, synchronizing on time. `ZERO` is
// documented (`graceful_shutdown`'s own rustdoc) as "signals, polls once, then escalates",
// which is exactly the ordering this test needs and nothing more.
#[test]
fn graceful_tree_terminate_refusal_still_sweeps_and_reaps() {
    let (child, stdin) = kill_only_blocker();
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::Containment);
    // A successful sweep is fresher, positive proof the group cleared, superseding the held
    // refusal — the call must report `Ok`, not resurface the disproved `Containment` error.
    // Released between the sweep and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
    let status = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect("a successful sweep must supersede the forced terminate refusal");
    crate::test_child::assert_killed("the root", status);
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
    let (child, stdin) = kill_only_blocker();
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::UnassessablePerMember);
    // Same supersession as the `Containment` test above: the sweep's success disproves the
    // held per-member-unconfirmed state, so the call must report `Ok`.
    // Released between the sweep and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
    let status = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect("a successful sweep must supersede the forced unassessable state");
    crate::test_child::assert_killed("the root", status);
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
// `crate::containment::fdmarker::is_teardown_mechanism_failure` gives the identical error shape reaching
// `Child::drop`. Regression test: folding this shape into the same hold-and-continue arm as
// the ordinary per-member case would silently disagree with the classifier for the same
// underlying error.
#[test]
fn graceful_tree_unassessable_mechanism_failure_fails_fast() {
    let (mut child, stdin) = blocker();
    term_fault::set_force_terminate(term_fault::Forced::UnassessableMechanism);
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("the forced listing-mechanism failure must surface immediately");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: Some(_), .. }),
        "got {err:?}"
    );
    // Fails fast: no grace was waited, no sweep ran, so the child is STILL ALIVE.
    assert_still_running(&mut child, stdin);
    cleanup(&mut child);
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
        // `exec` keeps the signalled root `cat` itself, so the SIGTERM assertion still means what it
        // says; the `AfterTerminate` release (below) ends it on EOF if the SIGTERM never came.
        cmd.args(["sh", "-c", "echo r; exec cat"]);
        cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
        cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    }
    #[cfg(windows)]
    let (listener, addr) = crate::test_child::registration_rendezvous();
    #[cfg(windows)]
    {
        cmd.executable(std::env::current_exe().expect("current_exe"))
            .args(crate::test_child::fixture_argv(
                crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_TEST,
            ));
        cmd.env(crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, addr);
        crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
        cmd.env(crate::test_child::ack::ACK_ENV, "1");
    }
    cmd.contain();
    #[cfg_attr(
        windows,
        allow(
            unused_mut,
            reason = "on windows only .containment()/.graceful_shutdown_tree() are called below, both &self; unix's child.stdout() needs &mut"
        )
    )]
    let mut child = cmd.spawn().expect("spawn");
    #[cfg(unix)]
    let stdin = child.stdin().expect("piped stdin");
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
        let mut sock = crate::test_child::accept_or_die(&listener, child.id());
        let mut tag = [0u8; 1];
        sock.read_exact(&mut tag).expect("registration tag");
        sock
    };
    let authoritative = matches!(
        child.containment(),
        crate::containment::Containment::CgroupV2 | crate::containment::Containment::JobObject
    );
    let armed = term_fault::ArmedKillTreeError::arm();
    // Released once `terminate_tree` has returned, before any watch: SIGTERM is then already
    // pending on the root, so it beats the EOF this release causes.
    #[cfg(unix)]
    let _release = term_fault::release_at(term_fault::HookPoint::AfterTerminate, stdin);
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
        _ = child.kill_tree(); // cleanup: the forced failure means the real sweep never ran
        let status = child.wait().expect("the root was observed exited, so it is reaped");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(libc::SIGTERM),
                "the root must die to the SIGTERM, not exit on its own, got {status:?}"
            );
        }
        #[cfg(windows)]
        assert_eq!(
            status.code(),
            Some(0xC000013A_u32 as i32),
            "the root must die to the console event, not to the cleanup sweep, got {status:?}"
        );
    }
}

// Regression test: on the `MembersRemain` branch (a drain-observable mechanism whose tree does
// NOT fully drain within `grace`), `root_exited` must come from its own zero-duration probe of the
// root, not be hardcoded `false`. Otherwise an already-exited-but-unreaped root is stranded as a
// zombie when the hard sweep also fails, because the best-effort reap is gated on `root_exited`.
//
// Fixture: the root shell ignores TERM (`trap ''` survives `exec`) and backgrounds a `cat` blocked
// on a stdin this test holds open, so the tree cannot drain. It then writes a readiness byte (the
// trap and background job are in place) and waits for a line on fd 4 before `exit 0`. The gate
// keeps the exit from racing `spawn()`.
// The test releases it with `x\n`: `read` returns on the newline, so the release does not depend
// on EOF, which a concurrent fork inheriting the write end would withhold. It then waits with
// `block_until_exit`, which does not reap, so the root is an unreaped zombie when
// `graceful_shutdown_tree` runs. Asserting `Present` at that point keeps the final `Gone` from
// passing vacuously: had the test reaped the root itself, a mutant that skips the function's own
// reap would still read `Gone`.
//
// The `exec 3<&0; cat <&3 3<&- &` idiom is explained at `test_child::BLOCKER_ARGV`. Without a
// kernel drain edge, the fixture still exercises the root-only watch, asserted below.
#[cfg(unix)]
#[test]
fn graceful_tree_members_remain_still_reaps_an_already_exited_root() {
    use std::io::{Read, Write};

    let mut cmd = crate::Command::new();
    cmd.args([
        "sh",
        "-c",
        "trap '' TERM; exec 3<&0; cat <&3 >/dev/null 3<&- & echo r; read _ <&4; exit 0",
    ]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.fd(4, crate::Stdio::pipe_in()).expect("set exit-gate pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    // Held for the test's whole body: dropping it delivers EOF to the backgrounded `cat`.
    let _stdin = child.stdin().expect("piped stdin");
    let mut exit_gate = child.fd_write_end(4.into()).expect("exit-gate write end");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .expect("readiness byte");
    let id = child.id();
    // The root is still blocked on `read _ <&4`: release it, then wait for its exit WITHOUT
    // reaping.
    exit_gate.write_all(b"x\n").expect("release the root's exit 0");
    drop(exit_gate);
    assert!(
        crate::wait::block_until_exit(id, None).expect("the root must exit"),
        "block_until_exit must observe the exit, not a timeout (None means unbounded)"
    );
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "the exited root must still be an unreaped zombie before graceful_shutdown_tree runs"
    );
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
    // The forced sweep failure was a stub, so the TERM-ignoring descendant is still alive; a
    // real sweep now (the seam is consumed) kills it.
    child.kill_tree().expect("cleanup sweep");
}

// Windows twin of `graceful_tree_members_remain_still_reaps_an_already_exited_root` above,
// reached via a job object instead of cgroup/process-group — but NOT a check on the same
// postcondition, because that postcondition does not translate. The Unix test proves an
// already-exited root is best-effort REAPED (`waitpid`-collected) even when the sweep also
// fails, so it never strands a zombie. Windows has no reap concept to strand: per the
// `shared_child` crate's own comment on its Windows backend (the dependency `SharedChild`
// replaced), "there's no such thing as reaping
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
// fixture's backgrounded, TERM-immune `cat`). The grandchild is itself a re-exec'd
// `fixture_registers_then_blocks`, blocked on a control socket connected DIRECTLY to the
// listener below — not to a socket the short-lived intermediate `fixture_survives_group_signal`
// process would itself own and then close on its own exit. That connect-and-tag IS the
// happens-before edge (the grandchild cannot tag until its own code is running, in its own
// group), over the same control-channel shape `tests/common::spawn_tree` uses (a stdout byte
// would not work here: the fixture's stdout is null — see the fixture's own doc). `sock` is held for this
// whole test: dropping it would deliver EOF and let the grandchild exit on its own, defeating
// the MembersRemain fixture.
#[cfg(windows)]
#[test]
fn windows_graceful_tree_members_remain_surfaces_the_forced_sweep_failure() {
    use std::io::Read;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();

    let mut cmd = crate::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(crate::test_child::fixture_argv(
            crate::test_child::FIXTURE_SURVIVES_GROUP_SIGNAL_TEST,
        ));
    cmd.env(crate::test_child::FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV, addr);
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    cmd.env(crate::test_child::ack::ACK_ENV, "1");
    cmd.contain();
    let child = std::sync::Arc::new(cmd.spawn().expect("spawn"));
    // The fixture exits at once and its descendant connects: see `accept_or_signalled`. The
    // watcher is detached, so the test returns its assertion or a failed kill even if the job
    // never drains.
    let drained = std::sync::Arc::new(crate::test_child::DrainSignal::new());
    {
        let (child, drained) = (child.clone(), drained.clone());
        std::thread::spawn(move || drained.watch(|| child.wait_tree()));
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Blocks until the survivor has connected, which it does only once it exists in its
        // own process group (see the fixture's own doc).
        let mut sock = crate::test_child::accept_or_signalled(&listener, &drained);
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
    }));
    // The forced failure was a stub, so the survivor lives; the real sweep (seam consumed) kills it
    // and drains the job.
    if let Err(e) = child.kill_tree() {
        let unwinding = outcome.as_ref().err().map(|p| {
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        });
        panic!("cleanup kill_tree failed ({e}); unwinding from: {unwinding:?}");
    }
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

// `accept_or_signalled` fails once the job drains with nothing having connected, instead of
// waiting forever. The contained fixture matches no test, so it exits at once and leaves no
// descendant.
#[cfg(windows)]
#[test]
fn death_watch_windows_accept_or_signalled_panics_when_the_tree_drains_before_anything_connects() {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let mut cmd = crate::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(crate::test_child::fixture_argv("test_child::__no_such_test__"));
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let drained = crate::test_child::DrainSignal::new();
    let result = std::thread::scope(|scope| {
        scope.spawn(|| drained.watch(|| child.wait_tree()));
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::test_child::accept_or_signalled(&listener, &drained)
        }))
    });
    let payload = result.expect_err("a drained job with no connection must panic");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("string panic payload");
    assert!(
        message.starts_with("the tree drained (") && message.ends_with(") before anything connected"),
        "got: {message:?}"
    );
    child.wait().expect("reap the root");
}

// A NON-containment terminate_tree error (modelling NoConsole/Unsupported) must NOT be held
// -- this is the pre-existing, still-documented "no signal sent, no grace waited, tree left
// running" contract from #46, unrelated to #61, and this task's scoping must not silently
// rewrite it (see this task's "Scope correction" note above). `Duration::ZERO` here too: the
// point is that the function returns before ever reaching the watch, at all, regardless of
// the requested grace, so there is nothing to synchronize on.
#[test]
fn graceful_tree_non_containment_terminate_error_fails_fast() {
    let (mut child, stdin) = blocker();
    term_fault::set_force_terminate(term_fault::Forced::Unsupported);
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("the forced Unsupported error must surface immediately");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    // Fails fast: no grace was waited, no sweep ran, so the child is STILL ALIVE.
    assert_still_running(&mut child, stdin);
    cleanup(&mut child);
}
