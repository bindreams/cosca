// `wait_and_reap` is the half of the teardown primitive that a caller which has ALREADY killed
// uses. Its whole point is that it issues no kill of its own, so its wait rests on the caller's
// kill instead of on a second one that can be refused.
//
// The fixture is the oracle. `test_child::fixture_registers_then_blocks` tags the rendezvous
// socket (proving it is live and executing its own code — no timer, no poll), blocks on a 1-byte
// read of that socket, and on receiving the byte exits 0 of its own accord. Exit code 0 is
// unreachable through a kill: `TerminateProcess(_, 1)` reports 1 and `SIGKILL` reports no code at
// all. So the status this test reads distinguishes "waited for the child's own exit" from "killed
// it and waited for that", which is exactly the difference between this function and `reap_now`.
//
// Runs on every target: the elevated-spawn cleanup path that needs the wait-only entry is
// `#[cfg(unix)]`, but the primitive and its Windows arm are not, and a kill re-added on either
// arm fails here.
#[tokio::test]
async fn wait_and_reap_waits_for_the_childs_own_exit_and_never_kills() {
    use std::io::{Read, Write};

    let (listener, addr) = crate::test_child::registration_rendezvous();
    let child = {
        // Raw tokio bypasses cosca's spawn path, so its internal `spawn_lock()` is taken here by
        // hand: a macOS fork must not transiently inherit another test's fd-marker write end.
        // Wrapping a *cosca* spawn this way would self-deadlock — the mutex is not reentrant.
        let _guard = crate::child::spawn::spawn_lock();
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args([
                "--test-threads=1",
                "--exact",
                crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_TEST,
            ])
            .env(crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, &addr)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the rendezvous fixture")
    };
    let pid = child.id().expect("tokio owns an un-reaped child");

    let (mut sock, _) = listener.accept().expect("accept the fixture's rendezvous connection");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the fixture's readiness tag");

    // Release the fixture: its blocking read returns and it exits 0 on its own.
    sock.write_all(b"g").expect("release the fixture");
    sock.flush().expect("flush the release byte");

    let mut child = super::wait_and_reap(child, pid, true).expect("a clean exit never leaves ownership uncertain");

    // No poll loop and no retry: `try_wait` is called exactly once, immediately. It can only
    // report an exit if `wait_and_reap` already blocked until the child had one.
    let status = child
        .try_wait()
        .expect("try_wait")
        .expect("wait_and_reap must return only after the child has exited");
    assert_eq!(
        status.code(),
        Some(0),
        "the fixture must have exited on its own; a kill inside wait_and_reap would report the \
         forced code instead ({status:?})"
    );
}

/// A tokio child that exits promptly and needs no external binary: this test binary with a
/// libtest filter that matches nothing. See `test_child::spawn_a_process_that_exits` for why the
/// filter is mandatory (an unfiltered re-exec runs the whole suite, including this test).
fn spawn_a_tokio_child_that_exits() -> ::tokio::process::Child {
    // Raw tokio, so it bypasses cosca's spawn path and its internal `spawn_lock()` — taken here
    // by hand instead. A cosca spawn must NOT be wrapped this way (the mutex is not reentrant).
    let _guard = crate::child::spawn::spawn_lock();
    ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn")
}

// `done_ok` is the whole diagnostic: an already-reaped child is legal for `Drop` (the user may
// have `wait()`ed) and a broken precondition for a caller whose child was never awaited. Both
// arms are pinned, so neither loosening the assert nor hard-firing it survives.
//
// Debug-only oracle, `kinfo_tests`' calm-release shape: `debug_assert!` is compiled out in the
// release lane, where the same straight-line code returns instead — which the post-call assert
// pins.
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "already-reaped child where one was impossible")
)]
#[tokio::test]
async fn wait_and_reap_refuses_an_already_reaped_child_the_caller_never_awaited() {
    let mut child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    child.wait().await.expect("wait");
    let child = super::wait_and_reap(child, pid, false).expect("an already-reaped child keeps its ownership");
    // Only reachable in release (debug panicked above, as expected):
    assert!(child.id().is_none(), "the child was reaped by the wait() above");
}

#[tokio::test]
async fn wait_and_reap_accepts_an_already_reaped_child_the_caller_may_have_awaited() {
    let mut child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    child.wait().await.expect("wait");
    // `Drop`'s disposition: legal, returns quietly, and keeps the (already-reaped) child.
    drop(super::wait_and_reap(child, pid, true));
}

// The value the elevated-spawn cleanup path passes. That child is killed and reaped without ever
// being awaited, so an already-reaped one means the precondition broke — passing `done_ok = true`
// here would swallow it silently, the same shape this entry exists to remove from that path.
//
// `#[cfg(unix)]` with the entry itself: the Windows elevation arm has no deferred password.
#[cfg(unix)]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "already-reaped child where one was impossible")
)]
#[tokio::test]
async fn the_elevated_cleanup_entry_refuses_an_already_reaped_child() {
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        // `cosca::Command::args` is the FULL argv; libtest drops slot 0 as the binary name.
        .args(["cosca_unit_tests", "--exact", "__cosca_no_such_test__"]);
    cmd.stdout(crate::stdio::Stdio::null()).expect("stdout null");
    cmd.stderr(crate::stdio::Stdio::null()).expect("stderr null");
    // NO `spawn_lock()` here: this is a cosca spawn, which takes it internally, and it is a plain
    // non-reentrant mutex. The raw `::tokio::process::Command` spawns elsewhere in this file take
    // it by hand precisely because they bypass that path — do not copy the guard across.
    let mut child = cmd.spawn().expect("spawn");
    child.wait().await.expect("wait");
    child.wait_and_reap_blocking();
    // Only reachable in release (debug panicked above, as expected):
    assert!(
        matches!(child.try_wait(), Ok(Some(_))),
        "the child was reaped by the wait() above"
    );
}

// `into_unreaped_parts` must drop tokio's OWN piped stdio (`child.stdin` / `stdout` / `stderr`
// inside `ProcSource::Tokio`), not just cosca's `os.pipes`/`os.owned_std`.
// Leaving tokio's read end of a piped stdout open with nobody draining it lets a writer child
// fill the pipe buffer and block forever in `write(2)`; the handed-back `Unreaped::wait().await`
// would then never resolve, because the child itself never exits.
//
// This synchronizes on the child's own exit, never a timeout: closing the read end here makes a
// writer that keeps going (`sh -c 'exec yes'`) see SIGPIPE/EPIPE, so its exit — and this test's
// `wait().await` — is bounded by that, not by a clock.
#[cfg(unix)]
#[tokio::test]
async fn into_unreaped_parts_drops_tokios_own_piped_stdio() {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sh", "-c", "exec yes"]);
    cmd.stdout(crate::stdio::Stdio::pipe()).expect("stdout pipe");
    let child = cmd.spawn().expect("spawn");
    let (held, retained) = child.into_unreaped_parts();

    let crate::child::unreaped::Held::Tokio(inner) = &held else {
        panic!("a Unix spawn always yields Held::Tokio");
    };
    assert!(
        inner.stdin.is_none(),
        "into_unreaped_parts must drop tokio's own piped stdin"
    );
    assert!(
        inner.stdout.is_none(),
        "into_unreaped_parts must drop tokio's own piped stdout, or a writer that outpaces its \
         reader blocks forever with nobody draining it"
    );
    assert!(
        inner.stderr.is_none(),
        "into_unreaped_parts must drop tokio's own piped stderr"
    );

    let mut unreaped = crate::tokio::Unreaped::with_retained(held, Some(retained));
    let status = unreaped
        .wait()
        .await
        .expect("the writer must exit once its pipe's read end is closed");
    assert!(
        !status.success(),
        "a writer that fills a closed pipe is ended by SIGPIPE/EPIPE, not a clean exit: {status:?}"
    );
}

// An unexpected wait failure leaves the reap to tokio and is asserted, so release — where the
// assert is compiled out — must still say so. The forced failure replaces the wait; the child is
// reaped by the `wait()` below.
#[tokio::test]
async fn a_failed_teardown_wait_is_logged() {
    let marker = "cosca-teardown-wait-fail-2e6d";
    crate::log_capture::install();
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mark = crate::log_capture::mark();
    super::fault::set_force_wait_failure(marker);
    // `child` moves into the closure: a marker failure is not ownership-uncertain (see
    // `crate::child::unreaped::releases_ownership`), so in release `wait_and_reap` hands it back;
    // in debug the assert panics first, and the moved-in child is dropped with that unwind — there
    // is nothing left to reap in that case, only the log and the panic itself to check.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        super::wait_and_reap(child, pid, false)
    }));
    assert_eq!(
        super::fault::take_force_wait_failure(),
        None,
        "the wait must consume the forced failure"
    );
    assert_eq!(
        outcome.is_err(),
        cfg!(debug_assertions),
        "the debug_assert fires in exactly the builds that keep it"
    );
    assert!(
        crate::log_capture::contains_since(mark, marker),
        "a failed teardown wait must be logged"
    );
    if let Ok(child) = outcome {
        let mut child = child.expect("a non-ownership-uncertain failure keeps the child (release only)");
        child.wait().await.expect("reap the child");
    }
}

/// `wait_and_reap`'s own ownership check: a wait that fails with `ECHILD` — this crate's
/// classification (`crate::child::unreaped::releases_ownership`) for "something else already
/// reaped this child, so the pid may now name another process" — must forget the tokio child
/// instead of returning it, since a caller that then dropped it normally would hand that pid to
/// tokio's orphan queue. This is the regression `wait_and_reap` (588f88b3) fixes.
///
/// No pre-check that the child is a real, still-unreaped zombie is needed here (unlike
/// `wait_forgets_a_tokio_child_that_loses_tokios_own_reap_race` in `unreaped_tests.rs`): the
/// forced `ECHILD` short-circuits `wait_and_reap` before its real `waitid` call ever runs, so the
/// child's actual state cannot affect which branch it takes. The `waitpid` below is the proof
/// instead — it can only succeed if `wait_and_reap` left the child un-reaped and untouched.
#[cfg(unix)]
#[tokio::test]
async fn wait_and_reap_forgets_the_child_when_ownership_is_uncertain() {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    super::fault::set_force_wait_echild();
    let outcome = super::wait_and_reap(child, pid, false);
    assert!(
        outcome.is_none(),
        "an ownership-uncertain wait must forget the child, not hand it back"
    );
    // Forgotten, not handed to tokio's orphan queue (which would race this `waitpid` for the same
    // pid, and never touches a `mem::forget`en child regardless): this test's own child, reaped by
    // hand, proving `wait_and_reap` left it genuinely un-reaped.
    nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None).expect("reap the child");
}
