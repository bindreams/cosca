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
    let mut child = {
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

    super::wait_and_reap(&mut child, pid, true);

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
    super::wait_and_reap(&mut child, pid, false);
    // Only reachable in release (debug panicked above, as expected):
    assert!(child.id().is_none(), "the child was reaped by the wait() above");
}

#[tokio::test]
async fn wait_and_reap_accepts_an_already_reaped_child_the_caller_may_have_awaited() {
    let mut child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    child.wait().await.expect("wait");
    super::wait_and_reap(&mut child, pid, true); // `Drop`'s disposition: legal, returns quietly
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
