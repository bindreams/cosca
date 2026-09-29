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
        // Raw tokio bypasses cosca's spawn path, so `spawn_tokio` takes `spawn_lock()` for it.
        crate::test_spawn::spawn_tokio(
            ::tokio::process::Command::from(crate::test_reexec::command(
                std::env::current_exe().expect("current_exe"),
            ))
            .args(crate::test_reexec::fixture_args(
                crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_TEST,
            ))
            .env(crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, &addr)
            .env(crate::test_child::ack::ACK_ENV, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
        )
        .expect("spawn the rendezvous fixture")
    };
    let pid = child.id().expect("tokio owns an un-reaped child");
    let target = crate::Process::from_pid(pid)
        .found()
        .expect("resolve the freshly spawned fixture's pid")
        .id();

    let mut sock = crate::test_child::accept_or_die(&listener, target);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the fixture's readiness tag");

    // Release the fixture: its blocking read returns and it exits 0 on its own.
    sock.write_all(b"g").expect("release the fixture");
    sock.flush().expect("flush the release byte");

    super::wait_and_reap(&mut child, pid);

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
    // Raw tokio bypasses cosca's spawn path; `spawn_tokio` takes `spawn_lock()` for it.
    crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::from(crate::test_reexec::command(
            std::env::current_exe().expect("current_exe"),
        ))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null()),
    )
    .expect("spawn")
}

// An already-reaped child is a broken precondition: every caller's child was never awaited.
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
    super::wait_and_reap(&mut child, pid);
    // Only reachable in release (debug panicked above, as expected):
    assert!(child.id().is_none(), "the child was reaped by the wait() above");
}

// The elevated-spawn cleanup path. That child is killed and reaped without ever being awaited, so
// an already-reaped one means the precondition broke, and must not be swallowed silently.
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
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
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

// `waitid` failing with anything but EINTR is a real OS outcome, not a contract violation: it must
// be logged at warn and the wait abandoned, in every build. A pid that is not this process's child
// makes `waitid` fail with ECHILD while tokio still owns the real child (`id()` is `Some`).
#[cfg(unix)]
#[tokio::test]
async fn wait_and_reap_warns_and_returns_when_waitid_fails() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut child = spawn_a_tokio_child_that_exits();
    assert!(child.id().is_some(), "tokio owns an un-reaped child");
    let not_our_child = i32::MAX as u32;

    super::wait_and_reap(&mut child, not_our_child);

    assert_eq!(
        crate::log_capture::levels_since(mark, &format!("waitid on pid {not_our_child} failed")),
        [log::Level::Warn]
    );
    child.wait().await.expect("reap the real child");
}

// A `waitid` that failed reaped nothing, so it records nothing: a fabricated exit-0 record would
// make `TeardownBlocker::assert_killed` blame the kill for a failed wait.
#[cfg(unix)]
#[tokio::test]
async fn wait_and_reap_records_no_reap_when_waitid_fails() {
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let mut child = spawn_a_tokio_child_that_exits();
    // Not `i32::MAX`: the warn-test above counts that pid's log line.
    let not_our_child = i32::MAX as u32 - 1;

    super::wait_and_reap(&mut child, not_our_child);

    assert_eq!(reaps.recorded(), vec![], "a failed waitid must record no reap");
    child.wait().await.expect("reap the real child");
}

/// What `waitid(WEXITED | WNOWAIT)` reports for `pid`, decoded by `exit_status_of`.
#[cfg(unix)]
fn waitid_status(pid: u32) -> std::process::ExitStatus {
    // SAFETY: an all-zero `siginfo_t` is a valid value; the kernel fills it in.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: a well-formed blocking `waitid` on this process's own un-reaped child.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
    super::exit_status_of(&info)
}

/// `exit_status_of` decodes a real child's `siginfo_t` to the status std reports for it.
#[cfg(unix)]
#[test]
fn exit_status_of_matches_std_for_exited_and_killed_children() {
    for script in ["exit 3", "kill -KILL $$"] {
        let mut child = crate::test_spawn::spawn(std::process::Command::new("sh").args(["-c", script])).expect("spawn");
        let decoded = waitid_status(child.id());
        let real = child.wait().expect("wait");
        assert_eq!(decoded, real, "`sh -c '{script}'`");
    }
}

/// A dumped child is not portably producible (a core file is a host side effect), so the
/// decoding is checked on the `si_code`/`si_status` pair itself: the low bits hold the signal and
/// bit 7 the core flag, as in std's wait status.
#[cfg(unix)]
#[test]
fn exit_status_from_parts_encodes_a_dumped_child() {
    use std::os::unix::process::ExitStatusExt as _;
    let dumped = super::exit_status_from_parts(libc::CLD_DUMPED, libc::SIGSEGV);
    assert_eq!(dumped.signal(), Some(libc::SIGSEGV));
    assert!(dumped.core_dumped(), "{dumped:?}");
    let killed = super::exit_status_from_parts(libc::CLD_KILLED, libc::SIGKILL);
    assert_eq!(killed.signal(), Some(libc::SIGKILL));
    assert!(!killed.core_dumped(), "{killed:?}");
    assert_eq!(super::exit_status_from_parts(libc::CLD_EXITED, 3).code(), Some(3));
}
