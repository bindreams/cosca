use super::{ProcSource, Waited};

/// `child` as a backend. Linux: holding a pidfd the test opened itself, as the spawn does (a raw
/// tokio child has none).
fn proc_source(child: ::tokio::process::Child) -> ProcSource {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{pidfd_open, Pid, PidfdFlags};
        let pid = child.id().expect("tokio owns an un-reaped child");
        let pidfd = pidfd_open(Pid::from_raw(pid as i32).expect("pid"), PidfdFlags::empty()).expect("pidfd_open");
        ProcSource::tokio(child).with_pidfd(pidfd)
    }
    #[cfg(not(target_os = "linux"))]
    ProcSource::tokio(child)
}

/// Consumes `pid`'s exit record with a raw `waitid(P_PID)`, behind its owner's back. Blocks until
/// the child has exited.
#[cfg(unix)]
fn reap_behind_the_owner(pid: u32) {
    // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: consumes the exit record of this process's own child.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
}

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
        // Raw tokio bypasses cosca's spawn path, so `spawn_tokio` takes `spawn_lock()` for it.
        crate::test_spawn::spawn_tokio(
            ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
                .args([
                    "--test-threads=1",
                    "--exact",
                    crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_TEST,
                ])
                .env(crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, &addr)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()),
        )
        .expect("spawn the rendezvous fixture")
    };
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);

    let (mut sock, _) = listener.accept().expect("accept the fixture's rendezvous connection");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the fixture's readiness tag");

    // Release the fixture: its blocking read returns and it exits 0 on its own.
    sock.write_all(b"g").expect("release the fixture");
    sock.flush().expect("flush the release byte");

    assert_eq!(proc.wait_and_reap(pid), Waited::Exited);

    // No poll loop and no retry: `try_wait` is called exactly once, immediately. It can only
    // report an exit if `wait_and_reap` already blocked until the child had one.
    let status = proc
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
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", "__cosca_no_such_test__"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn")
}

// An already-reaped child is a broken precondition for a caller whose child was never awaited, and
// `Drop` checks `is_reaped` before it reaches here, so the assert has no legal caller to spare.
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
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);
    proc.wait().await.expect("wait");
    proc.wait_and_reap(pid);
    // Only reachable in release (debug panicked above, as expected):
    assert!(proc.is_reaped(), "the child was reaped by the wait() above");
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

// A wait that cannot prove the child is still ours is `Foreign`, and records no reap: a fabricated
// exit-0 record would make `TeardownBlocker::assert_killed` blame the kill for a failed wait.
//
// macOS: a pid that is not this process's child makes `waitid` fail with `ECHILD` while tokio still
// owns the real child (`id()` is `Some`).
#[cfg(target_os = "macos")]
#[tokio::test]
async fn wait_and_reap_on_a_pid_that_is_not_our_child_is_foreign_and_records_no_reap() {
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let mut proc = proc_source(spawn_a_tokio_child_that_exits());
    let not_our_child = i32::MAX as u32;

    assert_eq!(proc.wait_and_reap(not_our_child), Waited::Foreign);

    assert_eq!(reaps.recorded(), vec![], "a failed waitid must record no reap");
    proc.wait().await.expect("reap the real child");
}

/// Linux: a child with no pidfd has nothing to prove it ours, and tokio's by-pid reap must not
/// run on its say-so.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn tokio_wait_and_reap_with_no_pidfd_is_foreign() {
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = ProcSource::tokio(child);

    assert_eq!(proc.wait_and_reap(pid), Waited::Foreign);

    assert_eq!(reaps.recorded(), vec![], "no wait ran, so no reap is recorded");
    proc.wait().await.expect("reap the real child");
}

/// A reaped-behind-its-back child the backend has been told to forget: `Foreign` warns once, naming
/// the pid and what it leaks, and the backend reports itself reaped.
#[cfg(unix)]
#[tokio::test]
async fn tokio_forget_foreign_warns_naming_the_leak() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);
    reap_behind_the_owner(pid);

    assert_eq!(proc.wait_and_reap(pid), Waited::Foreign);
    proc.forget_foreign();

    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, &format!("child {pid}"))
        .into_iter()
        .filter(|(level, _)| *level == log::Level::Warn)
        .collect();
    assert_eq!(warns.len(), 1, "exactly one warning: {warns:?}");
    assert!(warns[0].1.contains("leak"), "the warning must name the leak: {warns:?}");
    assert!(proc.is_reaped(), "a forgotten child has nothing left to reap");
}

/// The streams are separate objects, so forgetting the child leaks nothing by keeping them: a
/// caller who waits and then reads `stdout()` keeps its output.
///
/// Mutant: `forget_foreign` drops the streams.
#[cfg(unix)]
#[tokio::test]
async fn tokio_forget_foreign_keeps_the_untaken_stdout() {
    use ::tokio::io::AsyncReadExt as _;
    let child = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new("sh")
            .args(["-c", "echo hello"])
            .stdout(std::process::Stdio::piped()),
    )
    .expect("spawn");
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);
    reap_behind_the_owner(pid);

    assert_eq!(proc.wait_and_reap(pid), Waited::Foreign);
    proc.forget_foreign();

    let mut stdout = proc.take_stdout().expect("the untaken stdout survives the forget");
    let mut line = String::new();
    stdout.read_to_string(&mut line).await.expect("read");
    assert_eq!(line, "hello\n");
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
