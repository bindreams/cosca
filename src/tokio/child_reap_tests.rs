use super::{ProcSource, Waited};
#[cfg(target_os = "macos")]
use crate::test_groups::{tracer_group, Group};

/// `child` as a backend, as the spawn builds it: Linux holds a pidfd the test opens itself (a raw
/// tokio child has none), macOS the child's unique id.
pub(in crate::tokio::child) fn proc_source(child: ::tokio::process::Child) -> ProcSource {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{pidfd_open, Pid, PidfdFlags};
        let pid = child.id().expect("tokio owns an un-reaped child");
        let pidfd = pidfd_open(Pid::from_raw(pid as i32).expect("pid"), PidfdFlags::empty()).expect("pidfd_open");
        ProcSource::new(child, pidfd)
    }
    #[cfg(target_os = "macos")]
    {
        let pid = child.id().expect("tokio owns an un-reaped child");
        ProcSource::new(
            child,
            crate::signal::read_identity(pid).expect("the identity is readable"),
        )
    }
    #[cfg(windows)]
    ProcSource::new(child)
}

/// Blocks until `pid` has exited, without consuming its exit record.
#[cfg(unix)]
pub(in crate::tokio::child) fn wait_exited_unreaped(pid: u32) {
    // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waits for this process's own child without consuming it.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
}

/// Consumes `pid`'s exit record with a raw `waitid(P_PID)`, behind its owner's back. Blocks until
/// the child has exited.
#[cfg(unix)]
pub(in crate::tokio::child) fn reap_behind_the_owner(pid: u32) {
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
#[skuld::test]
async fn wait_and_reap_waits_for_the_childs_own_exit_and_never_kills() {
    use std::io::{Read, Write};

    let (listener, addr) = crate::test_child::registration_rendezvous();
    let child = {
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
    let mut proc = proc_source(child);
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
#[skuld::test]
async fn wait_and_reap_refuses_an_already_reaped_child_the_caller_never_awaited() {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);
    proc.wait().await.expect("wait");
    proc.wait_and_reap(pid);
    // Only reachable in release (debug panicked above, as expected):
    assert!(proc.is_reaped(), "the child was reaped by the wait() above");
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
#[skuld::test]
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

// A wait that cannot prove the child is still ours is `Foreign`, and records no reap: a fabricated
// exit-0 record would make `TeardownBlocker::assert_killed` blame the kill for a failed wait.
//
// macOS: a pid that is not this process's child fails the unique-id check while tokio still owns
// the real child (`id()` is `Some`).
#[cfg(target_os = "macos")]
#[skuld::test]
async fn wait_and_reap_on_a_pid_that_is_not_our_child_is_foreign_and_records_no_reap() {
    crate::tokio::test_runtime::assert_current_thread();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let child = spawn_a_tokio_child_that_exits();
    let real_pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);
    let not_our_child = i32::MAX as u32;

    assert_eq!(proc.wait_and_reap(not_our_child), Waited::Foreign);

    assert_eq!(reaps.recorded(), vec![], "a refused wait must record no reap");
    proc.forget_foreign();
    reap_behind_the_owner(real_pid);
}

/// A child reaped behind its back is foreign to a wait through its pidfd or its pid, and the wait
/// records no reap.
///
/// Mutant: `wait_and_reap` treats a refused wait as an exit, or records one.
#[cfg(unix)]
#[skuld::test]
async fn wait_and_reap_of_a_child_reaped_behind_the_owner_is_foreign() {
    crate::tokio::test_runtime::assert_current_thread();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);
    reap_behind_the_owner(pid);

    assert_eq!(proc.wait_and_reap(pid), Waited::Foreign);

    assert_eq!(reaps.recorded(), vec![], "no exit was observed, so no reap is recorded");
    proc.forget_foreign();
}

/// A reaped-behind-its-back child the backend has been told to forget: `Foreign` warns once, naming
/// the pid and what it leaks, and the backend reports itself reaped.
#[cfg(unix)]
#[skuld::test]
async fn tokio_forget_foreign_warns_naming_the_leak() {
    crate::tokio::test_runtime::assert_current_thread();
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

/// After the forget there is nothing left to wait for: `wait` and `try_wait` answer `ECHILD`.
///
/// Mutant: `try_wait` on a forgotten child answers `Ok(None)` (still running), or `wait` an exit.
#[cfg(unix)]
#[skuld::test]
async fn a_forgotten_child_answers_echild_to_wait_and_try_wait() {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);
    reap_behind_the_owner(pid);
    proc.forget_foreign();

    for waited in [proc.try_wait().map(drop), proc.wait().await.map(drop)] {
        match waited {
            Err(crate::error::Error::Io(e)) => assert_eq!(e.raw_os_error(), Some(libc::ECHILD), "{e}"),
            other => panic!("a forgotten child must answer ECHILD, got {other:?}"),
        }
    }
}

/// The streams are separate objects, so forgetting the child leaks nothing by keeping them: a
/// caller who waits and then reads `stdout()` keeps its output.
///
/// Mutant: `forget_foreign` drops the streams.
#[cfg(unix)]
#[skuld::test]
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

/// Dropping a backend that nothing released or forgot, which is what an unwind does to one, hands
/// tokio's `Child` to its own drop only when the handle shows the child ours.
///
/// Mutant: the implicit drop forgets every child.
#[cfg(unix)]
#[skuld::test]
async fn dropping_a_backend_implicitly_releases_a_child_shown_ours() {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let proc = proc_source(child);
    wait_exited_unreaped(pid);
    let backend_drops = super::fault::count_backend_drops();

    drop(proc);

    assert_eq!(backend_drops.get(), 1, "a child shown ours is released to tokio's drop");
}

/// The same drop forgets tokio's `Child` when the peek fails: a child nothing can answer for
/// is not tokio's to reap by pid.
///
/// Mutant: a failed peek counts as ours.
#[cfg(unix)]
#[skuld::test]
async fn dropping_a_backend_implicitly_forgets_a_child_whose_peek_failed() {
    use crate::wait::exit_only::seams::force_peek_once;
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let proc = proc_source(child);
    wait_exited_unreaped(pid);
    let backend_drops = super::fault::count_backend_drops();
    let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure 5b1d")));

    drop(proc);

    assert_eq!(backend_drops.get(), 0, "tokio's Child must have been forgotten");
    reap_behind_the_owner(pid); // still ours: nothing reaped it by pid
}

/// The same drop forgets tokio's `Child` when the handle shows the child reaped elsewhere: tokio's
/// drop would reap by a pid that may name another process.
///
/// Mutant: the implicit drop releases every child.
#[cfg(unix)]
#[skuld::test]
async fn dropping_a_backend_implicitly_forgets_a_child_reaped_elsewhere() {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let proc = proc_source(child);
    reap_behind_the_owner(pid);
    let backend_drops = super::fault::count_backend_drops();

    drop(proc);

    assert_eq!(backend_drops.get(), 0, "tokio's Child must have been forgotten");
}

/// `wait` closes the untaken stdin before it waits, as tokio's own `wait` does, so a child that
/// reads stdin to EOF can exit. The streams live in the backend, not in tokio's `Child`, so the
/// backend does it. Observed after one poll, which has run the close and not the wait.
///
/// The test holds a second write end of `cat`'s stdin so the close cannot end it: if `cat` exited
/// early, the single poll could reap it, and `reap_now` requires a never-awaited child.
///
/// Mutant: `wait` leaves stdin open.
#[cfg(unix)]
#[skuld::test]
async fn wait_closes_the_untaken_stdin_first() {
    use std::future::Future;
    use std::os::fd::AsFd;
    let child = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn");
    let pid = child.id().expect("tokio owns an un-reaped child");
    let held_writer = child
        .stdin
        .as_ref()
        .expect("piped stdin")
        .as_fd()
        .try_clone_to_owned()
        .expect("duplicate the stdin write end");
    let mut proc = proc_source(child);
    {
        let mut waiting = Box::pin(proc.wait());
        std::future::poll_fn(|cx| {
            drop(waiting.as_mut().poll(cx));
            std::task::Poll::Ready(())
        })
        .await;
    }
    let ProcSource::Tokio { stdin, .. } = &proc else {
        panic!("a tokio backend");
    };
    let closed = stdin.is_none();
    assert!(!proc.is_reaped(), "the one poll finished the wait");
    proc.reap_now(pid); // the test's own `cat`: end it whatever happened
    drop(held_writer);
    assert!(closed, "wait must close stdin before it waits");
}

/// An implicit drop after `wait` has collected the status (tokio's `id()` is `None`: nothing is
/// left to reap by pid) still hands the backend to tokio's drop.
///
/// Mutant: the implicit drop forgets a child tokio already reaped.
#[cfg(unix)]
#[skuld::test]
async fn dropping_a_backend_implicitly_after_wait_releases_it() {
    let child = spawn_a_tokio_child_that_exits();
    let mut proc = proc_source(child);
    proc.wait().await.expect("wait");
    assert!(proc.is_reaped());
    let backend_drops = super::fault::count_backend_drops();

    drop(proc);

    assert_eq!(backend_drops.get(), 1, "a reaped child's backend is released");
}

/// An implicit drop that forgets the child says so at debug, except while unwinding: a logger that
/// panics then aborts the process. The unwind here is a plain panic, and its record is checked.
///
/// Mutant: the drop logs whether or not the thread is panicking.
#[cfg(unix)]
#[skuld::test]
async fn an_implicit_drop_logs_its_forget_only_when_not_unwinding() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let reaped_elsewhere = || {
        let child = spawn_a_tokio_child_that_exits();
        let pid = child.id().expect("tokio owns an un-reaped child");
        let proc = proc_source(child);
        reap_behind_the_owner(pid);
        proc
    };
    let marker = "dropped without a release";

    let mark = crate::log_capture::mark();
    drop(reaped_elsewhere());
    assert!(
        crate::log_capture::contains_since(mark, marker),
        "a plain drop logs the forget"
    );

    let proc = reaped_elsewhere();
    let mark = crate::log_capture::mark();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = proc;
        panic!("unwind with the backend held");
    }));
    assert!(unwound.is_err());
    assert!(
        !crate::log_capture::contains_since(mark, marker),
        "no log may run while the thread unwinds"
    );
}

/// Without evidence of a foreign reap nothing is forgotten: a live child stays tokio's.
///
/// Mutant: `forget_if_foreign` forgets unconditionally.
#[cfg(unix)]
#[skuld::test]
async fn forget_if_foreign_leaves_a_child_nothing_has_reaped() {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let mut proc = proc_source(child);
    wait_exited_unreaped(pid);

    proc.forget_if_foreign();

    assert!(!proc.is_reaped(), "an unreaped zombie is still tokio's to reap");
    proc.wait().await.expect("tokio reaps it");
}

/// `wait_and_reap_blocking` on a child reaped behind its owner's back forgets it.
///
/// Mutant: no forget in `wait_and_reap_blocking`.
#[cfg(unix)]
#[skuld::test]
async fn wait_and_reap_blocking_forgets_a_foreign_reaped_child() {
    let mut child = spawn_cosca_child_that_exits();
    reap_behind_the_owner(child.id().pid());

    child.wait_and_reap_blocking();

    assert!(child.proc_mut().is_reaped(), "a foreign-reaped child must be forgotten");
}

/// `kill` that finds the child gone forgets a foreign reap, so a later drop or wait cannot reap
/// by pid.
///
/// Mutant: `Child::kill` does not forget on `Sent::Gone`.
#[cfg(unix)]
#[skuld::test]
async fn kill_of_a_foreign_reaped_child_forgets_it() {
    let mut child = spawn_cosca_child_that_exits();
    reap_behind_the_owner(child.id().pid());

    child.kill().expect("a kill of a foreign-reaped child answers Ok");

    assert!(child.proc_mut().is_reaped(), "a foreign-reaped child must be forgotten");
}

#[cfg(unix)]
fn spawn_cosca_child_that_exits() -> crate::tokio::Child {
    spawn_cosca_child_that_exits_result().expect("spawn")
}

#[cfg(unix)]
fn spawn_cosca_child_that_exits_result() -> Result<crate::tokio::Child, crate::error::Error> {
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        // `cosca::Command::args` is the FULL argv; libtest drops slot 0 as the binary name.
        .args(["cosca_unit_tests", "--exact", "__cosca_no_such_test__"]);
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    cmd.stdout(crate::stdio::Stdio::null()).expect("stdout null");
    cmd.stderr(crate::stdio::Stdio::null()).expect("stderr null");
    cmd.spawn()
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
#[skuld::test]
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
#[skuld::test]
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

// macOS: a pid is acted on only while it still has the child's unique id =====

/// A child that exited and is not reaped, behind a backend that holds `identity` for it.
#[cfg(target_os = "macos")]
fn exited_unreaped_with(identity: impl FnOnce(u64) -> Option<u64>) -> (ProcSource, u32) {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    wait_exited_unreaped(pid);
    let real = crate::signal::read_identity(pid)
        .expect("readable")
        .expect("a zombie still has a unique id");
    (ProcSource::new(child, identity(real)), pid)
}

/// The pid names an exited child of this process, so a bare `waitid` would answer at once: only
/// the unique id says it is not the child this backend spawned.
///
/// Mutant: `wait_and_reap` skips the unique-id peek.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_wait_and_reap_on_a_pid_with_another_unique_id_is_foreign() {
    let (mut proc, pid) = exited_unreaped_with(|real| Some(real ^ 1));

    assert_eq!(proc.wait_and_reap(pid), Waited::Foreign);

    proc.forget_foreign();
    reap_behind_the_owner(pid); // nothing reaped it
}

/// Mutant: `forget_if_foreign` peeks without the unique id.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_forget_if_foreign_on_a_pid_with_another_unique_id_forgets() {
    let (mut proc, pid) = exited_unreaped_with(|real| Some(real ^ 1));

    proc.forget_if_foreign();

    assert!(proc.is_reaped(), "a pid with another unique id is not the child");
    reap_behind_the_owner(pid);
}

/// A peek that fails cannot show the pid is the child's, so tokio must not reap it by pid: the
/// child is forgotten, as `wait_and_reap` does for the same failure.
///
/// Mutant: `forget_if_foreign` takes a failed peek for no evidence.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_forget_if_foreign_on_a_failed_peek_forgets() {
    use crate::wait::exit_only::seams::force_peek_once;
    let (mut proc, pid) = exited_unreaped_with(Some);
    let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));

    proc.forget_if_foreign();

    assert!(proc.is_reaped(), "a child that cannot be verified is forgotten");
    reap_behind_the_owner(pid);
}

/// No unique id means the child was already reaped when it was read, or the read was refused, so
/// its pid is never waited on, even though an exited child of this process holds it now.
///
/// Mutant: `wait_and_reap` peeks by pid when there is no id.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_wait_and_reap_with_no_unique_id_is_foreign() {
    let (mut proc, pid) = exited_unreaped_with(|_| None);

    assert_eq!(proc.wait_and_reap(pid), Waited::Foreign);

    proc.forget_foreign();
    reap_behind_the_owner(pid);
}

/// Mutant: `forget_if_foreign` peeks by pid when there is no id.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_forget_if_foreign_with_no_unique_id_forgets() {
    let (mut proc, pid) = exited_unreaped_with(|_| None);

    proc.forget_if_foreign();

    assert!(proc.is_reaped(), "a child with no unique id is foreign");
    reap_behind_the_owner(pid);
}

/// A unique-id read the child itself is refused fails the spawn with `Unassessable` and stops the
/// child before `exec`: the program did not run.
///
/// Mutants: the hook execs anyway (a child is left); the failure maps to `Gone`.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_a_refused_own_identity_read_fails_the_spawn_and_the_program_does_not_run() {
    crate::tokio::test_runtime::assert_current_thread();

    let _forced = crate::child::spawn::unique_report::seams::force_child_read_errno(libc::EPERM);
    use crate::child::spawn::identity_macos_tests::{ran_marker, RAN_ARGV};
    let (stdout, reader) = ran_marker();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(RAN_ARGV);
    cmd.stdout(stdout).expect("set stdout");

    let err = cmd.spawn().err();

    match err.expect("a refused identity read must fail the spawn") {
        crate::error::Error::Unassessable { detail, .. } => assert!(detail.contains("did not start"), "{detail}"),
        other => panic!("expected Unassessable, got {other:?}"),
    }
    crate::child::spawn::identity_macos_tests::assert_program_did_not_run(cmd, reader);
}

/// A wait whose peek or kqueue fails cannot show the child is ours, so it is `Foreign`, and tokio
/// must not reap it by pid.
///
/// Mutant: `wait_reapable` answers `Exited` on an error.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_wait_and_reap_on_a_failed_peek_is_foreign() {
    use crate::wait::exit_only::seams::force_peek_once;
    let (mut proc, pid) = exited_unreaped_with(Some);
    let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));

    assert_eq!(proc.wait_and_reap(pid), Waited::Foreign);

    proc.forget_foreign();
    reap_behind_the_owner(pid);
}

/// A zombie launchd holds (its tracer died) is not shown ours or reaped: `Foreign`, with a `warn`
/// saying so.
///
/// Mutant: `Awaited::Orphaned` is folded into `Gone` without a log.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_wait_and_reap_of_a_zombie_launchd_holds_warns_it_cannot_be_shown_ours() {
    use crate::wait::exit_only::seams::force_peek_once;
    use crate::wait::exit_only::{Foreign, Peek};
    crate::log_capture::install();
    let (mut proc, pid) = exited_unreaped_with(Some);
    let mark = crate::log_capture::mark();
    let _orphaned = force_peek_once(Ok(Peek::Foreign(Foreign::Orphaned)));

    assert_eq!(proc.wait_and_reap(pid), Waited::Foreign);

    let records = crate::log_capture::records_since_on_current_thread(mark, &format!("child {pid}"));
    assert!(
        records
            .iter()
            .any(|(level, text)| *level == log::Level::Warn && text.contains("cannot be shown to be ours or reaped")),
        "{records:?}"
    );
    proc.forget_foreign();
    reap_behind_the_owner(pid);
}

/// A child a tracer holds (as a debugger does) answers `ECHILD` to `waitid` and is still running.
/// `wait_and_reap` waits for the tracer's hand-back and answers `Exited`, so the zombie stays
/// reapable; it must not forget the child as "reaped by someone else", which would leave the zombie
/// for good. `TRACER`-group test, run in CI only.
///
/// Mutant: a by-pid `ECHILD` is taken for a foreign reap.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_wait_and_reap_of_a_child_a_tracer_holds_waits_for_the_hand_back(
    #[fixture(tracer_group)] _group: &Group,
) {
    use crate::test_support::tracer::{self, Mode, Report, Tracee};
    let (child, stdin) = tracer::spawn_tracee_tokio(Tracee::Plain).await;
    let pid = child.id().expect("tokio owns an un-reaped child");
    let unique = crate::signal::read_identity(pid).expect("readable");
    let mut helper = tracer::start(Mode::Auto).attach_tokio(&child);
    assert_eq!(helper.recv(), Report::Attached);
    let mut proc = ProcSource::new(child, unique);

    let waited = std::thread::scope(|s| {
        let waiter = s.spawn(|| proc.wait_and_reap(pid));
        drop(stdin);
        assert_eq!(helper.recv(), Report::Reaped);
        waiter.join().expect("the waiter")
    });

    assert_eq!(waited, Waited::Exited, "a held child is not foreign");
    assert!(!proc.is_reaped(), "the zombie is still tokio's to reap");
    drop(helper);
    let status = proc.wait().await.expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
}
