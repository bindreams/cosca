//! A foreign tracer for tests, as `gdb -p` is one: a re-exec of this test binary that seizes one of
//! the test's own children with `ptrace` without being its parent (`TRACER` group; needs
//! `COSCA_TEST_TRACER_CONSENT=1`).
//!
//! A tracee that dies while a foreign tracer holds it is a zombie the tracer alone can see: its
//! pidfd is readable, the parent's `waitid` finds no record, and the parent's own record appears
//! only after the tracer hands the zombie back: by reaping it with `waitpid`, or by exiting
//! (`exit_ptrace` detaches it; a debugger that quits). The tracer is [`foreign_tracer_helper`].
//!
//! A test takes `tracer_group`. A tracee that calls [`allow_any_tracer_now`] itself reports that it
//! returned, and the test reads that report before [`spawn_helper`]. [`Tracer`] calls block; a test
//! whose own thread blocks until the tracer hands the zombie back drives it from another thread.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};

#[cfg(feature = "tokio")]
use crate::test_child::Console;
use std::os::unix::process::CommandExt as _;
use std::process::{ChildStdin, ChildStdout};

use crate::containment::cgroup::test_support::KillOnDrop;
use crate::test_child::{fixture_command, fixture_path, is_marked_fixture_reexec};

/// Marks the helper re-exec; the value is the driver's pid.
const MARKER: &str = "COSCA_TESTCFG_SHARED_FOREIGN_TRACER";

const PID_ENV: &str = "COSCA_TESTCFG_SHARED_FOREIGN_TRACER_PID";

/// Set (to anything) for a helper that seizes its tracee with `PTRACE_O_TRACEEXIT`.
const HOLD_EXIT_ENV: &str = "COSCA_TESTCFG_SHARED_FOREIGN_TRACER_HOLD_EXIT";

/// The go bytes. `STOP` makes the helper stop the tracee and report it; `LET_EXIT` lets a tracee
/// held at its exit stop on from it; `REAP` and `EXIT` hand the zombie back.
pub(crate) const STOP: u8 = b's';
pub(crate) const LET_EXIT: u8 = b'c';
pub(crate) const REAP: u8 = b'r';
pub(crate) const EXIT: u8 = b'x';

fn say(line: &str) {
    // Not `println!`: it panics on a write error.
    writeln!(std::io::stdout(), "@@{line}@@").expect("write to the driver");
}

/// `waitpid(pid, __WALL)`, past `EINTR`.
fn waitpid_status(pid: libc::pid_t) -> libc::c_int {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if r != -1 {
            return status;
        }
        let e = std::io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(libc::EINTR), "waitpid: {e}");
    }
}

/// The foreign tracer: seize the pid in [`PID_ENV`] (or, without it, the pid on stdin's first line),
/// report, and act on each go byte from stdin:
/// `STOP` interrupts the tracee and reports the stop, `LET_EXIT` waits for the tracee's exit stop and
/// lets it on from it, `REAP` reaps the zombie with `waitpid` and reports, `EXIT` exits without
/// reaping. A no-op unless it is the re-exec the driver started.
///
/// It seizes with no options (unless [`spawn_helper_holding_exit`] asked for `PTRACE_O_TRACEEXIT`),
/// so the kill is not delayed by an exit stop, and the pidfd turns readable at the zombie. A tracee
/// held at its exit stop is still alive: it is a member of its cgroup, and no pidfd is readable.
#[skuld::test]
fn foreign_tracer_helper() {
    if !is_marked_fixture_reexec(MARKER) {
        return;
    }
    let pid: libc::pid_t = match std::env::var(PID_ENV) {
        Ok(pid) => pid,
        // Started before its tracee existed: see [`spawn_unseized_helper`].
        Err(_) => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).expect("the tracee's pid");
            line
        }
    }
    .trim()
    .parse()
    .expect("a pid");
    // SAFETY: a ptrace request on a pid; variadic `addr`/`data` are read as pointers: typed nulls.
    let null = std::ptr::null_mut::<libc::c_void>;
    let options = if std::env::var_os(HOLD_EXIT_ENV).is_some() {
        libc::PTRACE_O_TRACEEXIT
    } else {
        0
    };
    let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, null(), options as usize as *mut libc::c_void) };
    assert_eq!(rc, 0, "PTRACE_SEIZE: {}", std::io::Error::last_os_error());
    say("seized");
    loop {
        let mut go = [0u8; 1];
        std::io::stdin().read_exact(&mut go).expect("the driver's go byte");
        match go[0] {
            EXIT => return,
            STOP => {
                // SAFETY: as above.
                let rc = unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, pid, null(), null()) };
                assert_eq!(rc, 0, "PTRACE_INTERRUPT: {}", std::io::Error::last_os_error());
                let status = waitpid_status(pid);
                assert!(libc::WIFSTOPPED(status), "waitpid: not a stop: {status:#x}");
                say("stopped");
            }
            LET_EXIT => {
                let status = waitpid_status(pid);
                assert!(
                    libc::WIFSTOPPED(status) && status >> 16 == libc::PTRACE_EVENT_EXIT,
                    "waitpid: not the exit stop: {status:#x}"
                );
                // SAFETY: as above.
                let rc = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, null(), null()) };
                assert_eq!(rc, 0, "PTRACE_CONT: {}", std::io::Error::last_os_error());
                say("continued");
            }
            REAP => {
                // The driver saw the pidfd readable, so a killed tracee is a zombie, which `waitpid`
                // reports before any stop. One that was not killed and ran on to its own exit
                // reports the signals it was sent first (`SIGPIPE` on its closed stdout, say): a
                // debugger lets each one through, as `gdb` does.
                let status = loop {
                    let status = waitpid_status(pid);
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        break status;
                    }
                    assert!(
                        libc::WIFSTOPPED(status),
                        "waitpid: neither a stop nor an exit: {status:#x}"
                    );
                    // A signal-delivery-stop passes its signal on; an event or group stop passes none.
                    let signal = if status >> 16 == 0 { libc::WSTOPSIG(status) } else { 0 };
                    // SAFETY: as above.
                    let rc =
                        unsafe { libc::ptrace(libc::PTRACE_CONT, pid, null(), signal as usize as *mut libc::c_void) };
                    assert_eq!(rc, 0, "PTRACE_CONT: {}", std::io::Error::last_os_error());
                };
                say(&format!("exit {status}"));
                say("reaped");
                return;
            }
            other => panic!("an unknown go byte {other:#x}"),
        }
    }
}

/// Lets any process trace the child `cmd` spawns: it calls [`allow_any_tracer_now`] before exec.
pub(crate) fn allow_any_tracer(cmd: &mut std::process::Command) {
    // SAFETY: `allow_any_tracer_now` is a raw `prctl` syscall, async-signal-safe, and touches only
    // the forked child.
    unsafe {
        cmd.pre_exec(allow_any_tracer_now);
    }
}

/// A [`BLOCKER_ARGV`](crate::test_child::BLOCKER_ARGV) child that any tracer may seize, its stdin held
/// open by the returned `Child`, which a test keeps until the child is gone. Spawned under
/// `spawn_lock`.
#[cfg(feature = "tokio")]
pub(crate) fn blocker() -> std::process::Child {
    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    allow_any_tracer(&mut cmd);
    crate::test_spawn::spawn(&mut cmd).expect("spawn the tracee")
}

/// Lets any process trace this one (`PR_SET_PTRACER`), which Yama's scope 1 requires of a tracer
/// that is no ancestor. For a tracee that cannot take [`allow_any_tracer`], such as one spawned by
/// `cosca::tokio::Command`, which has no `pre_exec`. Until it returns, [`spawn_helper`]'s seize
/// fails: the tracee reports after it, and the driver reads that report first.
pub(crate) fn allow_any_tracer_now() -> std::io::Result<()> {
    match rustix::process::set_ptracer(rustix::process::PTracer::Any) {
        // `INVAL`: no Yama, so nothing restricts a tracer and nothing needs allowing.
        Ok(()) | Err(rustix::io::Errno::INVAL) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A running foreign tracer.
pub(crate) struct Tracer {
    helper: std::process::Child,
    /// Ends the helper when the driver leaves, whatever the way.
    ends_helper: KillOnDrop,
    go: Option<ChildStdin>,
    lines: std::io::Lines<BufReader<ChildStdout>>,
}

/// Starts the helper on `pid`, which was spawned with [`allow_any_tracer`] or has reported that its
/// [`allow_any_tracer_now`] returned, and returns once it has seized the tracee.
pub(crate) fn spawn_helper(pid: u32) -> Tracer {
    let mut tracer = start_helper(Some(pid), false);
    tracer.expect("seized");
    tracer
}

/// [`spawn_helper`] whose tracee stops at its exit (`PTRACE_O_TRACEEXIT`) and stays a live member of
/// its cgroup, whatever kills it, until the tracer sends [`LET_EXIT`].
#[cfg(feature = "tokio")]
pub(crate) fn spawn_helper_holding_exit(pid: u32) -> Tracer {
    let mut tracer = start_helper(Some(pid), true);
    tracer.expect("seized");
    tracer
}

/// Starts the helper before its tracee exists, for a test that cannot start one once it does (its
/// spawning thread holds `spawn_lock` until the tracee dies); [`Tracer::seize`] names the tracee.
#[cfg_attr(
    not(feature = "tokio"),
    allow(dead_code, reason = "only the tokio spawn's tracer test uses it")
)]
pub(crate) fn spawn_unseized_helper() -> Tracer {
    start_helper(None, false)
}

fn start_helper(pid: Option<u32>, hold_exit: bool) -> Tracer {
    let mut cmd = fixture_command(fixture_path!(foreign_tracer_helper));
    if let Some(pid) = pid {
        cmd.env(PID_ENV, pid.to_string());
    }
    cmd.env(MARKER, std::process::id().to_string())
        .env_remove(HOLD_EXIT_ENV)
        .env_remove("RUST_TEST_NOCAPTURE")
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    if hold_exit {
        cmd.env(HOLD_EXIT_ENV, "1");
    }
    let mut helper = crate::test_spawn::spawn(&mut cmd).expect("spawn the foreign tracer");
    let ends_helper = KillOnDrop::of(&helper);
    let go = helper.stdin.take().expect("piped stdin");
    let lines = BufReader::new(helper.stdout.take().expect("piped stdout")).lines();
    Tracer {
        helper,
        ends_helper,
        go: Some(go),
        lines,
    }
}

impl Tracer {
    /// Has a helper from [`spawn_unseized_helper`] seize `pid`, which has reported that its
    /// [`allow_any_tracer_now`] returned, and returns once it has.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only the tokio spawn's tracer test uses it")
    )]
    pub(crate) fn seize(&mut self, pid: u32) {
        writeln!(self.go.as_mut().expect("the tracer is still driven"), "{pid}").expect("send the helper the pid");
        self.expect("seized");
    }

    /// Sends one go byte ([`STOP`], [`REAP`] or [`EXIT`]).
    pub(crate) fn send(&mut self, go_byte: u8) {
        self.go
            .as_mut()
            .expect("the tracer is still driven")
            .write_all(&[go_byte])
            .expect("send the helper a go byte");
    }

    /// Waits for the helper's `@@<expected>@@` line. Matches by suffix: the harness's
    /// `test <name> ... ` prefix may precede it.
    pub(crate) fn expect(&mut self, expected: &str) {
        let want = format!("@@{expected}@@");
        for line in &mut self.lines {
            if line.expect("read the helper's stdout").ends_with(&want) {
                return;
            }
        }
        panic!("the helper ended without reporting {expected:?}");
    }

    /// Waits for the helper's `@@reaped@@` line, as [`expect`](Self::expect) does, and answers the wait
    /// status it reaped the tracee with (`REAP` reports it just before).
    #[cfg(feature = "tokio")]
    pub(crate) fn expect_reaped(&mut self) -> libc::c_int {
        let mut status = None;
        for line in &mut self.lines {
            let line = line.expect("read the helper's stdout");
            if let Some((_, rest)) = line.split_once("@@exit ") {
                status = Some(rest.trim_end_matches("@@").parse().expect("the helper's wait status"));
            } else if line.ends_with("@@reaped@@") {
                return status.expect("the helper reports the status before it reaps");
            }
        }
        panic!("the helper ended without reporting \"reaped\"");
    }

    /// Closes the helper's stdin and waits for it to exit cleanly.
    pub(crate) fn finish(mut self) {
        drop(self.go.take());
        let status = self.helper.wait().expect("the helper exits");
        // Reaped: the guard's pidfd would refuse a kill of it.
        _ = self.ends_helper.defuse();
        assert!(status.success(), "{status:?}");
    }
}

/// Marks the [`tokio_tracee`] re-exec; the value is the driver's pid.
#[cfg(feature = "tokio")]
const TRACEE_MARKER: &str = "COSCA_TESTCFG_FOREIGN_TRACER_TOKIO_TRACEE";

/// A tracee for a `cosca::tokio::Command`, which has no `pre_exec`: it calls
/// [`allow_any_tracer_now`], reports `allowed`, and reads stdin to EOF. A no-op unless it is the
/// re-exec [`spawn_tokio_tracee`] started.
#[cfg(feature = "tokio")]
#[skuld::test]
fn tokio_tracee() {
    let driver = std::env::var(TRACEE_MARKER).ok();
    if driver != Some(std::os::unix::process::parent_id().to_string()) {
        return;
    }
    allow_any_tracer_now().expect("allow any tracer");
    say("allowed");
    std::io::copy(&mut std::io::stdin(), &mut std::io::sink()).expect("read stdin to EOF");
}

/// A `cosca::tokio::Command` for [`tokio_tracee`], with no stdio set: its `allowed` report goes to
/// its stdout.
#[cfg(feature = "tokio")]
pub(crate) fn tokio_tracee_command() -> crate::tokio::Command {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(crate::test_child::fixture_argv(fixture_path!(tokio_tracee)));
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    cmd.env(TRACEE_MARKER, std::process::id().to_string());
    cmd
}

/// Spawns [`tokio_tracee`] as a kill-on-drop `cosca::tokio::Child` and returns it, with its stdin,
/// once [`spawn_helper`] may seize it.
#[cfg(feature = "tokio")]
pub(crate) async fn spawn_tokio_tracee() -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    use ::tokio::io::AsyncBufReadExt as _;

    let mut cmd = tokio_tracee_command();
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    let mut child = cmd.spawn().await.expect("spawn the tracee");
    let stdin = child.stdin().expect("piped stdin");
    let mut lines = ::tokio::io::BufReader::new(child.stdout().expect("piped stdout")).lines();
    loop {
        let line = lines.next_line().await.expect("read the tracee's stdout");
        match line {
            Some(line) if line.ends_with("@@allowed@@") => return (child, stdin),
            Some(_) => {}
            None => panic!("the tracee ended without reporting \"allowed\""),
        }
    }
}

/// Who a failed spawn's slow-teardown warn names, for [`assert_warns_once_before_blocking`].
#[cfg(feature = "tokio")]
#[derive(Clone, Copy)]
pub(crate) enum Names {
    /// `child <pid>`, the pid `seized` answers.
    Pid,
    /// The spawned child whose pid the teardown does not know.
    Unknown,
}

/// The end of the one warn of a teardown's wait for the child it killed. At threshold zero a cgroup
/// leaf's drain warns too ("still waiting for it to drain"), and is not what these tests count.
#[cfg(feature = "tokio")]
const WAITING_FOR_EXIT: &str = "still waiting for it to exit";

/// What the teardown thread of [`assert_warns_once_before_blocking`] was doing when the test looked.
#[cfg(feature = "tokio")]
enum TeardownLook {
    /// It reached its first block or pause; `warned`: the warn of its wait for the child was out.
    Held { warned: bool },
    /// It returned (or panicked) with no block or pause: the tracer still held the zombie.
    Returned,
}

/// The slow-teardown threshold [`hold_teardown`]'s thread runs under.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy)]
enum Threshold {
    /// Due at once: the teardown's first bounded look is its last.
    Zero,
    /// Due after this long on a clock frozen when the thread starts, whose elapsed time is pinned
    /// to zero: no time passes unless the test says so, so the warn is never due.
    Frozen(std::time::Duration),
}

/// What [`hold_teardown`] found, before any assertion on it.
#[cfg(feature = "tokio")]
struct Held<R> {
    pid: u32,
    look: TeardownLook,
    /// Every warn of a wait for a child's exit since the call, whoever it names, and its levels.
    warns: Vec<String>,
    levels: Vec<log::Level>,
    status: i32,
    done: R,
}

/// Runs `teardown` on a thread of its own, under `threshold`, until the thread reaches its first
/// block or recheck pause, or returns; a leaf's drain is neither (the zombie the tracer holds is out
/// of the leaf). Then the tracer `seized` answers hands the zombie of its child back (`seized` runs
/// once the thread has started). The hooks only send: a panic in one would leave an armed drop
/// waiting on the zombie the tracer holds.
#[cfg(feature = "tokio")]
fn hold_teardown<R: Send>(
    threshold: Threshold,
    teardown: impl FnOnce() -> R + Send,
    seized: impl FnOnce() -> (u32, Tracer),
) -> Held<R> {
    use crate::wait::block_probe::{is_drain_wait, on_each_block, on_pause};

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (look_tx, look_rx) = std::sync::mpsc::channel::<bool>();

    // A panic inside the scope drops `tracer` first, and its helper's death hands the zombie back,
    // so the scope's join of the teardown thread ends.
    std::thread::scope(|s| {
        let thread = s.spawn(move || {
            let (_clock, _zero, _warn);
            match threshold {
                Threshold::Zero => _warn = crate::tokio::warn_slow_teardowns_after(std::time::Duration::ZERO),
                Threshold::Frozen(after) => {
                    _clock = crate::wait::test_clock::FrozenClockGuard::install();
                    _zero = crate::wait::test_clock::ZeroElapsedGuard::install();
                    _warn = crate::tokio::warn_slow_teardowns_after(after);
                }
            }
            // The senders live in the hooks alone, so a teardown that returns without a block or
            // pause closes the channel.
            let report = |tx: std::sync::mpsc::Sender<bool>| {
                move || {
                    let warned =
                        !crate::log_capture::records_since_on_current_thread(mark, WAITING_FOR_EXIT).is_empty();
                    _ = tx.send(warned);
                }
            };
            let at_block = report(look_tx.clone());
            let at_pause = report(look_tx);
            let _block = on_each_block(move |block| {
                if !is_drain_wait(block) {
                    at_block();
                }
            });
            let _pause = on_pause(at_pause);
            teardown()
        });
        let (pid, mut tracer) = seized();
        let look = match look_rx.recv() {
            Ok(warned) => TeardownLook::Held { warned },
            Err(_) => TeardownLook::Returned,
        };
        tracer.send(REAP);
        let status = tracer.expect_reaped();
        // A panic of the teardown's own (a contract message) is the test's.
        let done = thread.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        Held {
            pid,
            look,
            warns: crate::log_capture::records_since(mark, WAITING_FOR_EXIT),
            levels: crate::log_capture::levels_since(mark, WAITING_FOR_EXIT),
            status,
            done,
        }
    })
}

/// The tracee died of a `SIGKILL`, not of its own exit once the test released its stdin.
#[cfg(feature = "tokio")]
fn assert_killed(pid: u32, status: i32) {
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
        "the teardown's kill must end child {pid}, not its own exit once its stdin was released: {status:#x}"
    );
}

/// [`hold_teardown`] at threshold zero, which makes the warn due before the teardown's first block
/// or pause, with no clock involved. Asserts that the teardown did not return before the tracer let
/// go, that its first block or pause came after the warn, that exactly one warn, naming the child as
/// `names` says, said it was still waiting, and that the tracee died of a `SIGKILL`. Answers what
/// `teardown` returned.
///
/// A teardown that never warns, or whose kill sends nothing, fails an assertion here instead of
/// hanging: the tracer lets go at the first block or pause whatever the warn. The threshold is
/// zero for `teardown` and anything it reads on its thread; a caller that reads it earlier, on its
/// own thread, sets zero itself ([`crate::tokio::warn_slow_teardowns_after`]).
#[cfg(feature = "tokio")]
pub(crate) fn assert_warns_once_before_blocking<R: Send>(
    names: Names,
    teardown: impl FnOnce() -> R + Send,
    seized: impl FnOnce() -> (u32, Tracer),
) -> R {
    let Held {
        pid,
        look,
        warns,
        levels,
        status,
        done,
    } = hold_teardown(Threshold::Zero, teardown, seized);
    match look {
        TeardownLook::Held { warned: true } => {}
        TeardownLook::Held { warned: false } => {
            panic!("the teardown blocked or paused before it warned that it was still waiting for child {pid}")
        }
        TeardownLook::Returned => panic!("the teardown returned while the tracer still held child {pid}'s zombie"),
    }
    assert_killed(pid, status);
    let who = match names {
        Names::Pid => format!("child {pid}"),
        Names::Unknown => "pid unknown".to_owned(),
    };
    let named: Vec<_> = warns.iter().filter(|text| text.contains(&who)).collect();
    assert_eq!(named.len(), 1, "one warn before the blocking wait: {warns:?}");
    assert_eq!(levels, [log::Level::Warn], "exactly one warn, at warn");
    done
}

/// [`hold_teardown`] at a threshold of `after` on a frozen clock that no one advances, so the
/// teardown ends before the threshold: the tracer lets go at its first block or pause and the
/// teardown reaps the child. Asserts that no warn was said, that the first block or pause came
/// with none out, and that the tracee died of a `SIGKILL`. Answers what `teardown` returned.
///
/// A teardown that warns at once fails an assertion here. The frozen clock is the thread's: a
/// `teardown` that reads its threshold on its own thread, as the handshake's does, sees `after`.
#[cfg(feature = "tokio")]
pub(crate) fn assert_no_warn_before_the_threshold<R: Send>(
    after: std::time::Duration,
    teardown: impl FnOnce() -> R + Send,
    seized: impl FnOnce() -> (u32, Tracer),
) -> R {
    let Held {
        pid,
        look,
        warns,
        status,
        done,
        ..
    } = hold_teardown(Threshold::Frozen(after), teardown, seized);
    if matches!(look, TeardownLook::Returned) {
        panic!("the teardown returned while the tracer still held child {pid}'s zombie");
    }
    assert_killed(pid, status);
    assert!(warns.is_empty(), "no warn before the threshold passed: {warns:?}");
    done
}

/// [`assert_warns_once_before_blocking`] for a tracee `pid` that exists already: the teardown starts
/// only once the tracer has seized it.
#[cfg(feature = "tokio")]
pub(crate) fn assert_warns_once_after_seizing<R: Send>(
    names: Names,
    pid: u32,
    teardown: impl FnOnce() -> R + Send,
) -> R {
    let (seized_tx, seized_rx) = std::sync::mpsc::channel();
    assert_warns_once_before_blocking(
        names,
        move || {
            seized_rx.recv().expect("the tracer seized the child");
            teardown()
        },
        move || {
            let tracer = spawn_helper(pid);
            seized_tx.send(()).expect("let the teardown go on");
            (pid, tracer)
        },
    )
}

/// At least one child was reaped by a teardown, and each died of `SIGKILL`: the teardown's kill was
/// delivered, and the child did not exit `0` on its stdin's release.
#[cfg(feature = "tokio")]
#[track_caller]
pub(crate) fn assert_reaped_by_sigkill(reaps: &[(u32, std::process::ExitStatus)]) {
    use std::os::unix::process::ExitStatusExt as _;

    assert!(!reaps.is_empty(), "the teardown must have reaped the child");
    for (pid, status) in reaps {
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "pid {pid} must be SIGKILLed by its teardown kill, not exit once its stdin was released: {status:?}"
        );
    }
}
