//! The helper's state machine, run in the helper process by [`main`].
//!
//! The events are a syscall's result, `NOTE_EXIT`, `SIGCHLD` (XNU's word that the tracee
//! stopped), a signal byte (always read, since the pipe's `EVFILT_READ` is level-triggered), the
//! signal pipe's EOF, and a backoff's timeout. A backoff is the kqueue's own timeout, 1 ms
//! doubling to 50 ms, with no cap: it only paces the re-check of a real condition.
//!
//! **Blocking reports.** Before every wait with no timeout the helper reports `blocking <state>
//! eof` if the signal pipe's EOF ends that wait, or `blocking <state> exit` if only the tracee's
//! exit does. It skips the report when it already made it and has reported nothing since, so a
//! re-wait after an ignored event adds none. A test reads up to the wait it expects and acts
//! there, so a wrong path fails an assertion instead of hanging.
//!
//! **Settling.** The helper acts on a stop only once it has settled, every tracee thread out of
//! the running state: see [`sys::stop`].
//!
//! **Signals.** The tracee's stops are passed on as a debugger does. XNU discards a stop signal
//! (`SIGSTOP`, `SIGTSTP`, `SIGTTIN` or `SIGTTOU` with the default action) that `PT_CONTINUE`
//! delivers to a still-traced tracee (xnu `kern_sig.c`, `issignal`). So the helper keeps the
//! first such stop signal that stops the tracee, releases the tracee without it (`S2k`, `S3k`,
//! `S4k`), and re-sends it with `kill(2)` after `PT_DETACH` (`S4r`); XNU discards it only if
//! the detach left the tracee stopped (measured on CI: sometimes on macOS 26). A `SIGCONT`
//! passed on later drops it, since it would have continued the stopped tracee. Every other
//! signal is delivered at once with `PT_CONTINUE` (`S2s`, `S3s`, `S4s`). That includes a stop
//! signal the tracee catches, which runs its handler instead of stopping, and one it ignores
//! (`SIG_IGN`), which `issignal` discards (`case SIG_IGN`) as it would without tracing: passing
//! it on loses nothing, and re-sending it after the detach would be discarded too. The tracee's
//! disposition is read from `kinfo_proc`'s `p_sigcatch` and `p_sigignore`
//! ([`sys::disposition`]) while it is stopped. A thread in user mode cannot change it under the
//! read (`task_suspend_internal` stops it); a thread blocked in the kernel inside `sigaction`
//! (say on a page fault after `copyin`, before `setsigvec`) can, so the read is a best effort
//! there (`kern_sig.c`, `sigaction`). A `SIGSTOP` in S2 or S4
//! is taken for the one the attach or S4 sent, which `PT_CONTINUE` or `PT_DETACH` discards; a
//! client's own `SIGSTOP` there is indistinguishable from it.
//!
//! | State | Event or result | Next | Report |
//! |---|---|---|---|
//! | S-1 Awaiting pid | a `pid <n>` line, `n` > 0 | S0 | |
//! | S-1 | EOF before any byte | exit | |
//! | S-1 | any other line | exit with status 3 | stderr |
//! | S0 Register | `NOTE_EXIT`, `SIGCHLD` and the signal pipe registered | S1 | |
//! | S0 | a registration's receipt error | done | `error` |
//! | S1 Attach | `PT_ATTACH` succeeds | S2 (S1h under `S1:hold`) | |
//! | S1 | any error | done | `error` |
//! | S1h Held | backoff timeout, the tracee not stopped or its stop settling | S1h | |
//! | S1h | backoff timeout, the stop settled | S1hs: S1h with no more timeouts | |
//! | S1h | the stop peek fails | done | `error` |
//! | S1h | signal byte | S2 | |
//! | S1h | EOF | done, which exits at once; XNU kills the still-traced tracee | |
//! | S1h | `NOTE_EXIT` | S5 | |
//! | S2 Release | a `SIGSTOP` (the attach's) holds the tracee: `PT_CONTINUE` succeeds | S3 | `attached` |
//! | S2 | the tracee stopped by another stop signal with the default action | keep it, release the tracee; S2k, then S2b | |
//! | S2 | the tracee stopped by any other signal, or a stop signal it catches or ignores | pass it on; S2s, then S2b | |
//! | S2 | the tracee not stopped yet or its stop settling, or `PT_CONTINUE` fails with `EBUSY` | S2b | |
//! | S2b Backoff | timeout | retry S2's stop check | |
//! | S2b | `NOTE_EXIT`, signal byte or EOF | done: nothing may happen before `attached` | `error` |
//! | S2 | the stop peek, the disposition read, the release or `PT_CONTINUE` fails otherwise | done | `error` |
//! | S3 Traced | `SIGCHLD`, the tracee stopped by a stop signal with the default action | keep it, release the tracee; S3k, then S3 | |
//! | S3 | `SIGCHLD`, the tracee stopped by any other signal, or a stop signal it catches or ignores | pass it on; S3s, then S3 | |
//! | S3 | `SIGCHLD`, the tracee not stopped | S3 | |
//! | S3 | `SIGCHLD`, the stop settling | S3 with a backoff timeout that peeks again | |
//! | S3 | the disposition read or the release fails with `ESRCH` (the tracee is exiting) | S3 | |
//! | S3 | the stop peek, the disposition read or the release fails otherwise | done | `error` |
//! | S3, `auto` | `NOTE_EXIT` (wins over a byte in the same batch) | S5 | |
//! | S3, `auto` | signal byte or EOF | S4 | |
//! | S3, `hold` | `NOTE_EXIT`, then the zombie is confirmed | S3x | `exited` |
//! | S3, `hold` | `NOTE_EXIT`, but the zombie wait fails | done | `error` |
//! | S3, `hold` | signal byte or EOF, no `NOTE_EXIT` | S4 | |
//! | S3, `hold` | `NOTE_EXIT` and a signal byte or EOF in one batch | S3x, then S5 | `exited` |
//! | S3x Exited, held | signal byte or EOF | S5 | |
//! | S3x | `NOTE_EXIT` (only by injection: it is one-shot) | done | `error` |
//! | S4 Detach | `SIGSTOP` sent, then a `SIGSTOP` holds the tracee: `PT_DETACH` succeeds, then a kept stop signal is re-sent (S4r) | done | `detached` |
//! | S4 | re-sending the kept stop signal fails | done | `error` |
//! | S4 | the tracee stopped by another stop signal with the default action | keep it, release the tracee; S4k, then S4b | |
//! | S4 | the tracee stopped by any other signal, or a stop signal it catches or ignores | pass it on; S4s, then S4b | |
//! | S4 | the tracee not stopped yet or its stop settling, or `PT_DETACH` fails with `EBUSY` | S4b | |
//! | S4 | `SIGSTOP`, the disposition read, the release or `PT_DETACH` fails with `ESRCH` (the tracee is exiting) | S6, or S5 if `NOTE_EXIT` was seen | |
//! | S4 | the stop peek fails, or any other error | done | `error` |
//! | S4b Backoff | `NOTE_EXIT` | S5 | |
//! | S4b | timeout, signal byte (ignored) or EOF | back to S4's stop check | |
//! | S5 Reap | `wait4` reaps the tracee's exit | done | `reaped` |
//! | S5 | `wait4` returns a stop instead (the tracee has not exited) | done | `error` |
//! | S5 | `EINTR` | retry S5 | |
//! | S5 | any other error | done | `error` |
//! | S6 Exiting | `NOTE_EXIT` | S5 | |
//! | S6 | signal byte (ignored) or EOF | S6 again: `NOTE_EXIT` is certain, registered while the tracee lived | |
//! | any but S3 | `SIGCHLD` alone | the same state; in a backoff it reads as the timeout | |
//! | any | a report write fails (`EPIPE`: the test is gone) | done, which exits at its own failed report | |
//! | done | signal byte (ignored) | done again | |
//! | done | EOF | exit | |
//!
//! `EPERM` from `PT_CONTINUE` or `PT_DETACH` means the tracee is not traced by this helper, a
//! protocol error: XNU's `ptrace` looks the tracee up before it checks the tracing, and an
//! exiting process leaves the lookup before its tracing is cleared, so an exiting tracee gets
//! `ESRCH` (xnu `mach_process.c`, `kern_exit.c`).
//!
//! "Done" keeps the helper alive until the client closes the signal pipe, so the tracee's state
//! after a terminal report holds until then: a reaped zombie is already the test's, and the
//! helper's own exit changes nothing the test has not been told. A helper that exits while
//! still tracing leaves XNU to kill the tracee (measured), so a failed or abandoned helper never
//! leaves it stopped.
//!
//! **Injections** (`COSCA_UH_FORCE`): a list of `<tag>:<directive>`, each entry used once, in
//! order. [`FORCE_TAGS`] lists the tags and their directives. An entry the run never uses
//! panics the helper, failing the test.

use std::time::Duration;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use super::sys::{self, Disposition, Stop};
use super::{Mode, Until};

const FIRST_BACKOFF: Duration = Duration::from_millis(1);
const MAX_BACKOFF: Duration = Duration::from_millis(50);

/// The helper's exit status after a malformed pid line.
pub(super) const MALFORMED_PID_LINE: i32 = 3;

pub(super) fn main() {
    let marker = std::env::var("COSCA_UH_MARKER").expect("COSCA_UH_MARKER is set by the client");
    let mode = match std::env::var("COSCA_UH_MODE").as_deref() {
        Ok("auto") => Mode::Auto,
        Ok("hold") => Mode::Hold,
        other => panic!("COSCA_UH_MODE must be auto or hold, got {other:?}"),
    };
    let trace = std::env::var("COSCA_UH_TRACE").as_deref() == Ok("1");
    let mut forces = Forces::parse(&std::env::var("COSCA_UH_FORCE").unwrap_or_default());
    let note_exit_seen = match forces.take("seed").as_deref() {
        None => false,
        Some("NOTE_EXIT") => true,
        Some(other) => panic!("seed takes only NOTE_EXIT, got {other:?}"),
    };
    match read_pid_line() {
        PidLine::Pid(pid) => Machine {
            pid,
            mode,
            marker,
            trace,
            forces: &mut forces,
            note_exit_seen,
            kept: None,
            blocked: None,
            eof_seen: false,
        }
        .run(),
        PidLine::Eof => {}
        PidLine::Malformed(line) => {
            use std::io::Write as _;
            let message = format!(
                "tracer helper: malformed pid line {:?}\n",
                String::from_utf8_lossy(&line)
            );
            // The exit status carries the failure if this write does not.
            std::io::stderr()
                .lock()
                .write_all(message.as_bytes())
                .unwrap_or_default();
            std::process::exit(MALFORMED_PID_LINE);
        }
    }
    assert!(
        forces.0.is_empty(),
        "the run never used these COSCA_UH_FORCE entries: {:?}",
        forces.0
    );
}

enum PidLine {
    Pid(u32),
    Eof,
    /// Anything but `pid <n>` with `n` a positive `pid_t`: a pid of 0 or below would make
    /// `kill(2)` signal a process group.
    Malformed(Vec<u8>),
}

/// Reads a byte at a time, so no later signal byte is buffered away.
fn read_pid_line() -> PidLine {
    let mut line = Vec::new();
    loop {
        match sys::read_byte(0) {
            None if line.is_empty() => return PidLine::Eof,
            None => return PidLine::Malformed(line),
            Some(b'\n') => break,
            Some(byte) => line.push(byte),
        }
    }
    let pid = std::str::from_utf8(&line)
        .ok()
        .and_then(|line| line.strip_prefix("pid "))
        .and_then(|pid| pid.parse::<libc::pid_t>().ok())
        .filter(|&pid| pid > 0);
    match pid {
        Some(pid) => PidLine::Pid(pid as u32),
        None => PidLine::Malformed(line),
    }
}

struct Forces(Vec<(String, String)>);

/// The injection tags. A state tag (`S0`, `S1`, `S2`, `S4`, `S5`) takes `ok` or an errno name
/// or number, which replaces that state's syscall result; `S1` also takes `hold`, which enters
/// S1h. `S1h`, `S2b`, `S3`, `S3x`, `S4b` and `S6` take events (`NOTE_EXIT`, `SIGCHLD`,
/// `SIGNAL`, `EOF`, joined by `+` for one batch) in place of a `kevent`. `S1hstop`, `S2stop`,
/// `S3stop` and `S4stop` replace the stop peek's answer (a signal name, `none`, `settling`, or an
/// errno); `S2cont`, `S3cont` and `S4cont` replace the release's or
/// pass-through's result, `S4r` the re-send's, and `S2disp`, `S3disp` and `S4disp` the disposition
/// read's (`default`, `caught`, `ignored`, or an errno). `S4sigstop` takes `0` to skip S4's `SIGSTOP`,
/// `1` to send it, or an errno for its result; by default it is sent only when `S4`'s result is
/// not forced, because a real stop would leave a tracee the test needs to end by EOF stopped.
/// `seed:NOTE_EXIT` marks `NOTE_EXIT` as seen from the start, for S4's "else S5" branch that no
/// real run reaches. `gone:<report>` fails the write of that report as `EPIPE` would.
const FORCE_TAGS: &[&str] = &[
    "seed",
    "gone",
    "S0",
    "S1",
    "S1h",
    "S1hstop",
    "S2",
    "S2b",
    "S2stop",
    "S2cont",
    "S2disp",
    "S3",
    "S3stop",
    "S3cont",
    "S3disp",
    "S3x",
    "S4",
    "S4b",
    "S4stop",
    "S4cont",
    "S4disp",
    "S4sigstop",
    "S4r",
    "S5",
    "S6",
];

impl Forces {
    fn parse(raw: &str) -> Forces {
        Forces(
            raw.split(',')
                .filter(|entry| !entry.is_empty())
                .map(|entry| {
                    let (tag, directive) = entry
                        .split_once(':')
                        .unwrap_or_else(|| panic!("COSCA_UH_FORCE entry {entry:?} is not <tag>:<directive>"));
                    assert!(
                        FORCE_TAGS.contains(&tag),
                        "COSCA_UH_FORCE entry {entry:?} has an unknown tag; known: {FORCE_TAGS:?}"
                    );
                    (tag.to_string(), directive.to_string())
                })
                .collect(),
        )
    }

    fn take(&mut self, tag: &str) -> Option<String> {
        let at = self.0.iter().position(|(t, _)| t == tag)?;
        Some(self.0.remove(at).1)
    }

    /// Takes the first `tag` entry whose directive is `directive`, if any.
    fn take_exact(&mut self, tag: &str, directive: &str) -> bool {
        let Some(at) = self.0.iter().position(|(t, d)| t == tag && d == directive) else {
            return false;
        };
        self.0.remove(at);
        true
    }

    /// A forced stop-peek answer for `tag`, if any: a stopping signal, `none`, `settling`, or an
    /// errno.
    fn stop(&mut self, tag: &str) -> Option<Result<Stop, i32>> {
        self.take(tag).map(|directive| match directive.as_str() {
            "none" => Ok(Stop::Running),
            "settling" => Ok(Stop::Settling),
            "SIGTERM" => Ok(Stop::Stopped(libc::SIGTERM)),
            "SIGTSTP" => Ok(Stop::Stopped(libc::SIGTSTP)),
            name => Err(errno_named(name)),
        })
    }

    /// A forced disposition read for `tag`, if any: `default`, `caught`, `ignored`, or an errno.
    fn disposition(&mut self, tag: &str) -> Option<Result<Disposition, i32>> {
        self.take(tag).map(|directive| match directive.as_str() {
            "default" => Ok(Disposition::Default),
            "caught" => Ok(Disposition::Caught),
            "ignored" => Ok(Disposition::Ignored),
            name => Err(errno_named(name)),
        })
    }

    /// A forced syscall result for `tag`, if any: `ok`, or an errno.
    fn result(&mut self, tag: &str) -> Option<Result<(), i32>> {
        self.take(tag).map(|directive| match directive.as_str() {
            "ok" => Ok(()),
            name => Err(errno_named(name)),
        })
    }
}

fn errno_named(name: &str) -> i32 {
    match name {
        "EPERM" => libc::EPERM,
        "ESRCH" => libc::ESRCH,
        "EINTR" => libc::EINTR,
        "ECHILD" => libc::ECHILD,
        "EBUSY" => libc::EBUSY,
        "EINVAL" => libc::EINVAL,
        number => number
            .parse()
            .unwrap_or_else(|_| panic!("COSCA_UH_FORCE: unknown errno {number:?}")),
    }
}

/// Whether `signal`'s default action stops the process.
fn is_stop_signal(signal: i32) -> bool {
    matches!(signal, libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU)
}

/// What one `kevent` round (or one injection) delivered. All false is a backoff's timeout.
#[derive(Default)]
struct Batch {
    note_exit: bool,
    signal: bool,
    eof: bool,
    /// Only S3 acts on it; see [`Machine::wait_with`].
    sigchld: bool,
}

impl Batch {
    fn any(&self) -> bool {
        self.note_exit || self.signal || self.eof
    }

    /// The event an `error` report names, `NOTE_EXIT` first.
    fn cause(&self) -> &'static str {
        debug_assert!(self.any(), "cause() of a batch with no event");
        match (self.note_exit, self.signal, self.eof) {
            (true, _, _) => "NOTE_EXIT",
            (false, true, _) => "SIGNAL",
            (false, false, true) => "EOF",
            (false, false, false) => unreachable!("cause() of a batch with no event"),
        }
    }
}

#[derive(Clone, Copy)]
enum State {
    S0,
    S1,
    S1h,
    S2,
    S3,
    /// `release`: a signal byte or EOF already arrived with the `NOTE_EXIT`.
    S3x {
        release: bool,
    },
    S4,
    S5,
    S6,
}

/// Where a state goes: the next state, or exit.
enum Next {
    To(State),
    Exit,
}

/// A report write failed: the test is gone.
struct Gone;

/// How one round of S2's or S4's stop check ended.
enum Check {
    /// `act`'s result, the release's or pass-through's error, or `EBUSY` while no `SIGSTOP`
    /// holds the tracee.
    Result(Result<(), i32>),
    /// The stop peek failed with this errno.
    PeekFailed(i32),
}

type Step = Result<Next, Gone>;

fn to(state: State) -> Step {
    Ok(Next::To(state))
}

const EXIT: Step = Ok(Next::Exit);

struct Machine<'f> {
    pid: u32,
    mode: Mode,
    marker: String,
    trace: bool,
    forces: &'f mut Forces,
    note_exit_seen: bool,
    /// The stop signal to re-send after `PT_DETACH`.
    kept: Option<i32>,
    /// The last `blocking` report, until any other report follows it.
    blocked: Option<String>,
    eof_seen: bool,
}

impl Machine<'_> {
    fn run(mut self) {
        let kq = Kqueue::new().expect("create the helper's kqueue");
        let mut state = State::S0;
        while let Ok(Next::To(next)) = self.step(&kq, state) {
            state = next;
        }
        self.done();
    }

    /// Holds what the reports promised until the client closes the signal pipe. Each ignored
    /// byte re-enters `done`, so a test can see the helper still holding.
    fn done(&mut self) {
        loop {
            if self.block("done", Until::Eof).is_err() || sys::read_byte(0).is_none() || self.enter("done").is_err() {
                return;
            }
        }
    }

    fn step(&mut self, kq: &Kqueue, state: State) -> Step {
        match state {
            State::S0 => self.s0(kq),
            State::S1 => self.s1(),
            State::S1h => self.s1h(kq),
            State::S2 => self.s2(kq),
            State::S3 => self.s3(kq),
            State::S3x { release } => self.s3x(kq, release),
            State::S4 => self.s4(kq),
            State::S5 => self.s5(),
            State::S6 => self.s6(kq),
        }
    }

    fn s0(&mut self, kq: &Kqueue) -> Step {
        self.enter("S0")?;
        let registered = match self.forces.result("S0") {
            Some(forced) => forced,
            None => sys::watch_signal_pipe(kq)
                .and_then(|()| sys::watch_sigchld(kq))
                .and_then(|()| sys::watch_exit(kq, self.pid)),
        };
        match registered {
            Ok(()) => to(State::S1),
            Err(e) => self.fail(e, "S0"),
        }
    }

    fn s1(&mut self) -> Step {
        self.enter("S1")?;
        let hold = match self.forces.take("S1").as_deref() {
            None => false,
            Some("hold") => true,
            Some(name) => return self.fail(errno_named(name), "S1"),
        };
        match sys::attach(self.pid) {
            Ok(()) if hold => to(State::S1h),
            Ok(()) => to(State::S2),
            Err(e) => self.fail(e, "S1"),
        }
    }

    /// Peeks under the backoff until the attach's stop has settled, then waits for an event with
    /// no timeout.
    fn s1h(&mut self, kq: &Kqueue) -> Step {
        self.enter("S1h")?;
        let mut backoff = Some(FIRST_BACKOFF);
        loop {
            let batch = self.wait(kq, "S1h", backoff)?;
            if batch.note_exit {
                return to(State::S5);
            }
            if batch.eof {
                return EXIT;
            }
            if batch.signal {
                return to(State::S2);
            }
            let Some(current) = backoff else {
                continue;
            };
            match self.forces.stop("S1hstop").unwrap_or_else(|| sys::stop(self.pid)) {
                Ok(Stop::Stopped(_)) => {
                    self.enter("S1hs")?;
                    backoff = None;
                }
                Ok(Stop::Running | Stop::Settling) => backoff = Some(next_backoff(current)),
                Err(e) => return self.fail(e, "S1h"),
            }
        }
    }

    fn s2(&mut self, kq: &Kqueue) -> Step {
        self.enter("S2")?;
        let mut backoff = FIRST_BACKOFF;
        loop {
            let result = match self.forces.result("S2") {
                Some(forced) => forced,
                None => match self.act_once_stopped("S2", sys::resume)? {
                    Check::Result(result) => result,
                    Check::PeekFailed(e) => return self.fail(e, "S2"),
                },
            };
            match result {
                Ok(()) => return self.report_then("attached", to(State::S3)),
                Err(libc::EBUSY) => {
                    self.enter("S2b")?;
                    let batch = self.wait(kq, "S2b", Some(backoff))?;
                    if batch.any() {
                        return self.fail(batch.cause(), "S2b");
                    }
                    backoff = next_backoff(backoff);
                }
                Err(e) => return self.fail(e, "S2"),
            }
        }
    }

    fn s3(&mut self, kq: &Kqueue) -> Step {
        self.enter("S3")?;
        // While a stop settles, the next wait is a backoff that re-peeks: no SIGCHLD follows.
        let mut settling = None;
        let batch = loop {
            let batch = self.wait_with(kq, "S3", settling, true)?;
            if batch.sigchld || settling.is_some() {
                let stop = self.forces.stop("S3stop").unwrap_or_else(|| sys::stop(self.pid));
                let previous = settling.take();
                match stop {
                    Ok(Stop::Stopped(signal)) => match self.pass_on("S3", signal)? {
                        // Exiting: its NOTE_EXIT follows.
                        Ok(()) | Err(libc::ESRCH) => {}
                        Err(e) => return self.fail(e, "S3"),
                    },
                    Ok(Stop::Settling) => settling = Some(previous.map_or(FIRST_BACKOFF, next_backoff)),
                    Ok(Stop::Running) => {}
                    Err(e) => return self.fail(e, "S3"),
                }
            }
            if batch.any() {
                break batch;
            }
        };
        let release = batch.signal || batch.eof;
        match (self.mode, batch.note_exit) {
            (Mode::Auto, true) => to(State::S5),
            (Mode::Hold, true) => {
                self.block("S3", Until::Exit)?;
                match sys::await_zombie(self.pid) {
                    Ok(()) => self.report_then("exited", to(State::S3x { release })),
                    Err(e) => self.fail(e, "S3"),
                }
            }
            (_, false) => to(State::S4),
        }
    }

    fn s3x(&mut self, kq: &Kqueue, release: bool) -> Step {
        self.enter("S3x")?;
        if release {
            return to(State::S5);
        }
        let batch = self.wait(kq, "S3x", None)?;
        if batch.note_exit {
            return self.fail("NOTE_EXIT", "S3x");
        }
        to(State::S5)
    }

    fn s4(&mut self, kq: &Kqueue) -> Step {
        self.enter("S4")?;
        let mut forced = self.forces.result("S4");
        let stopped = match self.forces.take("S4sigstop").as_deref() {
            None if forced.is_none() => sys::kill(self.pid, libc::SIGSTOP),
            None | Some("0") => Ok(()),
            Some("1") => sys::kill(self.pid, libc::SIGSTOP),
            Some(name) => Err(errno_named(name)),
        };
        match stopped {
            Ok(()) => {}
            Err(libc::ESRCH) => return self.exiting(),
            Err(e) => return self.fail(e, "S4"),
        }
        let mut backoff = FIRST_BACKOFF;
        loop {
            let result = match forced.take() {
                Some(forced) => forced,
                None => match self.act_once_stopped("S4", sys::detach)? {
                    Check::Result(result) => result,
                    Check::PeekFailed(e) => return self.fail(e, "S4"),
                },
            };
            match result {
                Ok(()) => return self.detached(),
                Err(libc::ESRCH) => return self.exiting(),
                Err(libc::EBUSY) => {
                    self.enter("S4b")?;
                    if self.wait(kq, "S4b", Some(backoff))?.note_exit {
                        return to(State::S5);
                    }
                    backoff = next_backoff(backoff);
                    forced = self.forces.result("S4");
                }
                Err(e) => return self.fail(e, "S4"),
            }
        }
    }

    /// After `PT_DETACH`: re-sends the kept stop signal, which XNU would have discarded.
    fn detached(&mut self) -> Step {
        if let Some(signal) = self.kept.take() {
            let sent = self.forces.result("S4r").unwrap_or_else(|| sys::kill(self.pid, signal));
            if let Err(e) = sent {
                return self.fail(e, "S4");
            }
            self.enter("S4r")?;
        }
        self.report_then("detached", EXIT)
    }

    /// One round of S2's or S4's stop check, `tag` naming its injections and traces: `act`
    /// (`PT_CONTINUE` or `PT_DETACH`) once a `SIGSTOP` holds the tracee, [`Self::pass_on`] for
    /// another signal's stop.
    fn act_once_stopped(&mut self, tag: &str, act: fn(u32) -> Result<(), i32>) -> Result<Check, Gone> {
        let stop = self
            .forces
            .stop(&format!("{tag}stop"))
            .unwrap_or_else(|| sys::stop(self.pid));
        Ok(match stop {
            Err(e) => Check::PeekFailed(e),
            Ok(Stop::Stopped(libc::SIGSTOP)) => Check::Result(act(self.pid)),
            Ok(Stop::Stopped(signal)) => match self.pass_on(tag, signal)? {
                Ok(()) => Check::Result(Err(libc::EBUSY)),
                Err(e) => Check::Result(Err(e)),
            },
            Ok(Stop::Running | Stop::Settling) => Check::Result(Err(libc::EBUSY)),
        })
    }

    /// Releases the tracee from a stop by `signal`: keeps a default-action stop signal and
    /// releases the tracee without it (`<tag>k`), or delivers any other signal (`<tag>s`),
    /// including a stop signal the tracee catches or ignores.
    fn pass_on(&mut self, tag: &str, signal: i32) -> Result<Result<(), i32>, Gone> {
        let keep = if is_stop_signal(signal) {
            match self
                .forces
                .disposition(&format!("{tag}disp"))
                .unwrap_or_else(|| sys::disposition(self.pid, signal))
            {
                Ok(Disposition::Default) => true,
                Ok(Disposition::Caught | Disposition::Ignored) => false,
                Err(e) => return Ok(Err(e)),
            }
        } else {
            false
        };
        let delivered = if keep { 0 } else { signal };
        let result = self
            .forces
            .result(&format!("{tag}cont"))
            .unwrap_or_else(|| sys::cont(self.pid, delivered));
        if result.is_ok() {
            if keep {
                self.kept.get_or_insert(signal);
            } else if signal == libc::SIGCONT {
                self.kept = None;
            }
            self.enter(&format!("{tag}{}", if keep { "k" } else { "s" }))?;
        }
        Ok(result)
    }

    fn exiting(&self) -> Step {
        to(if self.note_exit_seen { State::S5 } else { State::S6 })
    }

    fn s5(&mut self) -> Step {
        self.enter("S5")?;
        let mut result = self.forces.result("S5");
        loop {
            let reaped = match result.take() {
                Some(forced) => forced,
                None => {
                    self.block("S5", Until::Exit)?;
                    sys::reap(self.pid)
                }
            };
            match reaped {
                Ok(()) => return self.report_then("reaped", EXIT),
                Err(libc::EINTR) => {}
                Err(e) => return self.fail(e, "S5"),
            }
        }
    }

    fn s6(&mut self, kq: &Kqueue) -> Step {
        self.enter("S6")?;
        if self.wait(kq, "S6", None)?.note_exit {
            to(State::S5)
        } else {
            to(State::S6)
        }
    }

    /// One `kevent` round, or the injection `tag` names. `timeout` `None` blocks.
    fn wait(&mut self, kq: &Kqueue, tag: &str, timeout: Option<Duration>) -> Result<Batch, Gone> {
        self.wait_with(kq, tag, timeout, false)
    }

    /// [`Self::wait`], reporting `SIGCHLD` only when `sigchld` (S3). Elsewhere a batch of
    /// `SIGCHLD` alone moves nothing: a timed wait returns it as its timeout, and an untimed one
    /// waits again.
    fn wait_with(&mut self, kq: &Kqueue, tag: &str, timeout: Option<Duration>, sigchld: bool) -> Result<Batch, Gone> {
        loop {
            let mut batch = match self.forces.take(tag) {
                Some(directive) => injected(tag, &directive),
                None => {
                    if timeout.is_none() {
                        // S6 ignores EOF; every other untimed wait ends on it.
                        let until = if tag == "S6" { Until::Exit } else { Until::Eof };
                        debug_assert!(
                            until == Until::Exit || !self.eof_seen,
                            "{tag} waits for an EOF that already came"
                        );
                        self.block(tag, until)?;
                    }
                    real_round(kq, timeout)
                }
            };
            self.note_exit_seen |= batch.note_exit;
            self.eof_seen |= batch.eof;
            batch.sigchld &= sigchld;
            if batch.any() || batch.sigchld || timeout.is_some() {
                return Ok(batch);
            }
        }
    }

    fn enter(&mut self, state: &str) -> Result<(), Gone> {
        if self.trace {
            self.report(&format!("state {state}"))?;
        }
        Ok(())
    }

    /// Reports the wait about to start at `state`, unless it is the last report.
    fn block(&mut self, state: &str, until: Until) -> Result<(), Gone> {
        let text = format!(
            "blocking {state} {}",
            match until {
                Until::Eof => "eof",
                Until::Exit => "exit",
            }
        );
        if self.blocked.as_deref() != Some(text.as_str()) {
            self.report(&text)?;
            self.blocked = Some(text);
        }
        Ok(())
    }

    fn report(&mut self, text: &str) -> Result<(), Gone> {
        self.blocked = None;
        if !self.forces.take_exact("gone", text) && write_report(&self.marker, text) {
            Ok(())
        } else {
            Err(Gone)
        }
    }

    fn report_then(&mut self, text: &str, next: Step) -> Step {
        self.report(text)?;
        next
    }

    /// Reports the failure and ends the run.
    fn fail(&mut self, cause: impl std::fmt::Display, state: &str) -> Step {
        self.report_then(&format!("error {cause} {state}"), EXIT)
    }
}

fn injected(tag: &str, directive: &str) -> Batch {
    let mut batch = Batch::default();
    for event in directive.split('+') {
        match event {
            "NOTE_EXIT" => batch.note_exit = true,
            "SIGNAL" => batch.signal = true,
            "EOF" => batch.eof = true,
            "SIGCHLD" => batch.sigchld = true,
            other => panic!("{tag} takes NOTE_EXIT, SIGCHLD, SIGNAL or EOF, got {other:?}"),
        }
    }
    batch
}

fn real_round(kq: &Kqueue, timeout: Option<Duration>) -> Batch {
    let timeout = timeout.map(crate::wait::backend::kevent_timeout);
    let blank = || KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0);
    let mut events = [blank(), blank(), blank()];
    let n = loop {
        match kq.kevent(&[], &mut events, timeout) {
            Ok(n) => break n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => panic!("kevent failed: {e}"),
        }
    };
    let mut batch = Batch::default();
    for event in &events[..n] {
        match event.filter() {
            Ok(EventFilter::EVFILT_PROC) => batch.note_exit = true,
            Ok(EventFilter::EVFILT_SIGNAL) => batch.sigchld = true,
            Ok(EventFilter::EVFILT_READ) => match sys::read_byte(0) {
                Some(_) => batch.signal = true,
                None => {
                    sys::unwatch_signal_pipe(kq);
                    batch.eof = true;
                }
            },
            other => panic!("kevent returned an event of an unregistered filter: {other:?}"),
        }
    }
    batch
}

fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_BACKOFF)
}

/// Writes `\n<marker> <text>\n` to the report pipe through raw `io::stdout()` (libtest
/// captures `println!`). `false` if the write failed: the test is gone.
#[must_use]
fn write_report(marker: &str, text: &str) -> bool {
    use std::io::Write as _;
    // One `write` per line, so no other writer's bytes land inside it.
    let line = format!("\n{marker} {text}\n");
    let mut out = std::io::stdout().lock();
    out.write_all(line.as_bytes()).and_then(|()| out.flush()).is_ok()
}

#[cfg(test)]
#[path = "machine_tests.rs"]
mod machine_tests;
