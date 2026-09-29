//! The helper's state machine, run in the helper process by [`main`].
//!
//! The events are a syscall's result, `NOTE_EXIT`, `SIGCHLD` (XNU's word that the tracee
//! stopped), a signal byte (always read, since the pipe's `EVFILT_READ` is level-triggered), the
//! signal pipe's EOF, and a backoff's timeout. A backoff is the kqueue's own timeout, 1 ms
//! doubling to 50 ms, with no cap: it only paces the re-check of a real condition.
//!
//! The tracee's stops are passed through as a debugger does: a signal that stops the traced
//! tracee is delivered to it with `PT_CONTINUE`, except a `SIGSTOP` in S2 or S4, which the
//! attach and S4 send, and which `PT_CONTINUE` or `PT_DETACH` discards. A client's own `SIGSTOP`
//! is indistinguishable from those. What XNU does with a stop signal passed through in S3 to a
//! still-traced tracee is not measured.
//!
//! | State | Event or result | Next | Report |
//! |---|---|---|---|
//! | S-1 Awaiting pid | a `pid <n>` line | S0 | |
//! | S-1 | EOF, or any other line | exit | |
//! | S0 Register | `NOTE_EXIT`, `SIGCHLD` and the signal pipe registered | S1 | |
//! | S0 | a registration's receipt error | done | `error` |
//! | S1 Attach | `PT_ATTACH` succeeds | S2 (S1h under `S1:hold`) | |
//! | S1 | any error | done | `error` |
//! | S1h Held (probe) | backoff timeout, not yet `SSTOP` | S1h, sampling `pbi_status` | probe lines |
//! | S1h | backoff timeout, `SSTOP` sampled | S1hs: S1h with no more timeouts | probe lines |
//! | S1h | signal byte | S2 | |
//! | S1h | EOF | exit; XNU kills the still-traced tracee | |
//! | S1h | `NOTE_EXIT` | S5 | |
//! | S2 Release | a `SIGSTOP` (the attach's) holds the tracee: `PT_CONTINUE` succeeds | S3 | `attached` |
//! | S2 | the tracee stopped by another signal | pass it through; S2s, then S2b | |
//! | S2 | the tracee not stopped yet, or `PT_CONTINUE` fails with `EBUSY` | S2b | |
//! | S2b Backoff | timeout | retry S2's `PT_CONTINUE` | |
//! | S2b | `NOTE_EXIT`, signal byte or EOF | done: nothing may happen before `attached` | `error` |
//! | S2 | the stop peek, the pass-through or `PT_CONTINUE` fails otherwise | done | `error` |
//! | S3 Traced | `SIGCHLD`, the tracee stopped by a signal | pass it through; S3s, then S3 | |
//! | S3 | `SIGCHLD`, the tracee not stopped | S3 | |
//! | S3 | the pass-through's `PT_CONTINUE` fails with `ESRCH` (the tracee is exiting) | S3 | |
//! | S3 | the stop peek or the pass-through fails otherwise | done | `error` |
//! | S3, `auto` | `NOTE_EXIT` (wins over a byte in the same batch) | S5 | |
//! | S3, `auto` | signal byte or EOF | S4 | |
//! | S3, `hold` | `NOTE_EXIT`, then the zombie is confirmed | S3x | `exited` |
//! | S3, `hold` | `NOTE_EXIT`, but the zombie wait fails | done | `error` |
//! | S3, `hold` | signal byte or EOF, no `NOTE_EXIT` | S4 | |
//! | S3, `hold` | `NOTE_EXIT` and a signal byte or EOF in one batch | S3x, then S5 | `exited` |
//! | S3x Exited, held | signal byte or EOF | S5 | |
//! | S3x | `NOTE_EXIT` (only by injection: it is one-shot) | done | `error` |
//! | S4 Detach | `SIGSTOP` sent, then a `SIGSTOP` holds the tracee: `PT_DETACH` succeeds | done | `detached` |
//! | S4 | the tracee stopped by another signal | pass it through; S4s, then S4b | |
//! | S4 | the tracee not stopped yet, or `PT_DETACH` fails with `EBUSY` | S4b | |
//! | S4 | `SIGSTOP`, the pass-through or `PT_DETACH` fails with `ESRCH` (the tracee is exiting) | S6, or S5 if `NOTE_EXIT` was seen | |
//! | S4 | `PT_DETACH` or the pass-through fails with `EPERM` and `pbi_status` answers `ESRCH` | as `ESRCH` | |
//! | S4 | `EPERM` with anything else from `pbi_status` | done | `error` |
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
//! | any | a report or `state` write fails (`EPIPE`: the test is gone) | done | |
//! | done | signal byte (ignored) | done again | |
//! | done | EOF | exit | |
//!
//! "Done" keeps the helper alive until the client closes the signal pipe, so the tracee's state
//! after a terminal report holds until then: a reaped zombie is already the test's, and the
//! helper's own exit changes nothing the test has not been told. A helper that exits while
//! still tracing leaves XNU to kill the tracee (measured), so a failed or abandoned helper never
//! leaves it stopped.
//!
//! **Injections** (`COSCA_UH_FORCE`, a list of `<tag>:<directive>`, each entry used once, in
//! order): a state tag with an errno name or number, or `ok`, replaces that state's syscall
//! result; `S1:hold` enters S1h; `S1h`, `S2b`, `S3`, `S3x`, `S4b` and `S6` take events
//! (`NOTE_EXIT`, `SIGCHLD`, `SIGNAL`, `EOF`, joined by `+` for one batch) in place of a
//! `kevent`; `S2stop`, `S3stop` and `S4stop` replace the stop peek's answer (`SIGTERM`,
//! `SIGSTOP`, `none`, or an errno); `S2cont`, `S3cont` and `S4cont` replace the pass-through's
//! result;
//! `S4pidinfo:ESRCH|ok` replaces the `pbi_status` answer; `S4sigstop:0|1|<errno>` skips S4's
//! `SIGSTOP`, sends it, or replaces its result (by default it is sent only when `PT_DETACH` is
//! not forced, because a real stop would leave a tracee the test needs to end by EOF stopped);
//! `seed:NOTE_EXIT` marks `NOTE_EXIT` as seen from the start, for S4's "else S5" branch that no
//! real run reaches. An entry the run never uses panics the helper, failing the test.

use std::time::Duration;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use super::{sys, Mode};

const PROBE_MARKER: &str = "@@cosca-uh-probe@@";
const FIRST_BACKOFF: Duration = Duration::from_millis(1);
const MAX_BACKOFF: Duration = Duration::from_millis(50);

/// The helper process's body.
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
    if let Some(pid) = read_pid_line() {
        Machine {
            pid,
            mode,
            marker,
            trace,
            forces: &mut forces,
            note_exit_seen,
        }
        .run();
    }
    assert!(
        forces.0.is_empty(),
        "the run never used these COSCA_UH_FORCE entries: {:?}",
        forces.0
    );
}

/// S-1: reads the `pid <n>` line a byte at a time, so no later signal byte is buffered away.
fn read_pid_line() -> Option<u32> {
    let mut line = Vec::new();
    loop {
        match sys::read_byte(0)? {
            b'\n' => break,
            byte => line.push(byte),
        }
    }
    std::str::from_utf8(&line).ok()?.strip_prefix("pid ")?.parse().ok()
}

struct Forces(Vec<(String, String)>);

const FORCE_TAGS: &[&str] = &[
    "seed",
    "S0",
    "S1",
    "S1h",
    "S2",
    "S2b",
    "S2stop",
    "S2cont",
    "S3",
    "S3stop",
    "S3cont",
    "S3x",
    "S4",
    "S4b",
    "S4stop",
    "S4cont",
    "S4sigstop",
    "S4pidinfo",
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

    /// A forced stop-peek answer for `tag`, if any: a stopping signal, `none`, or an errno.
    fn stop(&mut self, tag: &str) -> Option<Result<Option<i32>, i32>> {
        self.take(tag).map(|directive| match directive.as_str() {
            "none" => Ok(None),
            "SIGTERM" => Ok(Some(libc::SIGTERM)),
            "SIGSTOP" => Ok(Some(libc::SIGSTOP)),
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
        "ENOTSUP" => libc::ENOTSUP,
        number => number
            .parse()
            .unwrap_or_else(|_| panic!("COSCA_UH_FORCE: unknown errno {number:?}")),
    }
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
        if self.note_exit {
            "NOTE_EXIT"
        } else if self.signal {
            "SIGNAL"
        } else {
            "EOF"
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

/// A report write failed (`EPIPE`): the test is gone, and the run ends.
struct Gone;

/// Why S2's or S4's stop check ended its round early.
enum Round {
    /// The stop peek failed with this errno.
    Failed(i32),
    Reported(Gone),
}

use Round::{Failed, Reported};

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
    fn done(&self) {
        while sys::read_byte(0).is_some() {
            if self.enter("done").is_err() {
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
            Err(e) => self.fail(&e.to_string(), "S0"),
        }
    }

    fn s1(&mut self) -> Step {
        self.enter("S1")?;
        let hold = match self.forces.take("S1").as_deref() {
            None => false,
            Some("hold") => true,
            Some(name) => return self.fail(&errno_named(name).to_string(), "S1"),
        };
        let attached = sys::attach(self.pid);
        if hold {
            let field = attached.map_or_else(|e| format!("errno {e}"), |()| "ok".to_string());
            probe(&format!("attach={field}"));
        }
        match attached {
            Ok(()) if hold => to(State::S1h),
            Ok(()) => to(State::S2),
            Err(e) => self.fail(&e.to_string(), "S1"),
        }
    }

    /// The feasibility probe's hold: samples `pbi_status` under the backoff until `SSTOP`, then
    /// waits for an event with no timeout.
    fn s1h(&mut self, kq: &Kqueue) -> Step {
        self.enter("S1h")?;
        let first = sys::pbi_status(self.pid);
        probe(&format!("pbi_status_first={}", fmt_status(first)));
        let mut backoff = Some(FIRST_BACKOFF);
        let mut rounds = 0u32;
        loop {
            let batch = self.wait(kq, "S1h", backoff);
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
            rounds += 1;
            let status = sys::pbi_status(self.pid);
            if status == Ok(libc::SSTOP) {
                self.enter("S1hs")?;
                probe(&format!("pbi_status_settled=4 after_rounds={rounds}"));
                let peek = match sys::stop_signal(self.pid) {
                    Ok(Some(signal)) => format!("stopped signal={signal}"),
                    Ok(None) => "running".to_string(),
                    Err(e) => format!("errno {e}"),
                };
                probe(&format!("helper_wstopped_peek={peek}"));
                backoff = None;
            } else {
                backoff = Some(next_backoff(current));
            }
        }
    }

    fn s2(&mut self, kq: &Kqueue) -> Step {
        self.enter("S2")?;
        let mut backoff = FIRST_BACKOFF;
        loop {
            let result = match self.forces.result("S2") {
                Some(forced) => forced,
                None => match self.act_once_stopped(["S2stop", "S2cont", "S2s"], sys::cont) {
                    Ok(result) => result,
                    Err(Failed(e)) => return self.fail(&e.to_string(), "S2"),
                    Err(Reported(gone)) => return Err(gone),
                },
            };
            match result {
                Ok(()) => return self.report_then("attached", to(State::S3)),
                Err(libc::EBUSY) => {
                    self.enter("S2b")?;
                    let batch = self.wait(kq, "S2b", Some(backoff));
                    if batch.any() {
                        return self.fail(batch.cause(), "S2b");
                    }
                    backoff = next_backoff(backoff);
                }
                Err(e) => return self.fail(&e.to_string(), "S2"),
            }
        }
    }

    fn s3(&mut self, kq: &Kqueue) -> Step {
        self.enter("S3")?;
        let batch = loop {
            let batch = self.wait_with(kq, "S3", None, true);
            if batch.sigchld {
                let stop = self.forces.stop("S3stop").unwrap_or_else(|| sys::stop_signal(self.pid));
                match stop {
                    Ok(Some(signal)) => {
                        let passed = self
                            .forces
                            .result("S3cont")
                            .unwrap_or_else(|| sys::cont_with(self.pid, signal));
                        match passed {
                            Ok(()) => self.enter("S3s")?,
                            // Exiting: its NOTE_EXIT follows.
                            Err(libc::ESRCH) => {}
                            Err(e) => return self.fail(&e.to_string(), "S3"),
                        }
                    }
                    Ok(None) => {}
                    Err(e) => return self.fail(&e.to_string(), "S3"),
                }
            }
            if batch.any() {
                break batch;
            }
        };
        let release = batch.signal || batch.eof;
        match (self.mode, batch.note_exit) {
            (Mode::Auto, true) => to(State::S5),
            (Mode::Hold, true) => match sys::await_zombie(self.pid) {
                Ok(()) => self.report_then("exited", to(State::S3x { release })),
                Err(e) => self.fail(&e.to_string(), "S3"),
            },
            (_, false) => to(State::S4),
        }
    }

    fn s3x(&mut self, kq: &Kqueue, release: bool) -> Step {
        self.enter("S3x")?;
        if release {
            return to(State::S5);
        }
        let batch = self.wait(kq, "S3x", None);
        if batch.note_exit {
            return self.fail("NOTE_EXIT", "S3x");
        }
        to(State::S5)
    }

    fn s4(&mut self, kq: &Kqueue) -> Step {
        self.enter("S4")?;
        let mut forced = self.forces.result("S4");
        let stopped = match self.forces.take("S4sigstop").as_deref() {
            None if forced.is_none() => sys::sigstop(self.pid),
            None | Some("0") => Ok(()),
            Some("1") => sys::sigstop(self.pid),
            Some(name) => Err(errno_named(name)),
        };
        match stopped {
            Ok(()) => {}
            Err(libc::ESRCH) => return self.exiting(),
            Err(e) => return self.fail(&e.to_string(), "S4"),
        }
        let mut backoff = FIRST_BACKOFF;
        loop {
            let result = match forced.take() {
                Some(forced) => forced,
                None => match self.act_once_stopped(["S4stop", "S4cont", "S4s"], sys::detach) {
                    Ok(result) => result,
                    Err(Failed(e)) => return self.fail(&e.to_string(), "S4"),
                    Err(Reported(gone)) => return Err(gone),
                },
            };
            match result {
                Ok(()) => return self.report_then("detached", EXIT),
                Err(libc::ESRCH) => return self.exiting(),
                Err(libc::EPERM) => {
                    // PT_DETACH's and PT_CONTINUE's only EPERM is "not traced": the tracee is
                    // past the point in exit where tracing is cleared, or this is a protocol error.
                    let gone = match self.forces.take("S4pidinfo").as_deref() {
                        Some("ESRCH") => true,
                        Some("ok") => false,
                        Some(other) => panic!("S4pidinfo takes ESRCH or ok, got {other:?}"),
                        None => sys::pbi_status(self.pid) == Err(libc::ESRCH),
                    };
                    return if gone {
                        self.exiting()
                    } else {
                        self.fail(&libc::EPERM.to_string(), "S4")
                    };
                }
                Err(libc::EBUSY) => {
                    self.enter("S4b")?;
                    if self.wait(kq, "S4b", Some(backoff)).note_exit {
                        return to(State::S5);
                    }
                    backoff = next_backoff(backoff);
                    forced = self.forces.result("S4");
                }
                Err(e) => return self.fail(&e.to_string(), "S4"),
            }
        }
    }

    /// One round of S2's or S4's stop check, `tags` naming its injections and its pass-through
    /// trace: `act` (`PT_CONTINUE` or `PT_DETACH`) once a `SIGSTOP` holds the tracee; the
    /// pass-through, then `EBUSY`, for another signal's stop; `EBUSY` while it runs.
    fn act_once_stopped(
        &mut self,
        [stop_tag, cont_tag, passed_trace]: [&str; 3],
        act: fn(u32) -> Result<(), i32>,
    ) -> Result<Result<(), i32>, Round> {
        let stop = self.forces.stop(stop_tag).unwrap_or_else(|| sys::stop_signal(self.pid));
        match stop.map_err(Failed)? {
            Some(libc::SIGSTOP) => Ok(act(self.pid)),
            Some(signal) => {
                let passed = self
                    .forces
                    .result(cont_tag)
                    .unwrap_or_else(|| sys::cont_with(self.pid, signal));
                match passed {
                    Ok(()) => {
                        self.enter(passed_trace).map_err(Reported)?;
                        Ok(Err(libc::EBUSY))
                    }
                    Err(e) => Ok(Err(e)),
                }
            }
            None => Ok(Err(libc::EBUSY)),
        }
    }

    /// S4's `ESRCH` row.
    fn exiting(&self) -> Step {
        to(if self.note_exit_seen { State::S5 } else { State::S6 })
    }

    fn s5(&mut self) -> Step {
        self.enter("S5")?;
        let mut result = self.forces.result("S5").unwrap_or_else(|| sys::reap(self.pid));
        loop {
            match result {
                Ok(()) => return self.report_then("reaped", EXIT),
                Err(libc::EINTR) => result = sys::reap(self.pid),
                Err(e) => return self.fail(&e.to_string(), "S5"),
            }
        }
    }

    /// An ignored event re-enters S6, so a test can see the self-transition.
    fn s6(&mut self, kq: &Kqueue) -> Step {
        self.enter("S6")?;
        if self.wait(kq, "S6", None).note_exit {
            to(State::S5)
        } else {
            to(State::S6)
        }
    }

    /// One `kevent` round, or the injection `tag` names. `timeout` `None` blocks.
    fn wait(&mut self, kq: &Kqueue, tag: &str, timeout: Option<Duration>) -> Batch {
        self.wait_with(kq, tag, timeout, false)
    }

    /// [`Self::wait`], reporting `SIGCHLD` only when `sigchld` (S3). Elsewhere a batch of
    /// `SIGCHLD` alone moves nothing: a timed wait returns it as its timeout, and an untimed one
    /// waits again.
    fn wait_with(&mut self, kq: &Kqueue, tag: &str, timeout: Option<Duration>, sigchld: bool) -> Batch {
        loop {
            let mut batch = match self.forces.take(tag) {
                Some(directive) => injected(tag, &directive),
                None => real_round(kq, timeout),
            };
            self.note_exit_seen |= batch.note_exit;
            batch.sigchld &= sigchld;
            if batch.any() || batch.sigchld || timeout.is_some() {
                return batch;
            }
        }
    }

    fn enter(&self, state: &str) -> Result<(), Gone> {
        if self.trace {
            self.report(&format!("state {state}"))?;
        }
        Ok(())
    }

    fn report(&self, text: &str) -> Result<(), Gone> {
        if write_report(&self.marker, text) {
            Ok(())
        } else {
            Err(Gone)
        }
    }

    fn report_then(&self, text: &str, next: Step) -> Step {
        self.report(text)?;
        next
    }

    /// Reports the failure and exits, whether or not the report could be written.
    fn fail(&self, cause: &str, state: &str) -> Step {
        match self.report(&format!("error {cause} {state}")) {
            Ok(()) | Err(Gone) => EXIT,
        }
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
    let timeout = timeout.map(|d| libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos().into(),
    });
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

/// Writes a probe line to the inherited stderr through raw `io::stderr()`: libtest captures
/// `eprintln!`, and discards it when the helper's own test passes.
fn probe(text: &str) {
    use std::io::Write as _;
    // One `write` per line: the test process writes to the same stderr pipe.
    let line = format!("{PROBE_MARKER} {text}\n");
    std::io::stderr()
        .lock()
        .write_all(line.as_bytes())
        .expect("write a probe line to stderr");
}

fn fmt_status(status: Result<u32, i32>) -> String {
    match status {
        Ok(status) => status.to_string(),
        Err(e) => format!("errno {e}"),
    }
}
