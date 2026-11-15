//! The Linux spawn core: one fork that execs, on [`fork_with_pidfd`].
//!
//! The parent builds everything the child needs ([`Program`]: argv, the env block, the candidates
//! `execve` tries) and a status channel, clones the child, and gets its pidfd from the clone. The
//! child runs the caller's `steps`, writes a ready record, and attempts the `execve`. A failed step is a
//! record on the channel and an `_exit` with the caller's code; a failed `execve` is a record and an
//! `_exit(127)`. The channel's write end is close-on-exec, so a successful `execve` closes it.
//!
//! # What the parent can know
//!
//! The parent reads the channel without blocking ([`Status::progress`]) and never waits for its end:
//! another thread's fork-without-exec may hold a copy of the write end for as long as it lives.
//!
//! - A failure record means the program did not start: a step failed, or every `execve` failed.
//! - No ready record means the child ended before it got to the `execve`: not started. A child whose
//!   ready record cannot be written ends too, with the step code, and does not exec; only a broken
//!   pipe (nobody reads) lets it exec.
//! - A ready record and no failure means the program started, or was killed between the ready record
//!   and the `execve`. [`Status::could_have_started`] says this much and no more: `Ok` means the
//!   spawn could not prove the program did not start, and the child's wait reports the signal.
//!
//! The child's writes to the channel never kill it with `SIGPIPE` and leave its signal mask,
//! disposition and pending signals as they were: a parent that dropped the read end costs the child
//! its records, not its `execve`.
//!
//! With [`CloneKind::Vfork`] the kernel holds the parent until the child's `execve` or exit, so every
//! record the child writes is in the channel when [`spawn`] returns; with [`CloneKind::Plain`] the
//! caller reads the channel as it runs on.
//!
//! # The child's contract
//!
//! The child comes from a raw clone ([`fork_with_pidfd`]): no atfork handler ran, and a lock any other
//! thread held at the clone, `malloc`'s included, is held for ever in the child. From the clone to the
//! `execve` the child makes raw system calls and async-signal-safe libc wrappers only: no allocation,
//! no formatting, no panic and no `debug_assert!` (both format), no `getenv`, no std I/O, nothing that
//! reads libc's cached thread id (`raise`, `abort`, `pthread_*`). `steps` is bound by this too, and so
//! is every function it calls. The core's own child code makes only `close`, `write`, `rt_sigprocmask`,
//! `rt_sigpending`, `rt_sigtimedwait`, `execve` and `_exit`, and calls `steps`.
//!
//! The vfork kind's child never waits on the parent: the parent is suspended until the child's `execve`
//! or exit, so a wait on it never ends. The kernel releases the parent when the child's address space
//! is released, at the `execve` or at the exit. The close-on-exec close of the pipe's write end is not
//! ordered before the release, so the end of the pipe is never read as "the `execve` happened".
//!
//! Neither the steps nor the program may close or replace the channel's write end before the `execve`.
//!
//! # Locking
//!
//! The caller holds `spawn_lock` across [`spawn`], as `fork_with_pidfd` requires.

use std::ffi::{CString, NulError, OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use rustix::io::Errno;

use crate::above_stdio::above_stdio;
use crate::os_process::linux::fork::{CloneKind, Fork, ForkFn, NewChild};

/// The program to execute, with everything `execve` is given, built before the clone so that the
/// child allocates nothing.
pub(crate) struct Program {
    /// Every candidate path, in the order the child tries them.
    candidates: Vec<*const libc::c_char>,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    /// For each candidate, `/bin/sh <candidate> <args…>`, for a program `execve` refuses with `ENOEXEC`.
    sh_argvs: Vec<Vec<*const libc::c_char>>,
    /// Keep the strings the pointers above point into alive.
    _strings: Vec<CString>,
}

const SH: &[u8] = b"/bin/sh\0";

impl Program {
    /// `candidates` in the order they are tried, `argv` (its first element is `argv[0]`), and exactly
    /// the environment `env` names. `Err` if any of them holds a NUL.
    pub(crate) fn new(
        candidates: &[OsString],
        argv: &[&OsStr],
        env: impl Iterator<Item = (OsString, OsString)>,
    ) -> Result<Program, NulError> {
        let cstring = |s: &OsStr| CString::new(s.as_bytes());
        let candidate_c = candidates.iter().map(|c| cstring(c)).collect::<Result<Vec<_>, _>>()?;
        let argv_c = argv.iter().map(|a| cstring(a)).collect::<Result<Vec<_>, _>>()?;
        let env_c = env
            .map(|(mut k, v)| {
                k.push("=");
                k.push(v);
                cstring(&k)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sh = CString::from_vec_with_nul(SH.to_vec()).expect("a literal with its NUL");
        let ptrs = |list: &[&CString]| -> Vec<*const libc::c_char> {
            list.iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect()
        };
        let argv_ptrs = ptrs(&argv_c.iter().collect::<Vec<_>>());
        let envp = ptrs(&env_c.iter().collect::<Vec<_>>());
        // `sh <candidate> <args…>`: the candidate takes the place of `argv[0]`.
        let sh_argvs = candidate_c
            .iter()
            .map(|candidate| {
                let mut list: Vec<&CString> = vec![&sh, candidate];
                list.extend(argv_c.iter().skip(1));
                ptrs(&list)
            })
            .collect();
        let candidate_ptrs = candidate_c.iter().map(|c| c.as_ptr()).collect();
        let mut strings = candidate_c;
        strings.extend(argv_c);
        strings.extend(env_c);
        strings.push(sh);
        Ok(Program {
            candidates: candidate_ptrs,
            argv: argv_ptrs,
            envp,
            sh_argvs,
            _strings: strings,
        })
    }
}

/// A step of the child that failed, in the caller's own terms. The program never runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StepFailure {
    /// What failed, as the caller numbers it.
    pub(crate) kind: u8,
    /// The errno, or whatever else the caller's kind carries; it fits 16 bits.
    pub(crate) value: u16,
}

/// Why the child ended before the program started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// A step failed.
    Step(StepFailure),
    /// Every `execve` failed; the errno is the one `execvp` would report.
    Exec(i32),
}

/// What the status channel has said so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    /// Nothing, and the channel is open: the child has not got as far as its ready record.
    Pending,
    /// The ready record, and nothing after it yet.
    Ready,
    /// The child failed before the program started.
    Failed(Failure),
    /// Every copy of the write end is closed: the `execve` closed the child's, or the child ended.
    /// `ready` is whether the ready record came first.
    Ended { ready: bool },
}

/// One record on the channel: a native-endian `u32`, `kind << 16 | value`. A write of four bytes to a
/// pipe is atomic, and the reader reads four at a time, so records never split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Record {
    Ready,
    Failed(Failure),
}

/// The kinds the core reserves; a caller's [`StepFailure::kind`] is a `u8`, so it cannot collide.
const KIND_READY: u16 = 0xffff;
const KIND_EXEC: u16 = 0xfffe;

impl Record {
    fn encode(self) -> [u8; 4] {
        let (kind, value) = match self {
            Record::Ready => (KIND_READY, 0),
            Record::Failed(Failure::Exec(errno)) => (KIND_EXEC, errno as u16),
            Record::Failed(Failure::Step(step)) => (u16::from(step.kind), step.value),
        };
        (u32::from(kind) << 16 | u32::from(value)).to_ne_bytes()
    }

    /// `Err` is the kind of a record that is neither one the core reserves nor a step's (a `u8`).
    fn decode(bytes: [u8; 4]) -> Result<Record, u16> {
        let word = u32::from_ne_bytes(bytes);
        let (kind, value) = ((word >> 16) as u16, word as u16);
        match kind {
            KIND_READY => Ok(Record::Ready),
            KIND_EXEC => Ok(Record::Failed(Failure::Exec(i32::from(value)))),
            kind => match u8::try_from(kind) {
                Ok(kind) => Ok(Record::Failed(Failure::Step(StepFailure { kind, value }))),
                Err(_) => Err(kind),
            },
        }
    }
}

/// The read end of the status channel.
#[derive(Debug)]
pub(crate) struct Status {
    read: OwnedFd,
    /// How the child was cloned: whether a channel with nothing in it means "not started".
    kind: CloneKind,
    ready: bool,
    /// A failure or the end, once read: the answer for good.
    settled: Option<Progress>,
    /// What made the channel unusable, once something did: for good.
    garbled: Option<Garbled>,
}

/// What the child never writes to the channel.
#[derive(Debug, Clone, Copy)]
enum Garbled {
    /// A read of this many bytes, fewer than a record.
    Short(usize),
    /// A record of this kind, which is neither a reserved one nor a step's.
    Kind(u16),
}

impl Garbled {
    fn error(self) -> io::Error {
        let what = match self {
            Garbled::Short(n) => format!("a short read of {n} bytes"),
            Garbled::Kind(kind) => format!("a record of kind {kind:#x}"),
        };
        io::Error::new(io::ErrorKind::InvalidData, format!("{what} from the status channel"))
    }
}

impl Status {
    /// What the channel says now, without blocking. Reads every record that is there: a failure is the
    /// answer even when the ready record is in the pipe before it, and once it or the end has been
    /// read it is the answer for good.
    ///
    /// A short read, or a record of a kind the child never writes, means something other than the
    /// child wrote to the channel: the bytes after it cannot be told from a record, so this and every
    /// later call is an error.
    pub(crate) fn progress(&mut self) -> io::Result<Progress> {
        if let Some(garbled) = self.garbled {
            return Err(garbled.error());
        }
        if let Some(settled) = self.settled {
            return Ok(settled);
        }
        loop {
            let mut bytes = [0u8; 4];
            match rustix::io::read(&self.read, &mut bytes) {
                Ok(4) => match Record::decode(bytes) {
                    Ok(Record::Ready) => self.ready = true,
                    Ok(Record::Failed(failure)) => return Ok(*self.settled.insert(Progress::Failed(failure))),
                    Err(kind) => return Err(self.garble(Garbled::Kind(kind))),
                },
                Ok(0) => return Ok(*self.settled.insert(Progress::Ended { ready: self.ready })),
                Ok(n) => return Err(self.garble(Garbled::Short(n))),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return Ok(if self.ready { Progress::Ready } else { Progress::Pending }),
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Ends the channel: a bug in debug builds, an error without them.
    fn garble(&mut self, garbled: Garbled) -> io::Error {
        self.garbled = Some(garbled);
        debug_assert!(false, "{}", garbled.error());
        garbled.error()
    }

    /// Whether the program could have started: `false` only when the channel shows that no `execve`
    /// ran. A failure, and an end with no ready record, show it. So does a channel with nothing in it
    /// yet when the clone was [`CloneKind::Vfork`]: the kernel held the parent until the child's
    /// `execve` or exit, so a child that had got as far as the ready record has written it. After a
    /// [`CloneKind::Plain`] clone the child runs beside the parent, and a channel with nothing in it
    /// shows nothing, so the answer is `true`. The one gap, both kinds: a kill between the ready
    /// record and the `execve`.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "for a spawn that reads its channel once, after the fact; the shim reads `progress`"
        )
    )]
    pub(crate) fn could_have_started(&mut self) -> io::Result<bool> {
        Ok(match self.progress()? {
            Progress::Ready | Progress::Ended { ready: true } => true,
            Progress::Pending => self.kind == CloneKind::Plain,
            Progress::Failed(_) | Progress::Ended { ready: false } => false,
        })
    }

    /// The descriptor to poll for the channel having something to say: readable on a record and on the
    /// end.
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }
}

/// The channel: a close-on-exec pipe, both ends moved out of the stdio slots, the read end
/// non-blocking.
fn channel(kind: CloneKind) -> io::Result<(Status, OwnedFd)> {
    let (read, write) = crate::pipe::pair()?;
    let read = above_stdio(OwnedFd::from(read))?;
    let write = above_stdio(OwnedFd::from(write))?;
    crate::pipe::set_nonblocking(&read)?;
    Ok((
        Status {
            read,
            kind,
            ready: false,
            settled: None,
            garbled: None,
        },
        write,
    ))
}

/// Why no child was made.
#[derive(Debug)]
pub(crate) enum SpawnError {
    /// Both clones were refused (`ENOSYS` or `EPERM`, the second's errno): the kernel or its filter
    /// cannot make a child with a pidfd.
    Unsupported(i32),
    /// The kernel refused the clone with this errno.
    Fork(i32),
    /// The status channel could not be made, with this errno.
    Pipe(i32),
}

/// The child as its parent sees it.
#[derive(Debug)]
pub(crate) struct Spawned {
    pub(crate) child: NewChild,
    pub(crate) status: Status,
}

/// Clones a child by `fork` (`fork_with_pidfd`, or a stand-in) of `kind`, which runs `steps` and then
/// `program`. A child whose step fails, or whose ready record cannot be written (a broken pipe aside),
/// exits with `step_exit`, distinct from the 127 of a failed `execve`.
///
/// # Safety
///
/// The caller holds `spawn_lock`. `steps` is bound by the child's contract (the module docs): raw
/// system calls and async-signal-safe libc wrappers only. When it returns `Err` the child writes the
/// failure and exits; it may also end the process itself. With [`CloneKind::Vfork`] it never waits on
/// the parent.
pub(crate) unsafe fn spawn(
    kind: CloneKind,
    fork: ForkFn,
    program: &Program,
    steps: &dyn Fn() -> Result<(), StepFailure>,
    step_exit: libc::c_int,
) -> Result<Spawned, SpawnError> {
    let (status, write) = channel(kind).map_err(|e| SpawnError::Pipe(e.raw_os_error().unwrap_or(libc::EIO)))?;
    // SAFETY: the caller's contract.
    match unsafe { fork(kind) } {
        Err(errno @ (libc::ENOSYS | libc::EPERM)) => Err(SpawnError::Unsupported(errno)),
        Err(errno) => Err(SpawnError::Fork(errno)),
        // SAFETY: this is the child, and the contract of `spawn` binds `steps`.
        Ok(Fork::Child) => unsafe { run_child(status.read.as_raw_fd(), write.as_raw_fd(), program, steps, step_exit) },
        Ok(Fork::Parent(child)) => {
            drop(write);
            Ok(Spawned { child, status })
        }
    }
}

/// Whether `errno` from `execve` means the next candidate is worth trying, as glibc's `execvp` reads it.
/// The shim's search reads the same errnos of its probes in `shim::program_path::classify`; the two
/// tables must agree.
fn tries_the_next(errno: libc::c_int) -> bool {
    matches!(
        errno,
        libc::ENOENT | libc::ENOTDIR | libc::ESTALE | libc::ENODEV | libc::ETIMEDOUT | libc::EACCES
    )
}

/// A signal set as the kernel's `rt_sig*` calls take it: one bit per signal, signal `n` at bit `n - 1`.
/// Eight bytes on every architecture the raw clone supports.
type KernelSigSet = u64;
const KERNEL_SIGSET_BYTES: usize = std::mem::size_of::<KernelSigSet>();
const SIGPIPE_SET: KernelSigSet = 1 << (libc::SIGPIPE - 1);

/// One `write` of `record`, retried on `EINTR`, that never kills the child with `SIGPIPE` and leaves
/// the child's signal state as it found it: `SIGPIPE` is blocked for the write, and the one a broken
/// pipe raised is taken off the queue before the mask is put back. The disposition is never touched:
/// the program inherits it. A `SIGPIPE` that was already pending is the program's and stays. `Err` is
/// the errno, or `EIO` for a write that took less than the whole record (a pipe's four-byte write is
/// whole or fails).
///
/// # Safety
///
/// Called only in the child of the clone, with a valid `fd`.
unsafe fn write_record(fd: RawFd, record: Record) -> Result<(), i32> {
    let bytes = record.encode();
    // SAFETY: the calling thread's errno.
    let errno = || unsafe { *libc::__errno_location() };
    // SAFETY: raw system calls on valid pointers to sets of the kernel's size, and `write` of `bytes`
    // for its length. The mask is the child's own: it has no `CLONE_THREAD`.
    unsafe {
        let mut mask: KernelSigSet = 0;
        if libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK as libc::c_long,
            &SIGPIPE_SET,
            &mut mask,
            KERNEL_SIGSET_BYTES,
        ) != 0
        {
            return Err(errno());
        }
        let mut pending: KernelSigSet = 0;
        libc::syscall(libc::SYS_rt_sigpending, &mut pending, KERNEL_SIGSET_BYTES);
        let written = loop {
            let n = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
            match n {
                4 => break Ok(()),
                -1 if errno() == libc::EINTR => {}
                -1 => break Err(errno()),
                _ => break Err(libc::EIO),
            }
        };
        if written == Err(libc::EPIPE) && pending & SIGPIPE_SET == 0 {
            // A dequeue, not a wait: the broken pipe queued its `SIGPIPE` before `write` returned.
            let none = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            libc::syscall(
                libc::SYS_rt_sigtimedwait,
                &SIGPIPE_SET,
                std::ptr::null_mut::<libc::c_void>(),
                &none,
                KERNEL_SIGSET_BYTES,
            );
        }
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK as libc::c_long,
            &mask,
            std::ptr::null_mut::<KernelSigSet>(),
            KERNEL_SIGSET_BYTES,
        );
        written
    }
}

/// Everything between the clone and the end of the child: the steps, the ready record, the `execve`s.
///
/// # Safety
///
/// Called only in the child of the clone, bound by the module's contract.
unsafe fn run_child(
    read: RawFd,
    write: RawFd,
    program: &Program,
    steps: &dyn Fn() -> Result<(), StepFailure>,
    step_exit: libc::c_int,
) -> ! {
    // SAFETY: raw system calls and async-signal-safe libc wrappers on valid arguments; nothing
    // allocates.
    unsafe {
        libc::close(read);
        if let Err(failure) = steps() {
            // A record that cannot be written is lost; the child ends either way.
            write_record(write, Record::Failed(Failure::Step(failure))).unwrap_or(());
            libc::_exit(step_exit)
        }
        // A broken pipe means nobody reads the records: the program runs, and its parent learns of it
        // by its wait. Any other failure leaves no ready record, which reads as "not started", so the
        // program must not start.
        match write_record(write, Record::Ready) {
            Ok(()) | Err(libc::EPIPE) => {}
            Err(_) => libc::_exit(step_exit),
        }
        // `execvp`'s rules, over candidates prepared before the clone: the next one on `ENOENT` and its
        // kin, and on `EACCES`, which is the answer only if nothing else is; anything else ends the
        // search.
        let mut errno = libc::ENOENT;
        let mut denied = false;
        let mut stopped = false;
        for (&candidate, sh_argv) in program.candidates.iter().zip(&program.sh_argvs) {
            libc::execve(candidate, program.argv.as_ptr(), program.envp.as_ptr());
            errno = *libc::__errno_location();
            if errno == libc::ENOEXEC {
                libc::execve(SH.as_ptr().cast(), sh_argv.as_ptr(), program.envp.as_ptr());
                errno = *libc::__errno_location();
            }
            if !tries_the_next(errno) {
                stopped = true;
                break;
            }
            denied |= errno == libc::EACCES;
        }
        if denied && !stopped {
            errno = libc::EACCES;
        }
        write_record(write, Record::Failed(Failure::Exec(errno))).unwrap_or(());
        libc::_exit(127)
    }
}

#[cfg(test)]
#[path = "fork_exec_tests.rs"]
mod fork_exec_tests;
