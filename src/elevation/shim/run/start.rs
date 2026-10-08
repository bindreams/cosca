//! After the answer `A`: the status pipe, the signal handlers, the program's resolution, the clone,
//! and the supervision loop, ending with the one frame (plan F, D1, D3, D8, D8c, D11).

use std::ffi::OsStr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::fs::{fcntl_setfl, OFlags};

use super::child::{self, Path, Prepared, Spawned};
use super::run_loop::Loop;
use super::signals::{self, Inherited};
use super::{Exit, Shim};
use crate::elevation::shim::codes;
use crate::elevation::shim::hooks::{Gate, Inject};
use crate::elevation::shim::program_path;
use crate::elevation::shim::protocol::{Errno, Frame, NotExecuted, ShimArgs};
use crate::elevation::shim::step::{conclude, LoopState};

/// A pipe, both ends close-on-exec.
fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = std::io::pipe()?;
    Ok((reader.into(), writer.into()))
}

fn nonblocking(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
    Ok(())
}

/// A host thread of the shim that reaps with `waitpid(-1)` once released (a test hook): `go` releases
/// it, and `done` becomes readable when it has reaped.
struct ReapingThread {
    go: OwnedFd,
    done: OwnedFd,
}

fn spawn_reaping_thread(log_fd: Option<RawFd>) -> std::io::Result<ReapingThread> {
    let (go_rx, go) = pipe()?;
    let (done, done_tx) = pipe()?;
    std::thread::Builder::new()
        .name("cosca-shim-host-reaper".into())
        .spawn(move || {
            let mut released = [0u8; 1];
            // SAFETY: `released` is valid for 1 byte.
            unsafe { libc::read(go_rx.as_raw_fd(), released.as_mut_ptr().cast(), 1) };
            let mut status = 0;
            // SAFETY: `status` is valid for the call.
            let reaped = unsafe { libc::waitpid(-1, &mut status, 0) };
            if let Some(fd) = log_fd {
                let line = format!("host thread: reaped pid {reaped}\n");
                // SAFETY: `line` is valid for its length.
                unsafe { libc::write(fd, line.as_ptr().cast(), line.len()) };
            }
            // SAFETY: one byte from a local.
            unsafe { libc::write(done_tx.as_raw_fd(), b"r".as_ptr().cast(), 1) };
        })?;
    Ok(ReapingThread { go, done })
}

/// Opens the test hook's loop-failure FIFO, non-blocking.
fn open_failure(path: &std::path::Path) -> Option<OwnedFd> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .ok()
}

pub(super) fn start_and_supervise(shim: &mut Shim, args: &ShimArgs, owner: &OwnedFd) -> Result<i32, Exit> {
    let saved_mask = signals::block_all();
    let inherited = Inherited::read();
    // The status pipe: the child's report of an `exec` failure, or of a termination before it. And
    // the pipe the shim's own signal handlers write to.
    let pipes = (|| -> std::io::Result<_> {
        if shim.injected(Inject::PipeFails) {
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        let status = pipe()?;
        let wake = pipe()?;
        nonblocking(status.0.as_fd())?;
        nonblocking(wake.0.as_fd())?;
        nonblocking(wake.1.as_fd())?;
        Ok((status, wake))
    })();
    let ((status_rx, status_tx), (wake_rx, wake_tx)) = match pipes {
        Ok(pipes) => pipes,
        Err(e) => {
            return Err(not_executed(
                shim,
                NotExecuted::SetupFailed(Errno(os_error(&e))),
                "cannot create a pipe",
                &e,
            ))
        }
    };
    signals::install(&inherited, wake_tx.as_raw_fd());
    signals::reset_sigchld();

    // D11: resolved before the clone, so that the child's only call is `execve`.
    let search = args.search_path.clone().or_else(|| std::env::var_os("PATH"));
    let exe = match program_path::resolve(&args.program, search.as_deref()) {
        Ok(exe) => exe,
        Err(Errno(errno)) => {
            let e = std::io::Error::from_raw_os_error(errno);
            let why = format!("{}", args.program.to_string_lossy());
            return Err(not_executed(shim, NotExecuted::ExecFailed(Errno(errno)), &why, &e));
        }
    };
    let argv: Vec<&OsStr> = std::iter::once(args.program.as_os_str())
        .chain(args.args.iter().map(|a| a.as_os_str()))
        .collect();
    let gate_path = shim.hooks.and_then(|h| h.child_gate());
    let prepared = Prepared::new(
        &exe,
        &argv,
        std::env::vars_os(),
        inherited,
        saved_mask,
        (status_rx.as_raw_fd(), status_tx.as_raw_fd()),
        shim.log.fd(),
        gate_path.as_deref().map(|p| p.as_os_str()),
        shim.hooks.is_some_and(|h| h.child_fault()),
    );
    let reaper = if shim.injected(Inject::ReapingHostThread) {
        match spawn_reaping_thread(shim.log.fd()) {
            Ok(reaper) => Some(reaper),
            Err(e) => {
                return Err(not_executed(
                    shim,
                    NotExecuted::SetupFailed(Errno(os_error(&e))),
                    "cannot start the host thread",
                    &e,
                ))
            }
        }
    } else {
        None
    };

    let faults = child::Faults {
        refuse_clone3: shim.injected(Inject::Clone3Enosys),
        fail: shim.injected(Inject::ForkFails),
    };
    let spawned: Result<(Spawned, Path), i32> = {
        let _lock = crate::child::spawn::spawn_lock();
        child::spawn(&prepared, faults)
    };
    let (child, path) = match spawned {
        Ok(ok) => ok,
        Err(errno) => {
            let e = std::io::Error::from_raw_os_error(errno);
            return Err(not_executed(shim, NotExecuted::ForkFailed(Errno(errno)), "fork", &e));
        }
    };
    drop(status_tx);
    shim.log
        .line(format_args!("forked child pid={} via {path:?}", child.pid));
    if let Some(reaper) = &reaper {
        // SAFETY: one byte from a local.
        unsafe { libc::write(reaper.go.as_raw_fd(), b"g".as_ptr().cast(), 1) };
    }
    shim.gate(Gate::AfterFork);
    if shim.injected(Inject::DieAfterFork) {
        shim.log.line(format_args!("seam: shim exits after fork"));
        return Err(Exit(codes::SUPERVISION));
    }
    signals::restore(&saved_mask);
    shim.log
        .line(format_args!("program pid={} (possibly started)", child.pid));
    if shim.injected(Inject::StealReap) {
        let mut status = 0;
        // SAFETY: `status` is valid for the call. A foreign reaper, played by the shim itself.
        unsafe { libc::waitpid(child.pid, &mut status, 0) };
        shim.log.line(format_args!("seam: reaped elsewhere"));
    }
    let failure = shim.hooks.and_then(|h| h.loop_failure()).and_then(|p| open_failure(&p));
    // D8c: the program has fds 0-2; the shim's own go.
    replace_stdio();
    shim.gate(Gate::BeforeLoop);

    let state = LoopState::new(shim.hooks.is_some());
    let finished = Loop {
        log: &shim.log,
        conn: shim.conn().as_fd(),
        owner: owner.as_fd(),
        child: &child,
        wake: wake_rx.as_fd(),
        status: status_rx.as_fd(),
        failure,
        host_reap_done: reaper.as_ref().map(|r| r.done.as_fd()),
        state,
    }
    .run();
    let verdict = conclude(finished.report, finished.reaped, finished.lost);
    match verdict.frame {
        Frame::NotExecuted(n) => shim
            .log
            .line(format_args!("refused 117: the program was not executed ({n:?})")),
        Frame::StatusLost => shim.log.line(format_args!(
            "status lost: the possibly-started program's status was collected by someone else"
        )),
        Frame::Lost(status) => shim.log.line(format_args!(
            "lost: the possibly-started program was killed, status {status}"
        )),
        _ => {}
    }
    if finished.conn_open {
        shim.send(verdict.frame);
    }
    Ok(verdict.exit_code)
}

/// Frame `F` and the stderr line for a failure before the program could run.
fn not_executed(shim: &Shim, report: NotExecuted, what: &str, e: &std::io::Error) -> Exit {
    shim.log
        .line(format_args!("refused {}: {what}: {e}", codes::NOT_EXECUTED));
    shim.stderr_line(format_args!(
        "{what}: {e}; the program was not started (exit {})",
        codes::NOT_EXECUTED
    ));
    shim.send(Frame::NotExecuted(report));
    Exit(codes::NOT_EXECUTED)
}

fn os_error(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// Replaces the shim's stdin, stdout and stderr with `/dev/null`.
fn replace_stdio() {
    if let Ok(null) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null") {
        for target in 0..3 {
            // SAFETY: `dup2` of a valid descriptor onto a standard one.
            unsafe { libc::dup2(null.as_raw_fd(), target) };
        }
    }
}
