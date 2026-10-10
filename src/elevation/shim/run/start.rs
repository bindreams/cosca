//! After the answer `A`: the status pipe, the program's resolution, the clone, the check that cosca
//! is still there, and the supervision loop, ending with the one frame.

use std::ffi::OsStr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

use rustix::fs::OFlags;
use rustix::process::{Pid, WaitOptions};

use super::child::{self, Path, Prepared, Spawned};
use super::fds::replace_stdio;
use super::run_loop::Loop;
use super::signals;
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

fn nonblocking(fd: &OwnedFd) -> std::io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    rustix::fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
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
            _ = rustix::io::read(&go_rx, &mut released);
            let reaped = rustix::process::wait(WaitOptions::empty());
            if let Some(fd) = log_fd {
                let pid = reaped.ok().flatten().map_or(-1, |(pid, _)| pid.as_raw_nonzero().get());
                let line = format!("host thread: reaped pid {pid}\n");
                // SAFETY: the hooks own the log descriptor for the life of the process.
                _ = rustix::io::write(unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }, line.as_bytes());
            }
            _ = rustix::io::write(&done_tx, b"r");
        })?;
    Ok(ReapingThread { go, done })
}

/// Opens the test hook's loop-failure FIFO, non-blocking. A test that asked for it and gets none
/// would pass without testing, so this panics.
fn open_failure(path: &std::path::Path) -> OwnedFd {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap_or_else(|e| panic!("the loop-failure seam: cannot open {}: {e}", path.display()))
}

pub(super) fn start_and_supervise(shim: &mut Shim, args: &ShimArgs, owner: &OwnedFd) -> Result<i32, Exit> {
    let saved_mask = signals::block_all();
    let inherited = shim.inherited.take().expect("the signals are caught before hello");
    // The status pipe: the child's report of an `exec` failure, or of a termination before it. And
    // the release pipe, which holds the child until cosca has been seen alive after the clone.
    let pipes = (|| -> std::io::Result<_> {
        if shim.injected(Inject::PipeFails) {
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        let status = pipe()?;
        let release = pipe()?;
        nonblocking(&status.0)?;
        Ok((status, release))
    })();
    let ((status_rx, status_tx), (release_rx, release_tx)) = match pipes {
        Ok(pipes) => pipes,
        Err(e) => {
            return Err(shim.not_executed(
                NotExecuted::SetupFailed(Errno(os_error(&e))),
                "cannot create a pipe",
                &e,
            ))
        }
    };
    signals::reset_sigchld();

    // Resolved before the clone, so that the child's only calls are `execve`.
    let search = args.search_path.clone().or_else(|| std::env::var_os("PATH"));
    let candidates = match program_path::resolve(&args.program, search.as_deref()) {
        Ok(candidates) => candidates,
        Err(Errno(errno)) => {
            let e = std::io::Error::from_raw_os_error(errno);
            let why = args.program.to_string_lossy().into_owned();
            return Err(shim.not_executed(NotExecuted::ExecFailed(Errno(errno)), &why, &e));
        }
    };
    let argv: Vec<&OsStr> = std::iter::once(args.program.as_os_str())
        .chain(args.args.iter().map(|a| a.as_os_str()))
        .collect();
    let gate_path = shim.hooks.and_then(|h| h.child_gate());
    let prepared = Prepared::new(
        &candidates,
        &argv,
        std::env::vars_os(),
        inherited,
        saved_mask,
        (status_rx.as_raw_fd(), status_tx.as_raw_fd()),
        (release_rx.as_raw_fd(), release_tx.as_raw_fd()),
        shim.log.fd(),
        gate_path.as_deref().map(|p| p.as_os_str()),
        shim.hooks.is_some_and(|h| h.child_fault()),
        shim.injected(Inject::ChildSetupFails),
    );
    let reaper = if shim.injected(Inject::ReapingHostThread) {
        match spawn_reaping_thread(shim.log.fd()) {
            Ok(reaper) => Some(reaper),
            Err(e) => {
                return Err(shim.not_executed(
                    NotExecuted::SetupFailed(Errno(os_error(&e))),
                    "cannot start the host thread",
                    &e,
                ))
            }
        }
    } else {
        None
    };

    shim.gate(Gate::BeforeClone);
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
            return Err(shim.not_executed(NotExecuted::ForkFailed(Errno(errno)), "fork", &e));
        }
    };
    drop((status_tx, release_rx));
    shim.log
        .line(format_args!("forked child pid={} via {path:?}", child.pid));
    // The child has its own copy of the blocked mask, and keeps it until its handlers are set up. The
    // shim's own signals are delivered from here on, those that arrived meanwhile first.
    signals::restore(&saved_mask);
    // The child is held before it arms anything. If cosca left, or a signal came, while the shim
    // prepared the start, the program never runs.
    shim.check_owner(owner, Some(&child))?;
    drop(release_tx);
    if let Some(reaper) = &reaper {
        _ = rustix::io::write(&reaper.go, b"g");
    }
    shim.gate(Gate::AfterFork);
    if shim.injected(Inject::DieAfterFork) {
        shim.log.line(format_args!("seam: shim exits after fork"));
        return Err(Exit(codes::SUPERVISION));
    }
    shim.log
        .line(format_args!("program pid={} (possibly started)", child.pid));
    if shim.injected(Inject::StealReap) {
        // A foreign reaper, played by the shim itself.
        _ = Pid::from_raw(child.pid).map(|pid| rustix::process::waitpid(Some(pid), WaitOptions::empty()));
        shim.log.line(format_args!("seam: reaped elsewhere"));
    }
    let failure = shim.hooks.and_then(|h| h.loop_failure()).map(|p| open_failure(&p));
    // The program has fds 0-2; the shim's own go.
    replace_stdio(&shim.log);
    shim.gate(Gate::BeforeLoop);

    let state = LoopState::new(shim.hooks.is_some());
    let finished = Loop {
        log: &shim.log,
        conn: shim.conn().as_fd(),
        owner: owner.as_fd(),
        child: &child,
        wake: shim.wake().rx.as_fd(),
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

fn os_error(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}
