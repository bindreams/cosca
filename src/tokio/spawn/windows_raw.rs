//! Async (tokio) raw `CreateProcessW` spawn backend.
//!
//! The async mirror of [`crate::child::spawn::windows_raw`]: it loads an `executable()`
//! independently of argv[0] (the case std/tokio cannot express on Windows), wires arbitrary
//! descriptors (fd >= 3, via the MSVCRT `lpReserved2` table), and applies containment (Job Object /
//! TreeWalk) — the full sync feature set. It reuses the sync backend's `CreateProcessW` FFI verbatim
//! (`spawn_step`/`create_process`, the fd-table encode + cap, the STARTUPINFOEXW/HANDLE_LIST build,
//! the containment decision, the lock/close discipline, the error-teardown) and differs only where
//! async demands it: piped ends come from the tokio overlapped-named-pipe machinery (std slots via
//! the stdin/stdout/stderr accessors, fd >= 3 via fd_read_end/fd_write_end), and the owned child is
//! a [`RawAsyncChild`] whose waits run on the blocking pool over a cancellable handle wait.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::process::ExitStatus;
use std::sync::Arc;

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    TerminateProcess, WaitForSingleObject, INFINITE, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use crate::child::spawn::windows_raw as sync_raw;
use crate::child::spawn::{attach_or_fault, dup, resolve_identity, resolve_non_merge, spawn_lock};
use crate::command::{Command, EnvOp};
use crate::error::Error;
use crate::stdio::{Fd, ResolvedStdio};
use crate::tokio::child::{Child, ProcSource};
use crate::tokio::stdio::OwnedStd;
use crate::wait::backend::{new_cancel_event, signal_cancel};

use sync_raw::{exit_status, wait_handle_or_cancel, AttributeList, WaitOutcome};

/// A raw `CreateProcessW` child driven from tokio. The process handle lives behind an `Arc` so a
/// dropped `wait()` future — or a dropped child — never closes a handle a blocking watcher is still
/// parked on: the blocking task holds its own clone until it returns. Async waits run on the
/// blocking pool over the shared cancellable handle wait; a cancel event (signaled by the future's
/// drop guard) releases a parked wait promptly.
#[derive(Debug)]
pub(crate) struct RawAsyncChild {
    proc: Arc<OwnedHandle>,
    /// The child's OS pid — retained for diagnostics (the `Child`'s stable `ProcessId` is the
    /// source of truth for containment queries).
    pid: u32,
    /// Memoized once the child has exited, so a second `wait`/`try_wait` is immediate and cannot
    /// re-read a status off a (post-close) recycled handle.
    exited: Option<ExitStatus>,
    /// A runas (UAC-elevated) child a lower-integrity parent may be unable to terminate: `Drop`
    /// tears it down best-effort WITHOUT blocking, so an unkillable elevated child never hangs.
    runas: bool,
    #[cfg(test)]
    observer: Option<WaitObserver>,
}

impl RawAsyncChild {
    pub(crate) fn new(proc: OwnedHandle, pid: u32) -> RawAsyncChild {
        RawAsyncChild {
            proc: Arc::new(proc),
            pid,
            exited: None,
            runas: false,
            #[cfg(test)]
            observer: None,
        }
    }

    /// A runas (UAC-elevated) child, torn down best-effort (never blocking) on `Drop`.
    pub(crate) fn new_runas(proc: OwnedHandle, pid: u32) -> RawAsyncChild {
        RawAsyncChild {
            proc: Arc::new(proc),
            pid,
            exited: None,
            runas: true,
            #[cfg(test)]
            observer: None,
        }
    }

    fn handle(&self) -> HANDLE {
        HANDLE(self.proc.as_raw_handle())
    }

    /// Block until the child exits, returning its status. Runs the blocking handle wait on the
    /// blocking pool; a `CancelGuard` in this future signals a cancel event on drop so an aborted
    /// or timed-out wait releases the parked watcher at once.
    pub(crate) async fn wait(&mut self) -> Result<ExitStatus, Error> {
        loop {
            if let Some(status) = self.exited {
                return Ok(status);
            }
            // Arc-owned handles: the blocking task holds clones for its whole lifetime, so dropping
            // this future (or the child) never closes a handle the task is parked on.
            let cancel = Arc::new(new_cancel_event()?);
            let proc = Arc::clone(&self.proc);
            let cancel_for_task = Arc::clone(&cancel);
            #[cfg(test)]
            let observer = self.observer.take();
            let task = ::tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                let (started, outcome_tx) = match observer {
                    Some(obs) => (Some(obs.started), Some(obs.outcome)),
                    None => (None, None),
                };
                // The task is on the blocking pool and about to park on the handle wait.
                #[cfg(test)]
                if let Some(tx) = started {
                    let _ = tx.send(());
                }
                let result = wait_handle_or_cancel(
                    HANDLE(proc.as_raw_handle()),
                    Some(HANDLE(cancel_for_task.as_raw_handle())),
                );
                #[cfg(test)]
                if let (Some(tx), Ok(outcome)) = (outcome_tx, result.as_ref()) {
                    let _ = tx.send(*outcome);
                }
                result
            });
            // Signals the cancel event if THIS future is dropped before the blocking wait returns,
            // releasing the parked watcher promptly. Harmless after completion (manual-reset event,
            // nothing waits on it any more). The Arcs above keep both handles live until the task
            // returns, so the signal races nothing.
            let _guard = CancelGuard(cancel);
            let outcome = match task.await {
                Ok(o) => o,
                // A JoinError (task panic / runtime shutdown) is not an exit — surface it.
                Err(_e) => return Err(Error::Io(std::io::Error::other("raw async wait task failed"))),
            };
            match outcome {
                Ok(WaitOutcome::Exited) => {
                    let status = exit_status(self.handle()).map_err(Error::Io)?;
                    self.exited = Some(status);
                    return Ok(status);
                }
                // Only `CancelGuard::drop` signals the cancel event, and it runs solely when THIS
                // future is dropped — in which case this continuation never executes. A defensive
                // re-wait (fresh event) preserves the "resolved ⇒ exited" postcondition if that
                // ever broke; never a false exit.
                Ok(WaitOutcome::Cancelled) => {
                    debug_assert!(false, "raw async wait resolved Cancelled while its future was live");
                    continue;
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }

    /// Exit status if the child has already exited (non-blocking), memoizing it.
    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        if let Some(status) = self.exited {
            return Ok(Some(status));
        }
        // SAFETY: our live, owned process handle; a zero timeout polls without blocking.
        let r = unsafe { WaitForSingleObject(self.handle(), 0) };
        if r == WAIT_OBJECT_0 {
            let status = exit_status(self.handle()).map_err(Error::Io)?;
            self.exited = Some(status);
            Ok(Some(status))
        } else if r == WAIT_TIMEOUT {
            Ok(None)
        } else {
            Err(Error::Io(std::io::Error::last_os_error()))
        }
    }

    /// Signal a hard kill (does not reap). Signal-only, so it never blocks.
    pub(crate) fn start_kill(&mut self) -> Result<(), Error> {
        // SAFETY: our live, owned process handle; exit code 1 is the forced-kill code.
        match unsafe { TerminateProcess(self.handle(), 1) } {
            Ok(()) => Ok(()),
            // `ACCESS_DENIED` has two causes: (a) our own child is already exiting (the OS teardown
            // window signals the denial before the object is signaled — a spurious kill error), or
            // (b) a runas child is genuinely higher-integrity than us. A static `can_terminate`
            // probe (shared with the sync `RawChild`) separates them WITHOUT racing a `try_wait`.
            // Only (b) is a real denial → surface the `Io` error so `Child::kill` maps it to the
            // typed `Unkillable`; (a) is Ok (signal-only, so never block here).
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {
                if self.runas && !sync_raw::can_terminate(self.pid) {
                    Err(Error::Io(std::io::Error::from_raw_os_error(
                        ERROR_ACCESS_DENIED.0 as i32,
                    )))
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(Error::Io(e.into())),
        }
    }

    /// Synchronous kill-then-reap for `Drop` (no reactor, no `wait()` future in flight). A plain
    /// child is `TerminateProcess`d so the wait returns at once. A runas child a lower-integrity
    /// parent cannot terminate is torn down best-effort WITHOUT blocking (universal teardown).
    pub(crate) fn reap_blocking(&mut self) {
        if self.exited.is_some() {
            return;
        }
        if self.runas {
            // SAFETY: our live, owned process handle.
            match unsafe { TerminateProcess(self.handle(), 1) } {
                Ok(()) => {
                    // It will exit; the wait is bounded by a real termination event.
                    // SAFETY: our live, owned process handle.
                    let _ = unsafe { WaitForSingleObject(self.handle(), INFINITE) };
                }
                Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {
                    if !matches!(self.try_wait(), Ok(Some(_))) {
                        log::warn!(
                            "elevated async child {} could not be terminated on drop; leaving it running",
                            self.pid
                        );
                    }
                }
                Err(e) => log::warn!("terminating elevated async child {} on drop failed: {e:?}", self.pid),
            }
            return;
        }
        let _ = self.start_kill();
        // SAFETY: our live, owned process handle; INFINITE is bounded by the kill above.
        let waited = unsafe { WaitForSingleObject(self.handle(), INFINITE) };
        debug_assert!(
            waited == WAIT_OBJECT_0,
            "raw async Drop did not observe child {} exit: {waited:?}",
            self.pid
        );
        let _ = waited;
    }

    /// Install the per-instance test wait observer on THIS child (see `WaitObserver`).
    #[cfg(test)]
    pub(crate) fn set_observer(
        &mut self,
        started: ::tokio::sync::oneshot::Sender<()>,
        outcome: ::tokio::sync::oneshot::Sender<WaitOutcome>,
    ) {
        self.observer = Some(WaitObserver { started, outcome });
    }
}

/// Signals the cancel event when the `wait()` future is dropped (aborted / timed-out), releasing
/// the parked blocking watcher. Harmless once the wait has already returned.
struct CancelGuard(Arc<OwnedHandle>);

impl Drop for CancelGuard {
    fn drop(&mut self) {
        // `signal_cancel` asserts loudly on failure (see wait/windows.rs); Drop cannot propagate.
        signal_cancel(&self.0);
    }
}

/// Per-instance test observable seam: the blocking wait closure signals when it has parked
/// (`started`) and reports its `WaitOutcome` — on THIS child's channels only, so a parallel test's
/// wait never fires into another test's receivers (a process-global seam would). Injected via
/// `RawAsyncChild::set_observer`; consumed on the next `wait()`.
#[cfg(test)]
#[derive(Debug)]
struct WaitObserver {
    started: ::tokio::sync::oneshot::Sender<()>,
    outcome: ::tokio::sync::oneshot::Sender<WaitOutcome>,
}

/// Spawn `cmd` via the async raw backend: an `executable()` loaded independently of argv[0], with
/// arbitrary descriptors (fd >= 3) and containment — the full sync feature set. Reuses the sync
/// backend's FFI (fd-table + HANDLE_LIST + containment decision + lock/close + error-teardown).
pub(crate) fn spawn_raw(cmd: &Command, fds: BTreeMap<Fd, ResolvedStdio>, kill_on_drop: bool) -> Result<Child, Error> {
    // Batch reject on the program token, resolve the executable, NUL-check, build the command line
    // — all shared verbatim with the sync raw backend.
    sync_raw::reject_batch_program(cmd)?;
    let image = cmd
        .executable_path()
        .map(sync_raw::resolve::resolve_executable)
        .transpose()?;
    if let Some(p) = &image {
        sync_raw::resolve::ensure_no_nul_wide(p.as_os_str())?;
    }
    if let Some(c) = cmd.cwd() {
        sync_raw::resolve::ensure_no_nul_wide(c.as_os_str())?;
    }
    let app_name: Option<Vec<u16>> = image.as_ref().map(|p| sync_raw::to_wide_nul(p.as_os_str()));
    let mut cmdline = sync_raw::raw_program_and_line(cmd)?; // each token NUL-checked
    cmdline.push(0);

    // Containment: mirror the sync raw backend's pre-spawn decision. Uncontained keeps the defaults
    // (flags 0, `mode: None`/`is_root: false`); a Strongest root spawns CREATE_SUSPENDED and is
    // job-assigned + resumed in `attach_or_fault`.
    let req = cmd.contain_request();
    let marker_present = std::env::var_os(crate::containment::NESTED_ENV).is_some();
    let is_root = !crate::containment::dispatch::is_nested(marker_present);
    // Composed and validated BEFORE `clear_std_handle_inheritance`, which is a process-global
    // `SetHandleInformation` on THIS process's std handles that nothing undoes: a refused spawn
    // must not have mutated the parent. The gate itself is unchanged — the call stays inside the
    // containment condition, only below the refusal.
    let plan = crate::command::flags::windows_spawn(
        &req,
        *cmd.flags_request(),
        is_root,
        crate::command::flags::SpawnBackend::Raw,
    )?;
    let marker_env = plan.marker_env;
    if req.mode.is_some() {
        crate::containment::windows::clear_std_handle_inheritance();
    }

    // Append the inherited root marker AFTER the user's env ops so it survives a user `env_clear()`
    // (mirrors the sync path).
    let env_block = if marker_env {
        let mut ops = cmd.env_ops().to_vec();
        ops.push(EnvOp::Set(
            OsString::from(crate::containment::NESTED_ENV),
            OsString::from("1"),
        ));
        sync_raw::resolve::build_env_block(&ops)?
    } else {
        sync_raw::resolve::build_env_block(cmd.env_ops())?
    };
    let cwd_w = cmd.cwd().map(|c| sync_raw::to_wide_nul(c.as_os_str()));

    // Cap the MSVCRT fd-table to the WORD-sized `cbReserved2` field BEFORE allocating any pipes.
    sync_raw::ensure_fd_table_fits(&fds)?;

    // Resolve 0/1/2 (always) plus any configured fd >= 3 to child handles: piped slots via the
    // tokio overlapped-pipe machinery (we own the async parent ends — std slots via the
    // stdin/stdout/stderr accessors, fd >= 3 via fd_read_end/fd_write_end), merges as dups, the rest
    // (inherit/file/null) via the shared core (which rejects inherit on fd >= 3).
    let (child_ends, owned_std, fd_pipes) = resolve_raw_ends(&fds)?;

    // Classify + encode the dense MSVCRT fd-table the child CRT reads back from `lpReserved2` — the
    // SAME layout + single HANDLE_LIST source as the sync backend.
    let table = sync_raw::build_fd_table(&child_ends)?;

    // STARTUPINFOEXW: STARTF_USESTDHANDLES + hStd* for 0/1/2; `lpReserved2` carries the fd-table so
    // the child CRT recovers fd >= 3; the HANDLE_LIST (`table.handles`) scopes inheritance AND backs
    // EXTENDED_STARTUPINFO_PRESENT. `table` (`bytes`) is kept alive until after CreateProcessW.
    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = HANDLE(child_ends[&Fd::STDIN].as_raw_handle());
    si.StartupInfo.hStdOutput = HANDLE(child_ends[&Fd::STDOUT].as_raw_handle());
    si.StartupInfo.hStdError = HANDLE(child_ends[&Fd::STDERR].as_raw_handle());
    si.StartupInfo.cbReserved2 = table.bytes.len() as u16; // fits: capped above
    si.StartupInfo.lpReserved2 = table.bytes.as_ptr() as *mut u8;
    // SINGLE handle source: `table.handles` is 0/1/2 + fd >= 3, each a distinct fresh dup (its
    // 0/1/2 entries ARE the hStd* handles), so no duplicate reaches the list.
    let all_handles: &[HANDLE] = &table.handles;
    let attr = AttributeList::build(all_handles)?;
    si.lpAttributeList = attr.as_ptr();
    // The complete word, composed above by the ONE function all three backends share — the two
    // structural bits this backend cannot spawn without included. Nothing ORs into it here.
    let flags = plan.creation_flags;

    // UNDER THE LOCK: mark the listed child ends inheritable, spawn, then CLOSE the child ends and
    // the attribute list BEFORE the guard releases on EVERY path (mirrors the sync raw backend —
    // an early `?` would drop the inner guard before `child_ends`/`attr`, exposing inheritable
    // handles to a concurrent spawn).
    let spawned = {
        let _guard = spawn_lock();
        let r = sync_raw::spawn_step(
            all_handles,
            app_name.as_deref(),
            &mut cmdline,
            &mut si,
            &env_block,
            &cwd_w,
            flags,
            *cmd.flags_request(),
        );
        drop(child_ends); // close the child ends inside the lock, on success AND error
        drop(attr); // DeleteProcThreadAttributeList before the guard releases
        r
    };
    let (proc, pid) = spawned?;

    // Identity read + attach BEFORE building `Child`, with the REAL mode + is_root (Job Object for a
    // Strongest root, else TreeWalk/Delegated), and the SAME kill+reap error-teardown as the
    // sync-raw/std path (dropping the OwnedHandle alone neither kills nor reaps on Windows). Spawn +
    // attach + identity are synchronous — no await before the identity read, so the runtime cannot
    // park and reap in between.
    let prepared = crate::containment::Prepared {
        mode: req.mode,
        is_root,
        // From the COMPOSED word, which carries the caller's flags as well as the containment
        // decision: a derivation reading only the containment half would report an in-process
        // route for a child this spawn deliberately put in another console.
        graceful: crate::containment::windows::mechanism_from_flags(flags),
    };
    let raw_handle = proc.as_raw_handle();
    let attachment = match attach_or_fault(pid, raw_handle, prepared) {
        Ok(v) => v,
        Err(e) => {
            sync_raw::raw_spawn_teardown(proc, pid);
            return Err(e);
        }
    };
    let id = match resolve_identity(pid) {
        crate::identity::Resolved::Found(id) => id,
        other => {
            sync_raw::raw_spawn_teardown(proc, pid);
            return Err(crate::child::spawn::spawn_identity_error(other));
        }
    };

    Ok(Child::from_parts(
        ProcSource::Raw(RawAsyncChild::new(proc, pid)),
        id,
        kill_on_drop,
        attachment,
        fd_pipes,
        owned_std,
    ))
}

/// The raw backend's resolved stdio ends: the child's handle ends (0/1/2 + fd >= 3) keyed by slot,
/// plus the async parent ends we own — std-slot pipes (for the stdin/stdout/stderr accessors) and
/// fd >= 3 pipes (for fd_read_end/fd_write_end), each keyed by slot.
type RawEnds = (
    BTreeMap<Fd, OwnedHandle>,
    BTreeMap<Fd, OwnedStd>,
    BTreeMap<Fd, OwnedStd>,
);

/// Resolve the child's handle ends (0/1/2 + fd >= 3) for the raw backend, plus the async parent ends
/// we own. Piped slots use OUR overlapped pipe (tokio owns none here — there is no
/// `tokio::process::Child`); merges dup their target's child end; the rest resolve via the shared
/// core (which rejects inherit on fd >= 3).
fn resolve_raw_ends(fds: &BTreeMap<Fd, ResolvedStdio>) -> Result<RawEnds, Error> {
    // Slots to resolve: 0/1/2 always, plus every configured fd >= 3.
    let slots: Vec<Fd> = {
        let mut v = vec![Fd::STDIN, Fd::STDOUT, Fd::STDERR];
        v.extend(fds.keys().copied().filter(|f| f.raw() >= 3));
        v
    };
    // Reject chained merges (single-level indirection only), mirroring the shared resolver.
    for &slot in &slots {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(&slot) {
            if matches!(fds.get(target), Some(ResolvedStdio::Merge(_))) {
                return Err(Error::Unsupported {
                    op: format!("merge {slot} -> {target} -> <another merge>"),
                    platform: "windows",
                    detail: "chained merges (merge-to-merge) are not supported; redirect to a \
                             concrete slot (pipe/file/null/inherit)"
                        .into(),
                });
            }
        }
    }
    let mut child_ends: BTreeMap<Fd, OwnedHandle> = BTreeMap::new();
    let mut owned_std: BTreeMap<Fd, OwnedStd> = BTreeMap::new();
    let mut fd_pipes: BTreeMap<Fd, OwnedStd> = BTreeMap::new();
    // First pass: non-merge slots. Piped slots use our overlapped pipe (async parent end stashed —
    // std slots for the stdin/stdout/stderr accessors, fd >= 3 for fd_read_end/fd_write_end); the
    // rest (inherit/file/null/unconfigured std) resolve via the shared core.
    for &slot in &slots {
        match fds.get(&slot) {
            Some(ResolvedStdio::Merge(_)) => continue, // second pass
            Some(ResolvedStdio::Pipe(dir)) => {
                let (child_end, parent) = crate::tokio::stdio::owned_overlapped_pipe(*dir)?;
                child_ends.insert(slot, child_end);
                if slot.raw() < 3 {
                    owned_std.insert(slot, parent);
                } else {
                    fd_pipes.insert(slot, parent);
                }
            }
            other => {
                let (child_end, parent) = resolve_non_merge(slot, other)?;
                debug_assert!(parent.is_none(), "a raw non-pipe slot yields no parent end");
                child_ends.insert(slot, child_end);
            }
        }
    }
    // Second pass: each merge dups its target's already-resolved child end.
    for &slot in &slots {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(&slot) {
            let src = child_ends.get(target).ok_or_else(|| Error::Unsupported {
                op: format!("merge {slot} -> {target}"),
                platform: "windows",
                detail: "merge target descriptor is not configured".into(),
            })?;
            child_ends.insert(slot, dup(src)?);
        }
    }
    Ok((child_ends, owned_std, fd_pipes))
}

#[cfg(test)]
#[path = "windows_raw_tests.rs"]
mod windows_raw_tests;
