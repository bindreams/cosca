//! Async spawn: a `::tokio::process::Command` over the sync spawn core via `as_std_mut`;
//! tokio owns piped std fds (except piped MERGE TARGETS — the pre-pass owns those pipes), we
//! own file/null/inherit/merge ends; identity is read before any await, then attach (with
//! error-path teardown).

use std::collections::BTreeMap;
use std::process::Stdio as StdStdio;

use crate::child::spawn::{build_std_command, dup, resolve_identity, resolve_stdio, PipeOwnership};
use crate::command::Command;
use crate::error::Error;
#[cfg(unix)]
use crate::stdio::Direction;
use crate::stdio::{Fd, ResolvedStdio};

use super::child::{reap_now, Child, ProcSource};
use crate::child::spawn::unkillable;

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let child = spawn_uncommitted(cmd)?;
    child.commit_kill_on_drop();
    Ok(child)
}

/// [`spawn`] up to the handle it returns, whose containment resource still tears the tree down
/// on drop whatever `kill_on_drop` says.
pub(super) fn spawn_uncommitted(cmd: &mut Command) -> Result<Child, Error> {
    // tokio's `process::Command::spawn` needs a running reactor; outside ANY runtime it panics on
    // Unix and defers the failure on Windows — reject that no-runtime case up front so it is a typed
    // Err on every platform.
    if ::tokio::runtime::Handle::try_current().is_err() {
        return Err(Error::Io(std::io::Error::other(
            "cosca::tokio::Command must be spawned from within a Tokio runtime",
        )));
    }

    let kill_on_drop = cmd.kill_on_drop_flag();

    // Elevation runs before fds are taken (mirrors sync). POSIX rewrites into a DERIVED command and
    // recurses (the derived command has elevation disabled → no re-entry); Windows builds the async
    // Child here (tokio::child::Child::from_parts is pub(super)).
    let mut elevation_report: Option<crate::elevation::ElevationReport> = None;
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            use crate::elevation::windows::{launch_runas, RunasOutcome};
            match launch_runas(&*cmd)? {
                RunasOutcome::Launched { proc, pid, id, report } => {
                    let raw = windows_raw::RawAsyncChild::new_runas(proc, pid);
                    let mut child = Child::from_parts(
                        ProcSource::Raw(raw),
                        id,
                        kill_on_drop,
                        crate::containment::Attachment::uac_elevated(),
                        super::child::FdPipes::new(),
                        std::collections::BTreeMap::new(),
                    );
                    child.set_elevation(Some(report));
                    return Ok(child);
                }
                RunasOutcome::AlreadyElevated => {
                    elevation_report = Some(crate::elevation::already_elevated_report(
                        crate::elevation::ElevatedStdio::Passthrough,
                    ));
                    // fall through to the normal async spawn of the (already-elevated) cmd
                }
            }
        }
        #[cfg(unix)]
        {
            let rw = crate::elevation::posix::rewrite(cmd)?;
            let backend_path = rw.backend_path;
            if let Some(mut derived) = rw.derived {
                // Same shared honest remap as the sync path (parity-by-construction): remap a
                // derived-backend exec failure to BackendUnavailable ONLY when the backend path is
                // the culprit. An already-elevated derived (sanitized original) has no backend path.
                let child = spawn_uncommitted(&mut derived);
                let mut child = match backend_path.as_deref() {
                    Some(bp) => child.map_err(|e| crate::elevation::remap_derived_spawn_error(e, bp))?,
                    None => child?,
                };
                // Set the report BEFORE handling the deferred password: a cleanup kill() in the
                // write-failure path must see the elevated state so an EPERM maps to the typed
                // `ElevationErrorKind::Unkillable` rather than leaking a raw Io.
                child.set_elevation(rw.report);
                let written = rw.password_write.map_or(Ok(()), |pw| pw.write_after_spawn());
                return finish_elevated(child, written);
            }
            // Defensive: the current POSIX `rewrite` always returns `Some(derived)` (it sanitizes
            // even the already-elevated case), so this no-derived fall-through is not reached today.
            elevation_report = rw.report;
        }
    }

    // Read the routing rule BEFORE the take, for the reason spelled out at
    // `crate::child::spawn::routes_to_raw_backend`: after it, a high-descriptor-only command
    // would take the std path and lose its descriptors in silence.
    #[cfg(windows)]
    let to_raw_backend = crate::child::spawn::routes_to_raw_backend(cmd);
    let mut fds = std::mem::take(cmd.fds_mut());

    // Route the cases tokio's `Command` cannot express to the raw `CreateProcessW` backend:
    // an `executable()` loaded independently of argv[0], OR arbitrary descriptors
    // (fd >= 3, wired through the MSVCRT `lpReserved2` table). The raw backend handles BOTH
    // contained and uncontained via its own async containment; everything else stays on
    // the std/tokio path, whose `prepare` applies containment for argv/commandline spawns.
    #[cfg(windows)]
    if to_raw_backend {
        // Attach the report on the AlreadyElevated fall-through too — an already-elevated
        // `executable()` command routes here (fd >= 3 on an elevated child is already rejected by
        // the Windows gate), and dropping the raw child without the report would lose its elevation
        // state (mirrors the sync `spawn_elevated` post-spawn set).
        let mut child = windows_raw::spawn_raw(cmd, fds, kill_on_drop)?;
        child.set_elevation(elevation_report);
        return Ok(child);
    }

    let std_cmd = build_std_command(cmd)?;
    let mut tcmd = ::tokio::process::Command::new(std::ffi::OsStr::new(""));
    *tcmd.as_std_mut() = std_cmd;
    // tokio's own `kill_on_drop` is intentionally left at its `false` default: cosca's
    // `Child::drop` is the SOLE owner of the kill, and the reaper's `run_teardown` of the
    // wait-and-release that follows it. Forwarding the builder's `kill_on_drop` to `tcmd` would
    // add a second, unsequenced kill inside that release region, where nothing orders it against
    // the wait.

    // Merge pre-pass: a piped STD slot targeted by a merge cannot stay tokio-owned (tokio's
    // internal pipe end is not ours to dup into the merging slots), so build OUR pipe for it
    // — BOTH directions (matches sync; no surprising asymmetry) —
    // assign every child end here, and stash the parent end for the accessors. Slots this
    // pass assigns are removed from `fds` (and from the resolution slot list below), so
    // `resolve_stdio` never sees them; any piped-merge shape NOT handled here still hits
    // the core's `Deferred` rejection — loud, never a silent fall-through. A chained merge
    // is left untouched for `resolve_stdio` to reject with the canonical error.
    let mut preassigned: BTreeMap<Fd, StdStdio> = BTreeMap::new();
    let mut owned_std: BTreeMap<Fd, super::stdio::OwnedStd> = BTreeMap::new();
    #[cfg(unix)]
    let mut merge_fd_ends: Vec<(Fd, crate::child::spawn::ChildEnd)> = Vec::new();
    let chained = fds
        .values()
        .any(|r| matches!(r, ResolvedStdio::Merge(t) if matches!(fds.get(t), Some(ResolvedStdio::Merge(_)))));
    if !chained {
        let targets: std::collections::BTreeSet<Fd> = fds
            .values()
            .filter_map(|r| match r {
                ResolvedStdio::Merge(t) if t.raw() < 3 && matches!(fds.get(t), Some(ResolvedStdio::Pipe(_))) => {
                    Some(*t)
                }
                _ => None,
            })
            .collect();
        for target in targets {
            let Some(ResolvedStdio::Pipe(dir)) = fds.get(&target) else {
                unreachable!("targets were filtered to piped slots")
            };
            let dir = *dir;
            // Our pipe: the child end goes to the target slot and (dup'd) to each merging
            // slot; the parent end is stashed for the accessor. Windows: an overlapped
            // named-pipe pair whose mandatory `ConnectNamedPipe` is spawned as a real task
            // here, INSIDE the runtime (the stream wrapper polls it before its first I/O).
            #[cfg(unix)]
            let (child_end, parent_end) = {
                use crate::child::spawn::ChildEnd;
                use crate::child::ParentEnd;
                let (reader, writer) = std::io::pipe().map_err(Error::Io)?;
                match dir {
                    Direction::In => (ChildEnd::from(reader), ParentEnd::Writer(writer)),
                    Direction::Out => (ChildEnd::from(writer), ParentEnd::Reader(reader)),
                }
            };
            #[cfg(windows)]
            let (child_end, parent_end) = super::stdio::owned_overlapped_pipe(dir)?;
            // Merging slots: each gets a dup of the child end. A merging slot with
            // raw() >= 3 (Unix only — Windows routed fd >= 3 to the raw backend above) is not
            // assignable as std stdio: it joins the fd >= 3 child-ends collection the command-fds
            // block consumes, dup2'd into the child like any other fd >= 3 end — sync parity,
            // never silently dropped.
            let mergers: Vec<Fd> = fds
                .iter()
                .filter_map(|(slot, r)| match r {
                    ResolvedStdio::Merge(t) if *t == target => Some(*slot),
                    _ => None,
                })
                .collect();
            for slot in mergers {
                fds.remove(&slot);
                if slot.raw() < 3 {
                    preassigned.insert(slot, StdStdio::from(dup(&child_end)?));
                } else {
                    #[cfg(unix)]
                    merge_fd_ends.push((slot, dup(&child_end)?));
                    #[cfg(windows)]
                    unreachable!("fd >= 3 routed to the raw backend above");
                }
            }
            fds.remove(&target);
            preassigned.insert(target, StdStdio::from(child_end));
            owned_std.insert(target, parent_end);
        }
    }

    // Resolve our-owned child ends via the shared core. Piped STD slots are tokio-owned
    // (`Deferred`): they get no child end here and are assigned `Stdio::piped()` below.
    // Slots the merge pre-pass assigned are excluded — resolving them would fabricate
    // inherit ends that could leak into the command-fds mappings.
    let std_slots = [Fd::STDIN, Fd::STDOUT, Fd::STDERR];
    let resolve_std_slots = std_slots.iter().copied().filter(|s| !preassigned.contains_key(s));
    #[cfg(unix)]
    let all_slots: Vec<Fd> = {
        let mut v: Vec<Fd> = resolve_std_slots.collect();
        v.extend(fds.keys().copied().filter(|f| f.raw() >= 3));
        v
    };
    // Windows: fd >= 3 was routed to the raw backend above, and the slot list NEVER includes
    // fd >= 3 — a stray end cannot exist by construction, so no assert/drop pairing to keep in sync.
    #[cfg(windows)]
    let all_slots: Vec<Fd> = resolve_std_slots.collect();
    let (mut child_ends, parent_ends) = resolve_stdio(&fds, &all_slots, PipeOwnership::Deferred)?;
    // Deferred skips only the piped STD slots; every parent end here is an fd >= 3 pipe's.
    debug_assert!(
        parent_ends.keys().all(|f| f.raw() >= 3),
        "Deferred pipe ownership must only produce fd >= 3 parent ends"
    );

    for slot in std_slots {
        let stdio: StdStdio = match preassigned.remove(&slot) {
            // The merge pre-pass already assigned this slot (our owned pipe's child end,
            // or a dup of it for a merging slot).
            Some(pre) => pre,
            None => match fds.get(&slot) {
                Some(ResolvedStdio::Pipe(_)) => StdStdio::piped(),
                _ => StdStdio::from(
                    child_ends
                        .remove(&slot)
                        .unwrap_or_else(|| unreachable!("a configured non-pipe slot must have a resolved child end")),
                ),
            },
        };
        match slot {
            Fd::STDIN => tcmd.stdin(stdio),
            Fd::STDOUT => tcmd.stdout(stdio),
            _ => tcmd.stderr(stdio),
        };
    }
    debug_assert!(preassigned.is_empty(), "the pre-pass only assigns std slots");

    // Every child fd number this spawn will occupy, including fd >= 3 merge sources (not yet
    // folded into `child_ends` — see below), so the macOS fd-marker install places its own
    // descriptor above all of them rather than colliding with a user mapping.
    #[cfg(unix)]
    let reserved: Vec<i32> = child_ends
        .keys()
        .map(|fd| fd.raw())
        .chain(merge_fd_ends.iter().map(|(fd, _)| fd.raw()))
        .collect();
    #[cfg(not(unix))]
    let reserved: Vec<i32> = Vec::new();

    // Phase 1 (before spawn): root detection + pre-spawn containment setup, registered before
    // command-fds' dup2 pre_exec so the latter runs LAST in the child (see the ordering
    // rationale in child/spawn.rs). On macOS the spawn lock is widened to enclose `prepare`
    // through `drop(tcmd)` — see child/spawn.rs's matching comment for the race this closes
    // (dropping `tcmd` here drops the inner `std::process::Command` it wraps, which is what
    // actually owns the marker write end's supervisor-side copy).
    #[cfg(target_os = "macos")]
    let (mut prepared, child) = {
        let _guard = crate::child::spawn::spawn_lock();
        let mut prepared = crate::containment::prepare(
            tcmd.as_std_mut(),
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
        )?;

        // fd >= 3 merge SOURCES: their dup'd ends join the resolved fd >= 3 collection below
        // (the pre-pass removed those slots from `fds`, so the numbers cannot collide).
        for (fd, end) in merge_fd_ends {
            let prev = child_ends.insert(fd, end);
            debug_assert!(prev.is_none(), "pre-pass slots were removed from the resolved set");
        }

        use command_fds::{CommandFdExt, FdMapping};
        let mappings: Vec<FdMapping> = child_ends
            .into_iter()
            .map(|(fd, owned)| FdMapping {
                parent_fd: owned,
                child_fd: fd.raw(),
            })
            .collect();
        if !mappings.is_empty() {
            tcmd.as_std_mut()
                .fd_mappings(mappings)
                .expect("child fd numbers are unique (BTreeMap keys)");
        }

        let c = match tcmd.spawn().map_err(Error::Io) {
            Ok(c) => c,
            Err(e) => {
                return Err(abandoned(prepared.abandon_before_verdict(), e));
            }
        };
        drop(tcmd);
        (prepared, c)
    };
    #[cfg(not(target_os = "macos"))]
    let (mut prepared, child) = {
        let mut prepared = crate::containment::prepare(
            tcmd.as_std_mut(),
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
        )?;

        // fd >= 3 merge SOURCES: their dup'd ends join the resolved fd >= 3 collection below
        // (the pre-pass removed those slots from `fds`, so the numbers cannot collide).
        #[cfg(unix)]
        for (fd, end) in merge_fd_ends {
            let prev = child_ends.insert(fd, end);
            debug_assert!(prev.is_none(), "pre-pass slots were removed from the resolved set");
        }

        // On Unix, hand n>=3 child ends to command-fds — registered AFTER `prepare` so its dup2
        // pre_exec runs LAST in the child (see the ordering rationale in child/spawn.rs).
        #[cfg(unix)]
        {
            use command_fds::{CommandFdExt, FdMapping};

            let mappings: Vec<FdMapping> = child_ends
                .into_iter()
                .map(|(fd, owned)| FdMapping {
                    parent_fd: owned,
                    child_fd: fd.raw(),
                })
                .collect();
            if !mappings.is_empty() {
                tcmd.as_std_mut()
                    .fd_mappings(mappings)
                    .expect("child fd numbers are unique (BTreeMap keys)");
            }
        }

        // Serialize the spawn against the raw backend's inheritable-handle window via the shared
        // spawn lock: tokio's own handle-inheritance marking must not overlap a raw
        // `CreateProcessW` spawn on another thread (mirrors the sync std path).
        let c = {
            let _guard = crate::child::spawn::spawn_lock();
            // Classified at the SYSCALL — see the sync std path for why the whole spawn tree is
            // the wrong domain for this attribution.
            //
            // tokio can fail this spawn after its fork succeeded (its `build_child`: stdio
            // registration, its pidfd reaper, its signal driver), dropping the child neither killed
            // nor reaped, and it returns no pid. A cgroup leaf is still killed through when
            // `prepared` drops, since that needs no pid (see `cgroup`'s report contract). Under any
            // other containment — a process group, a session, a tree walk, none, or a spawn that
            // degraded — nothing reaches the child, and it keeps running.
            let spawned = tcmd.spawn().map_err(Error::Io);
            #[cfg(windows)]
            let spawned =
                spawned.map_err(|e| crate::command::flags::classify_spawn_syscall_error(e, *cmd.flags_request()));
            #[cfg(all(test, target_os = "linux"))]
            let spawned = crate::child::spawn::fault::post_fork_failure(
                spawned,
                prepared.cgroup_leaf.as_ref().map(|leaf| leaf.path()),
            );
            match spawned {
                Ok(c) => c,
                Err(e) => {
                    // Whatever tokio did with the child, the leaf's exchange says what became of
                    // it; without a leaf, nothing can tell.
                    return Err(abandoned(prepared.abandon_before_verdict(), e));
                }
            }
        };
        (prepared, c)
    };

    // Identity must be read before any await: spawn + attach are synchronous, so the runtime cannot
    // park and reap the child in between. Even if the child has already exited, tokio's held handle
    // pins the pid against reuse, so `ProcessId::of` still resolves it (as the sync spawn documents).
    let pid = child.id().expect("a freshly spawned, un-awaited tokio child has a pid");
    // Until `attach_or_fault` succeeds, a child created `CREATE_SUSPENDED` is still suspended —
    // on both teardown arms below, since identity is read before the attach.
    #[cfg(windows)]
    let suspended = prepared.created_suspended();
    let id = match resolve_identity(pid) {
        crate::identity::Resolved::Found(id) => id,
        // Mirror the attach-failure path below: tear the child down so a vanished-identity error
        // never leaks a live (Windows: still CREATE_SUSPENDED) process.
        other => {
            // The verdict first: tokio owns this child, so the leaf must not answer for it as an
            // abandoned spawn's, reaping a pid tokio's own reap is about to. Retained (not
            // dropped) when the verdict says the child was actually placed: otherwise `prepared`
            // dropping here would cgroup.kill and drain-wait the tree before this error even
            // returns — the caller's own `Unreaped` decides that instead (mirrors the
            // attach-failure arm below, and the elevated path).
            let attached = prepared.settle_verdict(pid);
            // Never awaited — an already-Done child is impossible.
            let handed_back = reap_now(
                child,
                pid,
                false,
                #[cfg(windows)]
                suspended,
                attached,
            );
            return Err(unkillable(
                crate::child::spawn::spawn_identity_error(other),
                handed_back,
            ));
        }
    };

    #[cfg(windows)]
    let proc_handle = child
        .raw_handle()
        .expect("a freshly spawned tokio child has a raw handle");
    let attach = crate::child::spawn::attach_or_fault(
        pid,
        #[cfg(windows)]
        proc_handle,
        prepared,
    );
    let attachment = match attach {
        Ok(v) => v,
        // The child is spawned (on Windows possibly CREATE_SUSPENDED) — tear it down so a failed
        // attach never leaks a live/suspended process.
        Err(e) => {
            // Never awaited — an already-Done child is impossible.
            let handed_back = reap_now(
                child,
                pid,
                false,
                #[cfg(windows)]
                suspended,
                // The attach itself failed: nothing was ever attached to retain.
                None,
            );
            return Err(unkillable(e, handed_back));
        }
    };

    // fd >= 3 parent ends: Unix's `command-fds`-wired reactor pipes; on Windows the std path
    // resolves none (fd >= 3 routes to the raw backend), so `parent_ends` is provably empty and the
    // Windows `FdPipes` (overlapped async ends) is empty.
    #[cfg(unix)]
    let pipes = parent_ends;
    #[cfg(windows)]
    let pipes = {
        debug_assert!(
            parent_ends.is_empty(),
            "the async std path resolves no fd >= 3 ends on Windows"
        );
        drop(parent_ends);
        super::child::FdPipes::new()
    };

    let mut child = Child::from_parts(ProcSource::Tokio(child), id, kill_on_drop, attachment, pipes, owned_std);
    child.set_elevation(elevation_report);
    Ok(child)
}

/// Async twin of the sync `finish_elevated` (see there).
#[cfg(unix)]
pub(super) fn finish_elevated(child: Child, written: Result<(), Error>) -> Result<Child, Error> {
    match written {
        Ok(()) => Ok(child),
        Err(write_err) => Err(elevated_write_failed(child, write_err)),
    }
}

#[cfg(windows)]
#[path = "spawn/windows_raw.rs"]
pub(crate) mod windows_raw;

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;

/// The error for a failed tokio spawn, given what it may have left behind of its child: nothing;
/// a child that refused the kill, handed back in [`Error::Unreaped`]; a zombie nothing
/// reaps; or a process nothing can reach.
///
/// tokio can fail a spawn after its fork, dropping the child neither killed nor reaped and
/// returning no pid. Only a cgroup leaf still reaches such a child, and only once the child has
/// told it who it is. The error cannot tell a failure before the fork from one after it, hence
/// "may". The last two are warned about once per errno at `warn`, then at `debug`, as a degraded
/// containment is reported.
fn abandoned(child: crate::containment::AbandonedChild, error: Error) -> Error {
    use crate::containment::AbandonedChild;

    type Warned = std::sync::Mutex<std::collections::BTreeSet<Option<i32>>>;
    static UNREAPED: Warned = std::sync::Mutex::new(std::collections::BTreeSet::new());
    static UNREACHABLE: Warned = std::sync::Mutex::new(std::collections::BTreeSet::new());
    let (warned, consequence) = match child {
        AbandonedChild::Ended => return error,
        // Out of cosca's reach, but not the caller's: handed back.
        AbandonedChild::HandedBack { kill, child } => {
            return unkillable(error, Some((kill, child)));
        }
        AbandonedChild::MaybeUnreaped => (
            &UNREAPED,
            "the child exits before `exec` but was left unreaped: it never reached the point where it \
             names itself, so nothing holds its pid",
        ),
        AbandonedChild::MaybeUnreachable => (
            &UNREACHABLE,
            "the child was left running and nothing can reach it: only a cgroup v2 leaf is killed \
             without the child's pid",
        ),
    };
    warn_after_fork_into(warned, &error, consequence);
    error
}

/// The async twin of `crate::child::spawn::elevated_write_failed`: its tree is killed through its
/// containment, then its root by its own handle; a root the kill cannot end is handed back in
/// [`Error::Unreaped`]. The root's reap is blocking (`try_wait` cannot reap a just-killed child,
/// so it would leak a zombie), and waits only on this kill.
#[cfg(unix)]
pub(crate) fn elevated_write_failed(mut child: Child, write_err: Error) -> Error {
    use crate::child::unreaped::{kill_error_to_io, Checked};
    let tree = crate::child::spawn::tree_note(child.containment().can_teardown().then(|| child.kill_tree_members()));
    let auth_failed = |note: String| Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: format!("{write_err}; {note}{tree}"),
    };
    #[cfg(test)]
    let killed = match crate::child::spawn::fault::take_force_kill_failure() {
        Some((marker, kind)) => Err(Error::Io(std::io::Error::new(kind, marker))),
        None => child.kill(),
    };
    #[cfg(not(test))]
    let killed = child.kill();
    let kill = match killed {
        // SIGKILL is uncatchable, so this wait — which never kills again — is bounded.
        Ok(()) => {
            child.wait_and_reap_blocking();
            return auth_failed("the elevated child was terminated".into());
        }
        Err(e) => kill_error_to_io(e),
    };
    let (held, retained) = child.into_unreaped_parts();
    match held.check() {
        Checked::Running(held) => Error::Unreaped {
            error: Box::new(auth_failed(
                "the elevated child could not be terminated and is handed back".into(),
            )),
            kill,
            child: crate::Unreaped::with_retained(held, Some(retained)),
        },
        Checked::Reaped => auth_failed("the elevated child had already exited".into()),
        Checked::Uncertain(e) => auth_failed(format!(
            "the elevated child could not be terminated ({kill}), and its ownership is uncertain ({e}); \
             it was released"
        )),
    }
}

/// Say that if the failed spawn forked, `consequence` — against an explicit "already warned" set,
/// returning the level it chose.
fn warn_after_fork_into(
    warned: &std::sync::Mutex<std::collections::BTreeSet<Option<i32>>>,
    error: &Error,
    consequence: &str,
) -> log::Level {
    let errno = match error {
        Error::Io(e) => e.raw_os_error(),
        _ => None,
    };
    let level = crate::warn_once::report_level(warned, errno);
    log::log!(
        level,
        "tokio spawn failed ({error}); if it failed after forking, {consequence}"
    );
    level
}
