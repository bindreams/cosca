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

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
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
            match launch_runas(cmd)? {
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
                let child = spawn(&mut derived);
                let mut child = match backend_path.as_deref() {
                    Some(bp) => child.map_err(|e| crate::elevation::remap_derived_spawn_error(e, bp))?,
                    None => child?,
                };
                // Set the report BEFORE handling the deferred password: a cleanup kill() in the
                // write-failure path must see the elevated state so an EPERM maps to the typed
                // Unkillable rather than leaking a raw Io.
                child.set_elevation(rw.report);
                if let Some(pw) = rw.password_write {
                    if let Err(write_err) = pw.write_after_spawn() {
                        // Do NOT orphan the running elevated child on a genuine write failure:
                        // kill + reap, folding the teardown outcome into the error detail. A
                        // successful kill() (SIGKILL, uncatchable) is followed by a BLOCKING reap
                        // (try_wait cannot reap a just-killed child, so it would leak a zombie); an
                        // Err kill() (e.g. Unkillable) can't be reaped, so fall back to a
                        // non-blocking try_wait() and note the child may still be running.
                        let kill_note = match child.kill() {
                            Ok(()) => {
                                child.reap_blocking();
                                "the elevated child was terminated".to_string()
                            }
                            Err(e) => {
                                let _ = child.try_wait();
                                format!("the elevated child could not be terminated ({e})")
                            }
                        };
                        return Err(Error::Elevation {
                            kind: crate::error::ElevationErrorKind::AuthFailed,
                            detail: format!("{write_err}; {kill_note}"),
                        });
                    }
                }
                return Ok(child);
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
    // `Child::drop` (attached.hard_kill + reap_now) is the SOLE teardown owner. Forwarding the
    // builder's `kill_on_drop` to `tcmd` would make tokio fire its own kill and race reap_now.

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
    let (prepared, mut child) = {
        let _guard = crate::child::spawn::spawn_lock();
        let prepared = crate::containment::prepare(
            tcmd.as_std_mut(),
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
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

        let c = tcmd.spawn().map_err(Error::Io)?;
        drop(tcmd);
        (prepared, c)
    };
    #[cfg(not(target_os = "macos"))]
    let (prepared, mut child) = {
        let prepared = crate::containment::prepare(
            tcmd.as_std_mut(),
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
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
            tcmd.spawn().map_err(Error::Io)?
        };
        (prepared, c)
    };

    // Identity must be read before any await: spawn + attach are synchronous, so the runtime cannot
    // park and reap the child in between. Even if the child has already exited, tokio's held handle
    // pins the pid against reuse, so `ProcessId::of` still resolves it (as the sync spawn documents).
    let pid = child.id().expect("a freshly spawned, un-awaited tokio child has a pid");
    let id = match resolve_identity(pid) {
        crate::identity::Resolved::Found(id) => id,
        // Mirror the attach-failure path below: tear the child down so a vanished-identity error
        // never leaks a live (Windows: still CREATE_SUSPENDED) process.
        other => {
            reap_now(&mut child, pid, false); // never awaited — an already-Done child is impossible
            return Err(crate::child::spawn::spawn_identity_error(other));
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
            reap_now(&mut child, pid, false); // never awaited — an already-Done child is impossible
            return Err(e);
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

#[cfg(windows)]
#[path = "spawn/windows_raw.rs"]
pub(crate) mod windows_raw;

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;
