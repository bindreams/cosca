//! Async spawn: a `::tokio::process::Command` over the sync spawn core via `as_std_mut`;
//! tokio owns piped std fds (except piped MERGE TARGETS — the pre-pass owns those pipes), we
//! own file/null/inherit/merge ends; identity is read before any await, then attach (with
//! error-path teardown).

use std::collections::BTreeMap;
use std::process::Stdio as StdStdio;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use crate::child::spawn::build_std_command;
use crate::child::spawn::{dup, resolve_identity, resolve_stdio, Classify, PipeOwnership, SpawnFailure};
use crate::command::Command;
use crate::error::{ChildFate, Error};
use crate::identity::Resolved;
#[cfg(unix)]
use crate::stdio::Direction;
use crate::stdio::{Fd, ResolvedStdio};

use super::child::{Child, ProcSource};
#[cfg(unix)]
use crate::signal::Sent;

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, SpawnFailure> {
    let child = spawn_uncommitted(cmd)?;
    child.commit_kill_on_drop();
    Ok(child)
}

/// [`spawn`] up to the handle it returns, whose containment resource still tears the tree down
/// on drop whatever `kill_on_drop` says.
///
/// Every failure says whether the program could have started; see [`SpawnFailure`].
pub(super) fn spawn_uncommitted(cmd: &mut Command) -> Result<Child, SpawnFailure> {
    // tokio's `process::Command::spawn` needs a running reactor; outside ANY runtime it panics on
    // Unix and defers the failure on Windows — reject that no-runtime case up front so it is a typed
    // Err on every platform.
    if ::tokio::runtime::Handle::try_current().is_err() {
        return Err(SpawnFailure::NotStarted(Error::Io(std::io::Error::other(
            "cosca::tokio::Command must be spawned from within a Tokio runtime",
        ))));
    }

    // Before anything is made or forked: a pidfd that is refused means no child, and no leaf.
    #[cfg(target_os = "linux")]
    crate::wait::backend::probe_pidfd_support().not_started()?;

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
            let rw = crate::elevation::posix::rewrite(cmd).not_started()?;
            let backend_path = rw.backend_path;
            if let Some(mut derived) = rw.derived {
                // Same shared honest remap as the sync path (parity-by-construction): remap a
                // derived-backend exec failure to BackendUnavailable ONLY when the backend path is
                // the culprit. An already-elevated derived (sanitized original) has no backend path.
                // From here the child is the backend: its elevated program may outlive what happens to it.
                let wrapper = rw.report.as_ref().is_some_and(|r| r.via.program_outlives_child());
                let spawned = (|| {
                    let child = spawn_uncommitted(&mut derived);
                    let mut child = match backend_path.as_deref() {
                        Some(bp) => child.map_err(|f| f.map(|e| crate::elevation::remap_derived_spawn_error(e, bp)))?,
                        None => child?,
                    };
                    // Set the report BEFORE handling the deferred password: a cleanup kill() in the
                    // write-failure path must see the elevated state so an EPERM maps to the typed
                    // Unkillable rather than leaking a raw Io.
                    child.set_elevation(rw.report);
                    let written = rw.password_write.map_or(Ok(()), |pw| pw.write_after_spawn());
                    finish_elevated(child, written)
                })();
                return spawned.map_err(|failure| if wrapper { failure.behind_wrapper() } else { failure });
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

    #[cfg(target_os = "linux")]
    let (std_cmd, handshake) =
        crate::child::spawn::build_std_command_with(cmd, crate::child::spawn::pidfd_handshake::register)
            .not_started()?;
    #[cfg(target_os = "macos")]
    let (std_cmd, report) =
        crate::child::spawn::build_std_command_with(cmd, crate::child::spawn::unique_report::register).not_started()?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let std_cmd = build_std_command(cmd).not_started()?;
    let mut tcmd = ::tokio::process::Command::new(std::ffi::OsStr::new(""));
    *tcmd.as_std_mut() = std_cmd;
    // tokio's own `kill_on_drop` is intentionally left at its `false` default: cosca's
    // `Child::drop` is the SOLE owner of the kill, and it releases tokio's `Child` right after.
    // Forwarding the builder's `kill_on_drop` to `tcmd` would add a second, unsequenced kill
    // inside that release, where nothing orders it against the tree kill.

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
                let (reader, writer) = std::io::pipe().not_started()?;
                match dir {
                    Direction::In => (ChildEnd::from(reader), ParentEnd::Writer(writer)),
                    Direction::Out => (ChildEnd::from(writer), ParentEnd::Reader(reader)),
                }
            };
            #[cfg(windows)]
            let (child_end, parent_end) = super::stdio::owned_overlapped_pipe(dir).not_started()?;
            // Merging slots: each gets a dup of the child end. A merging slot with
            // raw() >= 3 (Unix only — Windows routed fd >= 3 to the raw backend above) is not
            // assignable as std stdio: it joins the fd >= 3 child-ends collection the fd_map
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
                    preassigned.insert(slot, StdStdio::from(dup(&child_end).not_started()?));
                } else {
                    #[cfg(unix)]
                    merge_fd_ends.push((slot, dup(&child_end).not_started()?));
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
    // inherit ends that could leak into the fd_map mappings.
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
    let (mut child_ends, parent_ends) = resolve_stdio(&fds, &all_slots, PipeOwnership::Deferred).not_started()?;
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

    // The pidfd the handshake opens; the child keeps it (Linux).
    #[cfg(target_os = "linux")]
    let mut held_pidfd: Option<std::os::fd::OwnedFd> = None;

    // Phase 1 (before spawn): root detection + pre-spawn containment setup, registered before
    // fd_map's dup2 pre_exec so the latter runs LAST in the child (see the ordering
    // rationale in child/spawn.rs). On macOS the spawn lock is widened to enclose `prepare`
    // through `drop(tcmd)` — see child/spawn.rs's matching comment for the race this closes
    // (dropping `tcmd` here drops the inner `std::process::Command` it wraps, which is what
    // actually owns the marker write end's supervisor-side copy).
    #[cfg(target_os = "macos")]
    let (mut prepared, child, unique) = {
        let _guard = crate::child::spawn::spawn_lock();
        let mut prepared = crate::containment::prepare(
            tcmd.as_std_mut(),
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
        )
        .not_started()?;
        let report = report.open(&_guard).not_started()?;

        // fd >= 3 merge SOURCES: their dup'd ends join the resolved fd >= 3 collection below
        // (the pre-pass removed those slots from `fds`, so the numbers cannot collide).
        for (fd, end) in merge_fd_ends {
            let prev = child_ends.insert(fd, end);
            debug_assert!(prev.is_none(), "pre-pass slots were removed from the resolved set");
        }

        use crate::child::spawn::fd_map;
        let mappings: Vec<fd_map::FdMapping> = child_ends
            .into_iter()
            .map(|(fd, owned)| fd_map::FdMapping {
                parent_fd: owned,
                child_fd: fd.raw(),
            })
            .collect();
        fd_map::install(tcmd.as_std_mut(), mappings).not_started()?;

        #[allow(
            clippy::disallowed_methods,
            reason = "spawn_lock is held by `_guard` at the top of this function"
        )]
        let (spawned, unique) = report.run(|| {
            let spawned = tcmd.spawn();
            #[cfg(test)]
            let spawned = crate::child::spawn::fault::fail_tokio_spawn_after_fork(spawned);
            spawned.map_err(Error::Io)
        });
        let c = match spawned {
            Ok(c) => c,
            Err(e) => {
                let e = crate::child::spawn::unique_report::failed_spawn_error(e, &unique);
                // Without an id the program never ran, but who collected the child is open: a signal
                // after the refusal makes std return `Ok`, and tokio's own setup can then drop the
                // child unreaped. With an id, or a report that could not be read or was malformed,
                // the program may have run, and may still be running only if tokio's own setup failed
                // after std returned `Ok`: a std `Err` has already collected the child.
                use crate::child::spawn::unique_report::Report;
                use crate::containment::AbandonedChild;
                // A child that had not reported may yet `exec`, with nothing holding it.
                let front = cmd.elevation_front();
                let abandoned = match unique {
                    Report::ChildRefused(_) | Report::Missing => AbandonedChild::MaybeUnreaped,
                    Report::Unwritten => AbandonedChild::MaybeUnreachable,
                    _ => prepared.abandon_before_verdict(front.is_some()),
                };
                // tokio's error does not say whether std's spawn failed, so only the report can prove
                // the program never ran.
                return Err(if crate::child::spawn::unique_report::proves_no_exec(&unique) {
                    warn_for_abandoned(abandoned, &e);
                    SpawnFailure::NotStarted(e)
                } else {
                    abandoned_failure(abandoned, e, front)
                });
            }
        };
        drop(tcmd);
        (prepared, c, unique)
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
        )
        .not_started()?;
        // A front this host could not place after a cgroup kill is refused before it is spawned.
        #[cfg(target_os = "linux")]
        if let Some(leaf) = prepared
            .cgroup_leaf
            .as_ref()
            .filter(|_| cmd.elevation_front().is_some())
        {
            crate::containment::cgroup::front_placement(|| leaf.id()).not_started()?;
        }

        // fd >= 3 merge SOURCES: their dup'd ends join the resolved fd >= 3 collection below
        // (the pre-pass removed those slots from `fds`, so the numbers cannot collide).
        #[cfg(unix)]
        for (fd, end) in merge_fd_ends {
            let prev = child_ends.insert(fd, end);
            debug_assert!(prev.is_none(), "pre-pass slots were removed from the resolved set");
        }

        // Serialize the spawn against the raw backend's inheritable-handle window via the shared
        // spawn lock: tokio's own handle-inheritance marking must not overlap a raw
        // `CreateProcessW` spawn on another thread (mirrors the sync std path). On Linux the lock
        // also spans the pidfd handshake's channel, from its creation to its helper's join.
        let _guard = crate::child::spawn::spawn_lock();

        // Linux: the child is held before `exec` until the parent holds the pidfd it sent, which
        // the child then keeps. Its hook was registered first of all, so `fd_map`'s, which may
        // `dup2` a mapping onto the channel's descriptor number, runs after it is done.
        // A front spawned for a cgroup leaf is left to the leaf, which alone knows whether it holds
        // the front, with the handshake's pidfd for a child the leaf cannot name (see
        // `Handshake::leaving_front`).
        #[cfg(target_os = "linux")]
        let left_pidfd = crate::child::spawn::pidfd_handshake::LeftPidfd::default();
        #[cfg(target_os = "linux")]
        let handshake = handshake.open(&_guard).not_started()?.leaving_front(
            cmd.elevation_front(),
            prepared.cgroup_leaf.is_some().then(|| std::rc::Rc::clone(&left_pidfd)),
        );

        // On Unix, hand n>=3 child ends to fd_map — registered AFTER `prepare` so its dup2
        // pre_exec runs LAST in the child (see the ordering rationale in child/spawn.rs).
        #[cfg(unix)]
        {
            use crate::child::spawn::fd_map;

            let mappings: Vec<fd_map::FdMapping> = child_ends
                .into_iter()
                .map(|(fd, owned)| fd_map::FdMapping {
                    parent_fd: owned,
                    child_fd: fd.raw(),
                })
                .collect();
            fd_map::install(tcmd.as_std_mut(), mappings).not_started()?;
        }

        let c = {
            // Classified at the SYSCALL — see the sync std path for why the whole spawn tree is
            // the wrong domain for this attribution.
            //
            // tokio can fail this spawn after its fork succeeded (its `build_child`: stdio
            // registration, its pidfd reaper, its signal driver), dropping the child neither killed
            // nor reaped, and it returns no pid. A cgroup leaf is still killed through when
            // `prepared` drops, since that needs no pid (see `cgroup`'s report contract). Under any
            // other containment — a process group, a session, a tree walk, none, or a spawn that
            // degraded — nothing reaches the child, and it keeps running.
            #[cfg(target_os = "linux")]
            let spawned = {
                #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard` above")]
                let held = handshake.run(|| {
                    let spawned = tcmd.spawn();
                    #[cfg(test)]
                    let spawned = crate::child::spawn::fault::fail_tokio_spawn_after_fork(
                        spawned,
                        prepared.cgroup_leaf.as_ref().map(|leaf| leaf.path()),
                    );
                    spawned
                });
                held.map(|held| {
                    held_pidfd = Some(held.pidfd);
                    held.child
                })
            };
            // Windows: tokio's error does not say whether `CreateProcess` failed, or tokio's own setup
            // after it.
            #[cfg(not(target_os = "linux"))]
            let spawned = {
                #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard` above")]
                let spawned = tcmd.spawn();
                #[cfg(test)]
                let spawned = crate::child::spawn::fault::fail_tokio_spawn_after_fork(spawned);
                let spawned = spawned.map_err(Error::Io);
                #[cfg(windows)]
                let spawned =
                    spawned.map_err(|e| crate::command::flags::classify_spawn_syscall_error(e, *cmd.flags_request()));
                spawned
            };
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
                    let front = cmd.elevation_front();
                    #[cfg(target_os = "linux")]
                    {
                        // Whatever tokio did with the child, the leaf's exchange says what became of
                        // it; the handshake already answered for a child it held, except a front
                        // spawned for a leaf, which the leaf answers for.
                        let left_to_leaf = front.is_some() && prepared.cgroup_leaf.is_some();
                        let abandoned = prepared.abandon_before_verdict(front.is_some(), left_pidfd.take());
                        return Err(abandoned_after_handshake(abandoned, e, front, left_to_leaf));
                    }
                    // Windows: only the leaf's exchange could say what became of a child tokio
                    // dropped.
                    #[cfg(windows)]
                    {
                        let abandoned = prepared.abandon_before_verdict(front.is_some());
                        return Err(abandoned_failure(abandoned, e, front));
                    }
                }
            }
        };
        (prepared, c)
    };

    // Identity must be read before any await: spawn + attach are synchronous, so the runtime cannot
    // park and reap the child in between. The read is then checked through the backend's handle
    // (below), since on Unix nothing pins the pid against a foreign reap and reuse.
    let pid = child.id().expect("a freshly spawned, un-awaited tokio child has a pid");
    #[cfg(windows)]
    let proc_handle = child
        .raw_handle()
        .expect("a freshly spawned tokio child has a raw handle");
    // macOS: the unique id every by-pid signal to this child is checked against. Without one the
    // backend acts on the pid never, and the spawn fails below once the backend exists.
    #[cfg(target_os = "macos")]
    let (identity, not_adopted) = match crate::child::spawn::unique_report::adopted_id(unique, pid) {
        Ok(unique) => (Some(unique), None),
        Err(not_adopted) => (None, Some(not_adopted)),
    };
    // Built first so failure arms tear the child down through its handle, not its pid. On macOS a
    // child with no adopted id is id-less, and the spawn fails below.
    #[cfg(target_os = "linux")]
    let proc = {
        // Before `child` moves into the backend: a panic here would drop tokio's `Child` by value.
        let held_pidfd = held_pidfd.expect("a spawned child holds the pidfd its handshake opened");
        ProcSource::new(child, held_pidfd)
    };
    #[cfg(target_os = "macos")]
    let mut proc = ProcSource::new(child, identity);
    #[cfg(windows)]
    let proc = ProcSource::new(child);
    #[cfg(target_os = "macos")]
    if let Some(not_adopted) = not_adopted {
        #[cfg(test)]
        crate::child::spawn::fault::capture(crate::identity::ProcessId::of(pid));
        prepared.settle_verdict(pid);
        use crate::child::spawn::unique_report::Unadoptable;
        let error = not_adopted.error;
        let left = crate::child::spawn::FrontFate::LeftUnreaped;
        let front = cmd.elevation_front();
        return Err(match not_adopted.why {
            Unadoptable::DiedBeforeExec => {
                // Only a corpse is left, and tokio's `Child` must not reap it by pid.
                proc.forget_because("died before exec");
                SpawnFailure::NotStarted(error)
            }
            // It may yet report and `exec`: forgotten, as a corpse would be, but left running.
            Unadoptable::Unreported => {
                proc.forget_because(
                    "had not reported its unique id when its spawn returned; it is not adopted, and may be running",
                );
                SpawnFailure::started(left.note(error, front, Some(pid)), ChildFate::Running { id: None })
            }
            // An elevation front is sent nothing and handed to no reaper: left unreaped, as the sync
            // spawn leaves it, and the error says so.
            Unadoptable::Unverified if front.is_some() => {
                proc.forget_because("is an elevation front, sent nothing, and left unreaped");
                SpawnFailure::started(left.note(error, front, Some(pid)), ChildFate::Running { id: None })
            }
            // With no id the backend neither signals nor waits by pid: the child is forgotten, with
            // a warning naming it, and left running.
            Unadoptable::Unverified => SpawnFailure::started(error, proc.reap_now(pid, None)),
        });
    }
    // The pidfd the handshake opened, which the backend just built holds. Were it ever gone, the child
    // is torn down as an unverifiable one: no panic after the fork.
    #[cfg(target_os = "linux")]
    let Some(handle) = proc.child_handle(pid) else {
        debug_assert!(false, "a freshly spawned tokio child holds its pidfd");
        let fate = proc.reap_now(pid, None);
        return Err(SpawnFailure::started(
            crate::child::spawn::spawn_identity_error(Resolved::Unknown),
            fate,
        ));
    };
    #[cfg(test)]
    crate::child::spawn::fault::run_at(crate::child::spawn::fault::SpawnPoint::BeforeIdentity, pid);
    #[cfg(unix)]
    let front = cmd.elevation_front();
    // A front's leaf subtree, captured while it exists: a failure arm drops the leaf, killing it.
    #[cfg(target_os = "linux")]
    let subtree = crate::child::spawn::front_subtree(front.and(prepared.cgroup_leaf.as_ref()));
    #[cfg(unix)]
    if front.is_some() {
        prepared.watch_front(pid);
    }
    // The handle checks the read: a pid alone does not say whom it names once something else has
    // reaped the child. The backend exists already, so a failure here tears the child down through
    // it, and a panic unwinds through `ProcSource`'s `Drop`. The attach below takes this identity
    // and does not re-read the root's.
    let (resolved, mut why) = match proc.target() {
        Some(through) => resolve_identity(pid, &through),
        // Contract: a freshly spawned child holds its handle on every platform.
        None => {
            debug_assert!(false, "a freshly spawned tokio child holds its handle");
            (Resolved::Unknown, crate::child::spawn::Diagnosis::default())
        }
    };
    let id = match resolved {
        Resolved::Found(id) => id,
        // Tear the child down so a vanished-identity error never leaks a live (Windows: still
        // CREATE_SUSPENDED) process.
        other => {
            // Settle the leaf's verdict before any kill, so the kill never races its reads.
            crate::child::spawn::settle_before_teardown(
                &mut prepared,
                #[cfg(target_os = "linux")]
                handle,
                #[cfg(not(target_os = "linux"))]
                pid,
            );
            // An elevation front is sent nothing (see `ProcSource::leave_front`). Its containment
            // goes first: a cgroup leaf's drop kills it, so the teardown waits for a contained front
            // that kill reached, and says what became of it.
            #[cfg(unix)]
            if let Some(front) = front {
                #[cfg(target_os = "linux")]
                drop(prepared);
                // macOS: a front whose identity was refused or found gone is left unverified, as the
                // sync spawn leaves it.
                #[cfg(target_os = "macos")]
                let (fate, child_fate) = leave_unverified_front(
                    &mut proc,
                    if matches!(other, Resolved::Gone) {
                        crate::containment::RootIdentity::Gone
                    } else {
                        crate::containment::RootIdentity::Unknown
                    },
                    &mut why,
                );
                // The read failed, so no identity is known.
                #[cfg(not(target_os = "macos"))]
                let (fate, child_fate) = proc.leave_front_noting(pid, front, None, subtree.as_ref(), &mut why);
                return Err(SpawnFailure::started(
                    fate.note(crate::child::spawn::spawn_identity_error(other), Some(front), Some(pid)),
                    child_fate,
                ));
            }
            // Linux: a failed check says nothing about the child, and its pidfd pins it whatever
            // the peek said, so it is killed and reaped through the pidfd, as the sync spawn does.
            #[cfg(target_os = "linux")]
            if matches!(other, Resolved::Unknown) {
                let child_fate = proc.teardown_through_pidfd(pid, None, &mut why);
                return Err(SpawnFailure::started(
                    crate::child::spawn::spawn_identity_error(other),
                    child_fate,
                ));
            }
            // macOS: nothing pins the pid, so a child the handle still cannot show ours is
            // forgotten, not signalled; tokio's `Child` is not dropped, as its drop reaps by pid.
            #[cfg(target_os = "macos")]
            let forgotten = matches!(other, Resolved::Unknown).then(|| {
                proc.forget_foreign_noting(&mut why);
                ChildFate::Running { id: None }
            });
            let child_fate = proc.reap_now_noting(pid, None, &mut why);
            #[cfg(target_os = "macos")]
            let child_fate = forgotten.unwrap_or(child_fate);
            return Err(SpawnFailure::started(
                crate::child::spawn::spawn_identity_error(other),
                child_fate,
            ));
        }
    };
    #[cfg(test)]
    crate::child::spawn::fault::run_at(crate::child::spawn::fault::SpawnPoint::BeforeAttach, pid);
    let attach = crate::child::spawn::attach_or_fault(
        id,
        #[cfg(target_os = "linux")]
        handle,
        #[cfg(windows)]
        proc_handle,
        prepared,
    );
    let attachment = match attach {
        Ok(v) => v,
        Err(error) => {
            #[cfg(target_os = "macos")]
            crate::child::spawn::assert_attach_cannot_fail(&error);
            #[cfg(unix)]
            if let Some(front) = front {
                // macOS: a front is sent nothing and left unreaped, as the sync spawn leaves it.
                #[cfg(target_os = "macos")]
                let (fate, child_fate) = {
                    proc.forget_because("is an elevation front whose attach failed, sent nothing, and left unreaped");
                    (
                        crate::child::spawn::FrontFate::LeftUnreaped,
                        ChildFate::Running { id: Some(id) },
                    )
                };
                // Elsewhere the failed attach has dropped the containment: a cgroup leaf's drop kills
                // and drains it, so a front in it is dying, and is waited for.
                #[cfg(not(target_os = "macos"))]
                let (fate, child_fate) = proc.leave_front(pid, front, Some(id), subtree.as_ref());
                return Err(SpawnFailure::started(
                    fate.note(error, Some(front), Some(pid)),
                    child_fate,
                ));
            }
            // macOS: killed and reaped through its verified unique id, as the sync spawn does, and
            // tokio's `Child` forgotten: its drop reaps by pid.
            #[cfg(target_os = "macos")]
            let child_fate = {
                let fate = crate::child::spawn::kill_and_reap_verified(
                    pid,
                    identity.expect("a spawn that reached the attach adopted its unique id"),
                    Some(id),
                );
                proc.forget_because("is a child whose attach failed, killed through its verified unique id");
                fate
            };
            // The child is spawned (on Windows possibly CREATE_SUSPENDED) - tear it down so a failed
            // attach never leaks a live/suspended process.
            #[cfg(not(target_os = "macos"))]
            let child_fate = proc.reap_now(pid, Some(id));
            return Err(SpawnFailure::started(error, child_fate));
        }
    };

    // fd >= 3 parent ends: Unix's `fd_map`-wired reactor pipes; on Windows the std path
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

    let mut child = Child::from_parts(proc, id, kill_on_drop, attachment, pipes, owned_std);
    child.set_elevation(elevation_report);
    child.set_front(cmd.elevation_front());
    Ok(child)
}

/// macOS: a front whose identity read found it reaped elsewhere (`Gone`) or could not be read
/// (`Unknown`) is left unverified, as the sync spawn's `leave_unverified_child` leaves any child:
/// sent nothing, and tokio's `Child` forgotten, since its drop reaps by pid.
#[cfg(target_os = "macos")]
fn leave_unverified_front(
    proc: &mut ProcSource,
    identity: crate::containment::RootIdentity,
    why: &mut crate::child::spawn::Diagnosis,
) -> (crate::child::spawn::FrontFate, ChildFate) {
    proc.forget_noting(
        match identity {
            crate::containment::RootIdentity::Gone => "was reaped by someone else",
            crate::containment::RootIdentity::Unknown => {
                "is an elevation front whose identity could not be read, sent nothing, and left unreaped"
            }
        },
        false,
        why,
    );
    let fate = match identity {
        crate::containment::RootIdentity::Gone => ChildFate::Gone,
        crate::containment::RootIdentity::Unknown => ChildFate::Running { id: None },
    };
    (crate::child::spawn::FrontFate::of_unverified(identity), fate)
}

/// Async twin of the sync `finish_elevated` (see there). The root's reap is blocking (`try_wait`
/// cannot reap a just-killed child, so it would leak a zombie), and waits only on this kill. The
/// front's gate is decided once, before the tree's kill. The backend has run, so the program may
/// have started.
#[cfg(unix)]
pub(super) fn finish_elevated(mut child: Child, written: Result<(), Error>) -> Result<Child, SpawnFailure> {
    let Err(write_err) = written else {
        return Ok(child);
    };
    let view = child.read_root_view("finish_elevated");
    // What forgetting tokio's `Child` leaked, if the cleanup forgot it: the one warn below says so.
    let mut forgot: Option<crate::child::drop_report::Forgot> = None;
    let mut skipped = None;
    // A live front outside a cgroup is not signalled, by its group or otherwise: the root's kill
    // below then says why.
    let gate = child.kill_gate();
    let front_closed = matches!(gate, crate::elevation::front::Gate::Closed(_));
    let exited_front = matches!(gate, crate::elevation::front::Gate::Exited);
    let tree: Option<Result<(), Error>> = (child.containment().can_teardown() && !front_closed).then(|| {
        skipped = child.kill_tree_members_unless_reaped(&view)?;
        // Unlike `Drop`, this path may block. Waiting for the drain here lets the handle's drop
        // remove the leaf on its first `rmdir` instead of leaving it behind with a warning
        // naming a `wait_tree` the caller never gets.
        child.block_until_members_drained().map_err(|e| Error::Containment {
            detail: format!("the kill succeeded, but its drain could not be watched ({e})"),
        })?;
        Ok(())
    });
    let tree_failure = match &tree {
        Some(Err(e)) => Some(e.to_string()),
        _ => None,
    };
    // The tree is settled when it was killed completely, was not for the cleanup to kill, or was
    // deliberately left alone because the root is reaped or unpinned.
    let tree_settled = tree.is_none() || child.tree_killed() || (skipped.is_some() && view.leaves_root_alone());
    let tree_warned = matches!(tree, Some(Err(_)));
    let mut tree_note = crate::child::spawn::report_tree_teardown(tree, &child.teardown_subject());
    if let Some(note) = skipped {
        tree_note.push_str(&format!("; its contained tree was not killed: {note}"));
    }
    // The root is settled when it is gone (killed and reaped, or reaped by someone else) or was
    // deliberately not signalled (an unpinned root, a live front). A refused kill leaves it to the
    // handle's drop to try again.
    let mut root_settled = true;
    let (root_note, fate) = if view.unpinned_root() {
        forgot = child.forget_for(&view);
        // Nothing was signalled, so a launchd-held zombie is `Gone`, as the classifier has it.
        #[cfg(target_os = "macos")]
        let fate = crate::wait::exit_only::Foreign::Orphaned.fate(false);
        #[cfg(not(target_os = "macos"))]
        let fate = crate::wait::exit_only::Foreign::Gone.fate(false);
        (
            format!(
                "the elevated child was left alone, neither signalled nor waited on: {}",
                view.why_number_untrusted()
            ),
            fate,
        )
    } else {
        let root = match gate {
            // Not asked again after the kill: a killed front can read as neither exited nor in its
            // cgroup, between leaving the cgroup's member list and becoming a zombie.
            crate::elevation::front::Gate::CgroupOnly if child.cgroup_was_killed() => {
                child.cgroup_kill_reached().map(|()| Sent::Delivered)
            }
            // No kill reached the cgroup: refused as `kill` refuses, naming why.
            crate::elevation::front::Gate::CgroupOnly => Err(child.cgroup_not_killed(tree_failure.as_deref())),
            crate::elevation::front::Gate::Closed(unkillable) => Err(unkillable),
            gate @ (crate::elevation::front::Gate::Open | crate::elevation::front::Gate::Exited) => {
                child.signal_gated(gate)
            }
        };
        // A child that is gone, or not verified to be ours, is forgotten here, not by the kill: tokio's
        // wait and drop reap by pid.
        if matches!(root, Ok(Sent::Gone | Sent::Unverified)) {
            forgot = child.forget_for(&view);
        }
        match root {
            Ok(Sent::Delivered) => {
                let (fate, forgotten) = child.wait_and_reap_blocking();
                forgot = forgotten;
                let note = if exited_front {
                    "the elevated child had already exited, and was reaped"
                } else {
                    "the elevated child was terminated"
                };
                (note.to_string(), fate)
            }
            // Reaped by someone else: nothing was terminated, and nothing is waited on by its number,
            // which may name another process by now.
            Ok(Sent::Gone) if exited_front => (
                "the elevated child had already exited, and was reaped by someone else".to_string(),
                ChildFate::Gone,
            ),
            Ok(Sent::Gone) => (
                "the elevated child could not be terminated (it was already reaped by someone else)".to_string(),
                ChildFate::Gone,
            ),
            // Nothing could be verified to signal: the child may still be running.
            Ok(Sent::Unverified) => {
                root_settled = false;
                (
                    "the elevated child could not be terminated (it could not be verified, and may still be running)"
                        .to_string(),
                    ChildFate::Running { id: Some(child.id()) },
                )
            }
            Err(e) => {
                root_settled = front_closed;
                // The `try_wait` reaps by pid: a child the handle shows reaped elsewhere is forgotten.
                forgot = child.forget_for(&view);
                let id = Some(child.id());
                let fate = match &forgot {
                    Some(forgot) if forgot.reaped_elsewhere() => ChildFate::Gone,
                    Some(_) => ChildFate::Running { id },
                    None => crate::child::spawn::fate_of_a_look(child.try_wait().map_err(|e| e.raw_os_error()), id),
                };
                (format!("the elevated child could not be terminated ({e})"), fate)
            }
        }
    };
    let mut report = crate::child::drop_report::DropReport::new("finish_elevated", &view);
    report.forgot = forgot;
    let warned = report.emit(false);
    child.end_cleanup(tree_settled && root_settled, warned || tree_warned);
    Err(SpawnFailure::started(
        Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: format!("{write_err}; {root_note}{tree_note}"),
        },
        fate,
    ))
}

/// tokio reaps its child by pid, on drop or from its orphan queue; the handshake leaves that reap to
/// it, and only makes it happen while the number is still the child's.
#[cfg(target_os = "linux")]
impl crate::child::spawn::pidfd_handshake::Spawned for ::tokio::process::Child {
    const ERR_PROVES_NO_EXEC: bool = false;

    fn pid(&self) -> Option<u32> {
        self.id()
    }

    /// Waits through the pidfd until the child is a zombie, then has tokio reap it at once.
    fn reap_unexecuted(mut self, pidfd: std::os::fd::OwnedFd) {
        crate::child::spawn::pidfd_handshake::await_unexecuted_exit(&pidfd, self.id());
        match self.try_wait() {
            Ok(Some(_)) => {}
            // A tracer holds the zombie: tokio's drop hands it to its orphan queue.
            Ok(None) => log::debug!(
                "{}: held by a tracer; left to tokio's reaper",
                crate::child::spawn::named(self.id())
            ),
            Err(e) => log::debug!(
                "{}: already reaped by someone else ({e})",
                crate::child::spawn::named(self.id())
            ),
        }
    }

    /// tokio reaps it, on drop or from its orphan queue.
    fn abandon_unreported(self, why: &str) {
        log::debug!(
            "{}: {why}; left to tokio's reaper",
            crate::child::spawn::named(self.id())
        );
    }
}

#[cfg(windows)]
#[path = "spawn/windows_raw.rs"]
pub(crate) mod windows_raw;

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/placement_reuse_tests.rs"]
mod placement_reuse_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/pidfd_tests.rs"]
mod pidfd_tests;

/// The fate of a child a failed tokio spawn abandoned with no handle on it (see
/// [`warn_for_abandoned`]). Linux's handshake holds a pidfd on it, and answers itself.
///
/// Off Linux nothing is known of such a child, because only a Linux cgroup leaf says more than
/// `MaybeUnreachable`, and the spawn answers the other two itself, so they are a contract breach
/// that claims nothing.
#[cfg(not(target_os = "linux"))]
fn abandoned_fate(child: crate::containment::AbandonedChild) -> ChildFate {
    use crate::containment::AbandonedChild;

    match child {
        AbandonedChild::Ended | AbandonedChild::MaybeUnreaped => {
            debug_assert!(false, "only a Linux cgroup leaf abandons a child as `{child:?}`");
            ChildFate::Unknown
        }
        AbandonedChild::Front(fate) => {
            debug_assert!(false, "only a Linux cgroup leaf finds an abandoned front");
            front_child_fate(fate)
        }
        AbandonedChild::MaybeUnreachable => ChildFate::Running { id: None },
    }
}

/// Say what a failed tokio spawn may have left behind of its child: nothing, a zombie nothing
/// reaps, or a process nothing can reach.
///
/// tokio can fail a spawn after its fork, dropping the child neither killed nor reaped and
/// returning no pid. Only a cgroup leaf still reaches such a child, and only once the child has
/// told it who it is. The error cannot tell a failure before the fork from one after it, hence
/// "may". Reported at `warn` every time. The fate of an elevation `front` the leaf found is noted
/// on the error instead, as the spawn's other failures note it.
fn warn_for_abandoned(child: crate::containment::AbandonedChild, error: &Error) {
    use crate::containment::AbandonedChild;

    let consequence = match child {
        AbandonedChild::Front(_) | AbandonedChild::Ended => return,
        AbandonedChild::MaybeUnreaped => {
            "the child exits before `exec`; if its spawn did not collect it, it is left unreaped, since it \
             never reached the point where it names itself and nothing holds its pid"
        }
        AbandonedChild::MaybeUnreachable => {
            "unless its spawn collected it, the child was left running and nothing \
             can reach it: only a cgroup v2 leaf is killed without the child's pid"
        }
    };
    log::warn!("tokio spawn failed ({error}); if it failed after forking, {consequence}");
}

/// The fate of an elevation front the leaf's abandonment found: reaped through the leaf, left
/// running, or in a place that could not be read.
fn front_child_fate(fate: crate::child::spawn::FrontFate) -> ChildFate {
    use crate::child::spawn::FrontFate;

    match fate {
        FrontFate::Reaped => ChildFate::Reaped,
        FrontFate::LeftUnreaped => ChildFate::Running { id: None },
        FrontFate::Unaccounted | FrontFate::Unplaced => ChildFate::Unknown,
        FrontFate::NotAFront => {
            debug_assert!(false, "an abandoned front is a front");
            ChildFate::Unknown
        }
    }
}

/// The failure of a tokio spawn that left a child with no handle on it (Windows, macOS): the program
/// may have started, and `abandoned` says what became of the child. A front the leaf found notes
/// its fate on the error.
#[cfg(not(target_os = "linux"))]
fn abandoned_failure(
    abandoned: crate::containment::AbandonedChild,
    error: Error,
    front: Option<crate::elevation::front::Front>,
) -> SpawnFailure {
    warn_for_abandoned(abandoned, &error);
    match abandoned {
        crate::containment::AbandonedChild::Front(fate) => {
            SpawnFailure::started(fate.note(error, front, None), front_child_fate(fate))
        }
        other => SpawnFailure::started(error, abandoned_fate(other)),
    }
}

/// The failure of a Linux tokio spawn once its leaf's abandonment ran. The handshake already
/// answered, and tore down any child it held; only a front spawned for a leaf (`left_to_leaf`) was
/// left to the leaf, whose abandonment answers for it.
#[cfg(target_os = "linux")]
fn abandoned_after_handshake(
    abandoned: crate::containment::AbandonedChild,
    failure: SpawnFailure,
    front: Option<crate::elevation::front::Front>,
    left_to_leaf: bool,
) -> SpawnFailure {
    use crate::containment::AbandonedChild;

    warn_for_abandoned(abandoned, failure.error());
    if !left_to_leaf {
        return failure;
    }
    failure.answered_by(|error| match abandoned {
        AbandonedChild::Front(fate) => (fate.note(error, front, None), front_child_fate(fate)),
        // Out of the leaf's reach, and not known to be dead.
        AbandonedChild::MaybeUnreachable => (error, ChildFate::Running { id: None }),
        AbandonedChild::Ended | AbandonedChild::MaybeUnreaped => (error, ChildFate::Unknown),
    })
}
