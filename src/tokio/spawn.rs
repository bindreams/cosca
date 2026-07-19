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
            "subprocess::tokio::Command must be spawned from within a Tokio runtime",
        )));
    }

    let mut fds = std::mem::take(cmd.fds_mut());
    let kill_on_drop = cmd.kill_on_drop_flag();

    // Route the cases tokio's `Command` cannot express to the raw `CreateProcessW` backend
    // (Plan 12): an `executable()` loaded independently of argv[0], OR arbitrary descriptors
    // (fd >= 3, wired through the MSVCRT `lpReserved2` table). The raw backend handles BOTH
    // contained and uncontained via its own async containment (Task 8); everything else stays on
    // the std/tokio path, whose `prepare` applies containment for argv/commandline spawns.
    #[cfg(windows)]
    if cmd.executable_path().is_some() || fds.keys().any(|f| f.raw() >= 3) {
        return windows_raw::spawn_raw(cmd, fds, kill_on_drop);
    }

    let std_cmd = build_std_command(cmd)?;
    let mut tcmd = ::tokio::process::Command::new(std::ffi::OsStr::new(""));
    *tcmd.as_std_mut() = std_cmd;
    // tokio's own `kill_on_drop` is intentionally left at its `false` default: subprocess's
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

    let prepared = crate::containment::prepare(tcmd.as_std_mut(), &cmd.contain_request());

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

    // Serialize the spawn against the raw backend's inheritable-handle window via the shared spawn
    // lock: tokio's own handle-inheritance marking must not overlap a raw `CreateProcessW` spawn on
    // another thread (mirrors the sync std path).
    let mut child = {
        let _guard = crate::child::spawn::spawn_lock();
        tcmd.spawn().map_err(Error::Io)?
    };

    // Identity must be read before any await: spawn + attach are synchronous, so the runtime cannot
    // park and reap the child in between. Even if the child has already exited, tokio's held handle
    // pins the pid against reuse, so `ProcessId::of` still resolves it (as the sync spawn documents).
    let pid = child.id().expect("a freshly spawned, un-awaited tokio child has a pid");
    let id = match resolve_identity(pid) {
        Some(id) => id,
        // Mirror the attach-failure path below: tear the child down so a vanished-identity error
        // never leaks a live (Windows: still CREATE_SUSPENDED) process.
        None => {
            reap_now(&mut child, pid, false); // never awaited — an already-Done child is impossible
            return Err(Error::Io(std::io::Error::other(
                "spawned async child vanished before identity read",
            )));
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
    let (containment, attached) = match attach {
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

    Ok(Child::from_parts(
        ProcSource::Tokio(child),
        id,
        attached,
        kill_on_drop,
        containment,
        pipes,
        owned_std,
    ))
}

#[cfg(windows)]
#[path = "spawn/windows_raw.rs"]
pub(crate) mod windows_raw;

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;
