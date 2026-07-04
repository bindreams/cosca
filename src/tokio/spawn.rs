//! Async spawn: a `::tokio::process::Command` over the sync spawn core via `as_std_mut`;
//! tokio owns piped std fds, we own file/null/inherit/merge ends; identity is read before any
//! await, then attach (with error-path teardown).

use std::process::Stdio as StdStdio;

use crate::child::spawn::{build_std_command, resolve_identity, resolve_stdio, PipeOwnership};
use crate::command::Command;
use crate::error::Error;
use crate::stdio::{Fd, ResolvedStdio};

use super::child::{reap_now, Child};

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    // tokio's `process::Command::spawn` needs a running reactor; outside ANY runtime it panics on
    // Unix and defers the failure on Windows — reject that no-runtime case up front so it is a typed
    // Err on every platform.
    if ::tokio::runtime::Handle::try_current().is_err() {
        return Err(Error::Io(std::io::Error::other(
            "subprocess::tokio::Command must be spawned from within a Tokio runtime",
        )));
    }

    let fds = std::mem::take(cmd.fds_mut());
    let kill_on_drop = cmd.kill_on_drop_flag();

    // fd >= 3 needs an async parent end (AsyncFd), not yet built; reject it loudly rather than
    // silently mis-wiring stdio. (Merge-into-a-piped-target is likewise rejected, inside
    // `resolve_stdio` under the `Deferred` strategy.)
    for slot in fds.keys() {
        if slot.raw() >= 3 {
            return Err(Error::Unsupported {
                op: format!("async {slot}"),
                platform: std::env::consts::OS,
                detail: "arbitrary descriptors (>= 3) are not yet supported on the async API".into(),
            });
        }
    }

    let std_cmd = build_std_command(cmd)?;
    let mut tcmd = ::tokio::process::Command::new(std::ffi::OsStr::new(""));
    *tcmd.as_std_mut() = std_cmd;
    // tokio's own `kill_on_drop` is intentionally left at its `false` default: subprocess's
    // `Child::drop` (attached.hard_kill + reap_now) is the SOLE teardown owner. Forwarding the
    // builder's `kill_on_drop` to `tcmd` would make tokio fire its own kill and race reap_now.

    // Resolve our-owned child ends via the shared core. PIPE slots are tokio-owned (`Deferred`):
    // they get no child end here and are assigned `Stdio::piped()` below.
    let std_slots = [Fd::STDIN, Fd::STDOUT, Fd::STDERR];
    let (mut child_ends, parent_ends) = resolve_stdio(&fds, &std_slots, PipeOwnership::Deferred)?;
    // `Deferred` skips every pipe slot before a parent end can be created, so this is provably
    // empty — assert it so a future stdio variant that violated it trips loudly, not silently leaks.
    debug_assert!(
        parent_ends.is_empty(),
        "Deferred pipe ownership must not produce parent ends"
    );
    let _ = parent_ends;

    for slot in std_slots {
        let stdio: StdStdio = match fds.get(&slot) {
            Some(ResolvedStdio::Pipe(_)) => StdStdio::piped(),
            _ => StdStdio::from(
                child_ends
                    .remove(&slot)
                    .unwrap_or_else(|| unreachable!("a configured non-pipe slot must have a resolved child end")),
            ),
        };
        match slot {
            Fd::STDIN => tcmd.stdin(stdio),
            Fd::STDOUT => tcmd.stdout(stdio),
            _ => tcmd.stderr(stdio),
        };
    }

    let prepared = crate::containment::prepare(tcmd.as_std_mut(), &cmd.contain_request());
    let mut child = tcmd.spawn().map_err(Error::Io)?;

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

    Ok(Child::from_parts(child, id, attached, kill_on_drop, containment))
}

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;
