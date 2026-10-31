//! std-only spawn: resolve the crate's `Stdio` model onto `std::process::Command`,
//! wire the program/args via the `quote` module, and adopt the child into a `SharedChild`.

use std::collections::BTreeMap;
use std::process::Stdio as StdStdio;

use crate::child::proc_handle::ProcHandle;
use crate::child::shared::SharedChild;
pub(crate) use crate::child::spawn::failure::{after_the_spawn, Classify, SpawnFailure};
use crate::child::{Child, ParentEnd};
use crate::command::{Command, CommandInput, EnvOp};
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::stdio::{Direction, Fd, ResolvedStdio};

// A child-side descriptor handed to std via `Stdio::from`.
#[cfg(unix)]
pub(crate) type ChildEnd = std::os::unix::io::OwnedFd;
#[cfg(windows)]
pub(crate) use windows_child_end::ChildEnd;

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, SpawnFailure> {
    let child = spawn_uncommitted(cmd)?;
    child.commit_kill_on_drop();
    Ok(child)
}

/// [`spawn`] up to the handle it returns, whose containment resource still tears the tree down
/// on drop whatever `kill_on_drop` says.
pub(crate) fn spawn_uncommitted(cmd: &mut Command) -> Result<Child, SpawnFailure> {
    let kill_on_drop = cmd.kill_on_drop_flag();
    // Elevation runs BEFORE spawn_unelevated's std::mem::take(cmd.fds_mut()), so the
    // effect layers see/modify cmd.fds() while it is still populated (the honest Windows
    // reject gate and the POSIX derived-command build both depend on it).
    if cmd.elevation_request().enabled {
        #[cfg(windows)]
        {
            return crate::elevation::windows::spawn_elevated(cmd, kill_on_drop);
        }
        #[cfg(unix)]
        {
            let crate::elevation::posix::PosixRewrite {
                mut derived,
                report,
                password_write,
                backend_path,
            } = crate::elevation::posix::rewrite(cmd).not_started()?;
            // From here the child is the backend: its elevated program may outlive what happens to it.
            let wrapper = report.as_ref().is_some_and(|r| r.via.program_outlives_child());
            let spawned = (|| {
                // The derived program IS the backend; remap an exec failure to
                // BackendUnavailable ONLY when the backend path is the culprit (a bad cwd
                // yields the same kind and stays a plain Io). An already-elevated derived
                // (sanitized original) has no backend path, so it is never remapped.
                let r = spawn_unelevated(&mut derived, kill_on_drop);
                let mut child = match backend_path.as_deref() {
                    Some(bp) => r.map_err(|f| f.map(|e| crate::elevation::remap_derived_spawn_error(e, bp)))?,
                    None => r?,
                };
                // Set the elevation report BEFORE handling the deferred password: a cleanup
                // kill() in the write-failure path must see the elevated state so an EPERM maps
                // to the typed Unkillable rather than leaking a raw Io.
                child.set_elevation(report);
                let written = password_write.map_or(Ok(()), |pw| pw.write_after_spawn());
                finish_elevated(child, written)
            })();
            return spawned.map_err(|failure| if wrapper { failure.behind_wrapper() } else { failure });
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err(SpawnFailure::NotStarted(Error::Unsupported {
                op: "elevation".into(),
                platform: std::env::consts::OS,
                detail: "no elevation backend on this platform".into(),
            }));
        }
    }
    spawn_unelevated(cmd, kill_on_drop)
}

/// Finish a POSIX elevated spawn whose deferred password write returned `written`.
///
/// On a failed write, do NOT orphan the running elevated child: kill its tree through its
/// containment when it has one, so a descendant forked before the failure dies too, then kill
/// and reap the root by its own handle, folding both outcomes into the error.
///
/// The reap follows the ROOT's kill alone. A tree kill can fail (a setuid member refusing the
/// signal) while the root dies, and a killed root must be waited for, or it stays a zombie. A
/// failed root kill (e.g. `Unkillable`) cannot be waited for, so it gets a non-blocking
/// `try_wait` and the note that it may still be running. A root already reaped (`Sent::Gone`) is
/// neither waited on nor `try_wait`ed, and is reported as "could not be terminated (it was already
/// reaped)".
///
/// A reaped root's number may name another process by now, so the tree kill is skipped when it
/// would name the tree by that number (a process group, a ppid walk), and the note says so. On Linux
/// 6.9+ the root's pidfd decides a process group instead: it is killed while it has a member. The
/// decision is one look at the root; each send by the group's number then checks the root again, as
/// for [`Child::kill_tree`].
///
/// A live front outside a cgroup (see [`Child::kill`]) is signalled by neither kill: the root's
/// kill is the typed `Unkillable`, and the note says so. A front that had already exited is reaped,
/// and the note says it had exited. A front in a cgroup is ended by the tree's cgroup kill alone,
/// read after it. The front's gate is decided once, before both kills.
///
/// The backend has run by now, so the program may have started: a backend that needed no password
/// runs it without reading one.
///
/// A root whose handle could not say whether it is reaped (`RootState::Unknown`) is killed through
/// its handle like any other, and the tree kills named by its number are skipped, as for a reaped
/// root. A root this process does not pin (`RootState::Unpinned`, macOS) is left alone: neither
/// signalled nor waited on, and the error says so; its fate is `Gone`, as the classifier
/// ([`Foreign::fate`](crate::wait::exit_only::Foreign::fate)) gives a zombie launchd holds. The event
/// warns once: the unsettled root, a failed reap and any other leftover share one record, labelled
/// `finish_elevated`.
///
/// The handle is disarmed only once the cleanup has settled both the tree and the root: each was
/// killed, is gone, or was deliberately left alone (a reaped or unpinned root, a live front).
/// Otherwise (a refused kill, a failed tree kill, a failed reap) the handle stays armed, so its drop
/// tries again; that drop does not warn of the event a second time.
#[cfg(unix)]
pub(crate) fn finish_elevated(mut child: Child, written: Result<(), Error>) -> Result<Child, SpawnFailure> {
    let Err(write_err) = written else {
        return Ok(child);
    };
    // A live front outside a cgroup is not signalled, by its group or otherwise: the root's kill
    // below then says why.
    let gate = child.kill_gate();
    // The look at the root, right before the tree kill it decides.
    let view =
        crate::containment::DropView::read("finish_elevated", child.id, || child.proc.state(), &child.tree_killed);
    let mut report = crate::child::drop_report::DropReport::new("finish_elevated", &view);
    let mut skipped = None;
    let front_closed = matches!(gate, crate::elevation::front::Gate::Closed(_));
    let tree = (child.containment().can_teardown() && !front_closed).then(|| {
        child
            .attached
            .hard_kill_marking_unless_reaped(
                &view,
                &child.tree_killed,
                &crate::containment::GroupRoot::new(child.proc.pidfd(), &|| child.group_number_holds()),
            )
            .map(|s| skipped = s)
    });
    let tree_failure = match &tree {
        Some(Err(e)) => Some(e.to_string()),
        _ => None,
    };
    // The tree is settled when it was killed completely, was not for the cleanup to kill, or was
    // deliberately left alone because the root is reaped or unpinned.
    let tree_settled = tree.is_none() || child.tree_killed.is_set() || (skipped.is_some() && view.leaves_root_alone());
    let (mut tree_note, tree_warn) = report_tree_teardown(tree, &child.attached.teardown_subject());
    report.tree = tree_warn;
    if let Some(note) = skipped {
        tree_note.push_str(&format!("; its contained tree was not killed: {note}"));
    }
    let exited_front = matches!(gate, crate::elevation::front::Gate::Exited);
    // The root is settled when it is gone (killed and reaped, or reaped by someone else) or was
    // deliberately not signalled (an unpinned root, a live front). A refused kill, or a reap that
    // failed, leaves it to the handle's drop to try again.
    let mut root_settled = true;
    let pid = child.id().pid();
    let (root_note, fate) = if view.unpinned_root() {
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
            crate::elevation::front::Gate::CgroupOnly if child.tree_killed.is_set() => {
                child.cgroup_kill_reached().map(|()| crate::signal::Sent::Delivered)
            }
            // No kill reached the cgroup: refused as `kill` refuses, naming why.
            crate::elevation::front::Gate::CgroupOnly => Err(crate::elevation::front::cgroup_not_killed_of(
                child.front,
                child.id().pid(),
                tree_failure.as_deref(),
            )),
            crate::elevation::front::Gate::Closed(unkillable) => Err(unkillable),
            gate => child.kill_sent_gated(gate),
        };
        match root {
            Ok(crate::signal::Sent::Gone) if exited_front => (
                "the elevated child had already exited, and was reaped by someone else".to_string(),
                ChildFate::Gone,
            ),
            Ok(crate::signal::Sent::Gone) => (
                "the elevated child could not be terminated (it was already reaped)".to_string(),
                ChildFate::Gone,
            ),
            // A sync child's kill always verifies: the pidfd or the handle names it, and on macOS the
            // unique id every production spawn adopts is held (`SharedChild::adopt` is test-only there).
            // Were it ever not, the child may still be running.
            Ok(crate::signal::Sent::Unverified) => {
                debug_assert!(false, "a sync child's kill always verifies its target");
                (
                    "the elevated child could not be terminated (it could not be verified, and may still be running)"
                        .to_string(),
                    ChildFate::Running { id: Some(child.id()) },
                )
            }
            Ok(crate::signal::Sent::Delivered) => {
                #[cfg(test)]
                fault::run_between_kill_and_wait();
                match wait_killed_elevated(&child) {
                    Ok(_status) => {
                        #[cfg(test)]
                        fault::record_teardown_reap(pid, _status);
                        let note = if exited_front {
                            "the elevated child had already exited, and was reaped"
                        } else {
                            "the elevated child was terminated"
                        };
                        (note.to_string(), ChildFate::Reaped)
                    }
                    Err(e) if exited_front => {
                        root_settled = false;
                        report
                            .left
                            .push(format!("could not reap the exited elevated child pid {pid}: {e}"));
                        (
                            format!("the elevated child had already exited, but could not be reaped ({e})"),
                            ChildFate::Killed,
                        )
                    }
                    Err(e) => {
                        root_settled = false;
                        report
                            .left
                            .push(format!("could not reap the killed elevated child pid {pid}: {e}"));
                        (
                            format!("the elevated child was killed but could not be reaped ({e})"),
                            ChildFate::Killed,
                        )
                    }
                }
            }
            Err(e) => {
                root_settled = front_closed;
                #[cfg(test)]
                fault::run_between_kill_and_wait();
                // The non-blocking look reaps a child that has exited by now.
                let fate = fate_of_a_look(child.try_wait().map_err(|e| e.raw_os_error()), Some(child.id()));
                (format!("the elevated child could not be terminated ({e})"), fate)
            }
        }
    };
    let warned = report.emit(&[]);
    if tree_settled && root_settled {
        child.kill_on_drop = false;
    }
    // The drop, armed to try again or not, need not warn of what the cleanup warned of again.
    child.reported = warned;
    Err(SpawnFailure::started(
        Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: format!("{write_err}; {root_note}{tree_note}"),
        },
        fate,
    ))
}

/// The fate of a child cosca did not kill (its kill was refused, or never sent), from one
/// non-blocking look that collects it if it has exited: `Reaped` then, `Running` if it has not
/// exited, `Gone` if the look found it reaped by someone else (`ECHILD`), and `Unknown` if the look
/// failed otherwise. `looked` carries the failed look's OS error, and `id` is the child's identity,
/// if the spawn had read one.
pub(crate) fn fate_of_a_look(
    looked: Result<Option<std::process::ExitStatus>, Option<i32>>,
    id: Option<ProcessId>,
) -> ChildFate {
    match looked {
        Ok(Some(_)) => ChildFate::Reaped,
        Ok(None) => ChildFate::Running { id },
        #[cfg(unix)]
        Err(Some(libc::ECHILD)) => ChildFate::Gone,
        Err(_) => ChildFate::Unknown,
    }
}

/// `child.wait()` after the root's kill, which a test can force to fail. The forced failure still
/// REAPS first, so the test that asks for it leaks nothing.
#[cfg(unix)]
fn wait_killed_elevated(child: &Child) -> Result<std::process::ExitStatus, Error> {
    let waited = child.wait();
    #[cfg(test)]
    if let Some(marker) = fault::take_force_reap_failure() {
        return waited.and(Err(Error::Io(std::io::Error::other(marker))));
    }
    waited
}

/// The head of the `warn` line [`report_tree_teardown`] logs.
#[cfg(unix)]
pub(crate) const TREE_TEARDOWN_WARN: &str = "tree teardown after a failed password write failed";

/// The marker of the warning about `leaf_path`'s tree teardown: unique to that leaf, so a twin
/// test running in parallel (same message text) is never miscounted.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn teardown_warn_marker(leaf_path: &std::path::Path) -> String {
    format!("{TREE_TEARDOWN_WARN} (cgroup leaf {})", leaf_path.display())
}

/// Report a failed password write's tree teardown, for both `finish_elevated` variants: the note
/// for the error's `detail`, and the text the cleanup's one `warn` carries (the tree and the root
/// are one event). `subject` names the tree, because the teardown error itself may not (see
/// `Attached::teardown_subject`).
///
/// `None`: no tree kill was tried, as the containment cannot tear one down. `Some(Ok)`: it worked.
/// Neither is reported.
#[cfg(unix)]
pub(crate) fn report_tree_teardown(
    tree: Option<Result<(), Error>>,
    subject: &dyn std::fmt::Display,
) -> (String, Option<String>) {
    let Some(Err(e)) = tree else {
        return (String::new(), None);
    };
    (
        format!("; its contained tree could not be killed ({subject}: {e})"),
        Some(format!("{TREE_TEARDOWN_WARN} ({subject}): {e}")),
    )
}

/// The one authority for Windows backend routing: does `cmd` go to the raw `CreateProcessW`
/// backend rather than std? Both routers read this — the sync one below and the async mirror in
/// `crate::tokio::spawn` — so the rule cannot be two copies that drift.
///
/// **Call it before `std::mem::take(cmd.fds_mut())`.** It reads `cmd.fds()`; after the take the
/// map is empty and the fd term silently evaluates false.
///
/// Pinned by `spawn_tests::routes_to_raw_backend_answers_for_executables_and_high_descriptors`,
/// which is also what makes the backend names in `tests/windows_creation_flags.rs` true for its
/// argv legs (an argv-only command reports the same `argv[0]` whichever backend spawned it).
#[cfg(windows)]
pub(crate) fn routes_to_raw_backend(cmd: &Command) -> bool {
    cmd.executable_path().is_some() || cmd.fds().keys().any(|slot| slot.raw() >= 3)
}

/// The non-elevated spawn core: resolve stdio, wire program/args, spawn, attach,
/// read identity, adopt. Shared by the ordinary path and the elevation paths'
/// already-elevated / derived-command continuations (which must spawn without
/// re-entering the elevation branch).
///
/// Every failure says whether the program could have started; see [`SpawnFailure`].
pub(crate) fn spawn_unelevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, SpawnFailure> {
    // Before anything is made or forked: a pidfd that is refused means no child, and no leaf.
    #[cfg(target_os = "linux")]
    crate::os_process::linux::open::probe_pidfd_support().not_started()?;
    // Read the routing rule BEFORE the take, which empties the map the rule reads. Evaluated
    // after, it would collapse to "does it have an executable()", and a high-descriptor-only
    // command would take the std path — whose fd >= 3 collection is unix-only, so the
    // descriptors would be dropped with no error and no panic.
    #[cfg(windows)]
    let to_raw_backend = routes_to_raw_backend(cmd);
    let fds = std::mem::take(cmd.fds_mut());

    // Windows routing. The raw `CreateProcessW` backend owns the cases std cannot
    // express: an `executable()` loaded independently of argv[0], and arbitrary descriptors
    // (fd >= 3) via the MSVCRT `lpReserved2` fd-table. It handles both uncontained and
    // CONTAINED children (Job Object / TreeWalk).
    #[cfg(windows)]
    if to_raw_backend {
        return windows_raw::spawn_raw(cmd, fds, kill_on_drop);
    }
    #[cfg(unix)]
    let mut steps = in_child::InChild::default();
    #[cfg(target_os = "linux")]
    let (mut std_cmd, handshake) = build_std_command_with(cmd, &mut steps, pidfd_handshake::register).not_started()?;
    #[cfg(target_os = "macos")]
    let (mut std_cmd, report) = build_std_command_with(cmd, &mut steps, unique_report::register).not_started()?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let mut std_cmd = build_std_command(cmd).not_started()?;

    // Resolve every configured slot to a child end via the shared core. Slots: 0/1/2
    // (defaulting to inherit) plus, on Unix, any configured n>=3. We own our pipes
    // (`std::io::pipe`) and keep the parent ends.
    let std_slots = [Fd::STDIN, Fd::STDOUT, Fd::STDERR];
    let all_slots: Vec<Fd> = {
        // Yield 0/1/2 first (even unconfigured, for inherit defaulting), then any
        // configured n>=3. The n>=3 collection is Unix-only: on Windows the routing
        // above (any fd>=3 goes to the raw backend) guarantees `fds` holds no fd>=3,
        // so the push is dead code there — cfg-gate it to make that explicit.
        #[cfg_attr(not(unix), allow(unused_mut, reason = "the n>=3 push below is unix-only"))]
        let mut v: Vec<Fd> = std_slots.to_vec();
        #[cfg(unix)]
        for &fd in fds.keys() {
            if fd.raw() >= 3 {
                v.push(fd);
            }
        }
        v
    };
    let (mut child_ends, parent_ends) =
        resolve_stdio(&fds, &all_slots, PipeOwnership::Owned, ParentStd::read()).not_started()?;

    // Hand 0/1/2 child ends to std (consumes them; std closes its copies on spawn).
    for slot in std_slots {
        if let Some(end) = child_ends.remove(&slot) {
            let stdio = StdStdio::from(end);
            match slot {
                Fd::STDIN => std_cmd.stdin(stdio),
                Fd::STDOUT => std_cmd.stdout(stdio),
                _ => std_cmd.stderr(stdio),
            };
        }
    }

    // Every child fd number this spawn will occupy, so the macOS fd-marker install (below)
    // places its own descriptor above all of them rather than colliding with a user mapping.
    #[cfg(unix)]
    let reserved: Vec<i32> = child_ends.keys().map(|fd| fd.raw()).collect();
    #[cfg(not(unix))]
    let reserved: Vec<i32> = Vec::new();

    // Phase 1 (before spawn): root detection + pre-spawn containment setup, whose in-child steps go
    // into `steps` (order and why: see `in_child`). The hook is registered right before the spawn,
    // after the fd map's step is added.
    //
    // On macOS, `prepare` also clears FD_CLOEXEC on the marker write end for the forked
    // child only (the supervisor's own copy stays CLOEXEC — see `fdmarker::install`'s doc
    // comment). That leaves a real, bounded window — between the clear and this spawn's own
    // `exec` — where a truly concurrent, unrelated `fork()` on another thread of THIS process
    // could transiently inherit the marker fd and carry it past its own `exec`. The shared,
    // process-wide `spawn_lock` (already used to serialize against the Windows raw backend)
    // is widened on macOS to enclose `prepare` through `drop(std_cmd)`, closing that window
    // against every other cosca-originated spawn; `install`'s doc comment names the residual
    // (a spawn racing this one via a path outside cosca's own spawn functions) that no local
    // code can close.
    #[cfg(target_os = "macos")]
    let (mut prepared, child, unique) = {
        let (prepared, spawned, first) = {
            let _guard = spawn_lock();
            let prepared = crate::containment::prepare(
                &mut std_cmd,
                &mut steps,
                &cmd.contain_request(),
                cmd.flags_request(),
                &reserved,
                cmd.fd_marker_suppressed(),
                cmd.env_ops(),
            )
            .not_started()?;
            let report = report.open(&_guard).not_started()?;

            // On Unix, hand n>=3 child ends to fd_map, whose step dup2's each OwnedFd to its target
            // number post-fork. The hook runs it last, after every step that may still need a
            // descriptor it could replace; std also dup2's 0/1/2 before any pre_exec runs (std
            // disables posix_spawn when hooks are registered), so our n>=3 mappings never clobber the
            // std stdio fds either. A duplicate child fd number is unreachable: child_ends keys come
            // from a BTreeMap, so each child fd number is unique.
            let mappings: Vec<fd_map::FdMapping> = child_ends
                .into_iter()
                .map(|(fd, owned)| fd_map::FdMapping {
                    parent_fd: owned,
                    child_fd: fd.raw(),
                })
                .collect();
            fd_map::install(&mut steps, mappings).not_started()?;
            steps.register(&mut std_cmd);

            #[allow(
                clippy::disallowed_methods,
                reason = "spawn_lock is held by `_guard`, taken at the top of this block"
            )]
            let (spawned, first) = report.run(|| std_cmd.spawn().map_err(Error::Io), |c| Some(c.id()));
            drop(std_cmd);
            (prepared, spawned, first)
        };
        // Outside the lock, which covers only the window before the ends are close-on-exec: the wait
        // for a report the first read missed has no bound.
        let unique = first.finish();
        // std collected the child of a spawn it failed, which never ran the program.
        let c = spawned
            .map_err(|e| unique_report::failed_spawn_error(e, &unique))
            .not_started()?;
        (prepared, c, unique)
    };
    // Linux holds the child before `exec` until the parent has its pidfd; see `pidfd_handshake`.
    // Everything from the channel's creation to the helper's join is under `spawn_lock`.
    #[cfg(target_os = "linux")]
    let (mut prepared, child, pidfd) = {
        let prepared = crate::containment::prepare(
            &mut std_cmd,
            &mut steps,
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
        )
        .not_started()?;
        // A front this host could not place after a cgroup kill is refused before it is spawned.
        if let Some(leaf) = prepared
            .cgroup_leaf
            .as_ref()
            .filter(|_| cmd.elevation_front().is_some())
        {
            crate::containment::cgroup::front_placement(|| leaf.id()).not_started()?;
        }

        let _guard = spawn_lock();
        // The handshake's hook was registered first of all (see `build_std_command_with`), so the fd
        // map, which may `dup2` a mapping onto any number including the channel's, runs after the
        // handshake is done.
        let handshake = handshake.open(&_guard).not_started()?;
        let mappings: Vec<fd_map::FdMapping> = child_ends
            .into_iter()
            .map(|(fd, owned)| fd_map::FdMapping {
                parent_fd: owned,
                child_fd: fd.raw(),
            })
            .collect();
        fd_map::install(&mut steps, mappings).not_started()?;
        steps.register(&mut std_cmd);

        // Classified at the SYSCALL, not around the whole spawn: an access-denied from stdio
        // resolution or the post-spawn attach has nothing to do with a breakaway request.
        #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard` above")]
        let held = handshake.run(|| std_cmd.spawn())?;
        (prepared, held.child, held.pidfd)
    };
    #[cfg(windows)]
    let (mut prepared, child) = {
        let prepared = crate::containment::prepare(
            &mut std_cmd,
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
        )
        .not_started()?;

        // The std Child is owned here so containment can job-assign + resume it. Serialize the
        // spawn against the raw backend's inheritable-handle window via the shared spawn lock: std's
        // own handle-inheritance marking must not overlap a raw spawn on another thread.
        let c = {
            let _guard = spawn_lock();
            // Classified at the SYSCALL, not around the whole spawn: an access-denied from stdio
            // resolution or the post-spawn attach has nothing to do with a breakaway request.
            #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `_guard` above")]
            let spawned = std_cmd.spawn().map_err(Error::Io);
            let spawned =
                spawned.map_err(|e| crate::command::flags::classify_spawn_syscall_error(e, *cmd.flags_request()));
            spawned.not_started()?
        };
        (prepared, c)
    };
    // Phase 2 (after spawn, before adopt): attach the mechanism (job/cgroup/...).
    // `prepared` is consumed here: Linux cgroup leaf ownership moves to Attached::Cgroup.
    #[cfg(windows)]
    let proc_handle = {
        use std::os::windows::io::AsRawHandle;
        child.as_raw_handle()
    };
    // Linux tears down through the pidfd the child sent: nothing there kills or reaps by pid.
    #[cfg(target_os = "linux")]
    let child = HeldStdChild {
        through: PidfdChild::new(Some(child.id()), pidfd),
        child,
    };
    let front = cmd.elevation_front();
    // macOS has no handle: the unique id the child reported before `exec` is what the identity is
    // checked against and the shared child is adopted with. The report decides first: a child that
    // died before `exec` is that, whatever an attach would find of its pid.
    #[cfg(target_os = "macos")]
    let unique = match unique_report::adopted_id(unique, child.id()) {
        Ok(unique) => unique,
        Err(not_adopted) => return Err(abandon_unadopted(child, not_adopted, front, prepared)),
    };
    // A front's leaf subtree, captured while it exists: a failure arm drops the leaf, killing it.
    #[cfg(target_os = "linux")]
    let subtree = front_subtree(front.and(prepared.cgroup_leaf.as_ref()));
    if front.is_some() {
        prepared.watch_front(child.id());
    }
    // Read the identity while we still own the un-reaped `std::process::Child`, and check the read
    // against the handle held since the spawn: a pid alone does not say whom it names once
    // something else has reaped the child. The attach takes this identity and does not re-read
    // the root's, so a reap and reuse after the check cannot make the containment name a stranger.
    // `SharedChild::adopt` reaps nothing, so this is also the identity it takes.
    #[cfg(test)]
    fault::run_at(fault::SpawnPoint::BeforeIdentity, child.id());
    #[cfg(target_os = "linux")]
    let through = child.through.target();
    #[cfg(target_os = "macos")]
    let through = crate::wait::exit_only::Target::pid(child.id(), Some(unique));
    #[cfg(windows)]
    let through = {
        use std::os::windows::io::AsHandle;
        crate::wait::exit_only::Target::Handle(child.as_handle())
    };
    let pid = child.id();
    #[cfg(target_os = "linux")]
    let handle = crate::containment::ChildHandle {
        pid,
        pidfd: std::os::fd::AsFd::as_fd(&child.through.pidfd),
    };
    let (resolved, mut why) = resolve_identity(pid, &through);
    let id = match resolved {
        crate::identity::Resolved::Found(id) => id,
        // Different diagnosis per arm: an OS refusal is not a vanish.
        other => {
            // Settle the leaf's verdict before any kill, so the kill never races its reads.
            settle_before_teardown(
                &mut prepared,
                #[cfg(target_os = "linux")]
                handle,
                #[cfg(not(target_os = "linux"))]
                pid,
            );
            // Linux 6.9+: the group the root may have left members in, whoever reaped the root.
            #[cfg(target_os = "linux")]
            if front.is_none() {
                kill_group_before_teardown(&prepared, handle, &mut why);
            }
            // A front's containment goes first: a cgroup leaf's drop kills it, so the teardown below
            // waits for a contained front that kill reached, and says what became of it.
            #[cfg(target_os = "linux")]
            if front.is_some() {
                drop(prepared);
            }
            #[cfg(target_os = "macos")]
            if front.is_none() {
                note_group_left_running(&prepared, pid, &mut why);
            }
            #[cfg(target_os = "macos")]
            let (fate, child_fate) = {
                let identity = if matches!(other, crate::identity::Resolved::Gone) {
                    crate::containment::RootIdentity::Gone
                } else {
                    crate::containment::RootIdentity::Unknown
                };
                // The read failed, so no identity is known.
                let child_fate = leave_unverified_child(child, identity, None, &mut why);
                (FrontFate::of_unverified(identity), child_fate)
            };
            // The read failed, so no identity is known.
            #[cfg(target_os = "linux")]
            let (fate, child_fate) =
                teardown_unadopted_or_front_noting(child, front, None, NO_WAIT_WARN, subtree.as_ref(), &mut why);
            #[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
            let (fate, child_fate) = teardown_unadopted_or_front_noting(child, front, None, NO_WAIT_WARN, &mut why);
            // The distinction must survive as a VARIANT, not as prose: a supervisor matching
            // on `Unassessable` to retry elevated would otherwise see an I/O failure and
            // treat a live, merely-unreadable child as a startup failure. A front's fate is a note.
            return Err(SpawnFailure::started(
                fate.note(spawn_identity_error(other), front, Some(pid)),
                child_fate,
            ));
        }
    };
    #[cfg(test)]
    fault::run_at(fault::SpawnPoint::BeforeAttach, child.id());
    let attachment = match attach_or_fault(
        id,
        #[cfg(target_os = "linux")]
        handle,
        #[cfg(windows)]
        proc_handle,
        prepared,
    ) {
        Ok(v) => v,
        Err(error) => {
            log::debug!("attach failed: {error}");
            // macOS: a front is left running and unreaped, sent nothing; any other child is killed
            // and reaped through its verified unique id.
            #[cfg(target_os = "macos")]
            let (fate, child_fate) = {
                assert_attach_cannot_fail(&error);
                if front.is_some() {
                    (
                        leave_front_after_attach_failure(child),
                        ChildFate::Running { id: Some(id) },
                    )
                } else {
                    (FrontFate::NotAFront, teardown_after_attach_failure(child, unique, id))
                }
            };
            // Off macOS: kill + reap so a failed attach never leaks the child (std `Child::drop`
            // neither kills nor reaps), unless it is a front. A failed attach has dropped the
            // containment already: a cgroup leaf's drop kills it, so a front in it is dying, and is
            // waited for.
            #[cfg(target_os = "linux")]
            let (fate, child_fate) = teardown_unadopted_or_front(child, front, Some(id), subtree.as_ref());
            #[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
            let (fate, child_fate) = teardown_unadopted_or_front(child, front, Some(id));
            return Err(SpawnFailure::started(fate.note(error, front, Some(pid)), child_fate));
        }
    };
    // The pidfd is already held, so adopting cannot fail.
    #[cfg(target_os = "linux")]
    let shared = SharedChild::adopt_opened(child.child, id, child.through.pidfd);
    #[cfg(target_os = "macos")]
    let shared = SharedChild::adopt_verified(child, id, unique);
    #[cfg(windows)]
    let shared = match SharedChild::adopt(child, id) {
        Ok(shared) => shared,
        Err((error, child)) => {
            let (error, fate) = teardown_after_failed_adoption(child, error, Some(id));
            return Err(SpawnFailure::started(error, fate));
        }
    };

    let mut child = Child::from_parts(ProcHandle::std(shared), id, parent_ends, kill_on_drop, attachment);
    child.set_front(cmd.elevation_front());
    Ok(child)
}

/// macOS: the identity is verified and the attach reads nothing, so an attach cannot fail. Only a
/// test seam makes it.
#[cfg(target_os = "macos")]
pub(crate) fn assert_attach_cannot_fail(error: &Error) {
    #[cfg(test)]
    debug_assert!(fault::force_attach_failure(), "a macOS attach cannot fail: {error}");
    #[cfg(not(test))]
    debug_assert!(false, "a macOS attach cannot fail: {error}");
    let _ = error;
}

/// macOS: a front whose attach failed is sent nothing and left running and unreaped, with a warning:
/// a kill would orphan the elevated program. Dropping the `std` `Child` closes our pipe ends only.
#[cfg(target_os = "macos")]
fn leave_front_after_attach_failure(child: std::process::Child) -> FrontFate {
    log::warn!(
        "elevation front pid {} is left running and unreaped, with nothing signalled or waited on by pid: its \
         attach failed, and a kill would orphan the elevated program",
        child.id()
    );
    drop(child);
    FrontFate::LeftUnreaped
}

/// macOS: a child whose attach failed is killed through its verified unique id and reaped only
/// after that id shows the zombie is ours.
/// - A kill that was delivered: wait for the exit, then reap once.
/// - A child already gone: nothing to do.
/// - A kill that failed: one verified, non-blocking reap, and the child is left.
///
/// The checks are not pins: macOS has no handle, so the kill has `via_verified_pid`'s window
/// between its id check and `kill(2)`, and the reap has `try_reap`'s between its id check and the
/// consuming `waitid`. A child that cannot be shown ours (a refused id read) is left with a `warn`;
/// a zombie launchd holds is not ours to reap, and is `Gone` (see [`Foreign::fate`]).
///
/// Dropping the `std` `Child` closes our pipe ends only.
#[cfg(target_os = "macos")]
fn teardown_after_attach_failure(child: std::process::Child, unique: u64, id: ProcessId) -> ChildFate {
    let fate = kill_and_reap_verified(child.id(), unique, Some(id), ZOMBIE_NOTE, None);
    drop(child);
    fate
}

/// The kill and reap of [`teardown_after_attach_failure`], for a child by its pid, whoever holds its
/// handle. `id` is its identity, if one was read. What it cannot do is one event, so one `warn`
/// carries every note (a verified foreign reap is a `debug`). `left_running` is the caller's note of
/// what becomes of a child this leaves running. `warn_after`: see [`kill_and_reap_unreported`].
#[cfg(target_os = "macos")]
pub(crate) fn kill_and_reap_verified(
    pid: u32,
    unique: u64,
    id: Option<ProcessId>,
    left_running: &str,
    warn_after: Option<std::time::Duration>,
) -> ChildFate {
    let mut notes = Vec::new();
    let mut breach = None;
    let (fate, kill) = kill_and_reap_noting(pid, unique, id, warn_after, &mut notes, &mut breach, |_| {});
    match kill {
        KillOutcome::Refused(why) => notes.insert(0, format!("could not be killed: {why}")),
        KillOutcome::Unverified => notes.insert(0, UNVERIFIED.to_owned()),
        KillOutcome::Delivered | KillOutcome::NotSent => {}
    }
    if matches!(fate, ChildFate::Running { .. }) {
        notes.push(left_running.to_owned());
    }
    if !notes.is_empty() {
        log::warn!("spawn teardown: pid {pid} {}", notes.join("; "));
    }
    // After the log: an assertion that fires first would take the warn with it.
    debug_assert!(breach.is_none(), "{}", breach.unwrap_or_default());
    fate
}

/// What a teardown that leaves its child running leaves behind, when nothing holds the child's handle.
#[cfg(target_os = "macos")]
const ZOMBIE_NOTE: &str = "is left unreaped: it stays a zombie once it exits";

/// What became of the kill of a teardown.
#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KillOutcome {
    /// `SIGKILL` was sent.
    Delivered,
    /// The id check found the child gone or its pid another process's: nothing was sent.
    NotSent,
    /// The child could not be verified, so nothing was sent.
    Unverified,
    /// The kill failed with this error; the child was not signalled.
    Refused(String),
}

/// What [`kill_and_reap_unreported`] did, before the event's one `warn`.
#[cfg(target_os = "macos")]
pub(crate) struct Unreported {
    pub(crate) fate: ChildFate,
    kill: KillOutcome,
    notes: Vec<String>,
    breach: Option<String>,
}

/// Kills and reaps `pid`, a child whose unique id `unique` arrived only after its spawn returned. Its
/// exec cannot be confirmed, so it is torn down through the id, as the other post-spawn failures are,
/// with its tree through `prepared`, its containment:
/// 1. the tree, while the root is alive, so a walk from it still finds its descendants (the walk's
///    own kill reaches the root first);
/// 2. the root, so it can add no member after its kill lands (a `setsid`, an `exec`, a fork);
/// 3. once the root is an unreaped zombie, whose pid still names its group, the tree again, for what
///    it added before it died: a child held between its report and a `setsid` escapes the first
///    `killpg`;
/// 4. the root's reap.
///
/// The root's wait is unbounded. With `warn_after`, it logs one `warn` naming `pid` once the wait
/// passes that long, and goes on waiting: the threshold is a message, never a decision. Otherwise it
/// warns nothing: [`Unreported::warn`] does, once.
#[cfg(target_os = "macos")]
pub(crate) fn kill_and_reap_unreported(
    pid: u32,
    unique: u64,
    prepared: crate::containment::Prepared,
    warn_after: Option<std::time::Duration>,
) -> Unreported {
    #[cfg(test)]
    fault::run_at(fault::SpawnPoint::BeforeLateTeardown, pid);
    let mut tree = LateTree::attach(pid, unique, prepared);
    tree.kill(Sweep::RootAlive);
    #[cfg(test)]
    fault::run_at(fault::SpawnPoint::BeforeLateRootKill, pid);
    let mut notes = Vec::new();
    let mut breach = None;
    let (fate, kill) = kill_and_reap_noting(pid, unique, tree.id, warn_after, &mut notes, &mut breach, |zombie| {
        tree.kill(Sweep::RootKilled { zombie })
    });
    let mut owed = std::mem::take(&mut tree.notes);
    owed.extend(tree.failure_note());
    notes.splice(0..0, owed);
    Unreported {
        fate,
        kill,
        notes,
        breach,
    }
}

/// Which sweep of a late child's tree [`LateTree::kill`] runs.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
enum Sweep {
    /// Before the root's kill, while its identity is fresh from [`LateTree::attach`].
    RootAlive,
    /// After the root's kill. `zombie`: the root is shown an unreaped zombie of ours, so its pid
    /// still names it and its group.
    RootKilled { zombie: bool },
}

/// What can reach the tree of a child whose report came late.
#[cfg(target_os = "macos")]
enum Reach {
    /// No tree of its own: uncontained, or a nested member of another root's.
    None,
    /// The containment, attached to the root, whose identity was read and shown ours.
    Attached(crate::containment::Attached),
    /// The root is not shown ours, so nothing may name the tree by its pid: only the fd marker's
    /// holders, which the kernel names by the marker pipe, can be reached.
    Holders(crate::containment::fdmarker::Marker),
}

/// The tree of a child whose report came late, and the notes its sweeps owe the teardown's `warn`.
#[cfg(target_os = "macos")]
struct LateTree {
    reach: Reach,
    /// The root's pid and the unique id it must still have for a send by its number.
    pid: u32,
    unique: u64,
    /// The root's identity, when the attach read it.
    id: Option<ProcessId>,
    /// The first sweep's failure. No later sweep is shown to reach what it missed, so none clears it:
    /// the root's kill reparents its descendants out of a walk from its pid, a member that refused the
    /// kill can leave the group, and a holder can close its marker.
    failed: Option<String>,
    /// Whether a sweep succeeded after `failed`, and none failed since.
    succeeded_after: bool,
    /// What the sweeps could not do.
    notes: Vec<String>,
}

#[cfg(target_os = "macos")]
impl LateTree {
    /// Reads the identity of `pid` and checks it against `unique`, then attaches `prepared` to it.
    /// A root that is gone or not shown ours keeps only its marker's holders, when it has a marker.
    /// A foreign reap after the check is the gap `Child::drop`'s tree kill accepts too.
    fn attach(pid: u32, unique: u64, prepared: crate::containment::Prepared) -> LateTree {
        use crate::identity::Resolved;
        let mut tree = LateTree {
            reach: Reach::None,
            pid,
            unique,
            id: None,
            failed: None,
            succeeded_after: false,
            notes: Vec::new(),
        };
        if prepared.mode.is_none() || !prepared.is_root {
            return tree;
        }
        let (resolved, mut why) = resolve_identity(pid, &crate::wait::exit_only::Target::pid(pid, Some(unique)));
        let unshown = match resolved {
            Resolved::Found(id) => {
                tree.id = Some(id);
                match attach_or_fault(id, prepared) {
                    Ok(attachment) => tree.reach = Reach::Attached(attachment.attached),
                    Err(e) => {
                        assert_attach_cannot_fail(&e);
                        tree.notes.push(format!("its tree was not killed: {e}"));
                    }
                }
                return tree;
            }
            Resolved::Gone => "the child is gone, or is not ours",
            Resolved::Unknown => "the child's identity could not be read",
        };
        match prepared.marker {
            Some(marker) => {
                tree.notes.push(why.fold(format!(
                    "{unshown}, so its tree is reached only through its marker's holders, not its process group \
                     or the processes its pid parents"
                )));
                tree.reach = Reach::Holders(crate::containment::fdmarker::Marker::without_root(marker));
            }
            None => tree.notes.push(why.fold(format!("its tree was not killed: {unshown}"))),
        }
        tree
    }

    /// Runs `sweep`.
    fn kill(&mut self, sweep: Sweep) {
        use crate::containment::Attached;
        match (&self.reach, sweep) {
            (Reach::None, _) => {}
            (Reach::Attached(attached), Sweep::RootAlive | Sweep::RootKilled { zombie: true }) => {
                let (pid, unique) = (self.pid, self.unique);
                // The root is this process's unreaped child, shown by a verified peek right before each
                // send by its pid.
                #[cfg(test)]
                crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterRootLook);
                let check = || {
                    let target = crate::wait::exit_only::Target::pid(pid, Some(unique));
                    let state = crate::signal::RootState::of_peek(crate::wait::exit_only::peek_verified(&target));
                    crate::child::tree_call::group_number_holds(pid, (state, false))
                };
                let result = match attached.hard_kill_report(&crate::containment::GroupRoot::new(None, &check)) {
                    (Err(e), _) => Err(e.to_string()),
                    (Ok(()), false) => Err("a member could not be killed".to_owned()),
                    (Ok(()), true) => Ok(()),
                };
                self.fold(result);
            }
            // The root is not shown ours any more: only the holders, and never the root.
            (Reach::Attached(Attached::FdMarker(m)), Sweep::RootKilled { zombie: false }) => {
                if let Err(e) = m.hard_kill_holders_only(m.root()) {
                    self.notes
                        .push(format!("its marker's holders were not all killed after its kill: {e}"));
                }
                self.notes.push(NOT_SWEPT_AGAIN.to_owned());
            }
            (Reach::Attached(_), Sweep::RootKilled { zombie: false }) => self.notes.push(NOT_SWEPT_AGAIN.to_owned()),
            (Reach::Holders(m), _) => {
                let result = m.hard_kill_holders_only(None).map_err(|e| e.to_string());
                self.fold(result);
            }
        }
    }

    /// Folds a sweep's result into [`failed`](Self::failed).
    fn fold(&mut self, result: Result<(), String>) {
        match (result, &self.failed) {
            (Err(e), None) => self.failed = Some(e),
            (Err(_), Some(_)) => self.succeeded_after = false,
            (Ok(()), failed) => self.succeeded_after = failed.is_some(),
        }
    }

    /// The `warn`'s note for a sweep that failed.
    fn failure_note(&mut self) -> Option<String> {
        let failed = self.failed.take()?;
        Some(if self.succeeded_after {
            format!(
                "its tree may not be fully killed: a kill of it failed ({failed}), and the later one that succeeded \
                 cannot be shown to reach what that one missed"
            )
        } else {
            format!("its tree was not fully killed: {failed}")
        })
    }
}

/// The note of a tree whose root was not shown an unreaped zombie once its kill was tried.
#[cfg(target_os = "macos")]
const NOT_SWEPT_AGAIN: &str = "it was not shown an unreaped zombie, so its tree was not killed again by its pid: what \
                               it started after the first kill of its tree may be left running";

/// What a teardown says of a child it could not verify.
#[cfg(target_os = "macos")]
const UNVERIFIED: &str = "could not be verified, so it was not signalled";

/// The one `warn` of a spawn whose child's report came late (see [`Report::Late`]).
#[cfg(target_os = "macos")]
const LATE: &str = "was spawned while at least two of this process's descriptors 0 to 2 were closed, so its exec \
                    cannot be confirmed and the program may have started; it was not adopted";

/// The sentence for what a teardown did, built from the kill and the fate, so that each is said only
/// when it happened.
#[cfg(target_os = "macos")]
fn said(kill: &KillOutcome, fate: ChildFate) -> String {
    let sent = match kill {
        KillOutcome::Delivered => "was sent SIGKILL".to_owned(),
        KillOutcome::NotSent => "was gone, or its pid names another process, so nothing was sent".to_owned(),
        KillOutcome::Unverified => UNVERIFIED.to_owned(),
        KillOutcome::Refused(why) => format!("could not be killed ({why})"),
    };
    let state = match fate {
        ChildFate::Reaped => "it was reaped",
        ChildFate::Killed => "its status was not collected",
        ChildFate::Running { .. } => "it is still running",
        ChildFate::Gone => "it is gone, or was reaped by someone else",
        ChildFate::Unknown => "what became of it is unknown",
    };
    format!("{sent}; {state}")
}

#[cfg(target_os = "macos")]
impl Unreported {
    /// The event's one `warn`: what happened to child `pid`. `tail` is what the caller did with the
    /// handle it holds, if that is worth saying (a forget's leak, a child left unreaped).
    pub(crate) fn warn(self, pid: u32, tail: Option<&str>) -> ChildFate {
        let mut line = format!("child {pid} {LATE}, and {}", said(&self.kill, self.fate));
        // `said` already says so, from the fate.
        for note in self.notes.iter().filter(|note| *note != "is still running") {
            line.push_str("; ");
            line.push_str(note);
        }
        if let Some(tail) = tail {
            line.push_str("; ");
            line.push_str(tail);
        }
        log::warn!("{line}");
        // After the log: an assertion that fires first would take the warn with it.
        debug_assert!(self.breach.is_none(), "{}", self.breach.unwrap_or_default());
        self.fate
    }

    /// What the sync spawn says of a child it leaves behind, when it is still running.
    pub(crate) fn zombie_tail(&self) -> Option<&'static str> {
        matches!(self.fate, ChildFate::Running { .. }).then_some(ZOMBIE_NOTE)
    }
}

/// The one `warn` for an elevation front whose report came late: it is sent nothing and left unreaped
/// (it stays a zombie once it exits), whatever the id says.
#[cfg(target_os = "macos")]
pub(crate) fn warn_late_front(pid: u32, tail: Option<&str>) {
    let tail = tail.map_or_else(String::new, |tail| format!("; {tail}"));
    log::warn!(
        "child {pid} {LATE}; it is an elevation front, so nothing was sent to it and it is left unreaped: it stays a \
         zombie once it exits{tail}"
    );
}

/// `warn_after`: see [`kill_and_reap_unreported`].
#[cfg(target_os = "macos")]
fn kill_and_reap_noting(
    pid: u32,
    unique: u64,
    id: Option<ProcessId>,
    warn_after: Option<std::time::Duration>,
    notes: &mut Vec<String>,
    breach: &mut Option<String>,
    after_kill: impl FnOnce(bool),
) -> (ChildFate, KillOutcome) {
    use crate::signal::{via_verified_pid, Sent, Sig};
    use crate::wait::exit_only::Foreign;
    use crate::wait::macos::Waited;

    let target = crate::wait::exit_only::Target::pid(pid, Some(unique));
    match via_verified_pid(pid, Some(unique), Sig::Kill) {
        Ok(Sent::Delivered) => {
            // A fixture that only the kill would end is released here when no kill was sent.
            #[cfg(test)]
            fault::run_between_kill_and_wait();
            let waited = await_exit_warning(pid, unique, warn_after);
            after_kill(matches!(waited, Ok(Waited::Reapable)));
            let fate = match waited {
                Ok(Waited::Reapable) => reap_verified(pid, &target, id, true, notes, breach),
                Ok(Waited::Gone) => {
                    log::debug!("spawn teardown: pid {pid} was reaped by someone else");
                    Foreign::Gone.fate(true)
                }
                Ok(Waited::Orphaned) => {
                    notes.push(unverifiable(&crate::signal::UNPINNED_WHY));
                    Foreign::Orphaned.fate(true)
                }
                Ok(Waited::DeadlinePassed) => {
                    debug_assert!(false, "an unbounded wait reported a passed deadline");
                    notes.push("is still running after its kill".to_owned());
                    ChildFate::Running { id }
                }
                // Nothing reaps it after this: the std `Child` reaps nothing, and tokio's is forgotten.
                Err(e) => {
                    notes.push(format!(
                        "could not be waited for ({e}), so it is left unreaped: it stays a zombie once it exits"
                    ));
                    ChildFate::Killed
                }
            };
            (fate, KillOutcome::Delivered)
        }
        Ok(Sent::Gone) => {
            log::debug!("spawn teardown: pid {pid} is already gone");
            after_kill(false);
            (Foreign::Gone.fate(false), KillOutcome::NotSent)
        }
        Ok(Sent::Unverified) => {
            debug_assert!(false, "`via_verified_pid` was given `Some(unique)`, so it verifies");
            after_kill(false);
            (ChildFate::Running { id }, KillOutcome::Unverified)
        }
        Err(kill) => {
            after_kill(false);
            let fate = reap_verified(pid, &target, id, false, notes, breach);
            (fate, KillOutcome::Refused(kill.to_string()))
        }
    }
}

/// Waits for the killed `pid` to become reapable. With `warn_after`, the wait that passes it logs one
/// `warn` and then goes on, unbounded ([`wait_warning`](crate::wait::teardown_warn::wait_warning)).
#[cfg(target_os = "macos")]
fn await_exit_warning(
    pid: u32,
    unique: u64,
    warn_after: Option<std::time::Duration>,
) -> std::io::Result<crate::wait::macos::Waited> {
    use crate::wait::macos::{await_reapable, Waited};

    // What the bounded look found, when it found the end: the unbounded wait answers it.
    crate::wait::teardown_warn::wait_warning(
        None,
        crate::wait::teardown_warn::Due::in_(warn_after),
        |found, until| match await_reapable(pid, Some(unique), Some(until)) {
            Ok(Waited::DeadlinePassed) => false,
            done => {
                *found = Some(done);
                true
            }
        },
        |after| warn_still_waiting(Some(pid), after),
        |found| found.unwrap_or_else(|| await_reapable(pid, Some(unique), None)),
    )
}

/// The one `warn` of a spawn teardown whose wait for the child it killed has passed `after`; the
/// wait goes on.
pub(crate) fn warn_still_waiting(pid: Option<u32>, after: std::time::Duration) {
    let who = pid.map_or_else(
        || "the spawned child (pid unknown)".to_owned(),
        |pid| format!("child {pid}"),
    );
    #[cfg(unix)]
    log::warn!(
        "{who} is not reapable {after:?} after its kill (it is still running, or a tracer holds its exit); still waiting for it to exit"
    );
    #[cfg(windows)]
    log::warn!("{who} has not exited {after:?} after its kill was requested; still waiting for it to exit");
}

/// How a failed spawn's wait for a child it killed warns once it is slow. `Option<Duration>` is the
/// plain threshold, warning by [`warn_still_waiting`]; a leaf's abandonment passes the warn of the
/// drop it belongs to, so that warn is the one that goes out and learns of it.
#[cfg(not(target_os = "macos"))]
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "only the Linux pidfd teardowns wait through it; Windows ignores the warn"
    )
)]
pub(crate) trait SlowWait {
    /// When a wait starting now is slow, and how long into it that is, or `None` if it never warns.
    fn due(&self) -> Option<(std::time::Instant, std::time::Duration)>;
    /// The one warn, for the wait for child `pid`.
    fn warn(&mut self, pid: Option<u32>, after: std::time::Duration);
}

#[cfg(not(target_os = "macos"))]
impl SlowWait for Option<std::time::Duration> {
    fn due(&self) -> Option<(std::time::Instant, std::time::Duration)> {
        self.map(|after| (crate::wait::now() + after, after))
    }

    fn warn(&mut self, pid: Option<u32>, after: std::time::Duration) {
        warn_still_waiting(pid, after);
    }
}

/// A teardown whose wait for the child it killed never warns: not an async spawn's.
#[cfg(not(target_os = "macos"))]
pub(crate) const NO_WAIT_WARN: Option<std::time::Duration> = None;

/// Runs `wait`, a failed spawn's blocking wait for the child `child` it killed, through
/// [`wait_warning`](crate::wait::teardown_warn::wait_warning), watching its pidfd.
#[cfg(target_os = "linux")]
fn wait_unadopted_warning<C: Unadopted, R>(
    child: &mut C,
    mut warn: impl SlowWait,
    wait: impl FnOnce(&mut C) -> R,
) -> R {
    use crate::wait::teardown_warn::{exit_visible_by, wait_warning, Due, ExitWatch};

    let pid = child.pid();
    wait_warning(
        child,
        warn.due().map(|(until, after)| Due { until, after }),
        |child, until| exit_visible_by(ExitWatch::PidFd(child.pidfd()), until),
        |after| warn.warn(pid, after),
        wait,
    )
}

/// The note for a child that cannot be shown to be ours or reaped.
#[cfg(target_os = "macos")]
fn unverifiable(why: &dyn std::fmt::Display) -> String {
    format!("cannot be shown to be ours or reaped ({why})")
}

/// [`teardown_after_attach_failure`]'s reap: consume `target`'s exit record only when a verified
/// peek shows the zombie is ours. Only a verified foreign reap is a `debug`; a child that cannot be
/// shown ours or reaped is noted for the teardown's one `warn`.
#[cfg(target_os = "macos")]
///
/// `killed`: whether cosca's kill was delivered, which decides the fate of a foreign verdict (see
/// [`Foreign::fate`]).
fn reap_verified(
    pid: u32,
    target: &crate::wait::exit_only::Target<'_>,
    id: Option<ProcessId>,
    killed: bool,
    notes: &mut Vec<String>,
    breach: &mut Option<String>,
) -> ChildFate {
    use crate::wait::exit_only::{peek_verified, try_reap, Foreign, Peek, Reap, Reaped};

    let foreign = |why: Foreign, notes: &mut Vec<String>| {
        match why {
            Foreign::Orphaned => notes.push(unverifiable(&crate::signal::UNPINNED_WHY)),
            Foreign::Gone | Foreign::Other => log::debug!("spawn teardown: pid {pid} was reaped by someone else"),
        }
        why.fate(killed)
    };
    match peek_verified(target) {
        Err(e) => {
            notes.push(unverifiable(&e));
            return ChildFate::Unknown;
        }
        Ok(Peek::Foreign(why)) => return foreign(why, notes),
        Ok(Peek::Running) => {
            notes.push("is still running".to_owned());
            return ChildFate::Running { id };
        }
        Ok(Peek::Exit(_)) => {}
    }
    match try_reap(target) {
        Ok(Reap::Reaped(Reaped::Status(_))) => ChildFate::Reaped,
        // The consuming `waitid` collected the zombie, whatever it reported.
        Ok(Reap::Reaped(Reaped::Unreadable { si_code })) => {
            notes.push(format!(
                "a consuming waitid returned si_code {si_code}, not an exit record"
            ));
            *breach = Some(format!("a consuming waitid on a zombie returned si_code {si_code}"));
            ChildFate::Reaped
        }
        Ok(Reap::Running) => {
            notes.push("is still running".to_owned());
            ChildFate::Running { id }
        }
        Ok(Reap::Foreign(why)) => foreign(why, notes),
        Err(e) => {
            notes.push(format!("could not be reaped: {e}"));
            ChildFate::Unknown
        }
    }
}

/// macOS: `child` could not be adopted, and the spawn fails with `not_adopted.error`. A child that
/// died before `exec` is only a corpse nothing collects, and the program did not start. A child
/// whose id came late may have started the program: it is killed and reaped by pid, each act checked
/// against that id, and its tree is killed through `prepared` (see [`kill_and_reap_unreported`]). A
/// `front` is sent nothing and left running and unreaped instead, and the error notes it. Any other
/// is never signalled or waited on by pid, and is left as `leave_unverified_child` leaves it.
#[cfg(target_os = "macos")]
fn abandon_unadopted(
    child: std::process::Child,
    not_adopted: unique_report::NotAdopted,
    front: Option<crate::elevation::front::Front>,
    prepared: crate::containment::Prepared,
) -> SpawnFailure {
    use unique_report::Unadoptable;

    let pid = child.id();
    let error = not_adopted.error;
    match not_adopted.why {
        Unadoptable::DiedBeforeExec => {
            log::warn!(
                "child {pid} died before exec; nothing is signalled or waited on by pid, so its status is not collected"
            );
            drop(child);
            SpawnFailure::NotStarted(error)
        }
        Unadoptable::Late(unique) => {
            #[cfg(test)]
            fault::capture(ProcessId::of(pid));
            // A front is sent nothing: it is left running and unreaped, with its note.
            if front.is_some() {
                warn_late_front(pid, None);
                drop(child);
                return SpawnFailure::started(
                    FrontFate::LeftUnreaped.note(error, front, Some(pid)),
                    // The id was reported, but no `ProcessId` was read from it.
                    ChildFate::Running { id: None },
                );
            }
            // Torn down through its unique id, exactly as every other post-spawn failure is. The `std`
            // `Child` is dropped after: it reaps nothing, so a child still running stays a zombie.
            let done = kill_and_reap_unreported(pid, unique, prepared, None);
            let tail = done.zombie_tail();
            let fate = done.warn(pid, tail);
            drop(child);
            SpawnFailure::started(error, fate)
        }
        Unadoptable::Unverified => {
            // No unique id was read, so there is no identity to give.
            let (error, fate) = teardown_after_failed_adoption(child, error, None);
            SpawnFailure::started(
                FrontFate::of_unverified(crate::containment::RootIdentity::Unknown).note(error, front, Some(pid)),
                fate,
            )
        }
    }
}

/// macOS: abandon `child` without signalling or waiting on it by pid, since nothing shows its pid
/// still names it. `RootIdentity::Gone` means someone else reaped it, so it is forgotten; otherwise
/// it is left unreaped. Dropping the `std` `Child` closes our pipe ends only. Either way
/// a warning names the pid, and the spawn still fails: the caller must not assume the program did
/// not start.
#[cfg(target_os = "macos")]
fn leave_unverified_child(
    child: std::process::Child,
    identity: crate::containment::RootIdentity,
    id: Option<ProcessId>,
    why: &mut Diagnosis,
) -> ChildFate {
    let pid = child.id();
    let fate = if identity == crate::containment::RootIdentity::Gone {
        log::warn!(
            "{}",
            why.fold(format!(
                "child {pid} was reaped by someone else; its pid may be reused, so nothing is signalled or waited on by pid"
            ))
        );
        ChildFate::Gone
    } else {
        log::warn!(
            "{}",
            why.fold(format!(
                "child {pid} cannot be shown to be ours (its identity could not be read); leaving it unreaped, with \
                 nothing signalled or waited on by pid, and it may still be running"
            ))
        );
        ChildFate::Running { id }
    };
    drop(child);
    fate
}

/// The spawned `child` could not be adopted. Answers `error`.
///
/// - **Windows:** its process handle could not be duplicated. The handle still pins the process, so
///   the child is torn down.
/// - **macOS:** its unique-id report is not an id (unreadable or malformed), so it is left alone
///   (see `leave_unverified_child`).
///
/// Not on Linux, where the pidfd is opened before `exec` (see `pidfd_handshake`) and adoption
/// cannot fail.
#[cfg(not(target_os = "linux"))]
fn teardown_after_failed_adoption(
    child: std::process::Child,
    error: Error,
    id: Option<ProcessId>,
) -> (Error, ChildFate) {
    #[cfg(test)]
    fault::capture(ProcessId::of(child.id()));
    #[cfg(target_os = "macos")]
    let fate = leave_unverified_child(
        child,
        crate::containment::RootIdentity::Unknown,
        id,
        &mut Diagnosis::default(),
    );
    #[cfg(not(target_os = "macos"))]
    let fate = teardown_unadopted(child, id);
    (error, fate)
}

/// Serializes spawns against the process-global inheritable-handle window: on Windows both the std
/// path and the raw `CreateProcessW` backend must mark child-side handles inheritable, spawn, then
/// un-mark/close without a concurrent spawn inheriting them. Held across that window on both paths.
/// It orders cosca's own spawns only: another spawner in the process that passes `bInheritHandles`
/// TRUE with no handle list is not under it, and can take those handles while they are inheritable
/// (see the module doc of `child::spawn::windows_raw`).
/// **Poison-tolerant:** a panic mid-spawn must not wedge every future spawn, so a poisoned lock is
/// recovered rather than propagated (the guarded data is unit — there is no invariant to protect).
pub(crate) fn spawn_lock() -> SpawnLockGuard {
    acquire_spawn_lock(|| {
        #[cfg(all(test, target_os = "macos"))]
        fault::spawn_lock_contended();
    })
}

static SPAWN_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Holds [`spawn_lock`]. Under `debug_assertions` (and in test builds) it also records that this
/// thread holds the non-reentrant mutex, so a nested acquire fails with a named panic instead of
/// deadlocking.
#[must_use = "if unused the spawn lock is released immediately; bind the guard for the whole window"]
pub(crate) struct SpawnLockGuard {
    _guard: std::sync::MutexGuard<'static, ()>,
}

thread_local! {
    /// Whether THIS thread holds `SPAWN_MUTEX`; set and cleared only by [`SpawnLockGuard`].
    /// `const`-initialized with no destructor, so reading it in a forked child is safe.
    #[cfg(any(test, debug_assertions))]
    static SPAWN_LOCK_HELD_BY_THIS_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(any(test, debug_assertions))]
impl Drop for SpawnLockGuard {
    fn drop(&mut self) {
        SPAWN_LOCK_HELD_BY_THIS_THREAD.with(|f| f.set(false));
    }
}

/// Takes `SPAWN_MUTEX`. `on_contended` runs first if it is already held, before this blocks.
fn acquire_spawn_lock(on_contended: impl FnOnce()) -> SpawnLockGuard {
    #[cfg(any(test, debug_assertions))]
    assert!(
        !spawn_lock_held_by_this_thread(),
        "spawn_lock re-entered: the mutex is not reentrant; drop the outer spawn_lock() (fork_running and cosca spawns take it themselves)"
    );
    let guard = match SPAWN_MUTEX.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => {
            on_contended();
            SPAWN_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
        }
    };
    #[cfg(any(test, debug_assertions))]
    SPAWN_LOCK_HELD_BY_THIS_THREAD.with(|f| f.set(true));
    SpawnLockGuard { _guard: guard }
}

/// Like [`spawn_lock`], but `on_contended` runs first if the lock is already held, before this
/// blocks on it.
#[cfg(all(target_os = "linux", test))]
pub(crate) fn spawn_lock_tracked(on_contended: impl FnOnce()) -> SpawnLockGuard {
    acquire_spawn_lock(on_contended)
}

/// Whether THIS thread currently holds `spawn_lock`'s mutex.
#[cfg(any(test, debug_assertions))]
pub(crate) fn spawn_lock_held_by_this_thread() -> bool {
    SPAWN_LOCK_HELD_BY_THIS_THREAD.with(|f| f.get())
}

#[cfg(any(not(any(target_os = "linux", target_os = "macos")), test))]
pub(crate) fn build_std_command(cmd: &Command) -> Result<std::process::Command, Error> {
    #[cfg(unix)]
    {
        let mut steps = in_child::InChild::default();
        let (mut std_cmd, ()) = build_std_command_with(cmd, &mut steps, |_| ())?;
        steps.register(&mut std_cmd);
        Ok(std_cmd)
    }
    #[cfg(not(unix))]
    build_std_command_with(cmd, |_| ()).map(|(std_cmd, ())| std_cmd)
}

/// [`build_std_command`], running `first` on the command before anything else is set on it, so a
/// hook `first` registers runs first in the child. Returns what `first` returned. On Unix this
/// registers no hook: the child's own steps go into `steps`, for the caller to register last.
pub(crate) fn build_std_command_with<R>(
    cmd: &Command,
    #[cfg(unix)] steps: &mut in_child::InChild,
    first: impl FnOnce(&mut std::process::Command) -> R,
) -> Result<(std::process::Command, R), Error> {
    // Program + args via the `quote` model.
    let StdLaunch {
        program,
        mut std_cmd,
        cwd,
        enter,
    } = match cmd.input() {
        CommandInput::Empty => return Err(Error::Io(std::io::Error::other("no program specified"))),
        CommandInput::Argv(argv) => {
            let (Resolved { program, cwd, enter }, rest) = resolve_program_argv(cmd, argv)?;
            let mut c = std::process::Command::new(&program);
            c.args(rest);
            // POSIX: when executable() overrides the loaded file, preserve the
            // user's argv[0] via arg0() — the executable as written when argv is
            // empty. Without this, std would set argv[0] to the (possibly completed)
            // program path, silently dropping the user's intended name.
            #[cfg(unix)]
            if let Some(exe) = cmd.executable_path() {
                use std::os::unix::process::CommandExt;
                c.arg0(argv.first().map_or(exe.as_os_str(), std::ffi::OsString::as_os_str));
            }
            StdLaunch {
                program,
                std_cmd: c,
                cwd,
                enter,
            }
        }
        CommandInput::CommandLine(line) => build_from_commandline(cmd, line)?,
    };
    // Reject .bat/.cmd (BatBadBut) on Windows, and an interior NUL everywhere — this is the std
    // backend's only NUL check, and the default Windows path. Judged on the token WE resolved,
    // not on `std_cmd.get_program()`: std's Unix constructor swaps a NUL-bearing program for a
    // `<string-with-nul>` sentinel, so reading it back would hide the exact token the gate exists
    // to judge (and would make this verdict differ by platform for reasons unrelated to Windows).
    reject_batch_path(std::path::Path::new(&program))?;
    apply_env(&mut std_cmd, cmd.env_ops());
    let first = first(&mut std_cmd);
    match cwd {
        #[cfg(unix)]
        Some(dir) if enter => enter_in_child(steps, &dir)?,
        #[cfg(not(unix))]
        Some(_) if enter => unreachable!("only anchor_posix asks the child to enter its directory"),
        Some(dir) => {
            std_cmd.current_dir(dir);
        }
        None => {}
    }
    Ok((std_cmd, first))
}

/// `chdir` to `dir` in the child, after std's own setup and just before its `execvp`, so a
/// relative program is read against the directory the child runs in, both relative to the cwd it
/// inherited (see `crate::resolve::exact::anchor_posix`).
///
/// This is what std's `current_dir` would mostly do already, and it is done here because std does
/// not promise it: "If the program path is relative (e.g., `"./script.sh"`), it's ambiguous
/// whether it should be interpreted relative to the parent's working directory or relative to
/// `current_dir`. The behavior in this case is platform specific and unstable". std 1.97.1 happens
/// to read it against the new directory on both of its paths — fork/exec (which it takes on
/// Apple for this case) and glibc's `posix_spawn` with `addchdir` — but either could change. std
/// documents `pre_exec` hooks as running in the child just before the exec, so the ordering is
/// pinned. The cost is that a hook rules out `posix_spawn`, for these commands only.
#[cfg(unix)]
fn enter_in_child(steps: &mut in_child::InChild, dir: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let dir = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_dir() contains an embedded NUL",
        ))
    })?;
    steps.enter(dir);
    Ok(())
}

/// The program to load and the directory to run it in.
struct Resolved {
    program: std::ffi::OsString,
    cwd: Option<std::path::PathBuf>,
    /// The child enters `cwd` itself; see `crate::resolve::exact::Anchored::enter`.
    enter: bool,
}

// Pick the executable file to load (`executable` overrides argv[0]/first-token). On POSIX an
// `Exact` program arrives in a form no exec searches (see `crate::resolve::exact::anchor_posix`);
// on Windows a set executable never reaches this std path, routing to the raw backend instead.
fn resolve_program(cmd: &Command, fallback: std::ffi::OsString) -> Result<Resolved, Error> {
    let as_given = |exe: Option<&std::path::Path>| Resolved {
        program: exe.map_or(fallback, |p| p.as_os_str().to_os_string()),
        cwd: cmd.cwd().map(std::path::Path::to_path_buf),
        enter: false,
    };
    #[cfg(unix)]
    if let Some(crate::command::ExecutableSpec::Exact(p)) = cmd.executable_spec() {
        let a = crate::resolve::exact::anchor_posix(p.as_os_str(), cmd.cwd())?;
        return Ok(Resolved {
            program: a.program.into_os_string(),
            cwd: a.cwd,
            enter: a.enter,
        });
    }
    Ok(as_given(cmd.executable_path()))
}

// Program + the trailing args (argv mode). `executable` overrides the loaded file; argv[0] is the
// conventional program name otherwise — POSIX argv[0] preservation happens at the caller (see
// build_std_command). On Windows a set `executable` never reaches this std path — it routes to
// the raw `CreateProcessW` backend, which preserves argv[0] independently of the loaded image.
fn resolve_program_argv<'a>(
    cmd: &'a Command,
    argv: &'a [std::ffi::OsString],
) -> Result<(Resolved, &'a [std::ffi::OsString]), Error> {
    if argv.is_empty() && cmd.executable_path().is_none() {
        return Err(Error::Io(std::io::Error::other("empty argv")));
    }
    let fallback = if argv.is_empty() {
        std::ffi::OsString::new()
    } else {
        argv[0].clone()
    };
    let program = resolve_program(cmd, fallback)?;
    let rest = if argv.is_empty() { argv } else { &argv[1..] };
    Ok((program, rest))
}

/// The resolved program token alongside the `std::process::Command` built from it and the
/// directory to run it in.
struct StdLaunch {
    program: std::ffi::OsString,
    std_cmd: std::process::Command,
    cwd: Option<std::path::PathBuf>,
    enter: bool,
}

#[cfg(unix)]
fn build_from_commandline(cmd: &Command, line: &std::ffi::OsString) -> Result<StdLaunch, Error> {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let words = crate::quote::posix::split(line.as_bytes())?;
    // `OsStringExt::from_vec` already yields an OsString; do NOT wrap it in
    // `OsString::from(..)` (that is redundant and fails type inference).
    let argv: Vec<OsString> = words.into_iter().map(OsString::from_vec).collect();
    if argv.is_empty() {
        return Err(Error::Io(std::io::Error::other("empty command line")));
    }
    let Resolved { program, cwd, enter } = resolve_program(cmd, argv[0].clone())?;
    let mut c = std::process::Command::new(&program);
    // When executable() overrides the loaded file, argv[0] from the command
    // line is the user's intended name — preserve it via arg0().
    if cmd.executable_path().is_some() {
        use std::os::unix::process::CommandExt;
        c.arg0(&argv[0]);
    }
    c.args(&argv[1..]);
    Ok(StdLaunch {
        program,
        std_cmd: c,
        cwd,
        enter,
    })
}

#[cfg(windows)]
fn build_from_commandline(cmd: &Command, line: &std::ffi::OsString) -> Result<StdLaunch, Error> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::process::CommandExt;
    // Windows is command-line-native. CRITICAL: std::process always PREPENDS a
    // quoted form of the program to lpCommandLine and then appends raw_arg. So
    // raw_arg must be the ARGS portion only (the line MINUS its first token);
    // passing the whole line would duplicate the program token in the child's
    // argv. We split the first token off with first_token_and_rest_wide.
    //
    // This std path is only reached for a commandline() WITHOUT executable(): a set
    // executable() routes to the raw `CreateProcessW` backend (which sets
    // lpApplicationName independently of lpCommandLine) before `build_std_command`
    // is ever called, on both the sync and async spawn paths.
    let wide: Vec<u16> = line.encode_wide().collect();
    let (first, rest) = crate::quote::windows::first_token_and_rest_wide(&wide)
        .ok_or_else(|| Error::Io(std::io::Error::other("empty command line")))?;
    let program = std::ffi::OsString::from_wide(&first);
    let mut c = std::process::Command::new(&program);
    c.raw_arg(std::ffi::OsString::from_wide(&rest)); // args only — program is prepended by std
    Ok(StdLaunch {
        program,
        std_cmd: c,
        cwd: cmd.cwd().map(std::path::Path::to_path_buf),
        enter: false,
    })
}

pub(crate) fn apply_env(std_cmd: &mut std::process::Command, ops: &[EnvOp]) {
    for op in ops {
        match op {
            EnvOp::Set(k, v) => {
                std_cmd.env(k, v);
            }
            EnvOp::Remove(k) => {
                std_cmd.env_remove(k);
            }
            EnvOp::Clear => {
                std_cmd.env_clear();
            }
        }
    }
}

/// The child-side ends (keyed by slot) plus, for `Owned` pipes, the parent ends — the
/// result of [`resolve_stdio`].
pub(crate) type ResolvedStdioEnds = (BTreeMap<Fd, ChildEnd>, BTreeMap<Fd, ParentEnd>);

/// How pipe slots are handled during stdio resolution — the sole axis on which the
/// sync and async spawn paths diverge.
#[derive(Clone, Copy)]
pub(crate) enum PipeOwnership {
    /// Sync: create the OS pipe now (`std::io::pipe`), keep the child end for the
    /// child, and return the parent end to the caller.
    Owned,
    /// Async: tokio owns the piped STD ends (0/1/2) — those slots are left out of the
    /// resolved child ends (the caller assigns `Stdio::piped()`), and a merge into a piped
    /// STD target is rejected (its end is tokio's, not ours to dup). fd >= 3 pipes are OURS
    /// on every path: they resolve like `Owned` and produce parent ends.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only the async spawn path constructs Deferred")
    )]
    Deferred,
}

/// Shared stdio-resolution core for both spawn paths. `slots` is the resolution order (0/1/2
/// always; the sync path adds Unix n>=3); the per-caller tails (fd>=3 policy, fd_map wiring,
/// final `Stdio` assignment) stay with each spawn.
pub(crate) fn resolve_stdio(
    fds: &BTreeMap<Fd, ResolvedStdio>,
    slots: &[Fd],
    pipe: PipeOwnership,
    parent_std: ParentStd,
) -> Result<ResolvedStdioEnds, Error> {
    // Reject merge-targeting-a-merge: the two-pass algorithm resolves only one level of
    // indirection. Transitive chaining (a fixpoint loop) is an unsupported design limit — redirect
    // to a concrete slot (pipe/file/null/inherit) instead.
    for &slot in slots {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(&slot) {
            if matches!(fds.get(target), Some(ResolvedStdio::Merge(_))) {
                return Err(Error::Unsupported {
                    op: format!("merge {slot} -> {target} -> <another merge>"),
                    platform: std::env::consts::OS,
                    detail: "chained merges (merge-to-merge) are not supported; \
                             redirect to a concrete slot (pipe/file/null/inherit)"
                        .into(),
                });
            }
        }
    }

    let mut child_ends: BTreeMap<Fd, ChildEnd> = BTreeMap::new();
    let mut parent_ends: BTreeMap<Fd, ParentEnd> = BTreeMap::new();

    // First pass: resolve non-merge slots. `Deferred` pipe slots are tokio-owned — skip
    // them. Std slots 0/1/2 default to inherit when unconfigured; an n>=3 slot has no
    // default, so skip an unconfigured one.
    for &slot in slots {
        let resolved = fds.get(&slot);
        match resolved {
            Some(ResolvedStdio::Merge(_)) => continue, // second pass
            Some(ResolvedStdio::Pipe(_)) if matches!(pipe, PipeOwnership::Deferred) && slot.raw() < 3 => continue,
            None if slot.raw() >= 3 => continue,
            _ => {
                let (child_end, parent) = resolve_non_merge(slot, resolved, parent_std)?;
                if let Some(p) = parent {
                    parent_ends.insert(slot, p);
                }
                child_ends.insert(slot, child_end);
            }
        }
    }

    // Second pass: dup each merge from its already-resolved target. With `Deferred` pipes
    // a merge into a pipe target has no child end of ours to dup — reject it.
    for &slot in slots {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(&slot) {
            if matches!(pipe, PipeOwnership::Deferred)
                && target.raw() < 3
                && matches!(fds.get(target), Some(ResolvedStdio::Pipe(_)))
            {
                return Err(Error::Unsupported {
                    op: format!("async merge {slot} -> {target} (piped)"),
                    platform: std::env::consts::OS,
                    detail: "merging into a piped target with a deferred (tokio-owned) pipe end needs \
                             the merge target resolved first; merge into file/null/inherit, or capture \
                             separately"
                        .into(),
                });
            }
            let src = child_ends.get(target).ok_or_else(|| Error::Unsupported {
                op: format!("merge {slot} -> {target}"),
                platform: std::env::consts::OS,
                detail: "merge target descriptor is not configured".into(),
            })?;
            child_ends.insert(slot, dup(src)?);
        }
    }

    Ok((child_ends, parent_ends))
}

// Resolve a non-merge slot to its child-side end + the parent's pipe end (if any).
pub(crate) fn resolve_non_merge(
    slot: Fd,
    r: Option<&ResolvedStdio>,
    parent_std: ParentStd,
) -> Result<(ChildEnd, Option<ParentEnd>), Error> {
    match r {
        None | Some(ResolvedStdio::Inherit) => Ok((inherit_end(slot, parent_std)?, None)),
        Some(ResolvedStdio::Null) => Ok((null_end()?, None)),
        Some(ResolvedStdio::File(f)) => Ok((file_end(f)?, None)),
        Some(ResolvedStdio::Pipe(dir)) => make_pipe(*dir),
        Some(ResolvedStdio::Merge(_)) => unreachable!("merge handled in second pass"),
    }
}

fn make_pipe(dir: Direction) -> Result<(ChildEnd, Option<ParentEnd>), Error> {
    let (reader, writer) = std::io::pipe().map_err(Error::Io)?;
    match dir {
        // Child reads: child gets the reader; parent keeps the writer.
        Direction::In => Ok((ChildEnd::from(reader), Some(ParentEnd::Writer(writer)))),
        // Child writes: child gets the writer; parent keeps the reader.
        Direction::Out => Ok((ChildEnd::from(writer), Some(ParentEnd::Reader(reader)))),
    }
}

pub(crate) fn dup(end: &ChildEnd) -> Result<ChildEnd, Error> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        end.as_fd().try_clone_to_owned().map_err(Error::Io)
    }
    #[cfg(windows)]
    {
        end.try_clone().map_err(Error::Io)
    }
}

fn null_end() -> Result<ChildEnd, Error> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(if cfg!(windows) { "NUL" } else { "/dev/null" })
        .map_err(Error::Io)?;
    Ok(ChildEnd::from(f))
}

fn file_end(f: &std::fs::File) -> Result<ChildEnd, Error> {
    // Dup the file so the caller's File stays usable.
    let dup = f.try_clone().map_err(Error::Io)?;
    Ok(ChildEnd::from(dup))
}

#[cfg_attr(
    not(windows),
    allow(unused_variables, reason = "only the Windows arm reads the parent's std handles")
)]
fn inherit_end(slot: Fd, parent_std: ParentStd) -> Result<ChildEnd, Error> {
    // Duplicate the parent's matching std stream. Bind the stream to a variable
    // before borrowing its descriptor (a temporary would be dropped while borrowed).
    // For n>=3, Stdio::inherit() has no defined parent stream to dup — a design limit
    // kept as a loud Unsupported on every path (the raw backend routes here too), never a
    // silent drop.
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let owned = match slot {
            Fd::STDIN => {
                let s = std::io::stdin();
                s.as_fd().try_clone_to_owned()
            }
            Fd::STDOUT => {
                let s = std::io::stdout();
                s.as_fd().try_clone_to_owned()
            }
            Fd::STDERR => {
                let s = std::io::stderr();
                s.as_fd().try_clone_to_owned()
            }
            other => {
                return Err(Error::Unsupported {
                    op: format!("Stdio::inherit() on {other}"),
                    platform: "unix",
                    detail: "inherit on fd >= 3 has no defined parent stream; \
                             use pipe/file/null instead"
                        .into(),
                })
            }
        };
        owned.map_err(Error::Io)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        // A null std handle (a GUI process's or a service's) is an absent end; so is -1, which `std`
        // reports as null. `parent_std` decides null-ness, so this end and the caller's
        // `STARTF_USESTDHANDLES` decision come from one read.
        let live = parent_std.is_live(slot);
        let owned = match slot {
            Fd::STDIN => {
                let s = std::io::stdin();
                dup_std_handle(s.as_handle(), live)
            }
            Fd::STDOUT => {
                let s = std::io::stdout();
                dup_std_handle(s.as_handle(), live)
            }
            Fd::STDERR => {
                let s = std::io::stderr();
                dup_std_handle(s.as_handle(), live)
            }
            // fd >= 3 has no defined parent std stream to dup (mirrors the Unix arm). Retained design
            // limit: the raw backend routes fd >= 3 inherit through here and rejects it too.
            other => {
                return Err(Error::Unsupported {
                    op: format!("Stdio::inherit() on {other}"),
                    platform: "windows",
                    detail: "inherit on fd >= 3 has no defined parent stream; \
                             use pipe/file/null instead"
                        .into(),
                })
            }
        };
        owned.map_err(Error::Io)
    }
}

/// A dup of this process's std handle `h`; absent when `live` is false (it was null when
/// [`ParentStd`] was read).
#[cfg(windows)]
fn dup_std_handle(h: std::os::windows::io::BorrowedHandle<'_>, live: bool) -> std::io::Result<ChildEnd> {
    use std::os::windows::io::AsRawHandle;
    if !live || h.as_raw_handle().is_null() {
        return Ok(ChildEnd::absent());
    }
    h.try_clone_to_owned().map(ChildEnd::from)
}

/// Which of this process's stdin, stdout and stderr handles were non-null when a spawn began.
///
/// Read once per spawn: the inherited ends and the Windows `STARTF_USESTDHANDLES` decision both
/// come from it, so a concurrent `SetStdHandle` cannot make them disagree. Empty off Windows.
#[derive(Clone, Copy)]
pub(crate) struct ParentStd {
    #[cfg(windows)]
    live: [bool; 3],
}

impl ParentStd {
    pub(crate) fn read() -> ParentStd {
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsHandle, AsRawHandle};
            ParentStd {
                live: [
                    !std::io::stdin().as_handle().as_raw_handle().is_null(),
                    !std::io::stdout().as_handle().as_raw_handle().is_null(),
                    !std::io::stderr().as_handle().as_raw_handle().is_null(),
                ],
            }
        }
        #[cfg(not(windows))]
        {
            ParentStd {}
        }
    }

    /// Whether the handle for std `slot` (0, 1 or 2) was non-null; `false` for any other slot,
    /// which has no parent stream (`inherit_end` refuses it).
    #[cfg(windows)]
    pub(crate) fn is_live(self, slot: Fd) -> bool {
        usize::try_from(slot.raw())
            .ok()
            .and_then(|i| self.live.get(i).copied())
            .unwrap_or(false)
    }

    /// Whether any of the three was non-null.
    #[cfg(windows)]
    pub(crate) fn any_live(self) -> bool {
        self.live.iter().any(|&l| l)
    }
}

/// The error for a spawn whose child could not be identified. `Gone` is an absence;
/// `Unknown` is an OS refusal about a child that may be running fine - never report the
/// second as the first.
pub(crate) fn spawn_identity_error(outcome: crate::identity::Resolved<ProcessId>) -> Error {
    match outcome {
        // An unavailable Linux `/proc` view is named; any other refusal is the OS's.
        crate::identity::Resolved::Unknown => crate::identity::unknown_identity_error("the spawned child")
            .unwrap_or_else(|| Error::Unassessable {
                detail: "the OS refused to report the spawned child's identity".into(),
                source: None,
            }),
        _ => Error::Io(std::io::Error::other(
            "the spawned child exited and was reaped by another party, or its zombie is held by one, before its \
             identity could be read",
        )),
    }
}

/// Read the spawned child's stable identity, then check through `through`, the handle held since
/// the spawn, that the read named our child.
///
/// - **Linux:** a peek through the pidfd after the read. `Running` and `Exit` keep the read (a
///   reap is irreversible, so the pid named our child throughout); `Foreign` is `Gone`; a failed
///   peek is `Unknown`, warned.
/// - **macOS:** the same, but the peek compares the pid's current unique id with the one `through`
///   carries; a mismatch is `Foreign`, an unreadable id is an error (`Unknown`), and `Orphaned`
///   (held by launchd after its tracer died) is `Gone`, as every foreign verdict is.
/// - **Windows:** the process handle pins the pid, so the read stands.
///
/// On macOS the `through` id is the one the child reported before `exec`.
///
/// What the check found out, when it could not show the read named our child, comes back as a
/// [`Diagnosis`]: the failed spawn's teardown carries it in its one `warn`.
pub(crate) fn resolve_identity(
    pid: u32,
    through: &crate::wait::exit_only::Target<'_>,
) -> (crate::identity::Resolved<ProcessId>, Diagnosis) {
    use crate::identity::Resolved;

    let read = resolve_identity_unchecked(pid);
    let Resolved::Found(_) = read else {
        return (read, Diagnosis::default());
    };
    #[cfg(test)]
    fault::run_at(fault::SpawnPoint::AfterIdentityRead, pid);
    #[cfg(unix)]
    {
        use crate::wait::exit_only::Peek;
        #[cfg(target_os = "linux")]
        let peeked = crate::wait::exit_only::peek(through);
        #[cfg(target_os = "macos")]
        let peeked = crate::wait::exit_only::peek_verified(through);
        match peeked {
            Ok(Peek::Running | Peek::Exit(_)) => (read, Diagnosis::default()),
            // macOS: held by launchd after its tracer died. It has exited and is not ours to reap, so it
            // is `Gone`, with a warning that its zombie is not collected.
            #[cfg(target_os = "macos")]
            Ok(Peek::Foreign(crate::wait::exit_only::Foreign::Orphaned)) => (
                Resolved::Gone,
                Diagnosis::of(format!(
                    "child {pid}: launchd holds its zombie, so its tracer died; it is not ours to reap"
                )),
            ),
            Ok(Peek::Foreign(_)) => (Resolved::Gone, Diagnosis::default()),
            Err(e) => (
                Resolved::Unknown,
                Diagnosis::of(format!(
                    "child {pid}: its identity could not be checked against its handle ({e}); it is not shown to be ours"
                )),
            ),
        }
    }
    #[cfg(windows)]
    {
        let _ = through;
        (read, Diagnosis::default())
    }
}

/// What the identity check found when it could not show the spawned child to be ours, owed to the
/// failed spawn's one `warn`.
///
/// The spawn's failure arm hands it to the teardown it runs. A step of that teardown that warns
/// [`fold`](Diagnosis::fold)s it into its text, so the check and the teardown are one record. When
/// no step warns, the diagnosis is logged on its own when it is dropped.
#[derive(Debug, Default)]
pub(crate) struct Diagnosis(Option<String>);

impl Diagnosis {
    /// A diagnosis to carry.
    #[cfg(unix)]
    fn of(text: String) -> Diagnosis {
        Diagnosis(Some(text))
    }

    /// Owe `text` too: the next [`fold`](Diagnosis::fold) leads with it, after what was owed.
    #[cfg(unix)]
    pub(crate) fn add(&mut self, text: impl std::fmt::Display) {
        match &mut self.0 {
            Some(owed) => owed.push_str(&format!("; {text}")),
            None => self.0 = Some(text.to_string()),
        }
    }

    /// `text`, led by the diagnosis if it is still owed, which it then no longer is.
    pub(crate) fn fold(&mut self, text: impl std::fmt::Display) -> String {
        match self.0.take() {
            Some(diagnosis) => format!("{diagnosis}; {text}"),
            None => text.to_string(),
        }
    }
}

impl Drop for Diagnosis {
    fn drop(&mut self) {
        // Not while unwinding: a logger that panics there would abort.
        if let Some(diagnosis) = self.0.take() {
            if !std::thread::panicking() {
                log::warn!("{diagnosis}");
            }
        }
    }
}

/// The unchecked half of [`resolve_identity`]: the read by pid alone, which nothing has yet shown
/// to name our child. Only `resolve_identity` and tests call it. A test-only fault seam (`fault`)
/// can force the vanished or unreadable branch.
pub(crate) fn resolve_identity_unchecked(pid: u32) -> crate::identity::Resolved<ProcessId> {
    #[cfg(test)]
    {
        if fault::force_identity_unknown() {
            fault::capture(ProcessId::of(pid));
            return crate::identity::Resolved::Unknown;
        }
        if fault::force_identity_vanished() {
            // Capture the child's real identity for the test to check what became of the child,
            // then simulate a vanish so `spawn` takes the identity-failure arm.
            fault::capture(ProcessId::of(pid));
            // The seam simulates a VANISH, not a refusal.
            return crate::identity::Resolved::Gone;
        }
    }
    ProcessId::of(pid)
}

/// `containment::attach` for the child whose identity `id` the spawn verified, with a test-only
/// seam to force its failure.
pub(crate) fn attach_or_fault(
    id: ProcessId,
    #[cfg(target_os = "linux")] child: crate::containment::ChildHandle<'_>,
    #[cfg(windows)] proc_handle: std::os::windows::io::RawHandle,
    prepared: crate::containment::Prepared,
) -> Result<crate::containment::Attachment, Error> {
    #[cfg(test)]
    if fault::force_attach_failure() {
        // Capture identity for the test to check what became of the child, then simulate an attach
        // failure so `spawn` takes the attach-error arm. The caller still holds the child, so the
        // verdict is taken before `prepared` drops, as a real attach takes it.
        fault::capture(crate::identity::Resolved::Found(id));
        let mut prepared = prepared;
        prepared.settle_verdict(
            #[cfg(target_os = "linux")]
            child,
            #[cfg(not(target_os = "linux"))]
            id.pid(),
        );
        // Model a REAL attach failure, which surfaces as `Error::Containment` (not `Error::Io`), so
        // the tests assert production behavior rather than the seam's fabricated variant.
        return Err(Error::Containment {
            detail: "forced attach failure (test seam)".into(),
        });
    }
    #[cfg(all(test, target_os = "linux"))]
    if let Some(attachment) = fault::take_attachment_override() {
        let mut prepared = prepared;
        prepared.settle_verdict(
            #[cfg(target_os = "linux")]
            child,
            #[cfg(not(target_os = "linux"))]
            id.pid(),
        );
        return Ok(attachment);
    }
    crate::containment::attach(
        id,
        #[cfg(target_os = "linux")]
        child,
        #[cfg(windows)]
        proc_handle,
        prepared,
    )
}

/// A spawned child that an error path abandons before adoption, killed and reaped by
/// [`teardown_unadopted`].
#[cfg(not(target_os = "macos"))]
trait Unadopted: Send + 'static {
    /// Its pid, for logs; `None` where the spawn that failed never handed the child back.
    fn pid(&self) -> Option<u32>;
    /// `Ok` for a child that has already exited.
    fn kill(&mut self) -> std::io::Result<()>;
    /// Whether the last `kill` delivered a signal, rather than finding the child already gone.
    #[cfg(unix)]
    fn kill_delivered(&self) -> bool {
        true
    }
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>>;
    /// Blocks until the child exits, and reaps it.
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus>;
    /// The pidfd naming it: every Linux child has one.
    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> std::os::fd::BorrowedFd<'_>;
}

/// `pid {pid}`, or what stands for an unknown one.
#[cfg(not(target_os = "macos"))]
pub(crate) fn named(pid: Option<u32>) -> String {
    match pid {
        Some(pid) => format!("pid {pid}"),
        None => "the spawned child (pid unknown)".to_string(),
    }
}

#[cfg(not(target_os = "macos"))]
#[cfg(not(target_os = "linux"))]
impl Unadopted for std::process::Child {
    fn pid(&self) -> Option<u32> {
        Some(std::process::Child::id(self))
    }
    fn kill(&mut self) -> std::io::Result<()> {
        std::process::Child::kill(self)
    }
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        std::process::Child::try_wait(self)
    }
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        std::process::Child::wait(self)
    }
}

/// A Linux child, by the pidfd it sent while it was held before `exec`. Kills and reaps through
/// the pidfd, never by pid.
#[cfg(target_os = "linux")]
struct PidfdChild {
    pid: Option<u32>,
    pidfd: std::os::fd::OwnedFd,
    /// Kept once reaped, as std keeps it: a later `try_wait` or `wait` answers it, not `ECHILD`.
    reaped: Option<std::process::ExitStatus>,
    /// Whether its kill delivered a signal (see [`Unadopted::kill_delivered`]).
    delivered: bool,
}

#[cfg(target_os = "linux")]
impl PidfdChild {
    fn new(pid: Option<u32>, pidfd: std::os::fd::OwnedFd) -> PidfdChild {
        PidfdChild {
            pid,
            pidfd,
            reaped: None,
            delivered: false,
        }
    }

    fn target(&self) -> crate::wait::exit_only::Target<'_> {
        use std::os::fd::AsFd;
        crate::wait::exit_only::Target::PidFd(self.pidfd.as_fd())
    }
}

#[cfg(target_os = "linux")]
impl Unadopted for PidfdChild {
    fn pid(&self) -> Option<u32> {
        self.pid
    }
    fn pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.pidfd.as_fd()
    }
    fn kill(&mut self) -> std::io::Result<()> {
        use std::os::fd::AsFd;
        // A zombie takes the signal too, so an exited child is `Ok`, and so is one reaped elsewhere.
        // An unknown pid (a child tokio dropped) is named 0 in the helper's log.
        let sent = crate::signal::via_pidfd(
            Some(self.pidfd.as_fd()),
            self.pid.unwrap_or(0),
            crate::signal::Sig::Kill,
        )?;
        self.delivered = matches!(sent, crate::signal::Sent::Delivered);
        Ok(())
    }
    #[cfg(unix)]
    fn kill_delivered(&self) -> bool {
        self.delivered
    }
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        use crate::wait::exit_only::{try_reap, Reap, Reaped};
        if self.reaped.is_some() {
            return Ok(self.reaped);
        }
        match try_reap(&self.target())? {
            Reap::Reaped(Reaped::Status(status)) => {
                self.reaped = Some(status);
                Ok(Some(status))
            }
            Reap::Reaped(Reaped::Unreadable { si_code }) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the child's exit record was unreadable (si_code {si_code})"),
            )),
            Reap::Running => Ok(None),
            Reap::Foreign(_) => Err(std::io::Error::from_raw_os_error(libc::ECHILD)),
        }
    }
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        use crate::wait::exit_only::{reap_blocking, Reaped};
        if let Some(status) = self.reaped {
            return Ok(status);
        }
        match reap_blocking(&self.target())? {
            Ok(Reaped::Status(status)) => {
                self.reaped = Some(status);
                Ok(status)
            }
            Ok(Reaped::Unreadable { si_code }) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the child's exit record was unreadable (si_code {si_code})"),
            )),
            Err(_) => Err(std::io::Error::from_raw_os_error(libc::ECHILD)),
        }
    }
}

/// A sync spawn's Linux child before adoption: std's handle, and the pidfd it is torn down through.
#[cfg(target_os = "linux")]
struct HeldStdChild {
    child: std::process::Child,
    through: PidfdChild,
}

#[cfg(target_os = "linux")]
impl HeldStdChild {
    fn id(&self) -> u32 {
        self.child.id()
    }
}

#[cfg(target_os = "linux")]
impl Unadopted for HeldStdChild {
    fn pid(&self) -> Option<u32> {
        Some(self.child.id())
    }
    fn pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.through.pidfd()
    }
    fn kill(&mut self) -> std::io::Result<()> {
        self.through.kill()
    }
    #[cfg(unix)]
    fn kill_delivered(&self) -> bool {
        self.through.kill_delivered()
    }
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.through.try_wait()
    }
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.through.wait()
    }
}

/// What a failed spawn's teardown did with its child, when that child is an elevation front (see
/// [`crate::elevation::front`]), which it never signals: a kill of it would orphan the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    target_os = "macos",
    allow(
        dead_code,
        reason = "macOS leaves an unverified child without tearing it down, so it is never reaped here"
    )
)]
pub(crate) enum FrontFate {
    /// Not a front: torn down as any child.
    NotAFront,
    /// It had exited, or a cgroup leaf's kill ended it, and was reaped.
    Reaped,
    /// It was running, and is left unreaped (it stays a zombie once it exits).
    LeftUnreaped,
    /// It could not be waited on: reaped by someone else, or unreadable.
    Unaccounted,
    /// Where it is could not be read, so it is not known whether its cgroup's kill ended it. It is
    /// left unreaped.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only a Linux cgroup leaf places a front")
    )]
    Unplaced,
}

impl FrontFate {
    /// The fate of a child left unverified (macOS: `leave_unverified_child`): one reaped by someone
    /// else is unaccounted for, and any other is left unreaped.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS leaves a child unverified")
    )]
    pub(crate) fn of_unverified(identity: crate::containment::RootIdentity) -> FrontFate {
        match identity {
            crate::containment::RootIdentity::Gone => FrontFate::Unaccounted,
            crate::containment::RootIdentity::Unknown => FrontFate::LeftUnreaped,
        }
    }

    /// A failed spawn's `error`, with what became of the front `pid` (unknown: `None`) noted, its
    /// variant and kind kept (see [`Error::with_note`]). Not a front's: `error` itself.
    pub(crate) fn note(self, error: Error, front: Option<crate::elevation::front::Front>, pid: Option<u32>) -> Error {
        let Some(front) = front else {
            return error;
        };
        let what = crate::elevation::front::describe(front, pid);
        let fate = match self {
            FrontFate::NotAFront => {
                debug_assert!(false, "a front's teardown reports its fate");
                return error;
            }
            FrontFate::Reaped => {
                "it was sent no signal of its own; it had exited, or its cgroup's kill ended it, and it was reaped"
            }
            FrontFate::LeftUnreaped => {
                "it was sent nothing, so the elevated program may be running; it is left unreaped"
            }
            FrontFate::Unaccounted => {
                "it was sent nothing and could not be waited on, so the elevated program may be running"
            }
            FrontFate::Unplaced => {
                "it was sent nothing, and where it is cannot be read, so the elevated program may be running; it \
                 is left unreaped"
            }
        };
        error.with_note(&format!("{what}; {fate}"))
    }
}

/// Settle `prepared`'s placement verdict in a failure arm after the fork, before the child is torn
/// down, so the teardown never races the verdict's reads.
pub(crate) fn settle_before_teardown(
    prepared: &mut crate::containment::Prepared,
    #[cfg(target_os = "linux")] child: crate::containment::ChildHandle<'_>,
    #[cfg(not(target_os = "linux"))] pid: u32,
) {
    prepared.settle_verdict(
        #[cfg(target_os = "linux")]
        child,
        #[cfg(not(target_os = "linux"))]
        pid,
    );
}

/// Linux 6.9+: kill the process group of a failed spawn's root before its teardown, as
/// [`Prepared::kill_group_before_attach`](crate::containment::Prepared::kill_group_before_attach)
/// decides. A refused kill is owed to `why`, the teardown's one warn, which says the group's
/// members may be left running. Not for an elevation front, which is sent nothing.
#[cfg(target_os = "linux")]
pub(crate) fn kill_group_before_teardown(
    prepared: &crate::containment::Prepared,
    child: crate::containment::ChildHandle<'_>,
    why: &mut Diagnosis,
) {
    if let Err(e) = prepared.kill_group_before_attach(child) {
        note_refused_group_kill(Some(child.pid), e, false, why);
    }
}

/// Owes `why` a refused kill of the process group of `pid`'s root through its pidfd, which says the
/// group's members may be left running. `reaped`: the root was already reaped, so it may never have
/// run the program. A std-collected failed exec cannot be told from a foreign reap (tokio does not
/// report std's failure), so both warn.
#[cfg(target_os = "linux")]
pub(crate) fn note_refused_group_kill(pid: Option<u32>, refusal: nix::errno::Errno, reaped: bool, why: &mut Diagnosis) {
    let named = named(pid);
    let reaped = if reaped {
        "; the child was already reaped, so it may never have run the program"
    } else {
        ""
    };
    match refusal {
        nix::errno::Errno::EINVAL => why.add(format!(
            "members of the process group of {named} may be left running: the kernel refused \
             PIDFD_SIGNAL_PROCESS_GROUP (EINVAL, expected below Linux 6.9), so nothing was sent to the \
             group, whose number may name another group{reaped}"
        )),
        e => why.add(format!(
            "spawn teardown could not kill the process group of {named} through its pidfd ({e}); its \
             members may be left running{reaped}"
        )),
    }
}

/// macOS: owes `why` that a failed spawn's cleanup sends the process group of the root `pid` nothing,
/// since macOS has no exact kill of a group, so its members may be left running. Only for a root
/// whose group is its containment, which is not an elevation front's.
#[cfg(target_os = "macos")]
pub(crate) fn note_group_left_running(prepared: &crate::containment::Prepared, pid: u32, why: &mut Diagnosis) {
    if prepared.group_is_containment() {
        why.add(format!(
            "members of the process group of pid {pid} may be left running: macOS has no exact kill of a \
             process group, so the group is sent nothing"
        ));
    }
}

/// The subtree of the leaf of an elevation front, captured while the leaf exists: a failure arm
/// drops the leaf, killing it. One that cannot be read leaves the front unplaceable by the arm,
/// which then leaves it unreaped.
#[cfg(target_os = "linux")]
pub(crate) fn front_subtree(
    leaf: Option<&crate::containment::cgroup::CgroupLeaf>,
) -> Option<crate::containment::cgroup::Subtree> {
    match leaf?.subtree() {
        Ok(subtree) => Some(subtree),
        Err(e) => {
            log::debug!("spawn: an elevation front's leaf subtree cannot be read ({e}); its teardown cannot place it");
            None
        }
    }
}

/// [`teardown_unadopted`], unless `child` is an elevation front: a kill of that would orphan the
/// elevated program. A front is sent nothing. One that has exited is reaped now. One a cgroup kill
/// landed on and reached (see [`Subtree::reached`](crate::containment::cgroup::Subtree::reached)) is
/// dying: its exit, which that kill bounds, is waited for, and it is reaped. Any other is left
/// unreaped, with nothing that waits for it, and stays a zombie once it exits. The caller returns
/// its error with the front's fate noted ([`FrontFate::note`]).
#[cfg(not(target_os = "macos"))]
fn teardown_unadopted_or_front(
    child: impl Unadopted,
    front: Option<crate::elevation::front::Front>,
    id: Option<ProcessId>,
    #[cfg(target_os = "linux")] subtree: Option<&crate::containment::cgroup::Subtree>,
) -> (FrontFate, ChildFate) {
    teardown_unadopted_or_front_noting(
        child,
        front,
        id,
        NO_WAIT_WARN,
        #[cfg(target_os = "linux")]
        subtree,
        &mut Diagnosis::default(),
    )
}

/// [`teardown_unadopted_or_front`] for a spawn whose identity check found `why`: the teardown's
/// `warn`, if it has one, carries it. Linux: with `warn`, the wait for a front or child the
/// teardown killed warns once it passes that long ([`warn_still_waiting`]), and goes on.
#[cfg(not(target_os = "macos"))]
fn teardown_unadopted_or_front_noting(
    mut child: impl Unadopted,
    front: Option<crate::elevation::front::Front>,
    id: Option<ProcessId>,
    warn: impl SlowWait,
    #[cfg(target_os = "linux")] subtree: Option<&crate::containment::cgroup::Subtree>,
    why: &mut Diagnosis,
) -> (FrontFate, ChildFate) {
    if front.is_none() {
        return (FrontFate::NotAFront, teardown_unadopted_noting(child, id, warn, why));
    }
    // Only Linux has a pidfd to wait on before the blocking reap.
    #[cfg(not(target_os = "linux"))]
    let _ = warn;
    // Dropping the handle afterwards closes it; it neither signals nor reaps the child.
    #[cfg(all(test, target_os = "linux"))]
    if fault::fronts_exit_before_teardown() {
        // The wait below ends only with the front, which only the leaf's kill brings about: that the
        // kill was written is checked first (and the record restarted for the next arm), so a
        // teardown that skipped it fails here instead of hanging.
        let steps = crate::containment::cgroup::fault::take_leaf_steps();
        crate::containment::cgroup::fault::record_leaf_steps();
        assert!(
            steps.iter().any(|s| s == "kill"),
            "the leaf's kill was written before the teardown waits for the front's exit: {steps:?}"
        );
        if let Some(pid) = child.pid() {
            crate::test_child::wait_until_zombie(pid);
        }
    }
    #[cfg(test)]
    let tried = if fault::fronts_seen_running() {
        Ok(None)
    } else {
        child.try_wait()
    };
    #[cfg(not(test))]
    let tried = child.try_wait();
    let fate = fate_of_a_look(tried.as_ref().map(|s| *s).map_err(std::io::Error::raw_os_error), id);
    match tried {
        Ok(Some(_)) => (FrontFate::Reaped, fate),
        Ok(None) => {
            #[cfg(target_os = "linux")]
            let mut unplaced = false;
            #[cfg(target_os = "linux")]
            if let (Some(subtree), Some(pid)) = (subtree, child.pid()) {
                match subtree.reached(pid, Some(child.pidfd())) {
                    Ok(true) => {
                        #[cfg(test)]
                        fault::run_between_kill_and_wait();
                        return match wait_unadopted_warning(&mut child, warn, |child| child.wait()) {
                            Ok(_status) => {
                                #[cfg(test)]
                                fault::record_teardown_reap(pid, _status);
                                (FrontFate::Reaped, ChildFate::Reaped)
                            }
                            Err(e) => {
                                log::warn!(
                                    "{}",
                                    why.fold(format!(
                                        "spawn teardown: elevation front {} could not be reaped ({e})",
                                        named(Some(pid))
                                    ))
                                );
                                (FrontFate::Unaccounted, ChildFate::Killed)
                            }
                        };
                    }
                    Ok(false) => {}
                    // Where it is cannot be read, so it is not known whether the kill ended it.
                    Err(e) => {
                        log::debug!(
                            "spawn teardown: elevation front {}'s cgroup cannot be read ({e})",
                            named(Some(pid))
                        );
                        unplaced = true;
                    }
                }
            }
            log::warn!(
                "{}",
                why.fold(format!(
                    "spawn teardown left elevation front {} running, unsignalled and unreaped: a kill would orphan \
                     the elevated program",
                    named(child.pid())
                ))
            );
            #[cfg(target_os = "linux")]
            if unplaced {
                return (FrontFate::Unplaced, ChildFate::Unknown);
            }
            (FrontFate::LeftUnreaped, fate)
        }
        // Reaped by someone else, or unreadable: nothing is signalled or waited on.
        Err(e) => {
            log::debug!(
                "spawn teardown: elevation front {} cannot be waited on ({e})",
                named(child.pid())
            );
            (FrontFate::Unaccounted, fate)
        }
    }
}

/// [`teardown_through_pidfd`] for an elevation front: sent nothing, reaped now only if it has
/// exited (see [`teardown_unadopted_or_front`]). `warn`: see
/// [`leave_front_through_pidfd_noting`].
#[cfg(target_os = "linux")]
pub(crate) fn leave_front_through_pidfd(
    pid: Option<u32>,
    pidfd: std::os::fd::OwnedFd,
    front: crate::elevation::front::Front,
    id: Option<ProcessId>,
    warn: impl SlowWait,
    subtree: Option<&crate::containment::cgroup::Subtree>,
) -> (FrontFate, ChildFate) {
    leave_front_through_pidfd_noting(pid, pidfd, front, id, warn, subtree, &mut Diagnosis::default())
}

/// [`leave_front_through_pidfd`] for a spawn whose identity check found `why`. With `warn`, the
/// wait for a front its leaf's kill ended warns once it passes that long ([`warn_still_waiting`]),
/// and goes on.
#[cfg(target_os = "linux")]
pub(crate) fn leave_front_through_pidfd_noting(
    pid: Option<u32>,
    pidfd: std::os::fd::OwnedFd,
    front: crate::elevation::front::Front,
    id: Option<ProcessId>,
    warn: impl SlowWait,
    subtree: Option<&crate::containment::cgroup::Subtree>,
    why: &mut Diagnosis,
) -> (FrontFate, ChildFate) {
    teardown_unadopted_or_front_noting(PidfdChild::new(pid, pidfd), Some(front), id, warn, subtree, why)
}

/// Kill and reap, through `pidfd`, the child of a spawn that failed after its fork, unless it is
/// already collected: std reaps the child of a spawn it fails; tokio can fail a spawn after std's
/// succeeded, and drops the child neither killed nor reaped.
/// `id` is the child's identity, if the spawn had read one. With `warn`, the wait for the
/// killed child warns once it passes that long ([`warn_still_waiting`]), and goes on.
#[cfg(target_os = "linux")]
pub(crate) fn teardown_through_pidfd(
    pid: Option<u32>,
    pidfd: std::os::fd::OwnedFd,
    id: Option<ProcessId>,
    warn: impl SlowWait,
) -> ChildFate {
    teardown_through_pidfd_noting(pid, pidfd, id, warn, &mut Diagnosis::default())
}

/// [`teardown_through_pidfd`] for a spawn whose identity check found `why`.
#[cfg(target_os = "linux")]
fn teardown_through_pidfd_noting(
    pid: Option<u32>,
    pidfd: std::os::fd::OwnedFd,
    id: Option<ProcessId>,
    warn: impl SlowWait,
    why: &mut Diagnosis,
) -> ChildFate {
    use crate::wait::exit_only::{peek, Peek};

    let child = PidfdChild::new(pid, pidfd);
    match peek(&child.target()) {
        Ok(Peek::Foreign(why)) => {
            log::debug!("{}: already collected when its spawn failed", named(pid));
            return why.fate(false);
        }
        Ok(Peek::Exit(_) | Peek::Running) => {}
        // `waitid` on a pidfd of this process's own child answers or says `ECHILD`.
        Err(e) => {
            log::warn!(
                "{}",
                why.fold(format!(
                    "{}: its spawn failed, and its pidfd could not be waited on ({e}); it is left as it is",
                    named(pid)
                ))
            );
            debug_assert!(false, "waitid on a spawned child's pidfd failed: {e}");
            return ChildFate::Unknown;
        }
    }
    teardown_unadopted_noting(child, id, warn, why)
}

/// Kill and reap a spawned child that an error path is abandoning before adoption, logging a
/// failure of either at `warn` and `debug_assert`ing it.
///
/// A child that could not be killed is NOT waited for here: it may still be running — a setuid
/// child such as `sudo` refuses our SIGKILL with EPERM — and a blocking `wait()` would hang the
/// spawn for as long as it runs. If it has not exited, it is handed to [`reap_in_background`],
/// which reaps it whenever it does, so it never lingers as a zombie. EPERM is the one kill failure
/// that is not asserted, because it is reachable without any bug.
///
/// `id` is the child's identity, if the spawn had read one.
#[cfg(windows)]
fn teardown_unadopted(child: impl Unadopted, id: Option<ProcessId>) -> ChildFate {
    teardown_unadopted_noting(child, id, NO_WAIT_WARN, &mut Diagnosis::default())
}

/// [`teardown_unadopted`] for a spawn whose identity check found `why`: the teardown's `warn`, if it
/// has one, carries it. Linux: with `warn`, the wait for the killed child warns once it passes
/// that long ([`warn_still_waiting`]), and goes on.
#[cfg(not(target_os = "macos"))]
fn teardown_unadopted_noting(
    mut child: impl Unadopted,
    id: Option<ProcessId>,
    warn: impl SlowWait,
    why: &mut Diagnosis,
) -> ChildFate {
    // Only Linux has a pidfd to wait on before the blocking reap.
    #[cfg(not(target_os = "linux"))]
    let _ = warn;
    // warn before any assert: `debug_assert` is compiled out in release, and a swallowed failure
    // would otherwise leave no trace at all there.
    if let Err(kill) = kill_unadopted(&mut child) {
        log::warn!(
            "{}",
            why.fold(format!(
                "spawn teardown failed to kill {}: {kill}; reaping it in the background once it exits",
                named(child.pid())
            ))
        );
        let looked = child.try_wait();
        let fate = fate_of_a_look(looked.as_ref().map(|s| *s).map_err(std::io::Error::raw_os_error), id);
        if !matches!(looked, Ok(Some(_))) {
            reap_in_background(child);
        }
        // After the handoff, so a debug build's panic cannot strand the child.
        debug_assert!(
            kill.kind() == std::io::ErrorKind::PermissionDenied,
            "sync spawn teardown failed to kill child: {kill}"
        );
        return fate;
    }
    #[cfg(test)]
    fault::run_between_kill_and_wait();
    #[cfg(target_os = "linux")]
    let reaped = wait_unadopted_warning(&mut child, warn, reap_unadopted);
    #[cfg(not(target_os = "linux"))]
    let reaped = reap_unadopted(&mut child);
    match reaped {
        Ok(_) => ChildFate::Reaped,
        // Reaped by someone else: a handled case, not a contract violation.
        #[cfg(unix)]
        Err(reap) if reap.raw_os_error() == Some(libc::ECHILD) => {
            log::debug!("spawn teardown: {} was reaped by someone else", named(child.pid()));
            // The kill went first: delivered, it is `Killed`; found nothing to signal, `Gone`.
            crate::wait::exit_only::Foreign::Gone.fate(child.kill_delivered())
        }
        Err(reap) => {
            log::warn!(
                "{}",
                why.fold(format!("spawn teardown failed to reap {}: {reap}", named(child.pid())))
            );
            debug_assert!(false, "sync spawn teardown failed to reap child: {reap}");
            ChildFate::Killed
        }
    }
}

/// Reap `child` on a detached thread once it exits on its own. The thread blocks on the child's
/// exit, an event outside this process's control; nothing waits for the thread.
#[cfg(not(target_os = "macos"))]
fn reap_in_background(mut child: impl Unadopted) {
    #[cfg(test)]
    let notify = fault::take_background_reap_notifier();
    let name = child
        .pid()
        .map_or_else(|| "cosca-reap".to_string(), |pid| format!("cosca-reap-{pid}"));
    let pid = named(child.pid());
    let reaper_pid = pid.clone();
    let spawned = std::thread::Builder::new().name(name).spawn(move || {
        let pid = reaper_pid;
        let reaped = child.wait().map(drop);
        if let Err(e) = &reaped {
            log::warn!("background reap of {pid} failed: {e}");
        }
        #[cfg(test)]
        if let Some(notify) = notify {
            _ = notify.send(reaped);
        }
    });
    if let Err(e) = spawned {
        log::warn!("could not start a thread to reap {pid}, which stays unreaped: {e}");
    }
}

/// `child.kill()`, `Ok` for a child that has already exited on every platform, and forceable to
/// fail by a test.
///
/// std returns `Ok` for an exited child on Windows (`TerminateProcess`'s `ACCESS_DENIED` is
/// checked with `try_wait`) and, on Unix, for one it has already waited on. An exited child it has
/// NOT waited on is left to `kill(2)`, whose answer for a zombie std does not promise — so an
/// `Err` here is checked the same way Windows' is, and dropped if the child has exited. (Linux
/// signals through the pidfd, which takes the signal for a zombie too.)
///
/// A test can also make `kill` fail for a child that has really exited (see
/// `fault::set_force_kill_error_after_exit`).
///
/// The forced failure KILLS AND REAPS first, so the test that asks for it leaks nothing although
/// the teardown then skips its own reap — unless it was set to leave the child alive.
#[cfg(not(target_os = "macos"))]
fn kill_unadopted(child: &mut impl Unadopted) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some((marker, kind, alive)) = fault::take_force_kill_failure() {
        if !alive {
            child.kill()?;
            // A fixture only that kill would end is released here.
            fault::run_between_kill_and_wait();
            let status = child.wait()?;
            fault::record_teardown_reap(child.pid().expect("a test's child has its pid"), status);
        }
        return Err(std::io::Error::new(kind, marker));
    }
    #[cfg(test)]
    let killed = match fault::take_force_kill_error_after_exit() {
        Some((marker, kind)) => {
            child.wait()?;
            Err(std::io::Error::new(kind, marker))
        }
        None => child.kill(),
    };
    #[cfg(not(test))]
    let killed = child.kill();
    match killed {
        Err(_) if matches!(child.try_wait(), Ok(Some(_))) => Ok(()),
        other => other,
    }
}

/// `child.wait()`, which a test can force to fail. The forced failure still REAPS first, so the
/// test that asks for it leaks nothing.
#[cfg(not(target_os = "macos"))]
fn reap_unadopted(child: &mut impl Unadopted) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(test)]
    let forced = fault::take_force_reap_failure();
    let status = child.wait()?;
    #[cfg(test)]
    // An unknown pid records as 0.
    fault::record_teardown_reap(child.pid().unwrap_or(0), status);
    #[cfg(test)]
    if let Some(marker) = forced {
        return Err(std::io::Error::other(marker));
    }
    Ok(status)
}

/// Test-only fault injection + assertions for the spawn error-teardown paths, shared by both spawns.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    use crate::identity::ProcessId;

    thread_local! {
        #[cfg(not(target_os = "macos"))]
        static FRONTS_SEEN_RUNNING: Cell<bool> = const { Cell::new(false) };
        #[cfg(target_os = "linux")]
        static FRONTS_EXIT_FIRST: Cell<bool> = const { Cell::new(false) };
    }

    /// While the guard lives, a failed spawn's teardown on this thread, and a leaf's abandonment,
    /// find every elevation front still running, as they find one its leaf's kill reached but that
    /// has not exited yet: in the kernel a task leaves its cgroup, which ends the leaf's drain,
    /// before its parent can collect it.
    #[cfg(target_os = "linux")]
    pub(crate) fn see_fronts_running() -> SeeFrontsRunning {
        FRONTS_SEEN_RUNNING.with(|f| f.set(true));
        SeeFrontsRunning(())
    }

    #[cfg(target_os = "linux")]
    #[must_use = "fronts are seen as they are again as soon as the guard is dropped"]
    pub(crate) struct SeeFrontsRunning(());

    #[cfg(target_os = "linux")]
    impl Drop for SeeFrontsRunning {
        fn drop(&mut self) {
            FRONTS_SEEN_RUNNING.with(|f| f.set(false));
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub(crate) fn fronts_seen_running() -> bool {
        FRONTS_SEEN_RUNNING.with(Cell::get)
    }

    /// While the guard lives, a failed spawn's teardown on this thread waits, before it reads an
    /// elevation front, until the front has exited (a `WNOWAIT` wait: it stays a zombie), so the
    /// teardown's own read finds the zombie its leaf's kill made. For a test whose kill is known to
    /// land: one that does not blocks.
    #[cfg(target_os = "linux")]
    pub(crate) fn exit_fronts_before_teardown() -> ExitFrontsFirst {
        FRONTS_EXIT_FIRST.with(|f| f.set(true));
        ExitFrontsFirst(())
    }

    #[cfg(target_os = "linux")]
    #[must_use = "fronts are read as they are again as soon as the guard is dropped"]
    pub(crate) struct ExitFrontsFirst(());

    #[cfg(target_os = "linux")]
    impl Drop for ExitFrontsFirst {
        fn drop(&mut self) {
            FRONTS_EXIT_FIRST.with(|f| f.set(false));
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn fronts_exit_before_teardown() -> bool {
        FRONTS_EXIT_FIRST.with(Cell::get)
    }

    /// A seam's hook, run with the child's pid.
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    type PidHook = Box<dyn FnOnce(u32)>;

    thread_local! {
        static FORCE_VANISH: Cell<bool> = const { Cell::new(false) };
        static FORCE_UNKNOWN: Cell<bool> = const { Cell::new(false) };
        static FORCE_ATTACH_FAIL: Cell<bool> = const { Cell::new(false) };
        static FORCE_REAP_FAIL: Cell<Option<&'static str>> = const { Cell::new(None) };
        static FORCE_KILL_FAIL: Cell<Option<(&'static str, std::io::ErrorKind, bool)>> = const { Cell::new(None) };
        static FORCE_KILL_ERROR_AFTER_EXIT: Cell<Option<(&'static str, std::io::ErrorKind)>> = const { Cell::new(None) };
        static BACKGROUND_REAP_NOTIFY: Cell<Option<std::sync::mpsc::Sender<std::io::Result<()>>>> = const { Cell::new(None) };
        static CAPTURED: Cell<Option<crate::identity::Resolved<ProcessId>>> = const { Cell::new(None) };
        static BETWEEN_KILL_AND_WAIT: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static SPAWN_PID: Cell<Option<u32>> = const { Cell::new(None) };
        #[cfg(windows)]
        static LATE_EXIT: Cell<bool> = const { Cell::new(false) };
        static BEFORE_IDENTITY: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static BEFORE_ATTACH: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static AFTER_IDENTITY_READ: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        #[cfg(target_os = "macos")]
        static BEFORE_LATE_TEARDOWN: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        #[cfg(target_os = "macos")]
        static BEFORE_LATE_ROOT_KILL: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static TEARDOWN_REAPS: std::cell::RefCell<Option<Vec<TeardownReap>>> = const { std::cell::RefCell::new(None) };
        #[cfg(target_os = "linux")]
        static ATTACHMENT_OVERRIDE: std::cell::RefCell<Option<crate::containment::Attachment>> =
            const { std::cell::RefCell::new(None) };
        #[cfg(all(target_os = "linux", feature = "tokio"))]
        static FORCE_POST_FORK_FAIL: Cell<bool> = const { Cell::new(false) };
        #[cfg(feature = "tokio")]
        static FAIL_TOKIO_SPAWN: Cell<bool> = const { Cell::new(false) };
        #[cfg(all(target_os = "linux", feature = "tokio"))]
        static AFTER_FAILED_TOKIO_FORK: std::cell::RefCell<Option<PidHook>> = const { std::cell::RefCell::new(None) };
        #[cfg(feature = "tokio")]
        static FORGOTTEN_PID: Cell<Option<u32>> = const { Cell::new(None) };
        #[cfg(all(target_os = "linux", feature = "tokio"))]
        static FORGOTTEN_LEAF: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
        #[cfg(all(target_os = "linux", feature = "tokio"))]
        static FORGOTTEN_PIDFD: std::cell::RefCell<Option<std::os::fd::OwnedFd>> = const { std::cell::RefCell::new(None) };
    }

    /// Fail the NEXT tokio spawn after its fork succeeded, the way tokio's own `build_child` can
    /// (stdio registration, its pidfd reaper, its signal driver): the child is dropped neither
    /// killed nor reaped, and the error returns while `Prepared` — with any cgroup leaf — drops.
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    pub(crate) fn set_force_post_fork_failure(on: bool) {
        FORCE_POST_FORK_FAIL.with(|f| f.set(on));
    }

    /// The pid of the child the last forced post-fork failure dropped. It is still this
    /// process's unreaped child, so the caller may wait on it.
    #[cfg(feature = "tokio")]
    pub(crate) fn take_forgotten_pid() -> Option<u32> {
        FORGOTTEN_PID.with(|f| f.take())
    }

    /// A pidfd for the child the last forced post-fork failure dropped.
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    pub(crate) fn take_forgotten_pidfd() -> Option<std::os::fd::OwnedFd> {
        FORGOTTEN_PIDFD.with(|f| f.borrow_mut().take())
    }

    /// The cgroup leaf of the spawn the last forced post-fork failure dropped, if it had one.
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    pub(crate) fn take_forgotten_leaf() -> Option<std::path::PathBuf> {
        FORGOTTEN_LEAF.with(|f| f.take())
    }

    /// While the guard lives, tokio's own `spawn()` on this thread fails after its fork, dropping the
    /// child neither killed nor reaped, as a failed reaper registration (`epoll_ctl`'s `ENOSPC` or
    /// `ENOMEM`) does. The child's pid is kept for [`take_forgotten_pid`].
    #[cfg(feature = "tokio")]
    pub(crate) fn fail_tokio_spawns_after_fork() -> FailTokioSpawns {
        FAIL_TOKIO_SPAWN.with(|f| f.set(true));
        FailTokioSpawns(())
    }

    /// [`fail_tokio_spawns_after_fork`], running `hook` with the next forgotten child's pid as the
    /// spawn fails, before anything tears the child down.
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    pub(crate) fn fail_tokio_spawns_after_fork_then(hook: impl FnOnce(u32) + 'static) -> FailTokioSpawns {
        AFTER_FAILED_TOKIO_FORK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        fail_tokio_spawns_after_fork()
    }

    #[cfg(feature = "tokio")]
    #[must_use = "spawns succeed again as soon as the guard is dropped"]
    pub(crate) struct FailTokioSpawns(());

    #[cfg(feature = "tokio")]
    impl Drop for FailTokioSpawns {
        fn drop(&mut self) {
            FAIL_TOKIO_SPAWN.with(|f| f.set(false));
            #[cfg(target_os = "linux")]
            AFTER_FAILED_TOKIO_FORK.with(|h| h.borrow_mut().take());
        }
    }

    /// While [`fail_tokio_spawns_after_fork`]'s guard lives, makes tokio's `spawn()` fail after its
    /// fork: the child is forgotten, and its pid, a pidfd on it and `leaf`, the cgroup leaf of the
    /// spawn, are kept for the `take_forgotten_*` readers. The spawn's own answer is what production
    /// gives a child tokio dropped.
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    pub(crate) fn fail_tokio_spawn_after_fork(
        spawned: std::io::Result<::tokio::process::Child>,
        leaf: Option<&std::path::Path>,
    ) -> std::io::Result<::tokio::process::Child> {
        if !FAIL_TOKIO_SPAWN.with(Cell::get) {
            return spawned;
        }
        FORGOTTEN_LEAF.with(|f| *f.borrow_mut() = leaf.map(std::path::Path::to_path_buf));
        let child = spawned?;
        if let (Some(hook), Some(pid)) = (AFTER_FAILED_TOKIO_FORK.with(|h| h.borrow_mut().take()), child.id()) {
            hook(pid);
        }
        forget_child(child);
        Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
    }

    /// [`fail_tokio_spawns_after_fork`] for a platform without the pidfd handshake: tokio's `spawn()`
    /// fails after its fork, and the child is forgotten, neither killed nor reaped. Its pid is kept
    /// for [`take_forgotten_pid`].
    #[cfg(all(not(target_os = "linux"), feature = "tokio"))]
    pub(crate) fn fail_tokio_spawn_after_fork(
        spawned: std::io::Result<::tokio::process::Child>,
    ) -> std::io::Result<::tokio::process::Child> {
        if !FAIL_TOKIO_SPAWN.with(Cell::get) {
            return spawned;
        }
        let child = spawned?;
        FORGOTTEN_PID.with(|f| f.set(child.id()));
        std::mem::forget(child);
        Err(std::io::Error::other(
            "forced tokio spawn failure after the fork (test seam)",
        ))
    }

    /// Forgets `child`, neither killed nor reaped, keeping its pid and a pidfd on it.
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    fn forget_child(child: ::tokio::process::Child) -> u32 {
        FORGOTTEN_PID.with(|f| f.set(child.id()));
        // A handle on the child that cannot come to name another process, taken while tokio still
        // pins its pid, so a test can prove the child reaped without probing a freed pid.
        let pidfd = child
            .id()
            .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
            .and_then(|pid| rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok())
            // Above 2: a test may have 0, 1 or 2 closed across the spawn, and restore them.
            .and_then(|pidfd| rustix::io::fcntl_dupfd_cloexec(&pidfd, 3).ok());
        FORGOTTEN_PIDFD.with(|f| *f.borrow_mut() = pidfd);
        let pid = child.id().expect("an unreaped child has its pid");
        std::mem::forget(child);
        pid
    }

    /// Fails the NEXT tokio spawn on this thread after the handshake concluded, forgetting its child
    /// as [`fail_tokio_spawn_after_fork`] does. That answer is the seam's own, not production's: a
    /// test through it checks the leaf and the warnings, never the answer (use
    /// [`fail_tokio_spawns_after_fork`] for that).
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    pub(crate) fn post_fork_failure(
        spawned: Result<::tokio::process::Child, super::SpawnFailure>,
        leaf: Option<&std::path::Path>,
    ) -> Result<::tokio::process::Child, super::SpawnFailure> {
        if !FORCE_POST_FORK_FAIL.with(|f| f.replace(false)) {
            return spawned;
        }
        FORGOTTEN_LEAF.with(|f| *f.borrow_mut() = leaf.map(std::path::Path::to_path_buf));
        let child = spawned?;
        let pid = forget_child(child);
        // Its pid names this spawn's failure, so a test can tell its log records from any other's.
        // It models tokio failing after std's spawn succeeded: after `exec`.
        Err(super::SpawnFailure::started(
            crate::error::Error::Io(std::io::Error::other(format!(
                "forced post-fork spawn failure (test seam) for child {pid}"
            ))),
            crate::error::ChildFate::Unknown,
        ))
    }

    pub(crate) fn set_force_identity_vanished(on: bool) {
        FORCE_VANISH.with(|f| f.set(on));
    }
    /// As [`set_force_identity_vanished`], but the identity read is refused (`Unknown`).
    #[cfg(unix)]
    pub(crate) fn set_force_identity_unknown(on: bool) {
        FORCE_UNKNOWN.with(|f| f.set(on));
    }
    pub(crate) fn force_identity_unknown() -> bool {
        FORCE_UNKNOWN.with(|f| f.get())
    }
    pub(crate) fn force_identity_vanished() -> bool {
        FORCE_VANISH.with(|f| f.get())
    }
    pub(crate) fn set_force_attach_failure(on: bool) {
        FORCE_ATTACH_FAIL.with(|f| f.set(on));
    }
    /// Hand the NEXT spawn on this thread `attachment` in place of the one `attach` would build,
    /// so a test can give a real child a leaf it shapes itself. TAKE semantics.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_attachment_override(attachment: crate::containment::Attachment) {
        ATTACHMENT_OVERRIDE.with(|f| *f.borrow_mut() = Some(attachment));
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_attachment_override() -> Option<crate::containment::Attachment> {
        ATTACHMENT_OVERRIDE.with(|f| f.borrow_mut().take())
    }

    pub(crate) fn force_attach_failure() -> bool {
        FORCE_ATTACH_FAIL.with(|f| f.get())
    }
    /// Make the next teardown reap on this thread fail with `marker` as its error. TAKE semantics:
    /// the teardown consumes it, and a test that set it asserts it was consumed, so it cannot
    /// outlive the spawn it was meant for.
    pub(crate) fn set_force_reap_failure(marker: &'static str) {
        FORCE_REAP_FAIL.with(|f| f.set(Some(marker)));
    }
    pub(crate) fn take_force_reap_failure() -> Option<&'static str> {
        FORCE_REAP_FAIL.with(|f| f.take())
    }
    /// Make the next teardown kill on this thread fail with an error of `kind` carrying `marker`,
    /// with the same TAKE semantics as [`set_force_reap_failure`].
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn set_force_kill_failure(marker: &'static str, kind: std::io::ErrorKind) {
        FORCE_KILL_FAIL.with(|f| f.set(Some((marker, kind, false))));
    }
    /// As [`set_force_kill_failure`] with an `Other` error, but the child is NOT killed first: it
    /// is left running, as a child that refused the kill would be.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn set_force_kill_failure_leaving_child_alive(marker: &'static str) {
        set_force_kill_failure_leaving_child_alive_as(marker, std::io::ErrorKind::Other);
    }
    /// As [`set_force_kill_failure_leaving_child_alive`], failing with `kind`. Also consumed by the
    /// async spawn's teardown (`ProcSource::reap_now`).
    #[cfg(any(not(target_os = "macos"), feature = "tokio"))]
    pub(crate) fn set_force_kill_failure_leaving_child_alive_as(marker: &'static str, kind: std::io::ErrorKind) {
        FORCE_KILL_FAIL.with(|f| f.set(Some((marker, kind, true))));
    }
    /// Make the next teardown kill on this thread wait for its child to exit on its own, then fail
    /// with an error of `kind` carrying `marker`: an `Err` from `kill` for a child that is gone.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn set_force_kill_error_after_exit(marker: &'static str, kind: std::io::ErrorKind) {
        FORCE_KILL_ERROR_AFTER_EXIT.with(|f| f.set(Some((marker, kind))));
    }
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn take_force_kill_error_after_exit() -> Option<(&'static str, std::io::ErrorKind)> {
        FORCE_KILL_ERROR_AFTER_EXIT.with(|f| f.take())
    }
    /// Have the next background reap started on this thread report its outcome on `notify`.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn set_background_reap_notifier(notify: std::sync::mpsc::Sender<std::io::Result<()>>) {
        BACKGROUND_REAP_NOTIFY.with(|f| f.set(Some(notify)));
    }
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn take_background_reap_notifier() -> Option<std::sync::mpsc::Sender<std::io::Result<()>>> {
        BACKGROUND_REAP_NOTIFY.with(|f| f.take())
    }
    #[cfg(any(not(target_os = "macos"), feature = "tokio"))]
    pub(crate) fn take_force_kill_failure() -> Option<(&'static str, std::io::ErrorKind, bool)> {
        FORCE_KILL_FAIL.with(|f| f.take())
    }
    pub(crate) fn capture(id: crate::identity::Resolved<ProcessId>) {
        CAPTURED.with(|c| c.set(Some(id)));
    }
    pub(crate) fn take_captured() -> Option<crate::identity::Resolved<ProcessId>> {
        CAPTURED.with(|c| c.take())
    }

    /// Makes the NEXT [`handle_signaled_by`](crate::wait::teardown_warn::handle_signaled_by) on this
    /// thread find its child not yet exited, whatever its handle says, so a test sees the warn of a
    /// wait that really ends at once. The guard clears it on drop, used or not.
    #[cfg(all(windows, feature = "tokio"))]
    pub(crate) fn set_late_exit() -> LateExit {
        LATE_EXIT.with(|f| f.set(true));
        LateExit(())
    }

    #[cfg(all(windows, feature = "tokio"))]
    #[must_use = "the override is cleared as soon as the guard is dropped"]
    pub(crate) struct LateExit(());

    #[cfg(all(windows, feature = "tokio"))]
    impl Drop for LateExit {
        fn drop(&mut self) {
            LATE_EXIT.with(|f| f.set(false));
        }
    }

    #[cfg(windows)]
    pub(crate) fn take_late_exit() -> bool {
        LATE_EXIT.with(|f| f.replace(false))
    }

    /// Run `hook` at the next kill-then-blocking-wait teardown on this thread, once the kill has
    /// returned `Ok` and before the wait: `teardown_unadopted`, the sync `finish_elevated`,
    /// `raw_spawn_teardown` (Windows), the async `wait_and_reap` and `teardown_through_pidfd`, or
    /// `await_unexecuted_exit`. See [`release_between_kill_and_wait`] and [`record_teardown_reaps`].
    pub(crate) fn set_between_kill_and_wait(hook: impl FnOnce() + 'static) -> ArmedBetweenKillAndWait {
        crate::oneshot_hook::arm(&BETWEEN_KILL_AND_WAIT, hook)
    }
    pub(crate) fn run_between_kill_and_wait() {
        crate::oneshot_hook::fire(&BETWEEN_KILL_AND_WAIT);
    }
    pub(crate) type ArmedBetweenKillAndWait = crate::oneshot_hook::Armed;

    /// What runs when a thread finds `spawn_lock` held, on any thread.
    #[cfg(target_os = "macos")]
    static ON_SPAWN_LOCK_CONTENDED: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> = std::sync::Mutex::new(None);

    /// Runs `hook` once, on the first thread of this process that then finds `spawn_lock` held, before
    /// that thread blocks on it. The guard drops an unfired hook.
    #[cfg(target_os = "macos")]
    pub(crate) fn on_spawn_lock_contended(hook: impl FnOnce() + Send + 'static) -> ContendedHook {
        let previous = ON_SPAWN_LOCK_CONTENDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(Box::new(hook));
        debug_assert!(previous.is_none(), "a contention hook is already armed");
        ContendedHook(())
    }

    #[cfg(target_os = "macos")]
    #[must_use = "the hook is dropped as soon as the guard is dropped"]
    pub(crate) struct ContendedHook(());

    #[cfg(target_os = "macos")]
    impl Drop for ContendedHook {
        fn drop(&mut self) {
            ON_SPAWN_LOCK_CONTENDED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn spawn_lock_contended() {
        let hook = ON_SPAWN_LOCK_CONTENDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// A point in a spawn where a test can run a hook.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum SpawnPoint {
        /// Right before the spawn reads the child's identity (the tokio spawn's macOS unique id is
        /// read earlier, before the backend exists).
        BeforeIdentity,
        /// Right before the spawn attaches the containment.
        BeforeAttach,
        /// Right after the spawn read the child's identity, before it checks the read against the
        /// child's handle.
        AfterIdentityRead,
        /// macOS: right before the teardown of a child whose unique id came late.
        #[cfg(target_os = "macos")]
        BeforeLateTeardown,
        /// macOS: in that teardown, after the first kill of the tree and before the root's kill.
        #[cfg(target_os = "macos")]
        BeforeLateRootKill,
    }

    fn hook_at(point: SpawnPoint) -> &'static std::thread::LocalKey<crate::oneshot_hook::OneShotHook> {
        match point {
            SpawnPoint::BeforeIdentity => &BEFORE_IDENTITY,
            SpawnPoint::BeforeAttach => &BEFORE_ATTACH,
            SpawnPoint::AfterIdentityRead => &AFTER_IDENTITY_READ,
            #[cfg(target_os = "macos")]
            SpawnPoint::BeforeLateTeardown => &BEFORE_LATE_TEARDOWN,
            #[cfg(target_os = "macos")]
            SpawnPoint::BeforeLateRootKill => &BEFORE_LATE_ROOT_KILL,
        }
    }

    /// Run `hook` once at the next `point` on this thread; the guard clears it on drop.
    #[cfg_attr(
        not(all(feature = "tokio", target_os = "linux")),
        allow(dead_code, reason = "only the Linux async spawn's tests arm a spawn point so far")
    )]
    pub(crate) fn set_at(point: SpawnPoint, hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
        crate::oneshot_hook::arm(hook_at(point), hook)
    }

    /// Fire the hook armed for `point`, if any. Called by both spawns with the child's pid, which
    /// the hook reads through [`spawn_pid`].
    pub(crate) fn run_at(point: SpawnPoint, pid: u32) {
        SPAWN_PID.with(|p| p.set(Some(pid)));
        crate::oneshot_hook::fire(hook_at(point));
        SPAWN_PID.with(|p| p.set(None));
    }

    /// The pid of the child the spawn that fired the running hook has just forked.
    #[cfg_attr(
        not(all(feature = "tokio", target_os = "linux")),
        allow(dead_code, reason = "only the Linux async spawn's tests arm a spawn point so far")
    )]
    pub(crate) fn spawn_pid() -> u32 {
        SPAWN_PID.with(Cell::get).expect("spawn_pid is read from a spawn hook")
    }

    /// A reaped teardown child's pid and exit status.
    type TeardownReap = (u32, std::process::ExitStatus);

    /// Record the pid and status of every child the teardowns listed at
    /// [`set_between_kill_and_wait`] wait on for real on this thread until the returned guard
    /// drops. A failed wait records nothing.
    pub(crate) fn record_teardown_reaps() -> TeardownReaps {
        let previous = TEARDOWN_REAPS.with(|r| r.borrow_mut().replace(Vec::new()));
        debug_assert!(previous.is_none(), "teardown reaps are already being recorded");
        TeardownReaps
    }
    pub(crate) fn record_teardown_reap(pid: u32, status: std::process::ExitStatus) {
        TEARDOWN_REAPS.with(|r| {
            if let Some(reaps) = r.borrow_mut().as_mut() {
                reaps.push((pid, status));
            }
        });
    }
    /// Stops the [`record_teardown_reaps`] recording on drop.
    #[must_use]
    pub(crate) struct TeardownReaps;
    impl TeardownReaps {
        /// The `(pid, status)` of each reap recorded so far, oldest first.
        pub(crate) fn recorded(&self) -> Vec<TeardownReap> {
            TEARDOWN_REAPS.with(|r| r.borrow().clone().unwrap_or_default())
        }

        /// At least one child was reaped, and each died of `SIGKILL` (Unix) or exit code 1
        /// (Windows): killed by the teardown, not merely reaped once it exited on its own.
        pub(crate) fn assert_killed(&self) {
            let reaps = self.recorded();
            assert!(!reaps.is_empty(), "the teardown must have reaped the child");
            for (pid, status) in reaps {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt as _;
                    assert_eq!(
                        status.signal(),
                        Some(libc::SIGKILL),
                        "pid {pid} must be SIGKILLed by its teardown kill, not merely reaped once it exits on its own: {status:?}"
                    );
                }
                #[cfg(windows)]
                assert_eq!(
                    status.code(),
                    Some(1),
                    "pid {pid} must be terminated by its teardown kill (`TerminateProcess` exits 1), not merely reaped once it exits on its own: {status:?}"
                );
            }
        }
    }
    impl Drop for TeardownReaps {
        fn drop(&mut self) {
            let reaps = TEARDOWN_REAPS.with(|r| r.borrow_mut().take());
            drop(reaps);
        }
    }

    /// A stdin for a child only a kill ends, its writer released as [`release_between_kill_and_wait`]
    /// does. Keep the guard alive through the assertion: dropping it clears the hook and recorder.
    ///
    /// The child must exit 0 on stdin EOF: `cat` on Unix, `more.com` on Windows (whose `findstr x`
    /// exits 1, which is what a kill reports) with a null stdout, because `more` echoes. Use
    /// [`teardown_blocker_parts`] to get the whole child.
    pub(crate) fn teardown_blocker_stdin() -> (crate::stdio::Stdio, TeardownBlocker) {
        let (reader, writer) = std::io::pipe().expect("pipe");
        #[cfg(unix)]
        let reader = std::os::fd::OwnedFd::from(reader);
        #[cfg(windows)]
        let reader = std::os::windows::io::OwnedHandle::from(reader);
        (
            crate::stdio::Stdio::from_file(std::fs::File::from(reader)),
            release_between_kill_and_wait(writer),
        )
    }

    /// [`teardown_blocker_stdin`] for a child a test already spawned; `held` is whatever only a kill
    /// ends the child without (its stdin writer, a control socket). It is dropped between the code
    /// under test's kill and its blocking wait ([`set_between_kill_and_wait`]), so a kill that sent
    /// nothing exits 0 and fails [`TeardownBlocker::assert_killed`] instead of hanging the wait.
    /// The reaps it makes are recorded. Arm it before the code under test runs and keep the guard
    /// through the assertion.
    pub(crate) fn release_between_kill_and_wait(held: impl Sized + 'static) -> TeardownBlocker {
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let release = set_between_kill_and_wait(release_hook(held, &fired));
        TeardownBlocker {
            _release: release,
            fired,
            reaps: record_teardown_reaps(),
        }
    }

    /// [`release_between_kill_and_wait`] for the sync `Child`'s kill-on-drop teardown, whose root
    /// kill is followed by a blocking wait inside `drop`: `held` is dropped once that kill returned.
    pub(crate) fn release_at_drop_kill(held: impl Sized + 'static) -> TeardownBlocker {
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let release = crate::graceful_hooks::at(
            crate::graceful_hooks::HookPoint::AfterDropKill,
            release_hook(held, &fired),
        );
        TeardownBlocker {
            _release: release,
            fired,
            reaps: record_teardown_reaps(),
        }
    }

    /// Releases the writer in `held` at every point where a sync teardown, a failed spawn's cleanup
    /// or a graceful shutdown waits for a root it has killed: after the drop's kill, before the
    /// shutdown's reap, between a kill and its wait. Once the kill returned, a root held only by
    /// that writer exits by itself, so a kill that sent nothing fails the test's assertion on what
    /// the kill should have ended instead of hanging the wait. Keep the guard through the teardown.
    /// `held` is a shared cell so the test can also release it by hand.
    #[cfg(target_os = "linux")]
    pub(crate) fn release_when_a_teardown_waits<T: 'static>(
        held: &std::rc::Rc<std::cell::Cell<Option<T>>>,
    ) -> Box<dyn std::any::Any> {
        use crate::graceful_hooks::{at, HookPoint};
        let release = || {
            let held = std::rc::Rc::clone(held);
            move || drop(held.take())
        };
        Box::new((
            at(HookPoint::AfterDropKill, release()),
            at(HookPoint::BeforeReap, release()),
            set_between_kill_and_wait(release()),
        ))
    }

    fn release_hook(held: impl Sized + 'static, fired: &std::rc::Rc<std::cell::Cell<bool>>) -> impl FnOnce() + 'static {
        let fired = std::rc::Rc::clone(fired);
        move || {
            drop(held);
            fired.set(true);
        }
    }

    /// Everything a test needs to configure a [`teardown_blocker_stdin`] child on either
    /// `Command` type: apply `argv`, `stdin`, and `stdout` when it is `Some`.
    pub(crate) struct TeardownBlockerParts {
        pub(crate) argv: Vec<std::ffi::OsString>,
        pub(crate) stdin: crate::stdio::Stdio,
        pub(crate) stdout: Option<crate::stdio::Stdio>,
        pub(crate) guard: TeardownBlocker,
    }

    /// The argv and stdio of a [`teardown_blocker_stdin`] child, for the sync and async `Command`.
    pub(crate) fn teardown_blocker_parts() -> TeardownBlockerParts {
        let (stdin, guard) = teardown_blocker_stdin();
        #[cfg(unix)]
        let (argv, stdout) = (crate::test_child::BLOCKER_ARGV.iter().map(Into::into).collect(), None);
        #[cfg(windows)]
        let (argv, stdout) = (
            vec![crate::test_child::windows_more().into_os_string()],
            Some(crate::stdio::Stdio::null()),
        );
        TeardownBlockerParts {
            argv,
            stdin,
            stdout,
            guard,
        }
    }

    /// See [`teardown_blocker_stdin`].
    #[must_use]
    pub(crate) struct TeardownBlocker {
        _release: ArmedBetweenKillAndWait,
        fired: std::rc::Rc<std::cell::Cell<bool>>,
        reaps: TeardownReaps,
    }
    impl TeardownBlocker {
        /// The `(pid, status)` of each reap the teardown recorded so far.
        #[cfg(any(unix, feature = "tokio"))]
        pub(crate) fn recorded(&self) -> Vec<TeardownReap> {
            self.reaps.recorded()
        }

        /// The teardown's kill fired the release hook, and every child it reaped died of
        /// `SIGKILL` (Unix) or exit code 1 (Windows).
        pub(crate) fn assert_killed(&self) {
            assert!(
                self.fired.get(),
                "the teardown must have reached its release hook (the kill returned)"
            );
            self.reaps.assert_killed();
        }

        /// The release hook fired: the teardown's kill returned. For a teardown whose reap is not
        /// recorded (the kernel's, or forced to fail).
        #[cfg(unix)]
        pub(crate) fn assert_released(&self) {
            assert!(
                self.fired.get(),
                "the teardown must have reached its release hook (the kill returned)"
            );
        }

        /// [`assert_killed`](Self::assert_killed) without requiring the release hook to have fired,
        /// for a teardown whose own kill may find the child already dying (a job object's close).
        #[cfg(windows)]
        pub(crate) fn assert_reaps_killed(&self) {
            self.reaps.assert_killed();
        }
    }

    /// Assert the spawned child was fully torn down — reuse-immune, via the child's stable identity
    /// (pid + start token). On Unix a not-yet-reaped zombie keeps that identity (Linux /proc
    /// persists; macOS `sysctl KERN_PROC` resolves zombies) → caught on ALL Unix; a reaped pid
    /// resolves to `None` or a *different* identity → passes, so a
    /// recycled pid never false-fails. Windows has no zombies, and its process-object cleanup is not
    /// synchronous with `wait()`, so there we assert only that the child is dead (`!is_alive()`, also
    /// reuse-immune via the start token).
    #[cfg(any(not(target_os = "macos"), feature = "tokio"))]
    pub(crate) fn assert_child_reaped(captured: crate::identity::Resolved<ProcessId>) {
        let crate::identity::Resolved::Found(captured) = captured else {
            panic!("the seam must capture a resolved identity, got {captured:?}");
        };
        #[cfg(unix)]
        match ProcessId::of(captured.pid()) {
            crate::identity::Resolved::Found(id) => assert_ne!(
                id, captured,
                "a failed spawn must fully reap its child (no lingering zombie at its identity)"
            ),
            crate::identity::Resolved::Gone => {}
            // NOT a panic: once the child is reaped its pid is free host-wide, so a recycle
            // between the failed `/proc` read and the `kill(pid, 0)` probe legitimately
            // yields Unknown. What matters is only that the pid no longer resolves to OUR
            // identity, and an unreadable stranger is not our child either.
            crate::identity::Resolved::Unknown => {}
        }
        #[cfg(windows)]
        assert_eq!(
            captured.is_alive(),
            crate::identity::Liveness::Dead,
            "a failed spawn must leave the child dead"
        );
    }
}

// The `.bat`/`.cmd` refusal every backend runs before it spawns.
#[path = "spawn/batch_gate.rs"]
mod batch_gate;
pub(crate) use batch_gate::reject_batch_path;

// cosca-owned fd mapping (replaces `command-fds` — see the module docs).
#[cfg(unix)]
#[path = "spawn/fd_map.rs"]
pub(crate) mod fd_map;

// The one `pre_exec` hook that runs every in-child step of a spawn.
#[cfg(unix)]
#[path = "spawn/in_child.rs"]
pub(crate) mod in_child;

// The `pre_exec` fd-channel primitive of `pidfd_handshake` and, on macOS, `unique_report`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "spawn/fd_channel.rs"]
pub(crate) mod fd_channel;

// A failed spawn's answer to whether the program could have started.
#[path = "spawn/failure.rs"]
pub(crate) mod failure;

// Linux: holds a forked child before `exec` until the parent has its pidfd.
#[cfg(target_os = "linux")]
#[path = "spawn/pidfd_handshake.rs"]
pub(crate) mod pidfd_handshake;

// Windows raw `CreateProcessW` spawn backend.
#[cfg(windows)]
#[path = "spawn/windows_raw.rs"]
pub(crate) mod windows_raw;

// Windows: a child-side handle that may be absent.
#[cfg(windows)]
#[path = "spawn/windows_child_end.rs"]
mod windows_child_end;

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/placement_reuse_tests.rs"]
mod placement_reuse_tests;

#[cfg(test)]
#[path = "spawn/spawn_lock_tests.rs"]
mod spawn_lock_tests;

#[cfg(all(test, unix))]
#[path = "spawn/exact_posix_tests.rs"]
mod exact_posix_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/identity_error_tests.rs"]
mod identity_error_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "spawn/identity_macos_tests.rs"]
pub(crate) mod identity_macos_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "spawn/late_report_tests.rs"]
pub(crate) mod late_report_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/identity_peek_tests.rs"]
mod identity_peek_tests;

#[cfg(target_os = "macos")]
#[path = "spawn/unique_report.rs"]
pub(crate) mod unique_report;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/front_teardown_tests.rs"]
mod front_teardown_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "spawn/identity_group_tests.rs"]
pub(crate) mod identity_group_tests;
