//! std-only spawn: resolve the crate's `Stdio` model onto `std::process::Command`,
//! wire the program/args via the `quote` module, and spawn through `shared_child`.

use std::collections::BTreeMap;
use std::process::Stdio as StdStdio;

use shared_child::SharedChild;

use crate::child::proc_handle::ProcHandle;
use crate::child::{Child, ParentEnd};
use crate::command::{Command, CommandInput, EnvOp};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::stdio::{Direction, Fd, ResolvedStdio};

// A child-side descriptor handed to std via `Stdio::from`.
#[cfg(unix)]
pub(crate) type ChildEnd = std::os::unix::io::OwnedFd;
#[cfg(windows)]
pub(crate) type ChildEnd = std::os::windows::io::OwnedHandle;

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let child = spawn_uncommitted(cmd)?;
    child.commit_kill_on_drop();
    Ok(child)
}

/// [`spawn`] up to the handle it returns, whose containment resource still tears the tree down
/// on drop whatever `kill_on_drop` says.
pub(crate) fn spawn_uncommitted(cmd: &mut Command) -> Result<Child, Error> {
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
                derived,
                report,
                password_write,
                backend_path,
            } = crate::elevation::posix::rewrite(cmd)?;
            let mut child = match derived {
                // The derived program IS the backend; remap an exec failure to
                // BackendUnavailable ONLY when the backend path is the culprit (a bad cwd
                // yields the same kind and stays a plain Io). An already-elevated derived
                // (sanitized original) has no backend path, so it is never remapped.
                Some(mut derived) => {
                    let r = spawn_unelevated(&mut derived, kill_on_drop);
                    match backend_path.as_deref() {
                        Some(bp) => r.map_err(|e| crate::elevation::remap_derived_spawn_error(e, bp))?,
                        None => r?,
                    }
                }
                // No derived command: the current POSIX `rewrite` always returns `Some` (it
                // sanitizes even the already-elevated case into a derived), so this is defensive.
                None => spawn_unelevated(cmd, kill_on_drop)?,
            };
            // Set the elevation report BEFORE handling the deferred password: a cleanup
            // kill() in the write-failure path must see the elevated state so an EPERM maps
            // to the typed Unkillable rather than leaking a raw Io.
            child.set_elevation(report);
            let written = password_write.map_or(Ok(()), |pw| pw.write_after_spawn());
            return finish_elevated(child, written);
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err(Error::Unsupported {
                op: "elevation".into(),
                platform: std::env::consts::OS,
                detail: "no elevation backend on this platform".into(),
            });
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
/// `try_wait` and the note that it may still be running.
#[cfg(unix)]
pub(crate) fn finish_elevated(child: Child, written: Result<(), Error>) -> Result<Child, Error> {
    let Err(write_err) = written else {
        return Ok(child);
    };
    let tree = child.containment().can_teardown().then(|| child.attached.hard_kill());
    let root_note = match child.kill() {
        Ok(()) => {
            let _ = child.wait();
            "the elevated child was terminated".to_string()
        }
        Err(e) => {
            let _ = child.try_wait();
            format!("the elevated child could not be terminated ({e})")
        }
    };
    Err(Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: format!("{write_err}; {root_note}{}", tree_note(tree)),
    })
}

/// `None`: no tree kill was tried, as the containment cannot tear one down.
#[cfg(unix)]
pub(crate) fn tree_note(tree: Option<Result<(), Error>>) -> String {
    match tree {
        Some(Err(e)) => format!("; its contained tree could not be killed ({e})"),
        _ => String::new(),
    }
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
pub(crate) fn spawn_unelevated(cmd: &mut Command, kill_on_drop: bool) -> Result<Child, Error> {
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
    let mut std_cmd = build_std_command(cmd)?;

    // Resolve every configured slot to a child end via the shared core. Slots: 0/1/2
    // (defaulting to inherit) plus, on Unix, any configured n>=3. We own our pipes
    // (`std::io::pipe`) and keep the parent ends.
    let std_slots = [Fd::STDIN, Fd::STDOUT, Fd::STDERR];
    let all_slots: Vec<Fd> = {
        // Yield 0/1/2 first (even unconfigured, for inherit defaulting), then any
        // configured n>=3. The n>=3 collection is Unix-only: on Windows the routing
        // above (any fd>=3 goes to the raw backend) guarantees `fds` holds no fd>=3,
        // so the push is dead code there — cfg-gate it to make that explicit.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut v: Vec<Fd> = std_slots.to_vec();
        #[cfg(unix)]
        for &fd in fds.keys() {
            if fd.raw() >= 3 {
                v.push(fd);
            }
        }
        v
    };
    let (mut child_ends, parent_ends) = resolve_stdio(&fds, &all_slots, PipeOwnership::Owned)?;

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

    // Phase 1 (before spawn): root detection + pre-spawn containment setup. This
    // MUST run before the fd_map block below so that fd_map installs
    // the LAST pre_exec hook. Why ordering matters: pre_exec hooks run in
    // registration order in the forked child. The Linux cgroup self-placement
    // hook (registered inside `prepare`) writes "0" to a pre-opened cgroup.procs
    // fd (CLOEXEC, which is still open between fork and exec). If
    // fd_map's dup2 ran FIRST, it could dup2 the user's fd over the number
    // that cgroup.procs fd occupies — closing/replacing it — so the later cgroup
    // write would hit a closed/wrong fd (silent CgroupV2->ProcessGroup downgrade,
    // or a stray "0" corrupting the user's fd). By running fd_map LAST, the
    // cgroup write+close happens while its fd is still valid; fd_map may then
    // freely reuse the now-closed slot. The same holds for the channel the child
    // reports that write's outcome through (`cgroup::ReportChannel`). Net child order: std stdio
    // (0/1/2) -> the `raw_executable()` chdir (`build_std_command`'s `enter_in_child`) ->
    // containment pre_execs (cgroup placement / setsid) -> fd_map dup2 (last).
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
    let (prepared, child) = {
        let _guard = spawn_lock();
        let prepared = crate::containment::prepare(
            &mut std_cmd,
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
        )?;

        // On Unix, hand n>=3 child ends to fd_map. This installs a pre_exec hook
        // that dup2's each OwnedFd to its target number post-fork. It is registered
        // LAST (after `prepare` above) so its dup2 cannot clobber the cgroup
        // self-placement fd; std also dup2's 0/1/2 before any pre_exec runs (std
        // disables posix_spawn when hooks are registered), so our n>=3 mappings never
        // clobber the std stdio fds either. A duplicate child fd number is unreachable:
        // child_ends keys come from a BTreeMap, so each child fd number is unique.
        let mappings: Vec<fd_map::FdMapping> = child_ends
            .into_iter()
            .map(|(fd, owned)| fd_map::FdMapping {
                parent_fd: owned,
                child_fd: fd.raw(),
            })
            .collect();
        fd_map::install(&mut std_cmd, mappings).map_err(Error::Io)?;

        let c = std_cmd.spawn().map_err(Error::Io)?;
        drop(std_cmd);
        (prepared, c)
    };
    #[cfg(not(target_os = "macos"))]
    let (prepared, child) = {
        let prepared = crate::containment::prepare(
            &mut std_cmd,
            &cmd.contain_request(),
            cmd.flags_request(),
            &reserved,
            cmd.fd_marker_suppressed(),
            cmd.env_ops(),
        )?;

        // On Unix, hand n>=3 child ends to fd_map. See the macOS branch above for why
        // this is registered LAST (after `prepare`).
        #[cfg(unix)]
        {
            let mappings: Vec<fd_map::FdMapping> = child_ends
                .into_iter()
                .map(|(fd, owned)| fd_map::FdMapping {
                    parent_fd: owned,
                    child_fd: fd.raw(),
                })
                .collect();
            fd_map::install(&mut std_cmd, mappings).map_err(Error::Io)?;
        }

        // The std Child is owned here so containment can job-assign + resume it. Serialize the
        // spawn against the raw backend's inheritable-handle window via the shared spawn lock: std's
        // own handle-inheritance marking must not overlap a raw spawn on another thread.
        let c = {
            let _guard = spawn_lock();
            // Classified at the SYSCALL, not around the whole spawn: an access-denied from stdio
            // resolution or the post-spawn attach has nothing to do with a breakaway request.
            let spawned = std_cmd.spawn().map_err(Error::Io);
            #[cfg(windows)]
            let spawned =
                spawned.map_err(|e| crate::command::flags::classify_spawn_syscall_error(e, *cmd.flags_request()));
            spawned?
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
    let attachment = match attach_or_fault(
        child.id(),
        #[cfg(windows)]
        proc_handle,
        prepared,
    ) {
        Ok(v) => v,
        // Mirror the async spawn's error teardown: kill + reap the just-spawned child so a failed
        // attach never leaks a running/zombie process (std `Child::drop` neither kills nor reaps).
        Err(e) => {
            teardown_unadopted(child);
            return Err(e);
        }
    };
    // Read identity BEFORE adopting into SharedChild. `SharedChild::new` calls
    // `try_wait()`, which REAPS an already-exited child — and a short-lived child
    // (e.g. `exit 0`, `sid-report`) can exit before we reach this point. Once
    // reaped, /proc/<pid> is gone and the identity is unresolvable (observed as a
    // load-dependent "vanished" race under parallel spawns). While we still own
    // the un-reaped `std::process::Child`, the child is at worst a zombie — on
    // Unix its /proc entry persists; on Windows the std Child pins the process
    // handle so the pid cannot be reused — so this read is race-free.
    let id = match resolve_identity(child.id()) {
        crate::identity::Resolved::Found(id) => id,
        // Same teardown for both arms (never leak the spawned child), different diagnosis:
        // an OS refusal is not a vanish.
        other => {
            teardown_unadopted(child);
            // The distinction must survive as a VARIANT, not as prose: a supervisor matching
            // on `Unassessable` to retry elevated would otherwise see an I/O failure and
            // treat a live, merely-unreadable child as a startup failure.
            return Err(spawn_identity_error(other));
        }
    };
    // Adopt AFTER the identity read (and after the containment resume) so
    // SharedChild's internal try_wait can reap-or-track without losing the identity.
    let shared = SharedChild::new(child).map_err(Error::Io)?;

    Ok(Child::from_parts(
        ProcHandle::Std(shared),
        id,
        parent_ends,
        kill_on_drop,
        attachment,
    ))
}

/// Serializes spawns against the process-global inheritable-handle window: on Windows both the std
/// path and the raw `CreateProcessW` backend must mark child-side handles inheritable, spawn, then
/// un-mark/close without a concurrent spawn inheriting them. Held across that window on both paths.
/// **Poison-tolerant:** a panic mid-spawn must not wedge every future spawn, so a poisoned lock is
/// recovered rather than propagated (the guarded data is unit — there is no invariant to protect).
pub(crate) fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    static SPAWN_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SPAWN_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn build_std_command(cmd: &Command) -> Result<std::process::Command, Error> {
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
    match cwd {
        Some(dir) if enter => enter_in_child(&mut std_cmd, &dir)?,
        Some(dir) => {
            std_cmd.current_dir(dir);
        }
        None => {}
    }
    Ok(std_cmd)
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
fn enter_in_child(std_cmd: &mut std::process::Command, dir: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    let dir = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_dir() contains an embedded NUL",
        ))
    })?;
    // SAFETY: `chdir` is async-signal-safe, and `dir` is allocated before the fork and only read
    // after it.
    unsafe {
        std_cmd.pre_exec(move || {
            if libc::chdir(dir.as_ptr()) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn enter_in_child(_: &mut std::process::Command, _: &std::path::Path) -> Result<(), Error> {
    unreachable!("only anchor_posix asks the child to enter its directory")
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
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    Deferred,
}

/// Shared stdio-resolution core for both spawn paths. `slots` is the resolution order (0/1/2
/// always; the sync path adds Unix n>=3); the per-caller tails (fd>=3 policy, fd_map wiring,
/// final `Stdio` assignment) stay with each spawn.
pub(crate) fn resolve_stdio(
    fds: &BTreeMap<Fd, ResolvedStdio>,
    slots: &[Fd],
    pipe: PipeOwnership,
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
                let (child_end, parent) = resolve_non_merge(slot, resolved)?;
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
pub(crate) fn resolve_non_merge(slot: Fd, r: Option<&ResolvedStdio>) -> Result<(ChildEnd, Option<ParentEnd>), Error> {
    match r {
        None | Some(ResolvedStdio::Inherit) => Ok((inherit_end(slot)?, None)),
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
        use std::os::windows::io::AsHandle;
        end.as_handle().try_clone_to_owned().map_err(Error::Io)
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

fn inherit_end(slot: Fd) -> Result<ChildEnd, Error> {
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
        let owned = match slot {
            Fd::STDIN => {
                let s = std::io::stdin();
                s.as_handle().try_clone_to_owned()
            }
            Fd::STDOUT => {
                let s = std::io::stdout();
                s.as_handle().try_clone_to_owned()
            }
            Fd::STDERR => {
                let s = std::io::stderr();
                s.as_handle().try_clone_to_owned()
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

/// The error for a spawn whose child could not be identified. `Gone` is an absence;
/// `Unknown` is an OS refusal about a child that may be running fine - never report the
/// second as the first. Mirrors `containment::dispatch::resolve_root_id`.
pub(crate) fn spawn_identity_error(outcome: crate::identity::Resolved<ProcessId>) -> Error {
    match outcome {
        crate::identity::Resolved::Unknown => Error::Unassessable {
            detail: "the OS refused to report the spawned child's identity".into(),
            source: None,
        },
        _ => Error::Io(std::io::Error::other(
            "spawned child vanished before its identity could be read",
        )),
    }
}

/// Read the spawned child's stable identity. A test-only fault seam (`fault`) can force the
/// vanished branch, exercising either spawn path's error-teardown arm deterministically.
pub(crate) fn resolve_identity(pid: u32) -> crate::identity::Resolved<ProcessId> {
    #[cfg(test)]
    if fault::force_identity_vanished() {
        // Capture the child's real identity for the test to prove it was reaped, then simulate a
        // vanish so `spawn` takes the teardown arm.
        fault::capture(ProcessId::of(pid));
        // The seam simulates a VANISH, not a refusal.
        return crate::identity::Resolved::Gone;
    }
    ProcessId::of(pid)
}

/// `containment::attach`, with a test-only seam to force its failure so the attach-error teardown
/// arm (which must kill+reap the just-spawned child) can be exercised deterministically.
pub(crate) fn attach_or_fault(
    pid: u32,
    #[cfg(windows)] proc_handle: std::os::windows::io::RawHandle,
    prepared: crate::containment::Prepared,
) -> Result<crate::containment::Attachment, Error> {
    #[cfg(test)]
    if fault::force_attach_failure() {
        // Capture identity for the test to prove the child is reaped, then simulate an attach
        // failure so `spawn` takes the attach-error teardown arm. The caller still holds the
        // child, so the verdict is taken before `prepared` drops, as a real attach takes it.
        fault::capture(ProcessId::of(pid));
        let mut prepared = prepared;
        prepared.settle_verdict(pid);
        // Model a REAL attach failure, which surfaces as `Error::Containment` (not `Error::Io`), so
        // the tests assert production behavior rather than the seam's fabricated variant.
        return Err(Error::Containment {
            detail: "forced attach failure (test seam)".into(),
        });
    }
    #[cfg(all(test, target_os = "linux"))]
    if let Some(attachment) = fault::take_attachment_override() {
        let mut prepared = prepared;
        prepared.settle_verdict(pid);
        return Ok(attachment);
    }
    crate::containment::attach(
        pid,
        #[cfg(windows)]
        proc_handle,
        prepared,
    )
}

/// Kill and reap a spawned child that an error path is abandoning before adoption, logging a
/// failure of either at `warn` and `debug_assert`ing it.
///
/// A child that could not be killed is NOT waited for here: it may still be running — a setuid
/// child such as `sudo` refuses our SIGKILL with EPERM — and a blocking `wait()` would hang the
/// spawn for as long as it runs. If it has not exited, it is handed to [`reap_in_background`],
/// which reaps it whenever it does, so it never lingers as a zombie. EPERM is the one kill failure
/// that is not asserted, because it is reachable without any bug.
fn teardown_unadopted(mut child: std::process::Child) {
    // warn before any assert: `debug_assert` is compiled out in release, and a swallowed failure
    // would otherwise leave no trace at all there.
    if let Err(kill) = kill_unadopted(&mut child) {
        log::warn!(
            "spawn teardown failed to kill pid {}: {kill}; reaping it in the background once it exits",
            child.id()
        );
        if !matches!(child.try_wait(), Ok(Some(_))) {
            reap_in_background(child);
        }
        // After the handoff, so a debug build's panic cannot strand the child.
        debug_assert!(
            kill.kind() == std::io::ErrorKind::PermissionDenied,
            "sync spawn teardown failed to kill child: {kill}"
        );
        return;
    }
    if let Err(reap) = reap_unadopted(&mut child) {
        log::warn!("spawn teardown failed to reap pid {}: {reap}", child.id());
        debug_assert!(false, "sync spawn teardown failed to reap child: {reap}");
    }
}

/// Reap `child` on a detached thread once it exits on its own. The thread blocks on the child's
/// exit, an event outside this process's control; nothing waits for the thread.
fn reap_in_background(mut child: std::process::Child) {
    #[cfg(test)]
    let notify = fault::take_background_reap_notifier();
    let pid = child.id();
    let spawned = std::thread::Builder::new()
        .name(format!("cosca-reap-{pid}"))
        .spawn(move || {
            let reaped = child.wait().map(drop);
            if let Err(e) = &reaped {
                log::warn!("background reap of pid {pid} failed: {e}");
            }
            #[cfg(test)]
            if let Some(notify) = notify {
                let _ = notify.send(reaped);
            }
        });
    if let Err(e) = spawned {
        log::warn!("could not start a thread to reap pid {pid}, which stays unreaped: {e}");
    }
}

/// `child.kill()`, `Ok` for a child that has already exited on every platform, and forceable to
/// fail by a test.
///
/// std returns `Ok` for an exited child on Windows (`TerminateProcess`'s `ACCESS_DENIED` is
/// checked with `try_wait`) and, on Unix, for one it has already waited on. An exited child it has
/// NOT waited on is left to `kill(2)`, whose answer for a zombie std does not promise — so an
/// `Err` here is checked the same way Windows' is, and dropped if the child has exited.
///
/// The forced failure KILLS AND REAPS first, so the test that asks for it leaks nothing although
/// the teardown then skips its own reap — unless it was set to leave the child alive.
fn kill_unadopted(child: &mut std::process::Child) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some((marker, kind, alive)) = fault::take_force_kill_failure() {
        if !alive {
            child.kill()?;
            child.wait()?;
        }
        return Err(std::io::Error::new(kind, marker));
    }
    match child.kill() {
        Err(_) if matches!(child.try_wait(), Ok(Some(_))) => Ok(()),
        other => other,
    }
}

/// `child.wait()`, which a test can force to fail. The forced failure still REAPS first, so the
/// test that asks for it leaks nothing.
fn reap_unadopted(child: &mut std::process::Child) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(test)]
    if let Some(marker) = fault::take_force_reap_failure() {
        child.wait()?;
        return Err(std::io::Error::other(marker));
    }
    child.wait()
}

/// Test-only fault injection + assertions for the spawn error-teardown paths, shared by both spawns.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    use crate::identity::ProcessId;

    thread_local! {
        static FORCE_VANISH: Cell<bool> = const { Cell::new(false) };
        static FORCE_ATTACH_FAIL: Cell<bool> = const { Cell::new(false) };
        static FORCE_REAP_FAIL: Cell<Option<&'static str>> = const { Cell::new(None) };
        static FORCE_KILL_FAIL: Cell<Option<(&'static str, std::io::ErrorKind, bool)>> = const { Cell::new(None) };
        static BACKGROUND_REAP_NOTIFY: Cell<Option<std::sync::mpsc::Sender<std::io::Result<()>>>> = const { Cell::new(None) };
        static CAPTURED: Cell<Option<crate::identity::Resolved<ProcessId>>> = const { Cell::new(None) };
        #[cfg(target_os = "linux")]
        static ATTACHMENT_OVERRIDE: std::cell::RefCell<Option<crate::containment::Attachment>> =
            const { std::cell::RefCell::new(None) };
        #[cfg(all(target_os = "linux", feature = "tokio"))]
        static FORCE_POST_FORK_FAIL: Cell<bool> = const { Cell::new(false) };
        #[cfg(all(target_os = "linux", feature = "tokio"))]
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
    #[cfg(all(target_os = "linux", feature = "tokio"))]
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

    #[cfg(all(target_os = "linux", feature = "tokio"))]
    pub(crate) fn post_fork_failure(
        spawned: Result<::tokio::process::Child, crate::error::Error>,
        leaf: Option<&std::path::Path>,
    ) -> Result<::tokio::process::Child, crate::error::Error> {
        if !FORCE_POST_FORK_FAIL.with(|f| f.replace(false)) {
            return spawned;
        }
        FORGOTTEN_LEAF.with(|f| *f.borrow_mut() = leaf.map(std::path::Path::to_path_buf));
        let child = spawned?;
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
        // Its pid names this spawn's failure, so a test can tell its log records from any other's.
        Err(crate::error::Error::Io(std::io::Error::other(format!(
            "forced post-fork spawn failure (test seam) for child {pid}"
        ))))
    }

    pub(crate) fn set_force_identity_vanished(on: bool) {
        FORCE_VANISH.with(|f| f.set(on));
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
    pub(crate) fn set_force_kill_failure(marker: &'static str, kind: std::io::ErrorKind) {
        FORCE_KILL_FAIL.with(|f| f.set(Some((marker, kind, false))));
    }
    /// As [`set_force_kill_failure`] with an `Other` error, but the child is NOT killed first: it
    /// is left running, as a child that refused the kill would be.
    pub(crate) fn set_force_kill_failure_leaving_child_alive(marker: &'static str) {
        set_force_kill_failure_leaving_child_alive_as(marker, std::io::ErrorKind::Other);
    }
    /// As [`set_force_kill_failure_leaving_child_alive`], failing with `kind`. Also consumed by the
    /// async spawn's teardown (`crate::tokio::child::reap_now`).
    pub(crate) fn set_force_kill_failure_leaving_child_alive_as(marker: &'static str, kind: std::io::ErrorKind) {
        FORCE_KILL_FAIL.with(|f| f.set(Some((marker, kind, true))));
    }
    /// Have the next background reap started on this thread report its outcome on `notify`.
    pub(crate) fn set_background_reap_notifier(notify: std::sync::mpsc::Sender<std::io::Result<()>>) {
        BACKGROUND_REAP_NOTIFY.with(|f| f.set(Some(notify)));
    }
    pub(crate) fn take_background_reap_notifier() -> Option<std::sync::mpsc::Sender<std::io::Result<()>>> {
        BACKGROUND_REAP_NOTIFY.with(|f| f.take())
    }
    pub(crate) fn take_force_kill_failure() -> Option<(&'static str, std::io::ErrorKind, bool)> {
        FORCE_KILL_FAIL.with(|f| f.take())
    }
    pub(crate) fn capture(id: crate::identity::Resolved<ProcessId>) {
        CAPTURED.with(|c| c.set(Some(id)));
    }
    pub(crate) fn take_captured() -> Option<crate::identity::Resolved<ProcessId>> {
        CAPTURED.with(|c| c.take())
    }

    /// Assert the spawned child was fully torn down — reuse-immune, via the child's stable identity
    /// (pid + start token). On Unix a not-yet-reaped zombie keeps that identity (Linux /proc
    /// persists; macOS `sysctl KERN_PROC` resolves zombies) → caught on ALL Unix; a reaped pid
    /// resolves to `None` or a *different* identity → passes, so a
    /// recycled pid never false-fails. Windows has no zombies, and its process-object cleanup is not
    /// synchronous with `wait()`, so there we assert only that the child is dead (`!is_alive()`, also
    /// reuse-immune via the start token).
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

// cosca-owned fd-mapping pre_exec (replaces `command-fds` — see the module docs for I14).
#[cfg(unix)]
#[path = "spawn/fd_map.rs"]
pub(crate) mod fd_map;

// Windows raw `CreateProcessW` spawn backend.
#[cfg(windows)]
#[path = "spawn/windows_raw.rs"]
pub(crate) mod windows_raw;

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod spawn_tests;

#[cfg(all(test, unix))]
#[path = "spawn/exact_posix_tests.rs"]
mod exact_posix_tests;
