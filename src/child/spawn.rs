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
            if let Some(pw) = password_write {
                if let Err(write_err) = pw.write_after_spawn() {
                    // Do NOT orphan the running elevated child on a genuine write failure:
                    // kill + reap it, folding the teardown outcome into the error detail. A
                    // successful kill() (SIGKILL, uncatchable) is followed by a BLOCKING wait()
                    // to actually reap; an Err kill() (e.g. Unkillable) can't be reaped, so fall
                    // back to a non-blocking try_wait() and note it may still be running.
                    let kill_note = match child.kill() {
                        Ok(()) => {
                            let _ = child.wait();
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
    // MUST run before the command-fds block below so that command-fds installs
    // the LAST pre_exec hook. Why ordering matters: pre_exec hooks run in
    // registration order in the forked child. The Linux cgroup self-placement
    // hook (registered inside `prepare`) writes "0" to a pre-opened cgroup.procs
    // fd (CLOEXEC, which is still open between fork and exec). If
    // command-fds' dup2 ran FIRST, it could dup2 the user's fd over the number
    // that cgroup.procs fd occupies — closing/replacing it — so the later cgroup
    // write would hit a closed/wrong fd (silent CgroupV2->ProcessGroup downgrade,
    // or a stray "0" corrupting the user's fd). By running command-fds LAST, the
    // cgroup write+close happens while its fd is still valid; command-fds may then
    // freely reuse the now-closed slot. The same holds for the channel the child
    // reports that write's outcome through (`cgroup::ReportChannel`). Net child order: std stdio
    // (0/1/2) -> the `raw_executable()` chdir (`build_std_command`'s `enter_in_child`) ->
    // containment pre_execs (cgroup placement / setsid) -> command-fds dup2 (last).
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

        // On Unix, hand n>=3 child ends to command-fds. This installs a pre_exec hook
        // that dup2's each OwnedFd to its target number post-fork. It is registered
        // LAST (after `prepare` above) so its dup2 cannot clobber the cgroup
        // self-placement fd; std also dup2's 0/1/2 before any pre_exec runs (std
        // disables posix_spawn when hooks are registered), so our n>=3 mappings never
        // clobber the std stdio fds either. FdMappingCollision is unreachable:
        // child_ends keys come from a BTreeMap, so each child fd number is unique.
        use command_fds::{CommandFdExt, FdMapping};
        let mappings: Vec<FdMapping> = child_ends
            .into_iter()
            .map(|(fd, owned)| FdMapping {
                parent_fd: owned,
                child_fd: fd.raw(),
            })
            .collect();
        if !mappings.is_empty() {
            std_cmd
                .fd_mappings(mappings)
                .expect("child fd numbers are unique (BTreeMap keys)");
        }

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

        // On Unix, hand n>=3 child ends to command-fds. See the macOS branch above for why
        // this is registered LAST (after `prepare`).
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
                std_cmd
                    .fd_mappings(mappings)
                    .expect("child fd numbers are unique (BTreeMap keys)");
            }
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
    // std runs a batch file through cmd.exe after `GetFullPathNameW`, so `setup.bat.` and
    // `C:\t\.bat` are batch files too; a `commandline()` tail would then reach cmd.exe unescaped.
    #[cfg(windows)]
    reject_normalised_batch_path(std::path::Path::new(&program))?;
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

/// The prefix Win32 acts on: everything before the first interior NUL, where `CreateProcessW` and
/// `PCWSTR` stop. Equal (and borrowed) when there is no NUL, which is how [`reject_batch_path_on`]
/// detects one without a platform-specific byte view at its own call site.
///
/// Host-independent on purpose — it computes the same prefix everywhere, which is what lets a
/// macOS run exercise the Win32 rule.
fn win32_prefix(prog: &std::path::Path) -> std::borrow::Cow<'_, std::path::Path> {
    use std::borrow::Cow;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = prog.as_os_str().as_bytes();
        match bytes.iter().position(|&b| b == 0) {
            Some(i) => Cow::Borrowed(std::path::Path::new(std::ffi::OsStr::from_bytes(&bytes[..i]))),
            None => Cow::Borrowed(prog),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let units: Vec<u16> = prog.as_os_str().encode_wide().collect();
        match units.iter().position(|&u| u == 0) {
            Some(i) => Cow::Owned(std::path::PathBuf::from(std::ffi::OsString::from_wide(&units[..i]))),
            None => Cow::Borrowed(prog),
        }
    }
    // Unreachable in any buildable configuration: `crate::wait`'s `compile_error!` rejects every
    // target that is not Linux, macOS or Windows. No portable byte view to split on either.
    #[cfg(not(any(unix, windows)))]
    {
        Cow::Borrowed(prog)
    }
}

/// Refuse a program whose Win32-NORMALISED path — `GetFullPathNameW`'s result, which is what
/// `CreateProcessW` loads — reaches a `.bat`/`.cmd`, for [`batch_refusal`]'s reason.
///
/// [`reject_batch_path`] reads `Path::extension()` of the token as written, which misses what
/// normalisation exposes: `setup.bat.` and `setup.bat ` (one trailing space) become `setup.bat`,
/// and `C:\t\.bat` has no extension to `Path` at all. This tests by suffix instead, as std's own
/// `has_bat_extension` does, on every data-stream piece of the final component, each trimmed of
/// trailing dots and spaces — so `x.bat::$DATA` is refused as its piece `x.bat`. Over-refusing a
/// stream spelling is the safe direction.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn reject_normalised_batch_path(full: &std::path::Path) -> Result<(), Error> {
    let text = full.as_os_str().to_string_lossy();
    let name = text
        .rsplit(['\\', '/'])
        .next()
        .expect("rsplit yields at least one piece");
    let is_batch = |piece: &str| {
        let piece = piece.trim_end_matches(['.', ' ']).to_ascii_lowercase();
        piece.ends_with(".bat") || piece.ends_with(".cmd")
    };
    if name.split(':').any(is_batch) {
        return Err(batch_refusal(full));
    }
    Ok(())
}

/// The refusal every batch gate returns, and the one statement of why.
///
/// Win32 runs a `.bat`/`.cmd` through `cmd.exe`, which re-parses the command line by rules of its
/// own — its metacharacters (`&`, `|`, `^`, `%`) act even inside the quoting cosca writes for
/// `CommandLineToArgvW`. So `args(["setup.bat", "a&calc"])` would also run `calc`. That is
/// CVE-2024-24576 (BatBadBut); cosca refuses the file rather than implement cmd.exe escaping.
fn batch_refusal(prog: &std::path::Path) -> Error {
    Error::Unsupported {
        op: format!("running {}", prog.display()),
        platform: "windows",
        detail: "cmd.exe batch escaping is not implemented (CVE-2024-24576); \
                 use .commandline() to pass an explicit, pre-escaped command line"
            .into(),
    }
}
const BATCH: &str = "cmd.exe batch escaping is not implemented (CVE-2024-24576); \
                     run it through cmd.exe yourself — .executable(\"cmd.exe\") plus a \
                     .commandline() you have escaped for cmd.exe";
const NO_FILE: &str = "the path names no file of its own, so which image loads is decided by \
                       the current directory or PATH — and a .bat-named directory there makes \
                       std::process substitute cmd.exe (CVE-2024-24576); name the executable";
// A verbatim path resolves against nothing, so NO_FILE's reason does not apply to one.
const VERBATIM_DOTDOT: &str = "a \\\\?\\ path is never normalised, so `..` is a literal file name \
                               here — and no file may be called that; name the executable";

/// Reject a program token carrying an interior NUL, or naming a `.bat`/`.cmd`: Win32 silently
/// truncates at the NUL (`PCWSTR` has no length), and a batch file is refused for
/// [`batch_refusal`]'s reason. Shared by every backend — the std path
/// (`build_std_command`), the raw one (`windows_raw::reject_batch_program`), and the elevated
/// `ShellExecuteEx` launch.
///
/// The rule, and why each half is a fact about Win32, is in [`reject_batch_path_on`]; this asks it
/// for the running host's verdict.
pub(crate) fn reject_batch_path(prog: &std::path::Path) -> Result<(), Error> {
    reject_batch_path_on(prog, cfg!(windows))
}

/// PURE given `win32`: the gate's rule with the platform as DATA rather than a `cfg!` buried in
/// it, so one host can ask for either verdict — the same reason `elevation::plan::Host` carries
/// its `Os`. Both are pinned from any host by `spawn_tests`, which matters because the Windows
/// branch — the whole `win32_effective_file_name` -> `is_batch_program` composition, where every
/// subtlety lives — would otherwise be covered by the two Windows CI lanes alone. Reading `cfg!`
/// here left it possible to revert this function to the `Path::extension()` rule it replaced and
/// stay green on four of six.
///
/// This gate is LIVE on the std path today, not merely a guard for some future backend. Rust's
/// own `std::process` detects a `.bat`/`.cmd` program, swaps it for `cmd.exe` and builds a batch
/// command line (`sys/process/windows.rs`'s `is_batch_file` -> `make_bat_command_line`), so
/// anything slipping past here is handed to exactly the quoting layer cosca has not implemented.
/// It goes live a second way once `ShellExecuteEx` is gated (#135), which has no such backstop.
///
/// An interior NUL is refused FIRST, under both verdicts, because `\0` is not a path separator
/// and neither `Path::extension()` nor the component walk below stops at one — so the name tested
/// is the INVERSE of what Win32 loads on each of the two NUL/batch shapes:
///
/// - `setup.bat` + NUL + `junk` → the effective name is `setup.bat\0junk`, yet Win32 loads the
///   real batch file `setup.bat`.
/// - `setup` + NUL + `.bat` → the effective name ends in `.bat`, yet Win32 loads `setup`, which is
///   no batch file — so the batch refusal would blame CVE-2024-24576 for a program that does not
///   carry that vector, and interpolate a raw U+0000 into a message bound for logs and terminals.
///
/// Refusing the NUL outright settles both shapes, and makes this gate SELF-SUFFICIENT rather than
/// a rule each caller must order its own NUL check in front of — the std backend, the DEFAULT
/// Windows path, has none to order. The reason given differs by verdict because the facts do: off
/// Win32 nothing truncates, so the token simply names no file.
///
/// The batch half is `win32`-only, because it too is a fact about Win32 rather than the request:
/// Win32 routes a `.bat`/`.cmd` through cmd.exe, which is what CVE-2024-24576 needs. Elsewhere a
/// clean `deploy.bat` is an ordinary executable the host runs, so refusing it would report "not
/// supported on windows" about a Linux or macOS host that runs it fine — and send its caller to
/// audit a batch vector that cannot reach them.
///
/// A path that resolves to NO NAME of its own is refused too, not accepted. std does not test the
/// string it was given: it runs the program through `GetFullPathNameW` (or the PATH search) and
/// applies `has_bat_extension` to the RESULT. A RELATIVE path that pops past its own first
/// component does not vanish — Win32 goes on popping into the ancestors of the current directory,
/// so with a cwd of `C:\w.bat` (a directory, which Windows permits) `x\..` resolves to `C:\w.bat`
/// and std substitutes `cmd.exe`. That is the hole this refusal closes.
///
/// A ROOTED path never reaches the cwd at all, so it is refused for having the same shape rather
/// than for the same danger — and what it clamps at depends on the root. A drive-rooted or
/// drive-relative path clamps at a root with no name of its own (`C:\`, `\`), which is not a
/// loadable image. A UNC path clamps at `\\server\share`, which DOES leave a named final
/// component, and that name is judged like any other — see [`win32_effective_file_name`].
///
/// A verbatim (`\\?\`) path is judged by a rule of its own — see [`verbatim_refusal`].
fn reject_batch_path_on(prog: &std::path::Path, win32: bool) -> Result<(), Error> {
    let loaded = win32_prefix(prog);
    if loaded.as_os_str() != prog.as_os_str() {
        // A literal: interpolating the token would put a raw U+0000 into a message bound for logs
        // and terminals, which is half of what this gate is removing.
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            if win32 {
                "the program path contains an embedded NUL, which Win32 would silently truncate"
            } else {
                "the program path contains an embedded NUL, so it names no file"
            },
        )));
    }
    if !win32 {
        return Ok(());
    }
    // Past the early return `loaded` and `prog` are the same string, so the rest reads `prog`.
    let text = prog.as_os_str().to_string_lossy();
    // Only backslashes spell the verbatim prefix; `\\?\` and `//?/` are different paths to
    // Win32, and only the first suppresses resolution.
    let refusal = if text.starts_with(r"\\?\") {
        verbatim_refusal(&text)
    } else {
        // The name Win32 will actually OPEN, not the one `Path::file_name()` reports: on
        // Windows those differ for any path ending in a `..` component, and the difference is
        // a live bypass.
        match win32_effective_file_name(prog) {
            Some(name) if is_batch_program(&name) => Some(BATCH),
            Some(_) => None,
            None => Some(NO_FILE),
        }
    };
    if let Some(detail) = refusal {
        return Err(Error::Unsupported {
            op: format!("running {}", prog.display()),
            platform: "windows",
            detail: detail.into(),
        });
    }
    Ok(())
}

pub(crate) fn apply_env(std_cmd: &mut std::process::Command, ops: &[EnvOp]) {
/// Whether a VERBATIM (`\\?\`) program reaches a batch file. std asks a different question of one
/// than it asks of any other path, and this is that question.
///
/// For an ordinary program std runs the string through `GetFullPathNameW` and tests the RESULT;
/// for a verbatim one it never makes that call, and `is_batch_file` is a literal test of the last
/// four UTF-16 units of the string as given. So `\\?\C:\x.bat.` ends in `bat.`, cmd.exe is not
/// substituted, and the image loads like any other — while the plain `C:\x.bat.` loses its
/// trailing dot on the way through `GetFullPathNameW` and reaches the batch file. The prefix does
/// not merely spell the same file differently; it selects a different resolution.
///
/// Measured on Windows runners, both architectures: `...`, `....`, `" "` and `"x "` are creatable,
/// listable and openable through the prefix, and both `CreateProcessW` and `std::process` spawn
/// them, while the plain spelling fails with access-denied. Refusing those refused a loadable
/// executable, which is why this is not the component machinery below with the trimming disabled.
///
/// The one other refusal is `..`, which no collapse turns into a path operation here: it is a
/// literal file name, and no file may be called that (measured: `ERROR_INVALID_NAME`). Other
/// unloadable spellings — a trailing separator, a final `.` — are left to fail with the OS's own
/// error, which says more about why than a security refusal would.
fn verbatim_refusal(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.ends_with(".bat") || lower.ends_with(".cmd") {
        return Some(BATCH);
    }
    // `/` is an ordinary filename character under the prefix, so only `\` separates.
    let last = text.rsplit('\\').next().expect("rsplit yields at least one piece");
    (last == "..").then_some(VERBATIM_DOTDOT)
}

/// Whether `file_name` names a batch script to Win32 — every stream piece, not just the name.
///
/// A name reaches a batch file if ANY piece [`ntfs_stream_names`] yields from it does. That
/// covers both ways one can be spelled at once:
///
/// - **As the filesystem resolves it.** `x.bat:s` names `x.bat` through a data stream, and
///   `x.bat ` / `x.bat.` reach it because Win32 strips trailing spaces and dots.
/// - **As written.** `ShellExecuteEx` reads the handler off the last `.` anywhere in the string
///   (`PathFindExtension`). std asks a differently-worded question with the same answer: it runs
///   the program through `GetFullPathNameW` — or, for a verbatim `\\?\` path, takes it literally —
///   and tests whether the result ENDS in `.bat`/`.cmd`, case-insensitively
///   (`sys/process/windows.rs`'s `has_bat_extension`). So `x.exe:payload.bat` is a batch file that
///   runs out of the alternate data stream — and it is refused as the PIECE `payload.bat`, not by
///   any separate rule. Testing the whole string for a batch extension beside this adds no
///   refusal; `the_stream_reading_subsumes_the_shell_reading` checks that exhaustively to six
///   characters and keeps it true.
///
/// Reading only the piece before the FIRST separator loosens the gate, because the extension then
/// comes from before the stream name.
///
/// Verbatim (`\\?\`) paths never reach here: nothing is trimmed or collapsed under that prefix,
/// and std tests the string as given, so [`verbatim_refusal`] owns them. Off Win32 nothing reaches
/// here at all — [`reject_batch_path_on`] returns before this, because a `.bat` is an ordinary
/// executable to every other host.
fn is_batch_program(file_name: &str) -> bool {
    ntfs_stream_names(file_name).any(is_batch_by_shell)
}

/// The final component of `prog` as Win32 will resolve it, collapsing `.` and `..` and stripping
/// the trailing dots and spaces Win32 removes from every component.
///
/// `Path::file_name()` is not good enough here, and the gap is exploitable. It returns `None` for
/// any path whose last component is `..`, so `x.bat\y\..` slipped the gate untouched — while
/// `GetFullPathNameW` collapses it straight back to `x.bat`, and `std::process` then detects the
/// batch extension and hands the program to `cmd.exe`. The same file refused as `x.bat` was
/// accepted spelled `x.bat\y\..`.
///
/// Special-casing `Component::ParentDir` would not close it either: `x.bat\y\.. ` has a final
/// component Rust parses as `Normal(".. ")`, which Win32 strips to `..` and resolves identically.
/// So the trailing-character stripping has to happen BEFORE the `.`/`..` test, which is the order
/// Win32 itself uses.
///
/// A component that is only dots and spaces yet is neither `.` nor `..` (`...`, `.. .`, a lone
/// space) trims away to nothing and DROPS OUT, popping nothing. Measured on a Windows runner:
/// `GetFullPathNameW(r"x.bat\y\...")` is `…\x.bat\y\`, so `y` survives and the batch file stays
/// covered.
///
/// `None` means the path named no file of its own: it was empty, was a bare root or drive prefix,
/// or popped its own components away. That last case did NOT collapse to nothing — a relative
/// path goes on popping into the ancestors of the current directory, so `x\..` resolves to
/// whatever the cwd is and `.` resolves to the cwd itself, while a rooted one clamps at its root.
/// The name is real, this gate just cannot see it, which is why [`reject_batch_path_on`] refuses
/// `None` rather than accepting it. A data-stream spelling is not that — `x.bat:` names a file and
/// comes back as one.
///
/// # A UNC root has a NAME, and `..` never pops it
///
/// `\\server\share` is a root the way `C:\` is, but unlike `C:\` its last component is a name.
/// Win32 skips server and share before it collapses anything (ReactOS's `RtlpCollapsePath` calls
/// `RtlpSkipUNCPrefix` first; .NET pins `\\LOCALHOST\share5\..` resolving to `\\LOCALHOST\share5`),
/// so no number of `..` reaches past the share, and a share named `x.bat` stays the effective name.
/// Walk a UNC path as if it had no root and every one of `\\srv\x.bat\..`, `//srv/x.bat/..`,
/// `\/srv\x.cmd\..`, `\\srv\x.bat\.. ` and `\\srv\x.bat\y\..\..` reduces to `srv` — not a batch
/// name, so the gate returns `Ok` on a token `std::process` hands straight to `cmd.exe`, and
/// `make_bat_command_line` appends the rest of a `.commandline()` verbatim. `GetFullPathNameW`
/// does no I/O, so the share need not exist for that to happen.
///
/// Server and share are POSITIONAL: Win32 takes the two segments after the `\\` without reading
/// them, so a `.`, `..` or empty segment there is part of the root rather than an operation on it.
/// That position has to be exact, not merely deep enough. A floor set one component too DEEP
/// suppresses a pop Win32 performs, and the final name moves to a later component: skip the
/// dots-only server in `\\...\x.bat\y\..` and the root becomes `x.bat\y`, the pop is clamped
/// away, and the gate judges `y` while Win32 resolves `\\...\x.bat`.
///
/// A `\\.\` or `//?/` device path puts its root in the same two positions (.NET's `GetRootLength`
/// counts `\\.\C:\` as the root of `\\.\C:\x`), so one rule covers both.
///
/// A literal `\\?\` never arrives: [`verbatim_refusal`] owns it.
///
/// # The token, not the resolved path (#144)
///
/// This runs on the program token AS WRITTEN, so it has to predict what that string resolves to
/// instead of resolving it. Two over-refusals are the price, both unchanged by the measurement
/// above. A path that pops past its own first component lands somewhere only the cwd can name, so
/// the gate refuses every one rather than guess. And a path whose final component drops out
/// resolves to a name with a trailing separator — `x.bat\...` is `…\x.bat\`, which std's
/// `has_bat_extension` does NOT read as a batch file — yet the gate judges the exposed `x.bat` and
/// refuses. #144 moves resolution ahead of the gate, at which point both collapse into a suffix
/// test on the resolved path and there is nothing left to predict.
fn win32_effective_file_name(prog: &std::path::Path) -> Option<String> {
    let text = prog.as_os_str().to_string_lossy();
    // Each surviving component, paired with whether it is the path's FIRST segment — the only
    // position a drive prefix can occupy.
    let mut stack: Vec<(&str, bool)> = Vec::new();
    let mut segments = text.split(['/', '\\']).enumerate();
    // A UNC (or `\\.\` device) root: the two segments after the leading pair, taken by POSITION
    // and never collapsed. `None` for a root with no share at all — `\\server` names nothing
    // loadable.
    let root = if starts_with_two_separators(&text) {
        segments.nth(1).expect("two separators are two empty segments");
        let (_, server) = segments.next()?;
        let (_, share) = segments.next()?;
        Some((server, share))
    } else {
        None
    };
    for (position, segment) in segments {
        // A repeated separator, never a component.
        if segment.is_empty() {
            continue;
        }
        // Trailing spaces go first, so `.. ` is recognised as the parent-directory component it
        // resolves to rather than as an ordinary file named `.. `.
        let segment = segment.trim_end_matches(' ');
        if segment == "." {
            continue;
        }
        if segment == ".." {
            // Popping an empty stack under a UNC root is popping into the root, which Win32
            // clamps at; `pop` on an empty stack is exactly that no-op.
            stack.pop();
            continue;
        }
        // Ordinary component: Win32 drops trailing dots and spaces. Nothing left of it means a
        // dots-and-spaces component, which drops out without popping.
        let name = segment.trim_end_matches([' ', '.']);
        if name.is_empty() {
            continue;
        }
        stack.push((name, position == 0));
    }
    if stack.is_empty() {
        if let Some((server, share)) = root {
            return unc_root_name(server, share);
        }
    }
    let (last, leading) = stack.pop()?;
    // A BARE drive prefix names no file — and only the first segment can be one. Elsewhere a
    // component ending in `:` is a data-stream spelling of a real file: `a:` is the file `a`, just
    // as `x.exe:` is the file `x.exe`, and returning `None` for either made the gate refuse a
    // loadable image over a one-character name.
    if leading && is_drive_prefix(last) {
        return None;
    }
    Some(last.to_string())
}

/// The name a path collapsed onto its UNC root resolves to, judged conservatively.
///
/// Win32 resolves it to `\\server\share`, so the share is the name std tests. The server is
/// judged as well: whether `..` spelled INSIDE the root is collapsed is not something this crate
/// has measured, and were it collapsed `\\x.bat\..` would resolve to `\\x.bat`. So a batch-named
/// server is returned in preference to the share, and a share that trims away to nothing names no
/// file — both over-refusals, and both in the direction this gate may err.
fn unc_root_name(server: &str, share: &str) -> Option<String> {
    let server = server.trim_end_matches([' ', '.']);
    if is_batch_program(server) {
        return Some(server.to_string());
    }
    let share = share.trim_end_matches([' ', '.']);
    (!share.is_empty()).then(|| share.to_string())
}

/// Whether the path opens with the two separators that make Win32 read a UNC root. Either
/// separator spells it in either position: `\\srv`, `//srv` and `\/srv` are one path to Win32.
fn starts_with_two_separators(text: &str) -> bool {
    let mut chars = text.chars();
    matches!((chars.next(), chars.next()), (Some('\\' | '/'), Some('\\' | '/')))
}

/// A bare `C:` — two bytes, a drive letter and a colon.
fn is_drive_prefix(component: &str) -> bool {
    matches!(component.as_bytes(), [d, b':'] if d.is_ascii_alphabetic())
}

/// Whether the shell would treat `name` as a batch file: the extension is everything after the
/// LAST `.` anywhere in the name, matching `PathFindExtension` and std's own `has_bat_extension`
/// (a case-insensitive `ends_with(".bat" | ".cmd")`, which is the same predicate).
///
/// Deliberately not `Path::extension()`, which differs in two ways that both matter. It returns
/// `None` for a name that IS `.bat` (a leading dot with no other dot), and it stops at nothing —
/// so `x.exe:payload.bat` reads as extension `exe:payload.bat` rather than the `bat` the shell
/// acts on.
fn is_batch_by_shell(name: &str) -> bool {
    match name.rfind('.') {
        Some(dot) => {
            let ext = name[dot + 1..].to_ascii_lowercase();
            ext == "bat" || ext == "cmd"
        }
        None => false,
    }
}

/// The file name and every data-stream name inside a path component, each trimmed the way Win32
/// trims a component.
///
/// Two normalisations, and the ORDER matters: split at the stream separators FIRST, then trim.
/// Note `x.bat:s ` does NOT discriminate — it yields `x.bat` either way, because trim-then-split
/// still splits. The witnesses are a trailing space or dot BEFORE the separator: `x.bat.:s`,
/// `x.bat :s`, `x.bat. :s`. Split-then-trim yields `x.bat` for all three; trim-then-split leaves
/// `x.bat.` / `x.bat ` / `x.bat. `, which the extension check then misses.
///
/// EVERY piece, not just the one before the first separator: taking only the first read
/// `x.exe:payload.bat:` as the file `x.exe`, losing the batch name, while the same stream spelled
/// `x.exe:payload.bat` was refused.
///
/// A leading `C:` is a drive, not a separator. Skipping it changes NO VERDICT — the only piece it
/// suppresses is a bare drive letter, one character with no dot in it, which is never a batch
/// name — and it is kept for the contract rather than the verdict: every piece this yields is a
/// name Win32 would open, and a drive letter is not one. The skip WAS load-bearing when only the
/// first piece was read, which is how `C:x.bat:s` came to be allowed while `x.bat:s` was refused.
fn ntfs_stream_names(name: &str) -> impl Iterator<Item = &str> {
    let rest = match name.get(..2) {
        Some(prefix) if is_drive_prefix(prefix) => &name[2..],
        _ => name,
    };
    rest.split(':').map(|part| part.trim_end_matches([' ', '.']))
}

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
/// always; the sync path adds Unix n>=3); the per-caller tails (fd>=3 policy, command-fds wiring,
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
