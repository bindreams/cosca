//! Windows raw `CreateProcessW` spawn backend.
//!
//! [`spawn_raw`] is the sync entry point: it loads an `executable()` file
//! independently of argv[0] (the case std cannot express on Windows), wiring the
//! child's std handles via `STARTUPINFOEXW` + a scoped `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
//! The process-handle + FFI primitives live in [`proc`]; program/env/NUL
//! resolution in [`resolve`]; the MSVCRT fd-table encoder (for fd >= 3)
//! in [`crt_fds`].
//!
//! # Why a handle list
//!
//! This backend gives a child exactly the handles cosca lists, and no other handle of this
//! process. That rests on Microsoft's guidance:
//!
//! - `bInheritHandles` TRUE with no list makes a child inherit every inheritable handle of this
//!   process ([`CreateProcessW`], Remarks), so the inheritable flag alone cannot scope a handle to one
//!   child ([Handle Inheritance] lists the two steps that make a handle inheritable).
//! - `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` names the handles one child inherits; each must be
//!   inheritable, and `bInheritHandles` must be TRUE ([`UpdateProcThreadAttribute`]).
//! - The flag is shared by all threads, so two threads that each mark a handle inheritable and
//!   spawn race; the list is the fix ([Raymond Chen, 2011]).
//!
//! The listed ends are marked inheritable, spawned and closed under [`spawn_lock`]. A list cannot
//! be empty: when `STARTF_USESTDHANDLES` is set and no end is listed, a NUL handle is the list.
//! Without that flag and without ends there is no list, `bInheritHandles` is FALSE and the child
//! inherits nothing.
//!
//! # What the list does not cover
//!
//! - The std route (a command with no `executable()` and no fd >= 3) is `std::process::Command`: it
//!   passes `bInheritHandles` TRUE with no list, so its child inherits every inheritable handle.
//!   That is why `spawn_lock` is held on both routes. A raw child ignores the ends of another cosca spawn because it has a
//!   list; a std-route spawn has none, and would take a raw spawn's ends if it ran in the window
//!   below.
//! - The ends are inheritable between the mark and the close. Another spawner in this process
//!   that passes `bInheritHandles` TRUE with no list (an application's or library's own
//!   `CreateProcessW`) can take them in that window: `spawn_lock` orders cosca's spawns only
//!   ([Raymond Chen, 2026]). His remedy, which cosca does not adopt, keeps the handles
//!   non-inheritable here, duplicates them into a helper process, and creates the child with
//!   that helper as its parent (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`).
//!
//! `windows_raw` here is `crate::child::spawn::windows_raw`; the async backend
//! `crate::tokio::spawn::windows_raw` has the same properties.
//!
//! [`CreateProcessW`]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
//! [Handle Inheritance]: https://learn.microsoft.com/en-us/windows/win32/sysinfo/handle-inheritance
//! [`UpdateProcThreadAttribute`]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
//! [Raymond Chen, 2011]: https://devblogs.microsoft.com/oldnewthing/20111216-00/?p=8873
//! [Raymond Chen, 2026]: https://devblogs.microsoft.com/oldnewthing/20260511-00/?p=112313

#[path = "windows_raw/crt_fds.rs"]
mod crt_fds;

#[path = "windows_raw/env_key.rs"]
mod env_key;

#[path = "windows_raw/env_snapshot.rs"]
pub(crate) mod env_snapshot;

// `pub(crate)`: the async raw backend (`crate::tokio::spawn::windows_raw`) reuses program/env/NUL
// resolution verbatim.
#[path = "windows_raw/resolve.rs"]
pub(crate) mod resolve;

#[path = "windows_raw/proc.rs"]
mod proc;

pub(crate) use proc::RawChild;
// The exit-status reader, which `wait::exit_only` reads a signalled handle's code through too.
pub(crate) use proc::exit_status;
// Additional seams the async raw backend reuses: the cancellable handle wait + its
// outcome. The sync path uses these only inside `proc`, so the re-export is tokio-only. (`create_process` is reached through the shared `spawn_step`, so it
// needs no re-export.)
#[cfg(feature = "tokio")]
pub(crate) use proc::{wait_handle_or_cancel, WaitOutcome};

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use crate::child::proc_handle::ProcHandle;
use crate::child::spawn::{
    attach_or_fault, null_end, reject_batch_path, resolve_identity, resolve_stdio, spawn_lock, ChildEnd, Classify,
    ParentStd, PipeOwnership, SpawnFailure,
};
use crate::child::Child;
use crate::command::{Command, CommandInput, EnvOp, ExecutableSpec};
use crate::error::{win32_io_error, ChildFate, Error};
use crate::stdio::{Fd, ResolvedStdio};

/// Spawn `cmd` via raw `CreateProcessW`. Handles descriptors 0/1/2 plus arbitrary fd >= 3 (wired
/// through the MSVCRT `lpReserved2` table), contained (Job Object / TreeWalk) or uncontained.
///
/// Everything up to `CreateProcessW` fails before the program could start; everything after may
/// come after it started.
pub(crate) fn spawn_raw(
    cmd: &Command,
    fds: BTreeMap<Fd, ResolvedStdio>,
    kill_on_drop: bool,
) -> Result<Child, SpawnFailure> {
    // .bat/.cmd rejected on the raw program token BEFORE resolution, so a bad/nonexistent batch
    // path still errors loudly (CVE-2024-24576) rather than surfacing as a spawn failure.
    reject_batch_program(cmd).not_started()?;

    let spawn_env = spawn_env(cmd).not_started()?;
    let Target { image, cwd } = target(cmd, &spawn_env).not_started()?;
    if let Some(p) = &image {
        resolve::debug_assert_no_nul_wide("program image", p.as_os_str());
    }
    let mut cmdline = raw_program_and_line(cmd).not_started()?; // each token NUL-checked
    cmdline.push(0);
    // AFTER `raw_program_and_line`, deliberately. Both reject the same three no-program states —
    // `CommandInput::Empty`, an empty argv, and a blank `commandline()` with no `executable()` —
    // but that function names WHICH one ("no program specified", "empty argv", "empty or
    // whitespace-only command line..."), whereas this can only report the internal invariant.
    // Ordering this first turned three ordinary caller mistakes into an `internal:` error and
    // made `raw_program_and_line`'s own blank-command-line check unreachable in production.
    //
    // This stays as the backstop that makes a NULL `lpApplicationName` UNREPRESENTABLE if those
    // two ever drift apart — a NULL would make `CreateProcessW` search for the image itself,
    // including the calling process's current directory.
    let app_name: Vec<u16> = app_name_wide(image.as_deref()).not_started()?;

    // Containment: mirror `prepare`'s pre-spawn decision on the raw path. An uncontained spawn keeps
    // the defaults (`contain_flags` 0, a `mode: None`/`is_root: false` `Prepared`); a Strongest root
    // spawns CREATE_SUSPENDED and is job-assigned + resumed in `attach_or_fault`.
    let req = cmd.contain_request();
    // Composed and validated BEFORE `clear_std_handle_inheritance`, which is a process-global
    // `SetHandleInformation` on THIS process's std handles that nothing undoes: a refused spawn
    // must not have mutated the parent.
    let plan = crate::command::flags::windows_spawn(
        &req,
        *cmd.flags_request(),
        spawn_env.is_root,
        crate::command::flags::SpawnBackend::Raw,
    )
    .not_started()?;
    debug_assert_eq!(plan.marker_env, spawn_env.marker_env, "the marker decision drifted");
    if req.mode.is_some() {
        crate::containment::windows::clear_std_handle_inheritance();
    }

    let cwd_w = Some(to_wide_nul(cwd.as_os_str()));

    // Cap the MSVCRT fd-table to the WORD-sized `cbReserved2` field BEFORE allocating anything.
    ensure_fd_table_fits(&fds).not_started()?;

    // Resolve 0/1/2 (always) plus any configured fd >= 3. `resolve_stdio` rejects inherit on fd >= 3.
    let slots: Vec<Fd> = {
        let mut v = vec![Fd::STDIN, Fd::STDOUT, Fd::STDERR];
        v.extend(fds.keys().copied().filter(|f| f.raw() >= 3));
        v
    };
    let parent_std = ParentStd::read();
    let (child_ends, parent_ends) = resolve_stdio(&fds, &slots, PipeOwnership::Owned, parent_std).not_started()?;

    // Classify each resolved child end (0/1/2 + fd >= 3) and encode the dense 0..=maxfd MSVCRT
    // fd-table the child CRT reads back from `lpReserved2`.
    let table = build_fd_table(&child_ends).not_started()?;

    // The table (`bytes`) and the attribute list stay alive until after CreateProcessW.
    let mut startup = startup_info(&child_ends, &table, parent_std).not_started()?;
    // The listed handles: `table.handles` (the non-null ends among 0/1/2 + fd >= 3, each a distinct
    // fresh dup from `resolve_stdio`, its 0/1/2 entries being the hStd* handles) or, when that is
    // empty, the filler. No duplicate reaches the list.
    let all_handles: Vec<HANDLE> = startup.handles(&table).to_vec();
    // The complete word, composed above by the ONE function all three backends share — the two
    // structural bits this backend cannot spawn without included. Nothing ORs into it here.
    let flags = plan.creation_flags;

    // UNDER THE LOCK: mark the listed child ends inheritable, spawn, then CLOSE the child ends and
    // the attribute list BEFORE the guard releases on EVERY path. An early `?` here would drop the
    // inner-scope guard before `child_ends`/`startup` (Rust drops inner locals first), leaving
    // inheritable handles exposed to a concurrent spawn — so compute a Result and drop explicitly.
    let spawned = {
        let _guard = spawn_lock();
        let r = spawn_step(
            &all_handles,
            &app_name,
            &mut cmdline,
            &mut startup.si,
            &spawn_env.block,
            &cwd_w,
            flags,
            *cmd.flags_request(),
        );
        drop(child_ends); // close the child ends inside the lock, on success AND error
        drop(startup); // DeleteProcThreadAttributeList and the filler before the guard releases
        r
    };
    let (proc, pid) = spawned.not_started()?;

    // Identity read + attach BEFORE building `Child`, with the SAME kill+reap teardown as the std
    // path (dropping the OwnedHandle alone neither kills nor reaps on Windows). The `Prepared`
    // carries the REAL mode + is_root computed above, so `attach_or_fault` assigns the Job Object
    // (Strongest root) or the TreeWalk/Delegated mechanism exactly as the std path does.
    let prepared = crate::containment::Prepared {
        mode: req.mode,
        is_root: spawn_env.is_root,
        // From the COMPOSED word, which carries the caller's flags as well as the containment
        // decision: a derivation reading only the containment half would report an in-process
        // route for a child this spawn deliberately put in another console.
        graceful: crate::containment::windows::mechanism_from_flags(flags),
        frozen: cmd.flags_request().suspended,
    };
    let raw_handle = proc.as_raw_handle();
    let id = match resolve_identity(
        pid,
        &crate::wait::exit_only::Target::Handle(std::os::windows::io::AsHandle::as_handle(&proc)),
    )
    .0
    {
        crate::identity::Resolved::Found(id) => id,
        other => {
            // The read failed, so no identity is known.
            let fate = raw_spawn_teardown(proc, pid, None);
            return Err(SpawnFailure::started(
                crate::child::spawn::spawn_identity_error(other),
                fate,
            ));
        }
    };
    let attachment = match attach_or_fault(id, raw_handle, prepared) {
        Ok(v) => v,
        Err(e) => {
            let fate = raw_spawn_teardown(proc, pid, Some(id));
            return Err(SpawnFailure::started(e, fate));
        }
    };

    Ok(Child::from_parts(
        ProcHandle::Raw(RawChild::new(proc, pid)),
        id,
        parent_ends,
        kill_on_drop,
        attachment,
    ))
}

/// Reject a descriptor set whose dense MSVCRT fd-table would exceed the WORD-sized `cbReserved2`
/// field, BEFORE any allocation (`encoded_len` is overflow-safe). `maxfd` is the largest configured
/// slot; 0/1/2 always resolve, so the `2` floor covers an empty/low map. `pub(crate)`: shared with
/// the async raw backend, which caps the same table.
pub(crate) fn ensure_fd_table_fits(fds: &BTreeMap<Fd, ResolvedStdio>) -> Result<(), Error> {
    let maxfd = fds.keys().map(|f| f.raw()).max().unwrap_or(2);
    if !crt_fds::table_fits(crt_fds::encoded_len(maxfd)) {
        return Err(Error::Unsupported {
            op: format!("fd {maxfd}"),
            platform: "windows",
            detail: "descriptor table exceeds the 64KiB cbReserved2 limit".into(),
        });
    }
    Ok(())
}

/// Classify each resolved child end (0/1/2 + fd >= 3) for its CRT device flags, then encode the
/// dense `0..=maxfd` MSVCRT fd-table the child CRT reads back from `lpReserved2`. The returned
/// `handles` are the non-null ends (0/1/2 + fd >= 3, each a distinct fresh dup), so no duplicate
/// reaches the HANDLE_LIST; [`Startup::handles`] says what is listed when there are none.
/// `pub(crate)`: shared with the async raw backend, which builds the identical table. Gate the
/// caller on [`ensure_fd_table_fits`] first.
pub(crate) fn build_fd_table(child_ends: &BTreeMap<Fd, ChildEnd>) -> Result<crt_fds::FdTable, Error> {
    let mut entries: BTreeMap<Fd, (HANDLE, crt_fds::FdKind)> = BTreeMap::new();
    for (&slot, end) in child_ends {
        let h = HANDLE(end.as_raw_handle());
        // A null end is a gap: not open in the child, not inherited. It comes from an inherited
        // null std handle (this process's, e.g. a GUI process's), or from a dup of one: `fd(3,
        // Stdio::merge(Fd::STDOUT))` with a null stdout leaves fd 3 closed in the child, as a null
        // std slot is.
        if h.0.is_null() {
            continue;
        }
        entries.insert(slot, (h, crt_fds::classify(h)?));
    }
    Ok(crt_fds::encode(&entries))
}

/// The environment-derived inputs of a raw spawn, all from ONE read of this process's environment,
/// so resolution, the containment decision and the child's block cannot see different ones.
pub(crate) struct SpawnEnv {
    /// This process's environment as read for this spawn.
    pub(crate) snapshot: env_snapshot::EnvSnapshot,
    /// The child's `PATH`, which resolution searches.
    pub(crate) path: Option<OsString>,
    /// The child's finished block. Built here, so a refused environment (an embedded NUL) is
    /// refused before the spawn mutates anything.
    pub(crate) block: Vec<u16>,
    pub(crate) is_root: bool,
    pub(crate) marker_env: bool,
}

/// Read this process's environment once and derive `cmd`'s [`SpawnEnv`] from it. The containment
/// marker decision is the pure `windows_contain_setup` that `flags::windows_spawn` also makes, taken
/// early so the image is resolved against the final environment, marker included.
pub(crate) fn spawn_env(cmd: &Command) -> Result<SpawnEnv, Error> {
    let snapshot = env_snapshot::EnvSnapshot::read()?;
    let marker_present = snapshot.var(OsStr::new(crate::containment::NESTED_ENV)).is_some();
    let is_root = !crate::containment::dispatch::is_nested(marker_present);
    let marker_env = crate::containment::dispatch::windows_contain_setup(&cmd.contain_request(), is_root).marker_env;
    let ops = child_ops(cmd.env_ops(), marker_env);
    // Verbatim only when nothing reads the environment for a decision: a contained spawn's
    // environment must be the one std would build from the same snapshot, and std cannot pass a
    // block verbatim.
    let child_env = if ops.is_empty() && cmd.contain_request().mode.is_none() {
        resolve::ChildEnv::inherit(&snapshot)
    } else {
        resolve::ChildEnv::capture(&snapshot, &ops)
    };
    Ok(SpawnEnv {
        path: child_env.path().map(OsStr::to_os_string),
        snapshot,
        block: child_env.into_block()?,
        is_root,
        marker_env,
    })
}

/// `ops`, plus the inherited root marker when `marker_env`. Appended AFTER the user's ops so it
/// survives a user `env_clear()` and is named as std names it, as the std path sets it after the
/// user's env.
pub(crate) fn child_ops(ops: &[EnvOp], marker_env: bool) -> Cow<'_, [EnvOp]> {
    if !marker_env {
        return Cow::Borrowed(ops);
    }
    let mut ops = ops.to_vec();
    ops.push(EnvOp::Set(
        OsString::from(crate::containment::NESTED_ENV),
        OsString::from("1"),
    ));
    Cow::Owned(ops)
}

/// Mark each listed handle inheritable, then spawn. Returns a Result WITHOUT `?`-ing so the caller
/// can close the child ends + attribute list before releasing the spawn lock on either arm.
/// `pub(crate)`: the async raw backend reuses the inheritable-mark + `create_process` window.
// `CreateProcessW`'s own parameter list, plus the request its failure is classified against.
// Bundling them would only rename the same values one call site deep.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors CreateProcessW's own parameter list plus the request its failure is classified against"
)]
pub(crate) fn spawn_step(
    handles: &[HANDLE],
    app: &[u16],
    cmdline: &mut [u16],
    si: &mut STARTUPINFOEXW,
    env: &[u16],
    cwd: &Option<Vec<u16>>,
    flags: u32,
    request: crate::command::flags::FlagsRequest,
) -> Result<(OwnedHandle, u32), Error> {
    debug_assert_eq!(
        handles.is_empty(),
        si.lpAttributeList.0.is_null(),
        "a HANDLE_LIST is attached exactly when there are handles to list"
    );
    for &h in handles {
        set_inherit(h)?;
    }
    // Only the syscall's own Result is classified — the inherit loop above stays outside, since
    // an access-denied from `SetHandleInformation` is not a breakaway denial.
    // `Some`, never `None`: `app` is non-optional here precisely so a NULL `lpApplicationName`
    // cannot be expressed at this layer. `proc::create_process` keeps the `Option` because it is
    // the thin, faithful Win32 wrapper; the policy that this backend never passes NULL lives here.
    // See [`app_name_wide`] for why NULL is a security boundary and not a convenience. `env` is
    // non-optional for the same reason: a NULL block would give the child this process's
    // environment as of NOW, not the snapshot its image was resolved against.
    proc::create_process(Some(app), cmdline, si, Some(env), cwd, flags)
        .map_err(|e| crate::command::flags::classify_spawn_syscall_error(e, request))
}

/// The file a raw spawn loads and the directory it runs in, from one effective cwd.
pub(crate) struct Target {
    /// `lpApplicationName`; `None` only when no program was given, which [`app_name_wide`] refuses.
    pub(crate) image: Option<PathBuf>,
    /// `lpCurrentDirectory`, always fully qualified: see [`resolve::effective_cwd`].
    pub(crate) cwd: PathBuf,
}

/// [`target_with`] on this process's cwd.
pub(crate) fn target(cmd: &Command, env: &SpawnEnv) -> Result<Target, Error> {
    target_with(cmd, env, || std::env::current_dir().map_err(Error::Io))
}

/// Which file this backend will load and where the child runs, from at most one read of this
/// process's cwd. The effective cwd ([`resolve::effective_cwd`]: `current_dir` completed, else that
/// read) is the child's `lpCurrentDirectory` and the base a searched program is resolved against.
///
/// `pub(crate)`: shared verbatim with the async raw backend so the two cannot silently diverge.
///
/// The three arms:
///
/// - `Search` — from `executable()`. Resolved through [`resolve::resolve_executable`]: the
///   effective cwd, the child's `PATH`, the `.exe` rules. Always absolute on success.
/// - `Exact` — from `raw_executable()`. Completed, never searched, by
///   [`resolve::absolutise_exact_on`] against this process's cwd, from the same read, as
///   `CreateProcessW` would complete it: no `PATH`, no `.exe`, no existence check.
/// - neither setter — a route here never implies either was called (it can be reached purely by
///   `fd >= 3`, see `routes_to_raw_backend`). [`program_token`] supplies argv[0] or the command
///   line's first token, and THAT is resolved as `Search` is, which is what keeps
///   `lpApplicationName` non-NULL. See [`app_name_wide`] for why NULL is a security boundary.
///
/// No arm is batch-checked here: [`reject_batch_program`] has judged the token by the name Win32
/// normalises it to, and resolution only prefixes a directory and may append `.exe`, so it never
/// turns a name the gate accepted into a `.bat`/`.cmd`.
pub(crate) fn target_with(
    cmd: &Command,
    env: &SpawnEnv,
    process_cwd: impl FnOnce() -> Result<PathBuf, Error>,
) -> Result<Target, Error> {
    // This process's cwd, read at most once and shared by every step below that needs it.
    let mut unread = Some(process_cwd);
    let mut read: Option<PathBuf> = None;
    let mut process_cwd = || -> Result<PathBuf, Error> {
        if let Some(cwd) = &read {
            return Ok(cwd.clone());
        }
        let first = unread
            .take()
            .expect("a failed cwd read ends the spawn, so it is never retried");
        let cwd = first()?;
        read = Some(cwd.clone());
        Ok(cwd)
    };
    // Each drive's own directory, probed at most once and shared likewise.
    let drive_dirs = resolve::DriveDirs::new(&env.snapshot);
    let cwd = resolve::effective_cwd(cmd.cwd(), &drive_dirs, &mut process_cwd)?;
    let path = env.path.as_deref();
    let image = match cmd.executable_spec() {
        Some(ExecutableSpec::Search(p)) => Some(resolve::resolve_executable(p, Some(&cwd), path)?),
        // Against this process's cwd, not `current_dir`: that is what `CreateProcessW` completes a
        // relative `lpApplicationName` against (see `Command::raw_executable`), from the same read.
        Some(ExecutableSpec::Exact(p)) => {
            let drive_cwd = |drive: &OsStr| Ok(drive_dirs.get(drive));
            Some(resolve::absolutise_exact_on(p, &mut process_cwd, drive_cwd)?.path)
        }
        None => program_token(cmd)
            .map(|t| resolve::resolve_executable(&t, Some(&cwd), path))
            .transpose()?,
    };
    Ok(Target { image, cwd })
}

/// The resolved image as the NUL-terminated wide string `CreateProcessW` takes for
/// `lpApplicationName` — erroring rather than yielding NULL.
///
/// A NULL `lpApplicationName` makes `CreateProcessW` perform its OWN image search, and step 2 of
/// that documented search is the CALLING process's current directory — the binary-planting hole
/// (CWE-426/427) this module's resolution exists to close.
///
/// In practice nothing reaches here with no image, because [`raw_program_and_line`] runs FIRST
/// and rejects the same three no-program states with a message naming which one. This is the
/// backstop, not the primary gate — and it is deliberately not ordered first, because doing so
/// reported ordinary caller mistakes as internal faults.
///
/// It earns its place because the primary gate is an argument rather than a check: `program_token`
/// yielding `Some` for every `CommandInput` arm that `raw_program_and_line` rejects is a
/// *pairwise agreement* between two functions, duplicated across the sync and async backends, and
/// the `CommandLine` arm re-derives `first_token_wide` independently rather than reusing
/// `program_token`. A fourth `CommandInput` variant, or a change to `first_token_wide`'s
/// empty-input contract, would break that agreement — and this is what stops the break becoming
/// CWE-426 rather than an error.
///
/// A hard error, not a `debug_assert!`: a release build must fail closed rather than hand
/// `CreateProcessW` a NULL and let it search.
pub(crate) fn app_name_wide(image: Option<&Path>) -> Result<Vec<u16>, Error> {
    let image = image.ok_or_else(|| {
        Error::Io(std::io::Error::other(
            "internal: the raw backend resolved no image; refusing to let CreateProcessW search for one",
        ))
    })?;
    Ok(to_wide_nul(image.as_os_str()))
}

/// Kill + reap a just-spawned child whose post-spawn attach/identity read failed, so a failed spawn
/// never leaks a running/zombie process (mirrors the std path's teardown). `pub(crate)`: the async
/// raw backend shares the identical error-teardown.
pub(crate) fn raw_spawn_teardown(proc: OwnedHandle, pid: u32, id: Option<crate::identity::ProcessId>) -> ChildFate {
    let rc = RawChild::new(proc, pid);
    // Windows only, so the std path-s invariant does NOT carry: there is no zombie to reap
    // and `rc.wait()` is a bare `WaitForSingleObject(handle, INFINITE)`. If the kill failed,
    // nothing asked the child to exit and that wait would park forever - a logged, leaked
    // child is strictly better.
    if let Err(e) = rc.kill() {
        log::warn!("raw spawn teardown: kill of pid {pid} failed: {e}; not waiting");
        return ChildFate::Running { id };
    }
    // A fixture only that kill would end is released here.
    #[cfg(test)]
    crate::child::spawn::fault::run_between_kill_and_wait();
    match rc.wait() {
        Ok(_status) => {
            #[cfg(test)]
            crate::child::spawn::fault::record_teardown_reap(pid, _status);
            ChildFate::Reaped
        }
        Err(e) => {
            log::warn!("raw spawn teardown failed to reap pid {pid}: {e}");
            debug_assert!(false, "raw spawn teardown failed to reap child: {e}");
            ChildFate::Killed
        }
    }
}

/// The `STARTUPINFOEXW` for a raw spawn, with what it points at.
///
/// Keep it, and the `FdTable` it was built from, alive until after `CreateProcessW`; drop it under
/// the spawn lock, with the child ends.
pub(crate) struct Startup {
    pub(crate) si: STARTUPINFOEXW,
    // Declared before `filler`: the list points into it and is deleted first.
    _attr: Option<AttributeList>,
    filler: Option<Filler>,
}

/// An inheritable-for-this-spawn NUL handle that is the whole HANDLE_LIST when no child end is
/// listed. It is in no std slot and no fd-table entry; the child inherits it and never uses it.
struct Filler {
    _nul: ChildEnd,
    list: Box<[HANDLE; 1]>,
}

impl Startup {
    /// The handles to mark inheritable and list: `table.handles`, or the filler when that is empty.
    pub(crate) fn handles<'a>(&'a self, table: &'a crt_fds::FdTable) -> &'a [HANDLE] {
        listed_handles(&self.filler, table)
    }
}

fn listed_handles<'a>(filler: &'a Option<Filler>, table: &'a crt_fds::FdTable) -> &'a [HANDLE] {
    match filler {
        Some(f) => &*f.list,
        None => &table.handles,
    }
}

/// The `STARTUPINFOEXW` for `child_ends` (0/1/2 + fd >= 3) and their encoded `table`: the std
/// handles, `table` as `lpReserved2` (so the child CRT recovers fd >= 3), and the HANDLE_LIST that
/// scopes inheritance to [`Startup::handles`].
///
/// A null end reaches the child as null, but only through `STARTF_USESTDHANDLES`: without the flag
/// the child gets this process's handle in that slot. So the flag is set whenever a child end or
/// this process's handle for any std slot (as read in `parent_std`) is non-null, and only when all six are null does the child
/// get the OS default, as with std. The flag requires `bInheritHandles`, which needs a HANDLE_LIST
/// (never blanket inheritance), and a list cannot be empty: when the flag is set and no child end
/// is listed, a NUL handle opened for this spawn is the list. Without the flag and without ends
/// there is no list.
pub(crate) fn startup_info(
    child_ends: &BTreeMap<Fd, ChildEnd>,
    table: &crt_fds::FdTable,
    parent_std: ParentStd,
) -> Result<Startup, Error> {
    // resolve_stdio with the 0/1/2 slot list always resolves all three (None -> inherit).
    let std_handle = |slot: Fd| HANDLE(child_ends[&slot].as_raw_handle());
    let mut si = STARTUPINFOEXW::default();
    let (stdin, stdout, stderr) = (std_handle(Fd::STDIN), std_handle(Fd::STDOUT), std_handle(Fd::STDERR));
    if [stdin, stdout, stderr].iter().any(|h| !h.0.is_null()) || parent_std.any_live() {
        si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = stdin;
        si.StartupInfo.hStdOutput = stdout;
        si.StartupInfo.hStdError = stderr;
    }
    si.StartupInfo.cbReserved2 = table.bytes.len() as u16; // fits: the caller capped it
    si.StartupInfo.lpReserved2 = table.bytes.as_ptr() as *mut u8;
    let flagged = si.StartupInfo.dwFlags.0 & STARTF_USESTDHANDLES.0 != 0;
    let filler = if flagged && table.handles.is_empty() {
        let nul = null_end()?;
        let list = Box::new([HANDLE(nul.as_raw_handle())]);
        Some(Filler { _nul: nul, list })
    } else {
        None
    };
    let listed = listed_handles(&filler, table);
    let attr = if listed.is_empty() {
        None
    } else {
        let attr = AttributeList::build(listed)?;
        si.lpAttributeList = attr.as_ptr();
        Some(attr)
    };
    Ok(Startup {
        si,
        _attr: attr,
        filler,
    })
}

/// Mark `h` inheritable (`bInheritHandles` + the HANDLE_LIST require it).
fn set_inherit(h: HANDLE) -> Result<(), Error> {
    // SAFETY: `h` is a live child-end handle we own; SetHandleInformation only toggles its flags.
    unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .map_err(|e| Error::Io(win32_io_error(e)))
}

pub(crate) fn to_wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Reject a `.bat`/`.cmd` program by the token that determines the loaded image: `executable()` if
/// set, else the argv[0] / command-line first token. Runs before resolution. `pub(crate)`: shared
/// with the async raw backend.
pub(crate) fn reject_batch_program(cmd: &Command) -> Result<(), Error> {
    let token = cmd.executable_path().map(PathBuf::from).or_else(|| program_token(cmd));
    if let Some(prog) = token {
        // `reject_batch_path` refuses an interior NUL itself, ahead of its own batch rule (see its
        // doc), so this check no longer decides the ORDER — it decides the WORDING. The raw
        // backend names its fields "program token", "argument 0", "environment key"; the shared
        // gate can only say "program path". `tests/raw_windows.rs` pins that vocabulary.
        resolve::ensure_no_nul_wide("program token", prog.as_os_str())?;
        reject_batch_path(&prog)?;
    }
    Ok(())
}

/// The program token (argv[0] / command-line first token) when `executable()` is unset. Can
/// itself return `None` — an empty argv, or a `commandline()` with no usable first token (see
/// [`crate::quote::windows::first_token_wide`]'s doc on empty/whitespace-only input). `pub(crate)`:
/// shared with the async raw backend, and with `spawn_raw` itself, which resolves a `Some` token
/// through [`resolve::resolve_executable`]. `lpApplicationName` ends up NULL only if BOTH
/// `executable()` is unset AND this returns `None` — [`raw_program_and_line`]'s three arms each
/// reject that combination outright before `CreateProcessW` is ever reached, which is what
/// actually keeps `lpApplicationName` from going NULL (a NULL `lpApplicationName` makes
/// `CreateProcessW` perform its OWN search, which includes the current directory — the exact
/// binary-planting hole this module's resolution otherwise closes).
pub(crate) fn program_token(cmd: &Command) -> Option<PathBuf> {
    match cmd.input() {
        CommandInput::Empty => None,
        CommandInput::Argv(argv) => argv.first().map(PathBuf::from),
        CommandInput::CommandLine(line) => {
            let wide: Vec<u16> = line.encode_wide().collect();
            crate::quote::windows::first_token_wide(&wide).map(|t| PathBuf::from(OsString::from_wide(&t)))
        }
    }
}

/// Build the child's command line. argv[0] is always the user's name (independent of the loaded
/// `executable()`); each token is NUL-checked. `commandline()` is passed through verbatim (the OS
/// parses argv[0] as its first token); `argv` is joined via the MSVCRT quoter. `pub(crate)`: shared
/// with the async raw backend.
pub(crate) fn raw_program_and_line(cmd: &Command) -> Result<Vec<u16>, Error> {
    match cmd.input() {
        CommandInput::Empty => {
            // executable() alone, no argv/commandline: the OS uses lpApplicationName as argv[0].
            if cmd.executable_path().is_some() {
                Ok(Vec::new())
            } else {
                Err(Error::Io(std::io::Error::other("no program specified")))
            }
        }
        CommandInput::Argv(argv) => {
            if argv.is_empty() && cmd.executable_path().is_none() {
                return Err(Error::Io(std::io::Error::other("empty argv")));
            }
            let mut wides: Vec<Vec<u16>> = Vec::with_capacity(argv.len());
            // Named by argv index: the command line is one joined string, so an unindexed label
            // would leave the caller to find which of `args([..])` carried the NUL. Index 0 is
            // argv[0] even when `executable()` names the loaded image — that token is checked
            // separately, as the "program token".
            for (i, a) in argv.iter().enumerate() {
                resolve::ensure_no_nul_wide(&format!("argument {i}"), a)?;
                wides.push(a.encode_wide().collect());
            }
            let refs: Vec<&[u16]> = wides.iter().map(Vec::as_slice).collect();
            Ok(crate::quote::windows::join_wide(&refs))
        }
        CommandInput::CommandLine(line) => {
            resolve::ensure_no_nul_wide("command line", line)?;
            // Mirrors the `Empty`/`Argv` arms above: with no `executable()` set, `program_token`
            // (and therefore `lpApplicationName`) depends on THIS line having a usable first
            // token. `first_token_wide` is documented to return `None` for an empty or
            // whitespace-only line, so without this check that case reached `CreateProcessW` with
            // `lpApplicationName == NULL` — which makes it perform its OWN image search,
            // including the current directory, reopening the binary-planting hole resolution
            // otherwise closes.
            if cmd.executable_path().is_none() {
                let wide: Vec<u16> = line.encode_wide().collect();
                if crate::quote::windows::first_token_wide(&wide).is_none() {
                    return Err(Error::Io(std::io::Error::other(
                        "empty or whitespace-only command line with no executable() set",
                    )));
                }
            }

            Ok(line.encode_wide().collect())
        }
    }
}

/// Initialize `buf` as a `PROC_THREAD_ATTRIBUTE_LIST` of one attribute. A `buf` smaller than the
/// sizing call reported fails with the plain Win32 code.
fn initialize_attribute_list(buf: &mut [u8]) -> Result<LPPROC_THREAD_ATTRIBUTE_LIST, Error> {
    let mut size = buf.len();
    let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr().cast());
    // SAFETY: `buf` is `size` bytes; the call fails rather than write past a buffer it finds too small.
    unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut size) }
        .map_err(|e| Error::Io(win32_io_error(e)))?;
    Ok(list)
}

/// Put the HANDLE_LIST attribute for `handles` into the initialized `list`. On failure `list` is
/// deleted and the error has the plain Win32 code.
fn add_handle_list_or_delete(list: LPPROC_THREAD_ATTRIBUTE_LIST, handles: &[HANDLE]) -> Result<(), Error> {
    // SAFETY: `list` is initialized; the HANDLE_LIST attribute takes an array of `handles.len()`
    // HANDLEs by pointer (not copied), which the caller keeps alive until the list is deleted.
    let update = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(handles.as_ptr().cast()),
            std::mem::size_of_val(handles),
            None,
            None,
        )
    };
    if let Err(e) = update {
        // SAFETY: `list` was initialized by the caller; delete it before its buffer drops.
        unsafe { DeleteProcThreadAttributeList(list) };
        return Err(Error::Io(win32_io_error(e)));
    }
    Ok(())
}

/// RAII owner of a `PROC_THREAD_ATTRIBUTE_LIST` carrying a HANDLE_LIST. Deletes the list on drop.
/// The slice passed to [`AttributeList::build`] must outlive the list (per
/// `UpdateProcThreadAttribute`): callers keep it alive across both `CreateProcessW` and this drop. `pub(crate)`: the async raw
/// backend builds the identical scoped inheritance list.
pub(crate) struct AttributeList {
    _buf: Vec<u8>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    pub(crate) fn build(handles: &[HANDLE]) -> Result<AttributeList, Error> {
        let mut size: usize = 0;
        // Sizing call: returns ERROR_INSUFFICIENT_BUFFER and writes the required byte count.
        // SAFETY: the null-list form is the documented way to query the buffer size.
        _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
        let mut buf: Vec<u8> = vec![0u8; size];
        let list = initialize_attribute_list(&mut buf)?;
        add_handle_list_or_delete(list, handles)?;
        Ok(AttributeList { _buf: buf, list })
    }

    pub(crate) fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: `list` was initialized in `build`; Delete is its paired teardown.
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}

#[cfg(test)]
#[path = "windows_raw_tests.rs"]
mod windows_raw_tests;
