//! Windows raw `CreateProcessW` spawn backend.
//!
//! [`spawn_raw`] is the sync entry point: it loads an `executable()` file
//! independently of argv[0] (the case std cannot express on Windows), wiring the
//! child's std handles via `STARTUPINFOEXW` + a scoped `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
//! The process-handle + FFI primitives live in [`proc`]; program/env/NUL
//! resolution in [`resolve`]; the MSVCRT fd-table encoder (for fd >= 3)
//! in [`crt_fds`].

#[path = "windows_raw/crt_fds.rs"]
mod crt_fds;

// `pub(crate)`: the async raw backend (`crate::tokio::spawn::windows_raw`) reuses program/env/NUL
// resolution verbatim.
#[path = "windows_raw/resolve.rs"]
pub(crate) mod resolve;

#[path = "windows_raw/proc.rs"]
mod proc;

pub(crate) use proc::RawChild;
// Additional seams the async raw backend reuses: the cancellable handle wait + its
// outcome, and the exit-status reader. The sync path uses these only inside `proc`, so the
// re-export is tokio-only. (`create_process` is reached through the shared `spawn_step`, so it
// needs no re-export.)
#[cfg(feature = "tokio")]
pub(crate) use proc::{exit_status, wait_handle_or_cancel, WaitOutcome};

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, OpenProcess, UpdateProcThreadAttribute,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_TERMINATE,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use crate::child::proc_handle::ProcHandle;
use crate::child::spawn::{
    attach_or_fault, reject_batch_path, resolve_identity, resolve_stdio, spawn_lock, ChildEnd, PipeOwnership,
};
use crate::child::Child;
use crate::command::{Command, CommandInput, EnvOp};
use crate::error::Error;
use crate::stdio::{Fd, ResolvedStdio};

/// Spawn `cmd` via raw `CreateProcessW`. Handles descriptors 0/1/2 plus arbitrary fd >= 3 (wired
/// through the MSVCRT `lpReserved2` table), contained (Job Object / TreeWalk) or uncontained.
pub(crate) fn spawn_raw(cmd: &Command, fds: BTreeMap<Fd, ResolvedStdio>, kill_on_drop: bool) -> Result<Child, Error> {
    // .bat/.cmd rejected on the raw program token BEFORE resolution, so a bad/nonexistent batch
    // path still errors loudly (CVE-2024-24576) rather than surfacing as a spawn failure.
    reject_batch_program(cmd)?;

    let image: Option<PathBuf> = cmd.executable_path().map(resolve::resolve_executable).transpose()?;
    if let Some(p) = &image {
        resolve::ensure_no_nul_wide(p.as_os_str())?;
    }
    if let Some(c) = cmd.cwd() {
        resolve::ensure_no_nul_wide(c.as_os_str())?;
    }
    let app_name: Option<Vec<u16>> = image.as_ref().map(|p| to_wide_nul(p.as_os_str()));
    let mut cmdline = raw_program_and_line(cmd)?; // each token NUL-checked
    cmdline.push(0);

    // Containment: mirror `prepare`'s pre-spawn decision on the raw path. An uncontained spawn keeps
    // the defaults (`contain_flags` 0, a `mode: None`/`is_root: false` `Prepared`); a Strongest root
    // spawns CREATE_SUSPENDED and is job-assigned + resumed in `attach_or_fault`.
    let req = cmd.contain_request();
    let (contain_flags, is_root, marker_env) = if req.mode.is_some() {
        let marker_present = std::env::var_os(crate::containment::NESTED_ENV).is_some();
        let is_root = !crate::containment::dispatch::is_nested(marker_present);
        crate::containment::windows::clear_std_handle_inheritance();
        let setup = crate::containment::dispatch::windows_contain_setup(&req, is_root);
        (setup.creation_flags, is_root, setup.marker_env)
    } else {
        (0u32, false, false)
    };

    // Append the inherited root marker AFTER the user's env ops so it survives a user `env_clear()`
    // (mirrors the std path setting the marker after the user's env).
    let env_block = if marker_env {
        let mut ops = cmd.env_ops().to_vec();
        ops.push(EnvOp::Set(
            OsString::from(crate::containment::NESTED_ENV),
            OsString::from("1"),
        ));
        resolve::build_env_block(&ops)?
    } else {
        resolve::build_env_block(cmd.env_ops())?
    };
    let cwd_w = cmd.cwd().map(|c| to_wide_nul(c.as_os_str()));

    // Cap the MSVCRT fd-table to the WORD-sized `cbReserved2` field BEFORE allocating anything.
    ensure_fd_table_fits(&fds)?;

    // Resolve 0/1/2 (always) plus any configured fd >= 3. `resolve_stdio` rejects inherit on fd >= 3.
    let slots: Vec<Fd> = {
        let mut v = vec![Fd::STDIN, Fd::STDOUT, Fd::STDERR];
        v.extend(fds.keys().copied().filter(|f| f.raw() >= 3));
        v
    };
    let (child_ends, parent_ends) = resolve_stdio(&fds, &slots, PipeOwnership::Owned)?;

    // Classify each resolved child end (0/1/2 + fd >= 3) and encode the dense 0..=maxfd MSVCRT
    // fd-table the child CRT reads back from `lpReserved2`.
    let table = build_fd_table(&child_ends)?;

    // STARTUPINFOEXW: STARTF_USESTDHANDLES + hStd* for 0/1/2; `lpReserved2` carries the fd-table so
    // the child CRT recovers fd >= 3; the HANDLE_LIST scopes inheritance AND backs
    // EXTENDED_STARTUPINFO_PRESENT. The table (`bytes`) is kept alive until after CreateProcessW.
    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = child_handle(&child_ends, Fd::STDIN);
    si.StartupInfo.hStdOutput = child_handle(&child_ends, Fd::STDOUT);
    si.StartupInfo.hStdError = child_handle(&child_ends, Fd::STDERR);
    si.StartupInfo.cbReserved2 = table.bytes.len() as u16; // fits: capped above
    si.StartupInfo.lpReserved2 = table.bytes.as_ptr() as *mut u8;
    // SINGLE handle source: `table.handles` is 0/1/2 + fd >= 3, each a distinct fresh dup from
    // `resolve_stdio` (its 0/1/2 entries ARE the hStd* handles), so no duplicate reaches the list.
    let all_handles: &[HANDLE] = &table.handles;
    let attr = AttributeList::build(all_handles)?;
    si.lpAttributeList = attr.as_ptr();
    let flags = CREATE_UNICODE_ENVIRONMENT.0 | EXTENDED_STARTUPINFO_PRESENT.0 | contain_flags;

    // UNDER THE LOCK: mark the listed child ends inheritable, spawn, then CLOSE the child ends and
    // the attribute list BEFORE the guard releases on EVERY path. An early `?` here would drop the
    // inner-scope guard before `child_ends`/`attr` (Rust drops inner locals first), leaving
    // inheritable handles exposed to a concurrent spawn — so compute a Result and drop explicitly.
    let spawned = {
        let _guard = spawn_lock();
        let r = spawn_step(
            all_handles,
            app_name.as_deref(),
            &mut cmdline,
            &mut si,
            &env_block,
            &cwd_w,
            flags,
        );
        drop(child_ends); // close the child ends inside the lock, on success AND error
        drop(attr); // DeleteProcThreadAttributeList before the guard releases
        r
    };
    let (proc, pid) = spawned?;

    // Identity read + attach BEFORE building `Child`, with the SAME kill+reap teardown as the std
    // path (dropping the OwnedHandle alone neither kills nor reaps on Windows). The `Prepared`
    // carries the REAL mode + is_root computed above, so `attach_or_fault` assigns the Job Object
    // (Strongest root) or the TreeWalk/Delegated mechanism exactly as the std path does.
    let prepared = crate::containment::Prepared {
        mode: req.mode,
        is_root,
    };
    let raw_handle = proc.as_raw_handle();
    let (containment, attached) = match attach_or_fault(pid, raw_handle, prepared) {
        Ok(v) => v,
        Err(e) => {
            raw_spawn_teardown(proc, pid);
            return Err(e);
        }
    };
    let id = match resolve_identity(pid) {
        Some(id) => id,
        None => {
            raw_spawn_teardown(proc, pid);
            return Err(Error::Io(std::io::Error::other(
                "spawned child vanished before its identity could be read",
            )));
        }
    };

    Ok(Child::from_parts(
        ProcHandle::Raw(RawChild::new(proc, pid)),
        id,
        parent_ends,
        kill_on_drop,
        containment,
        attached,
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
/// `handles` is the SINGLE inheritance source (0/1/2 + fd >= 3, each a distinct fresh dup), so no
/// duplicate reaches the HANDLE_LIST. `pub(crate)`: shared with the async raw backend, which builds
/// the identical table. Gate the caller on [`ensure_fd_table_fits`] first.
pub(crate) fn build_fd_table(child_ends: &BTreeMap<Fd, ChildEnd>) -> Result<crt_fds::FdTable, Error> {
    let mut entries: BTreeMap<Fd, (HANDLE, crt_fds::FdKind)> = BTreeMap::new();
    for (&slot, end) in child_ends {
        let h = HANDLE(end.as_raw_handle());
        entries.insert(slot, (h, crt_fds::classify(h)?));
    }
    Ok(crt_fds::encode(&entries))
}

/// Mark each listed handle inheritable, then spawn. Returns a Result WITHOUT `?`-ing so the caller
/// can close the child ends + attribute list before releasing the spawn lock on either arm.
/// `pub(crate)`: the async raw backend reuses the inheritable-mark + `create_process` window.
pub(crate) fn spawn_step(
    handles: &[HANDLE],
    app: Option<&[u16]>,
    cmdline: &mut [u16],
    si: &mut STARTUPINFOEXW,
    env: &Option<Vec<u16>>,
    cwd: &Option<Vec<u16>>,
    flags: u32,
) -> Result<(OwnedHandle, u32), Error> {
    for &h in handles {
        set_inherit(h)?;
    }
    proc::create_process(app, cmdline, si, env, cwd, flags)
}

/// Kill + reap a just-spawned child whose post-spawn attach/identity read failed, so a failed spawn
/// never leaks a running/zombie process (mirrors the std path's teardown). `pub(crate)`: the async
/// raw backend shares the identical error-teardown.
pub(crate) fn raw_spawn_teardown(proc: OwnedHandle, pid: u32) {
    let rc = RawChild::new(proc, pid);
    let _ = rc.kill();
    if let Err(_e) = rc.wait() {
        debug_assert!(false, "raw spawn teardown failed to reap child: {_e}");
    }
}

/// Does the caller hold `PROCESS_TERMINATE` on `pid`? A STATIC permission answer (a second
/// `OpenProcess`), used to separate a genuine higher-integrity runas denial from the OS
/// teardown-window `ACCESS_DENIED` WITHOUT racing a `try_wait`. Pid-reuse-safe when the caller
/// still holds a handle pinning the process object. Shared by the sync `RawChild` and the async
/// `RawAsyncChild` runas kill paths so both surface the same typed `Unkillable`.
pub(crate) fn can_terminate(pid: u32) -> bool {
    // SAFETY: the caller holds a live owned handle pinning the process object, so `pid` still
    // names THIS process; OpenProcess tolerates failure (returns Err).
    match unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) } {
        Ok(h) => {
            // SAFETY: `h` is an owned handle from a successful OpenProcess; close it once.
            let closed = unsafe { CloseHandle(h) };
            debug_assert!(closed.is_ok(), "CloseHandle of an owned probe handle should not fail");
            true
        }
        Err(_) => false,
    }
}

fn child_handle(ends: &BTreeMap<Fd, ChildEnd>, slot: Fd) -> HANDLE {
    // resolve_stdio with the 0/1/2 slot list always resolves all three (None -> inherit).
    HANDLE(ends[&slot].as_raw_handle())
}

/// Mark `h` inheritable (`bInheritHandles` + the HANDLE_LIST require it).
fn set_inherit(h: HANDLE) -> Result<(), Error> {
    // SAFETY: `h` is a live child-end handle we own; SetHandleInformation only toggles its flags.
    unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }.map_err(|e| Error::Io(e.into()))
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
        reject_batch_path(&prog)?;
    }
    Ok(())
}

/// The program token (argv[0] / command-line first token) when `executable()` is unset.
fn program_token(cmd: &Command) -> Option<PathBuf> {
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
            for a in argv {
                resolve::ensure_no_nul_wide(a)?;
                wides.push(a.encode_wide().collect());
            }
            let refs: Vec<&[u16]> = wides.iter().map(Vec::as_slice).collect();
            Ok(crate::quote::windows::join_wide(&refs))
        }
        CommandInput::CommandLine(line) => {
            resolve::ensure_no_nul_wide(line)?;
            Ok(line.encode_wide().collect())
        }
    }
}

/// RAII owner of a `PROC_THREAD_ATTRIBUTE_LIST` carrying a HANDLE_LIST. Deletes the list on drop.
/// The handle array it references must outlive the list (per `UpdateProcThreadAttribute`): callers
/// keep `all_handles` alive across both `CreateProcessW` and this drop. `pub(crate)`: the async raw
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
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
        let mut buf: Vec<u8> = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr().cast());
        // SAFETY: `buf` is `size` bytes, matching the queried requirement; count = 1 (one attribute).
        unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut size) }
            .map_err(|e| Error::Io(e.into()))?;
        // SAFETY: `list` is initialized; the HANDLE_LIST attribute takes an array of `handles.len()`
        // HANDLEs by pointer (not copied), which the caller keeps alive until this list is deleted.
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
            // SAFETY: `list` was initialized above; delete it before `buf` drops.
            unsafe { DeleteProcThreadAttributeList(list) };
            return Err(Error::Io(e.into()));
        }
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
