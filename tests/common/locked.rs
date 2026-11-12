//! The ONLY place `tests/` forks a RAW `std::process::Command` (or tokio's) — one not going
//! through `cosca::Command`, which takes the same lock internally.
//!
//! Cargo runs `#[test]` fns in one binary concurrently, alongside cosca spawns and (on macOS)
//! `FdMarker` sweeps. A raw fork without the lock can inherit another spawn's transient
//! descriptors, or a live marker before it `exec`s, and a concurrent sweep can then SIGKILL it.
//! Every wrapper takes `cosca::test_spawn_lock()` around the fork only; the wait runs unlocked.
//!
//! The lock is not reentrant: never call these while holding `cosca::test_spawn_lock()` or from
//! inside a `cosca::Command` spawn; re-entry panics under `debug_assertions`. A test that must
//! hold the guard for its whole body cannot use them and calls the raw method under its own guard
//! with an `#[allow]` that says so.
//!
//! On Windows [`spawn_locked`] makes its child `CREATE_NO_WINDOW`, so a test run from a process with
//! no console opens no window. A test that needs its own flags spawns through [`spawn_locked_with`],
//! which replaces whatever `creation_flags` the command already had and adds `CREATE_NO_WINDOW`
//! unless the console is `Asked`. A test that needs a console of its own, or a flag word `std` cannot
//! express, uses [`spawn_locked_raw`], which hides the window of a console it creates.
//!
//! This file is also compiled into the library's tests (`src/test_spawn_tests` on Unix,
//! `src/test_spawn` on Windows, for [`spawn_locked_raw`]), which run the spawn-window scenario
//! against these exact wrappers. It names no other part of `tests/common`.

use std::process::{Child, Command, ExitStatus, Output, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

#[cfg(windows)]
use super::console_flags;

/// [`Command::spawn`] under `cosca::test_spawn_lock()`.
pub fn spawn_locked(cmd: &mut Command) -> std::io::Result<Child> {
    #[cfg(windows)]
    cmd.creation_flags(console_flags::word(0, console_flags::Console::Hidden));
    spawn_held(cmd)
}

/// [`spawn_locked`] with `flags` as the creation word, plus `CREATE_NO_WINDOW` unless `console` is
/// [`Asked`](console_flags::Console::Asked).
#[cfg(windows)]
pub fn spawn_locked_with(cmd: &mut Command, flags: u32, console: console_flags::Console) -> std::io::Result<Child> {
    cmd.creation_flags(console_flags::word(flags, console));
    spawn_held(cmd)
}

/// A process made by [`spawn_locked_raw`]: what a test needs of a `std::process::Child`, plus the
/// initial thread's handle. Dropping it kills the process, so a panicking test leaves no child.
#[cfg(windows)]
pub struct RawChild {
    process: std::os::windows::io::OwnedHandle,
    thread: std::os::windows::io::OwnedHandle,
    pid: u32,
    tid: u32,
}

#[cfg(windows)]
impl RawChild {
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// The initial thread's id.
    pub fn thread_id(&self) -> u32 {
        self.tid
    }

    /// Hands both handles over as the `PROCESS_INFORMATION` `CreateProcessW` would have filled in,
    /// for a harness that takes it and closes them itself. Nothing kills the process on the way.
    pub fn into_process_information(self) -> windows::Win32::System::Threading::PROCESS_INFORMATION {
        use std::os::windows::io::IntoRawHandle as _;
        use windows::Win32::Foundation::HANDLE;
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped, so each field is moved out exactly once.
        let (process, thread) = unsafe { (std::ptr::read(&this.process), std::ptr::read(&this.thread)) };
        windows::Win32::System::Threading::PROCESS_INFORMATION {
            hProcess: HANDLE(process.into_raw_handle()),
            hThread: HANDLE(thread.into_raw_handle()),
            dwProcessId: this.pid,
            dwThreadId: this.tid,
        }
    }

    /// The process handle, which this `RawChild` keeps owning.
    pub fn process(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        use std::os::windows::io::AsHandle as _;
        self.process.as_handle()
    }

    /// The initial thread's handle, which this `RawChild` keeps owning.
    pub fn thread(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        use std::os::windows::io::AsHandle as _;
        self.thread.as_handle()
    }

    /// `TerminateProcess` with exit code 1. Fails on a process that already exited.
    pub fn kill(&self) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Threading::TerminateProcess;
        // SAFETY: `self.process` is a live handle this `RawChild` owns.
        unsafe { TerminateProcess(HANDLE(self.process.as_raw_handle()), 1) }.map_err(Into::into)
    }

    /// Blocks until the process exits, then returns its exit code.
    pub fn wait(&self) -> std::io::Result<u32> {
        use std::os::windows::io::AsRawHandle as _;
        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
        let handle = HANDLE(self.process.as_raw_handle());
        // SAFETY: `handle` is a live process handle this `RawChild` owns.
        if unsafe { WaitForSingleObject(handle, INFINITE) } != WAIT_OBJECT_0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut code = 0u32;
        // SAFETY: as above; `code` is a valid out-pointer.
        unsafe { GetExitCodeProcess(handle, &mut code) }?;
        Ok(code)
    }
}

#[cfg(windows)]
impl Drop for RawChild {
    fn drop(&mut self) {
        // `TerminateProcess` on an already-exited process fails harmlessly; the handles close after.
        _ = self.kill();
    }
}

/// Where a [`spawn_locked_raw_with`] child's standard handles come from.
#[cfg(windows)]
#[derive(Clone, Copy, Default)]
pub enum RawStdio<'a> {
    /// Ours, as `std`'s spawn gives them.
    #[default]
    Inherit,
    /// None: the child gets null handles and inherits nothing else either.
    Null,
    /// Stdout and stderr both go to this handle, stdin is null.
    Output(std::os::windows::io::BorrowedHandle<'a>),
}

/// What [`spawn_locked_raw_with`] adds to [`spawn_locked_raw`]'s defaults.
#[cfg(windows)]
#[derive(Clone, Copy, Default)]
pub struct RawOptions<'a> {
    /// The exact image to run (`lpApplicationName`: no search, no extension added). `None` lets the
    /// command line's first token say, with `CreateProcessW`'s own search.
    pub image: Option<&'a str>,
    pub stdio: RawStdio<'a>,
}

/// [`spawn_locked_raw_with`] with [`RawOptions::default()`]: the command line names the image and
/// the child gets our standard handles.
#[cfg(windows)]
pub fn spawn_locked_raw(
    exe: &str,
    args: &[&str],
    env: &[(&str, &str)],
    flags: u32,
    console: console_flags::Console,
) -> std::io::Result<RawChild> {
    spawn_locked_raw_with(exe, args, env, flags, console, RawOptions::default())
}

/// Spawn `exe` with `args` (argv[1..]) through `CreateProcessW` under `cosca::test_spawn_lock()`,
/// with our environment plus `env`, the standard handles `options.stdio` names, and `flags` combined
/// with `console` as the creation word. When the flags create a console (`CREATE_NEW_CONSOLE`) it
/// sets `SW_HIDE` in `STARTUPINFO` (which `std` cannot), so that console opens no window;
/// `CREATE_NO_WINDOW` cannot do that beside it. Otherwise it leaves the show state alone, since a GUI
/// child's first `ShowWindow` would take `SW_HIDE` as its default.
///
/// A failed `CreateProcessW` is the `io::Error` whose `raw_os_error` is the Win32 code.
#[cfg(windows)]
pub fn spawn_locked_raw_with(
    exe: &str,
    args: &[&str],
    env: &[(&str, &str)],
    flags: u32,
    console: console_flags::Console,
    options: RawOptions<'_>,
) -> std::io::Result<RawChild> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, GetCurrentProcess, CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    /// An inheritable duplicate of `handle`, a live handle of ours.
    fn inheritable(handle: HANDLE) -> std::io::Result<OwnedHandle> {
        let mut dup = HANDLE::default();
        // SAFETY: `handle` is live; `dup` is a valid out-pointer.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut dup,
                0,
                true,
                DUPLICATE_SAME_ACCESS,
            )
        }?;
        // SAFETY: `DuplicateHandle` returned a fresh handle that nothing else owns.
        Ok(unsafe { OwnedHandle::from_raw_handle(dup.0) })
    }

    /// An inheritable duplicate of one of our standard handles, as `std` makes for `Stdio::inherit`;
    /// `None` when we have none.
    fn inheritable_std_handle(which: STD_HANDLE) -> std::io::Result<Option<OwnedHandle>> {
        // SAFETY: reads process state only.
        let Ok(handle) = (unsafe { GetStdHandle(which) }) else {
            return Ok(None);
        };
        if handle.is_invalid() {
            return Ok(None);
        }
        inheritable(handle).map(Some)
    }

    let wide_args: Vec<Vec<u16>> = std::iter::once(exe)
        .chain(args.iter().copied())
        .map(|a| a.encode_utf16().collect())
        .collect();
    let refs: Vec<&[u16]> = wide_args.iter().map(Vec::as_slice).collect();
    let mut cmdline = cosca::quote::windows::join_wide(&refs);
    cmdline.push(0); // `CreateProcessW` requires a NUL-terminated, writable buffer.

    let block =
        super::windows_env::env_block(std::env::vars_os().chain(env.iter().map(|&(k, v)| (k.into(), v.into()))));
    let mut pi = PROCESS_INFORMATION::default();
    // The inheritable duplicates exist only under the lock, so no other spawn in this process
    // inherits them; they drop (close) before the guard does.
    let _guard = cosca::test_spawn_lock();
    let (stdin, stdout, stderr) = match options.stdio {
        RawStdio::Inherit => (
            inheritable_std_handle(STD_INPUT_HANDLE)?,
            inheritable_std_handle(STD_OUTPUT_HANDLE)?,
            inheritable_std_handle(STD_ERROR_HANDLE)?,
        ),
        RawStdio::Null => (None, None, None),
        RawStdio::Output(out) => (
            None,
            Some(inheritable(HANDLE(out.as_raw_handle()))?),
            Some(inheritable(HANDLE(out.as_raw_handle()))?),
        ),
    };
    let image: Option<Vec<u16>> = options
        .image
        .map(|image| image.encode_utf16().chain(std::iter::once(0)).collect());
    let raw = |h: &Option<OwnedHandle>| h.as_ref().map_or(HANDLE::default(), |h| HANDLE(h.as_raw_handle()));
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: if flags & CREATE_NEW_CONSOLE.0 != 0 {
            STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES
        } else {
            STARTF_USESTDHANDLES
        },
        wShowWindow: SW_HIDE.0 as u16,
        hStdInput: raw(&stdin),
        hStdOutput: raw(&stdout),
        hStdError: raw(&stderr),
        ..Default::default()
    };
    // SAFETY: `cmdline` is a NUL-terminated, writable UTF-16 buffer; `block` is a sorted,
    // double-NUL-terminated UTF-16 block (`CREATE_UNICODE_ENVIRONMENT`); `si` and `pi` are valid,
    // correctly-sized in/out parameters; each std handle is a live inheritable duplicate or NULL (the process has none);
    // `image` is a NUL-terminated UTF-16 buffer that outlives the call.
    unsafe {
        CreateProcessW(
            image.as_ref().map_or(PCWSTR::null(), |image| PCWSTR(image.as_ptr())),
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            !matches!(options.stdio, RawStdio::Null),
            windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(
                console_flags::word(flags, console) | CREATE_UNICODE_ENVIRONMENT.0,
            ),
            Some(block.as_ptr().cast()),
            None,
            &si,
            &mut pi,
        )
    }
    // `windows` reports an HRESULT; the `io::Error` carries the Win32 code it wraps.
    .map_err(|e| std::io::Error::from_raw_os_error(e.code().0 & 0xFFFF))?;
    // SAFETY: `CreateProcessW` returned two fresh handles that nothing else owns.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(pi.hProcess.0),
            OwnedHandle::from_raw_handle(pi.hThread.0),
        )
    };
    Ok(RawChild {
        process,
        thread,
        pid: pi.dwProcessId,
        tid: pi.dwThreadId,
    })
}

fn spawn_held(cmd: &mut Command) -> std::io::Result<Child> {
    let _guard = cosca::test_spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "`_guard` is spawn_lock")]
    cmd.spawn()
}

/// [`Command::output`] with the lock held for the spawn only. Like `output`, it overrides stdin
/// (null) and stdout/stderr (piped), discarding any caller setting.
pub fn output_locked(cmd: &mut Command) -> std::io::Result<Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    spawn_locked(cmd)?.wait_with_output()
}

/// [`Command::status`] with the lock held for the spawn only.
pub fn status_locked(cmd: &mut Command) -> std::io::Result<ExitStatus> {
    spawn_locked(cmd)?.wait()
}

/// `tokio::process::Command::spawn` under `cosca::test_spawn_lock()`.
#[cfg(feature = "tokio")]
pub fn spawn_locked_tokio(cmd: &mut ::tokio::process::Command) -> std::io::Result<::tokio::process::Child> {
    #[cfg(windows)]
    cmd.creation_flags(console_flags::word(0, console_flags::Console::Hidden));
    let _guard = cosca::test_spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "`_guard` is spawn_lock")]
    cmd.spawn()
}

/// The tokio twin of [`output_locked`], with the same stdio override.
#[cfg(feature = "tokio")]
pub async fn output_locked_tokio(cmd: &mut ::tokio::process::Command) -> std::io::Result<Output> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    spawn_locked_tokio(cmd)?.wait_with_output().await
}

/// The tokio twin of [`status_locked`].
#[cfg(feature = "tokio")]
pub async fn status_locked_tokio(cmd: &mut ::tokio::process::Command) -> std::io::Result<ExitStatus> {
    spawn_locked_tokio(cmd)?.wait().await
}
