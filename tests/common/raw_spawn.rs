//! The ONE raw `CreateProcessW` spawn a test uses: for a test that needs a flag word `std` cannot
//! express, a console of its own, `lpApplicationName`, or a suspended start.
//!
//! It takes `cosca::test_spawn_lock()` around the spawn only, like the wrappers in `locked.rs`, and
//! the same rules apply: the lock is not reentrant, so never call it while holding the lock or from
//! inside a `cosca::Command` spawn.
//!
//! This file is also compiled into the library's Windows tests (`src/test_spawn`), so it may use
//! only `console_flags` and `windows_env` beside itself.
#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::PROCESS_INFORMATION;

use super::console_flags;

/// A process made by [`spawn_locked_raw`]: what a test needs of a `std::process::Child`, plus the
/// initial thread's handle. Dropping it kills the process, so a panicking test leaves no child.
pub struct RawChild {
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
    tid: u32,
}

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
    #[allow(dead_code, reason = "tests/ use it; the library's tests do not")]
    pub fn into_process_information(self) -> PROCESS_INFORMATION {
        use std::os::windows::io::IntoRawHandle as _;
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped, so each field is moved out exactly once.
        let (process, thread) = unsafe { (std::ptr::read(&this.process), std::ptr::read(&this.thread)) };
        PROCESS_INFORMATION {
            hProcess: HANDLE(process.into_raw_handle()),
            hThread: HANDLE(thread.into_raw_handle()),
            dwProcessId: this.pid,
            dwThreadId: this.tid,
        }
    }

    /// The process handle, which this `RawChild` keeps owning.
    pub fn process(&self) -> BorrowedHandle<'_> {
        use std::os::windows::io::AsHandle as _;
        self.process.as_handle()
    }

    /// The initial thread's handle, which this `RawChild` keeps owning.
    pub fn thread(&self) -> BorrowedHandle<'_> {
        use std::os::windows::io::AsHandle as _;
        self.thread.as_handle()
    }

    /// `TerminateProcess` with exit code 1. Fails on a process that already exited.
    pub fn kill(&self) -> std::io::Result<()> {
        use windows::Win32::System::Threading::TerminateProcess;
        // SAFETY: `self.process` is a live handle this `RawChild` owns.
        unsafe { TerminateProcess(HANDLE(self.process.as_raw_handle()), 1) }.map_err(win32_error)
    }

    /// Blocks until the process exits, then returns its exit code.
    #[allow(dead_code, reason = "tests/ use it; the library's tests do not")]
    pub fn wait(&self) -> std::io::Result<u32> {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
        let handle = HANDLE(self.process.as_raw_handle());
        // SAFETY: `handle` is a live process handle this `RawChild` owns.
        if unsafe { WaitForSingleObject(handle, INFINITE) } != WAIT_OBJECT_0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut code = 0u32;
        // SAFETY: as above; `code` is a valid out-pointer.
        unsafe { GetExitCodeProcess(handle, &mut code) }.map_err(win32_error)?;
        Ok(code)
    }
}

impl Drop for RawChild {
    fn drop(&mut self) {
        // `TerminateProcess` on an already-exited process fails harmlessly; the handles close after.
        _ = self.kill();
    }
}

/// `e` as the `io::Error` std reports for the same failure: an `HRESULT_FROM_WIN32` value as the
/// Win32 code it wraps, any other HRESULT as itself. The `windows` crate's own conversion keeps the
/// whole HRESULT, so `raw_os_error` would not be the Win32 code.
fn win32_error(e: windows::core::Error) -> std::io::Error {
    let code = e.code().0 as u32;
    if code & 0xFFFF_0000 == 0x8007_0000 {
        std::io::Error::from_raw_os_error((code & 0xFFFF) as i32)
    } else {
        std::io::Error::from_raw_os_error(code as i32)
    }
}

/// Where a [`spawn_locked_raw_with`] child's standard handles come from.
#[derive(Clone, Copy, Default)]
pub enum RawStdio<'a> {
    /// Ours, as `std`'s spawn gives them.
    #[default]
    Inherit,
    /// None: the child gets null handles and inherits nothing else either.
    Null,
    /// Stdout and stderr both go to this handle (one inheritable duplicate of it), stdin is null.
    #[allow(dead_code, reason = "tests/ construct it; the library's tests do not")]
    Output(BorrowedHandle<'a>),
}

/// What [`spawn_locked_raw_with`] adds to [`spawn_locked_raw`]'s defaults.
#[derive(Clone, Copy, Default)]
pub struct RawOptions<'a> {
    /// Pass `exe` as `lpApplicationName`: the exact image, no search, no extension added. Otherwise
    /// the command line's first token (`exe`) names the image, with `CreateProcessW`'s own search.
    pub exact_image: bool,
    /// Pass no command line (`lpCommandLine` NULL), so `args` must be empty. Needs `exact_image`:
    /// `CreateProcessW` has no image to run without one of the two.
    #[allow(dead_code, reason = "tests/ set it; the library's tests do not")]
    pub no_command_line: bool,
    /// Always quote the command line's first token (`exe`), where `join_wide` quotes only a name
    /// with a blank. For a probe whose recorded input is a quoted argv[0].
    pub quote_exe: bool,
    pub stdio: RawStdio<'a>,
}

/// [`spawn_locked_raw_with`] with [`RawOptions::default()`].
#[allow(dead_code, reason = "tests/ use it; the library's tests use `spawn_locked_raw_with`")]
pub fn spawn_locked_raw(
    exe: impl AsRef<OsStr>,
    args: &[impl AsRef<OsStr>],
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
pub fn spawn_locked_raw_with(
    exe: impl AsRef<OsStr>,
    args: &[impl AsRef<OsStr>],
    env: &[(&str, &str)],
    flags: u32,
    console: console_flags::Console,
    options: RawOptions<'_>,
) -> std::io::Result<RawChild> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, GetCurrentProcess, CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, STARTF_USESHOWWINDOW,
        STARTF_USESTDHANDLES, STARTUPINFOW,
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
        }
        .map_err(win32_error)?;
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

    debug_assert!(
        !options.no_command_line || (options.exact_image && args.is_empty() && !options.quote_exe),
        "no command line needs `exact_image`, no `args` and no `quote_exe`"
    );
    let exe = exe.as_ref();
    let mut cmdline = (!options.no_command_line).then(|| {
        let wide_exe: Vec<u16> = exe.encode_wide().collect();
        let wide_args: Vec<Vec<u16>> = args.iter().map(|a| a.as_ref().encode_wide().collect()).collect();
        let refs: Vec<&[u16]> = wide_args.iter().map(Vec::as_slice).collect();
        let mut cmdline = if options.quote_exe {
            // An image path has no `"` and, quoted, no trailing-backslash run to double.
            let mut cmdline: Vec<u16> = [b'"' as u16].into_iter().chain(wide_exe).chain([b'"' as u16]).collect();
            if !refs.is_empty() {
                cmdline.push(b' ' as u16);
                cmdline.extend(cosca::quote::windows::join_wide(&refs));
            }
            cmdline
        } else {
            let mut all = vec![wide_exe.as_slice()];
            all.extend(&refs);
            cosca::quote::windows::join_wide(&all)
        };
        cmdline.push(0); // `CreateProcessW` requires a NUL-terminated, writable buffer.
        cmdline
    });
    let image: Option<Vec<u16>> = options
        .exact_image
        .then(|| exe.encode_wide().chain(std::iter::once(0)).collect());

    let block =
        super::windows_env::env_block(std::env::vars_os().chain(env.iter().map(|&(k, v)| (k.into(), v.into()))));
    let mut pi = PROCESS_INFORMATION::default();
    // The inheritable duplicates exist only under the lock, so no other spawn in this process
    // inherits them; `_duplicates` drops (closes them) before the guard does.
    let _guard = cosca::test_spawn_lock();
    let null = HANDLE::default();
    let (_duplicates, [stdin, stdout, stderr]): (Vec<OwnedHandle>, [HANDLE; 3]) = match options.stdio {
        RawStdio::Inherit => {
            let dups = [
                inheritable_std_handle(STD_INPUT_HANDLE)?,
                inheritable_std_handle(STD_OUTPUT_HANDLE)?,
                inheritable_std_handle(STD_ERROR_HANDLE)?,
            ];
            let handles = dups
                .each_ref()
                .map(|dup| dup.as_ref().map_or(null, |dup| HANDLE(dup.as_raw_handle())));
            (dups.into_iter().flatten().collect(), handles)
        }
        RawStdio::Null => (Vec::new(), [null; 3]),
        RawStdio::Output(out) => {
            let dup = inheritable(HANDLE(out.as_raw_handle()))?;
            let handle = HANDLE(dup.as_raw_handle());
            (vec![dup], [null, handle, handle])
        }
    };
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: if flags & CREATE_NEW_CONSOLE.0 != 0 {
            STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES
        } else {
            STARTF_USESTDHANDLES
        },
        wShowWindow: SW_HIDE.0 as u16,
        hStdInput: stdin,
        hStdOutput: stdout,
        hStdError: stderr,
        ..Default::default()
    };
    // SAFETY: `cmdline`, when present, is a NUL-terminated, writable UTF-16 buffer; `block` is a
    // sorted, double-NUL-terminated UTF-16 block (`CREATE_UNICODE_ENVIRONMENT`); `si` and `pi` are
    // valid, correctly-sized in/out parameters; each std handle is a live inheritable duplicate or
    // NULL (the process has none); `image` is a NUL-terminated UTF-16 buffer that outlives the call.
    unsafe {
        CreateProcessW(
            image.as_ref().map_or(PCWSTR::null(), |image| PCWSTR(image.as_ptr())),
            cmdline.as_mut().map(|cmdline| PWSTR(cmdline.as_mut_ptr())),
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
    .map_err(win32_error)?;
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
