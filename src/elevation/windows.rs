//! Windows elevation effect layer (`cfg(windows)`): token-based detection and the
//! `ShellExecuteEx("runas")` reduced-child spawn.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation, TokenIntegrityLevel,
    TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::plan::{BackendSet, Host, Os};

struct OwnedToken(HANDLE);
impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: a token handle owned by this guard, closed exactly once.
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

fn open_process_token() -> Option<OwnedToken> {
    // SAFETY: standard token query; the handle is wrapped in a guard.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        Some(OwnedToken(token))
    }
}

pub(super) fn is_elevated() -> bool {
    let Some(token) = open_process_token() else {
        log::warn!("could not open the process token to query elevation; assuming not elevated");
        return false;
    };
    // SAFETY: fixed-size TOKEN_ELEVATION query on a live token.
    unsafe {
        let mut e = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut e as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok();
        if !ok {
            log::warn!("TokenElevation query failed; assuming not elevated");
            return false;
        }
        e.TokenIsElevated != 0
    }
}

/// The current token's integrity RID (e.g. Medium/High), or `None` if unreadable.
pub(super) fn integrity_level() -> Option<u32> {
    let token = open_process_token()?;
    // SAFETY: two-call GetTokenInformation into an 8-byte-aligned buffer;
    // TOKEN_MANDATORY_LABEL's Sid pointer field requires 8-byte alignment, so a
    // Vec<u64> backing avoids the align-1 UB a Vec<u8> would cause. The Sid pointer
    // is read via addr_of! + read_unaligned — never a misaligned reference.
    unsafe {
        let mut ret = 0u32;
        let _ = GetTokenInformation(token.0, TokenIntegrityLevel, None, 0, &mut ret);
        if ret == 0 {
            log::debug!("could not size the integrity-level token info; integrity unknown");
            return None;
        }
        let words = (ret as usize).div_ceil(8);
        let mut buf = vec![0u64; words];
        let cap = (words * 8) as u32;
        if let Err(e) = GetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            cap,
            &mut ret,
        ) {
            log::debug!("TokenIntegrityLevel query failed: {e:?}; integrity unknown");
            return None;
        }
        let label_ptr = buf.as_ptr() as *const TOKEN_MANDATORY_LABEL;
        let sid = std::ptr::read_unaligned(std::ptr::addr_of!((*label_ptr).Label.Sid));
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() || *count_ptr == 0 {
            log::debug!("integrity SID has no sub-authorities; integrity unknown");
            return None;
        }
        let last = (*count_ptr as u32) - 1;
        Some(*GetSidSubAuthority(sid, last))
    }
}

pub(super) fn detect() -> Host {
    if let Some(rid) = integrity_level() {
        log::debug!("current process integrity RID = 0x{rid:04x}");
    }
    Host {
        elevated: is_elevated(),
        has_tty: false, // Windows never prompts on a TTY — UAC is a GUI gate.
        available: BackendSet::default(),
        os: Os::Windows,
        arg_max: None,
    }
}

use crate::command::Command;
use crate::error::Error;
use crate::stdio::ResolvedStdio;

/// Enforce the honest capability matrix for Windows elevation. ShellExecuteEx(runas)
/// passes NO handles and no environment, and a Job Object cannot span the integrity
/// boundary — so every non-inherit slot, every fd >= 3, any explicit env, and
/// `.contain()` is a loud `Unsupported`, never a silent lie.
pub(crate) fn reject_unsupported_config(cmd: &Command) -> Result<(), Error> {
    let unsupported = |op: &str, detail: &str| {
        Err(Error::Unsupported {
            op: op.into(),
            platform: "windows",
            detail: detail.into(),
        })
    };
    for (&slot, resolved) in cmd.fds() {
        if slot.raw() >= 3 {
            return unsupported(
                "fd >= 3 on an elevated Windows child",
                "runas exposes no descriptor-passing mechanism; fd >= 3 needs the (deferred) broker",
            );
        }
        if !matches!(resolved, ResolvedStdio::Inherit) {
            return unsupported(
                "captured/redirected stdio on an elevated Windows child",
                "runas exposes no stdio-handle mechanism; capture/redirect needs the (deferred) broker. \
                 Use inherit(), or elevate on POSIX.",
            );
        }
    }
    if !cmd.env_ops().is_empty() {
        return unsupported(
            "env forwarding to an elevated Windows child",
            "runas provides no environment mechanism; forwarding needs the (deferred) broker",
        );
    }
    if cmd.contain_request().mode.is_some() {
        return unsupported(
            ".contain() + elevate on Windows",
            "a Job Object cannot span the integrity boundary of a runas child (deferred)",
        );
    }
    // `ShellExecuteEx` accepts no creation flags at all, so every flag intent except window
    // suppression has no mechanism here and is refused rather than silently dropped. Stated over
    // the RECORDED state, not "a method was called": `creation_flags(0)` requests nothing.
    let flags = cmd.flags_request();
    if flags.detached {
        return unsupported(
            "detached() + elevate on Windows",
            "the runas launch takes a show-command and no creation flags, so DETACHED_PROCESS              cannot be expressed. Elevate without it, or spawn unelevated.",
        );
    }
    if flags.breakaway_from_job {
        return unsupported(
            "breakaway_from_job() + elevate on Windows",
            "the runas launch takes a show-command and no creation flags, so              CREATE_BREAKAWAY_FROM_JOB cannot be expressed — and the runas child is created by a              system service, not by this process's job.",
        );
    }
    if flags.raw != 0 {
        return unsupported(
            "creation_flags() + elevate on Windows",
            "the runas launch takes a show-command and no creation flags, so an arbitrary              dwCreationFlags word cannot be expressed. no_window() is the one flag intent that              survives here, lowered to the launch's show-command.",
        );
    }
    Ok(())
}

/// The show-command the consent launch uses, from the caller's flag request.
///
/// Pure, so the selection is unit-testable without a UAC prompt.
///
/// **Reached only when a consent prompt is actually used.** `runas` returns
/// `Transition::RunAsIs => RunasOutcome::AlreadyElevated` before it builds the
/// `SHELLEXECUTEINFOW`, and `spawn_elevated`'s `AlreadyElevated` arm falls through to
/// `spawn_unelevated` — so an already-elevated caller's `.elevate().no_window()` is carried by
/// `CREATE_NO_WINDOW` on the ordinary backends and never touches this function.
///
/// The two lowerings differ observably for a graphical child: the show-command is the shell's
/// initial show state for the whole launched application, where the creation flag concerns the
/// child's console only.
#[cfg(windows)]
pub(crate) fn runas_show_command(
    flags: &crate::command::flags::FlagsRequest,
) -> windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD {
    use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};
    if flags.no_window {
        SW_HIDE
    } else {
        SW_SHOWNORMAL
    }
}

// ===== ShellExecuteEx("runas") launch =====

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows::Win32::System::Threading::{GetProcessId, TerminateProcess};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::child::proc_handle::ProcHandle;
use crate::child::spawn::windows_raw::RawChild;
use crate::command::CommandInput;
use crate::containment::Attachment;
use crate::elevation::plan::Transition;
use crate::elevation::{ElevatedStdio, ElevatedVia, ElevationReport, Privilege};
use crate::error::ElevationErrorKind;
use crate::identity::ProcessId;

/// `ERROR_CANCELLED` (1223) as an HRESULT (0x800704C7) — the UAC-declined code.
const ERROR_CANCELLED_HRESULT: windows::core::HRESULT = windows::core::HRESULT(0x800704C7_u32 as i32);

fn wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// The outcome of a runas launch. `Launched` carries the owned handle, pid, stable
/// identity, and the report — the async path builds its own `Child` from these.
pub(crate) enum RunasOutcome {
    AlreadyElevated,
    Launched {
        proc: OwnedHandle,
        pid: u32,
        id: ProcessId,
        report: ElevationReport,
    },
}

/// Balances a `CoInitializeEx` with `CoUninitialize` only when WE incremented the refcount.
struct ComInit {
    uninit: bool,
}
impl ComInit {
    fn init() -> Result<ComInit, Error> {
        // SAFETY: COM apartment init on the calling thread; balanced in Drop.
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        if hr == S_OK || hr == S_FALSE {
            // S_FALSE = already initialized on this thread WITH the refcount incremented,
            // so it still requires a matching CoUninitialize.
            Ok(ComInit { uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            // Already initialized in a different apartment model; we did NOT increment.
            Ok(ComInit { uninit: false })
        } else {
            Err(Error::Elevation {
                kind: ElevationErrorKind::AuthFailed,
                detail: format!("CoInitializeEx failed before ShellExecuteEx: {hr:?}"),
            })
        }
    }
}
impl Drop for ComInit {
    fn drop(&mut self) {
        if self.uninit {
            // SAFETY: balances our CoInitializeEx that incremented the refcount.
            unsafe { CoUninitialize() };
        }
    }
}

/// Program (loaded image) + the joined parameter line. Honors `executable()`; an
/// argv[0] distinct from a set `executable()` cannot be preserved by runas.
fn program_and_params(cmd: &Command) -> Result<(OsString, OsString), Error> {
    let CommandInput::Argv(argv) = cmd.input() else {
        return Err(Error::Unsupported {
            op: "elevation of a commandline() command".into(),
            platform: "windows",
            detail: "runas elevation requires an argv command (set .args([...]))".into(),
        });
    };
    if argv.is_empty() {
        return Err(Error::Unsupported {
            op: "elevation of an empty command".into(),
            platform: "windows",
            detail: "set a program via .args([...]) before .elevate()".into(),
        });
    }
    let program = match cmd.executable_path() {
        Some(exe) => {
            if argv[0].as_os_str() != exe.as_os_str() {
                return Err(Error::Unsupported {
                    op: "elevation with an argv[0] distinct from executable()".into(),
                    platform: "windows",
                    detail: "ShellExecuteEx(runas) cannot set an argv[0] independent of the loaded image".into(),
                });
            }
            exe.as_os_str().to_os_string()
        }
        None => argv[0].clone(),
    };
    let tail_wide: Vec<Vec<u16>> = argv[1..].iter().map(|a| a.encode_wide().collect()).collect();
    let tail_refs: Vec<&[u16]> = tail_wide.iter().map(|v| v.as_slice()).collect();
    let joined = crate::quote::windows::join_wide(&tail_refs);
    Ok((program, OsString::from_wide(&joined)))
}

// Both the sync (`spawn_elevated`) and async spawn arms route an elevated `Command` here.
pub(crate) fn launch_runas(cmd: &mut Command) -> Result<RunasOutcome, Error> {
    launch_runas_with_host(cmd, &Host::detect())
}

/// PURE given `host` (the Windows gate seam): gate, plan, then ShellExecuteEx(runas).
pub(crate) fn launch_runas_with_host(cmd: &mut Command, host: &Host) -> Result<RunasOutcome, Error> {
    let req = cmd.elevation_request();
    let (backend, auth) = (req.backend, req.auth.clone());
    // Structural config gate FIRST — privilege-independent (before the short-circuit), so
    // an already-elevated caller gets the same verdict for piped/env/contain/commandline.
    reject_unsupported_config(cmd)?;
    let (program, params) = program_and_params(cmd)?; // validates commandline()/argv0 too

    match host.plan(Privilege::Elevated, backend, auth) {
        Transition::RunAsIs => return Ok(RunasOutcome::AlreadyElevated),
        Transition::Reject { error } => return Err(error),
        Transition::ElevatePosix { .. } => unreachable!("planner never yields ElevatePosix on a windows host"),
        Transition::ElevateMacosGui { .. } => {
            unreachable!("planner never yields ElevateMacosGui on a windows host")
        }
        Transition::ElevateWindows { .. } => {}
    }

    let dir = cmd.cwd().map(|d| wide_nul(d.as_os_str()));
    let file_w = wide_nul(program.as_os_str());
    let params_w = wide_nul(params.as_os_str());
    let verb_w = wide_nul(OsStr::new("runas"));

    let com = ComInit::init()?;
    // SAFETY: `info` is fully initialized with the correct cbSize; the wide buffers
    // outlive the call; SEE_MASK_NOCLOSEPROCESS yields an owned hProcess.
    let proc: OwnedHandle = unsafe {
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb_w.as_ptr()),
            lpFile: PCWSTR(file_w.as_ptr()),
            lpParameters: PCWSTR(params_w.as_ptr()),
            lpDirectory: dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
            nShow: runas_show_command(cmd.flags_request()).0,
            ..Default::default()
        };
        ShellExecuteExW(&mut info).map_err(|e| {
            if e.code() == ERROR_CANCELLED_HRESULT {
                Error::Elevation {
                    kind: ElevationErrorKind::AuthDeclined,
                    detail: "the UAC elevation prompt was declined".into(),
                }
            } else {
                Error::Elevation {
                    kind: ElevationErrorKind::AuthFailed,
                    detail: format!("ShellExecuteEx(runas) failed: {e}"),
                }
            }
        })?;
        if info.hProcess.is_invalid() {
            return Err(Error::Elevation {
                kind: ElevationErrorKind::AuthFailed,
                detail: "ShellExecuteEx(runas) returned no process handle".into(),
            });
        }
        OwnedHandle::from_raw_handle(info.hProcess.0 as std::os::windows::io::RawHandle)
    };
    drop(com);

    // Identity from the OWNED handle — no second OpenProcess.
    let handle = HANDLE(proc.as_raw_handle());
    // SAFETY: `handle` is our live, owned process handle.
    let pid = unsafe { GetProcessId(handle) };
    let id = if pid != 0 {
        crate::identity::windows_identity_from_handle(handle, pid)
    } else {
        None
    };
    let Some(id) = id else {
        // Auth SUCCEEDED but we cannot track the child. Terminate it, and report the
        // ACTUAL outcome (terminated vs still-running) in the detail — the kind stays neutral.
        // SAFETY: `handle` is live; terminating our own launched child.
        let terminated = unsafe { TerminateProcess(handle, 1) }.is_ok();
        let detail = if terminated {
            "the elevated child launched but its identity could not be resolved; it was terminated".into()
        } else {
            format!("the elevated child (pid {pid}) launched but its identity could not be resolved and could not be terminated; it may still be running")
        };
        return Err(Error::Elevation {
            kind: ElevationErrorKind::Untracked,
            detail,
        });
    };

    let report = ElevationReport {
        via: ElevatedVia::WindowsUac,
        stripped_env: Vec::new(),
        stdio: ElevatedStdio::OwnConsole,
    };
    Ok(RunasOutcome::Launched { proc, pid, id, report })
}

pub(crate) fn spawn_elevated(cmd: &mut Command, kill_on_drop: bool) -> Result<crate::child::Child, Error> {
    match launch_runas(cmd)? {
        RunasOutcome::AlreadyElevated => {
            let mut child = crate::child::spawn::spawn_unelevated(cmd, kill_on_drop)?;
            child.set_elevation(Some(crate::elevation::already_elevated_report(
                ElevatedStdio::Passthrough,
            )));
            Ok(child)
        }
        RunasOutcome::Launched { proc, pid, id, report } => {
            // A dedicated non-blocking-kill handle (RawChild::new_runas): a higher-integrity
            // child a medium parent cannot terminate never hangs Drop.
            let mut child = crate::child::Child::from_parts(
                ProcHandle::Raw(RawChild::new_runas(proc, pid)),
                id,
                BTreeMap::new(),
                kill_on_drop,
                Attachment::uac_elevated(),
            );
            child.set_elevation(Some(report));
            Ok(child)
        }
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
