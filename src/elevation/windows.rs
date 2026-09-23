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
            if let Err(e) = unsafe { windows::Win32::Foundation::CloseHandle(self.0) } {
                log::warn!("CloseHandle of an owned token failed: {e}");
                debug_assert!(false, "CloseHandle of an owned token should not fail: {e}");
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
            "the runas launch takes a show-command and no creation flags, so DETACHED_PROCESS \
             cannot be expressed. Elevate without it, or spawn unelevated.",
        );
    }
    if flags.breakaway_from_job {
        return unsupported(
            "breakaway_from_job() + elevate on Windows",
            "the runas launch takes a show-command and no creation flags, so \
             CREATE_BREAKAWAY_FROM_JOB cannot be expressed — and the runas child is created by a \
             system service, not by this process's job.",
        );
    }
    if flags.raw != 0 {
        return unsupported(
            "creation_flags() + elevate on Windows",
            "the runas launch takes a show-command and no creation flags, so an arbitrary \
             dwCreationFlags word cannot be expressed. no_window() is the one flag intent that \
             survives here, lowered to the launch's show-command.",
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
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, RPC_E_CHANGED_MODE, S_FALSE, S_OK,
};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};
use windows::Win32::System::Threading::{GetProcessId, TerminateProcess};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::child::proc_handle::ProcHandle;
use crate::child::spawn::windows_raw::resolve::ensure_no_nul_wide;
use crate::child::spawn::windows_raw::RawChild;
use crate::command::ExecutableSpec;
use crate::containment::Attachment;
use crate::elevation::plan::Transition;
use crate::elevation::shell_file::{self, AppPath};
use crate::elevation::{ElevatedStdio, ElevatedVia, ElevationReport, Privilege};
use crate::error::ElevationErrorKind;
use crate::identity::ProcessId;

/// `ERROR_CANCELLED` (1223) as an HRESULT (0x800704C7) — the UAC-declined code.
const ERROR_CANCELLED_HRESULT: windows::core::HRESULT = windows::core::HRESULT(0x800704C7_u32 as i32);

/// A NUL-terminated wide string for a `SHELLEXECUTEINFOW` field, REFUSING an interior NUL.
///
/// `PCWSTR` stops at the first NUL, so a value containing one is silently TRUNCATED rather than
/// rejected — and every field here decides something security-relevant:
///
/// - `lpFile` truncated at the NUL would load a DIFFERENT FILE than the caller named, elevated.
/// - `lpDirectory` would run the elevated child somewhere other than `current_dir()` asked for.
/// - `lpParameters` would drop everything after the NUL, silently shortening the argument line an
///   elevated program acts on.
///
/// The raw `CreateProcessW` backend already refuses all three via its own NUL checks, so this
/// closes the interior-NUL divergence between the elevated and unelevated paths. `ShellExecuteEx`
/// RESOLVING a program `CreateProcessW` would refuse — completing an extension-less token, or
/// dispatching `.lnk`, `.vbs`, `.msc`, … through an association — is closed by the gates in
/// `plan_runas`, not here.
///
/// Fallible rather than a check at each call site, so the unchecked sink does not exist: every
/// string field of the `SHELLEXECUTEINFOW` is built here. `what` names the field for the error.
/// `lpParameters` is additionally checked per argv ELEMENT by [`ensure_no_nul_wide`] before the
/// join, because by the time it is one string the refusal can no longer say which `args([..])`
/// entry carried the NUL; the check here stays as the field's own, so removing that loop cannot
/// open an unchecked sink.
///
/// The predicate and its message come from the raw `CreateProcessW` backend rather than being
/// restated here. Two copies of one sentence is exactly how the wording drifted apart before —
/// "elevated program path" against "program path" — over a defect neither backend describes
/// differently.
fn wide_nul(what: &str, s: &OsStr) -> Result<Vec<u16>, Error> {
    ensure_no_nul_wide(what, s)?;
    Ok(s.encode_wide().chain(std::iter::once(0)).collect())
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

/// The argv runas can work from at all. Split from [`elevated_program`] and [`elevated_params`] so
/// the program's NUL check can sit between them — see [`plan_runas`].
fn elevated_argv(cmd: &Command) -> Result<&[OsString], Error> {
    super::elevation_argv(
        cmd,
        &super::ArgvRefusals {
            platform: "windows",
            op_prefix: "elevation",
            commandline: "runas elevation requires an argv command (set .args([...]))",
            argv0: "ShellExecuteEx(runas) cannot set an argv[0] independent of the loaded image",
        },
    )
}

/// The loaded image. Honors `executable()`. A `raw_executable()` program is additionally COMPLETED to an absolute
/// path — see the `Exact` arm below for why that is the opposite of searching for it.
fn elevated_program(cmd: &Command, argv: &[OsString]) -> Result<OsString, Error> {
    // The token AS WRITTEN, before any completion: argv[0], or the explicit executable.
    // `elevated_argv` refused an argv[0] distinct from a set executable, so the two agree.
    let token = cmd
        .executable_path()
        .map_or_else(|| argv[0].clone(), |exe| exe.as_os_str().to_os_string());

    // An `Exact` token is completed, never passed through: `ShellExecuteEx` would search a
    // relative `lpFile`. See `absolutise_exact`'s doc for why this sink needs that and
    // `CreateProcessW` does not, and for the `PATHEXT` residue [`plan_runas`]'s allowlist covers.
    //
    // A `Search` token is NOT resolved here: `executable()` on the elevated path reaches
    // `ShellExecuteEx`'s own search unresolved, as `executable()`'s doc says, and
    // [`plan_runas`]'s allowlist bounds what that search can pick.
    //
    // Completion runs BEFORE [`plan_runas`]'s `wide_nul("program path", ..)`, so it must not blunt
    // that field's NUL attribution: `absolutise_exact` refuses an interior NUL itself, under the
    // same "program path" name, ahead of every other field and of its own shape checks.
    //
    // Spelled out rather than `_ =>`: the discriminant IS the feature here, and this is the
    // security sink. A future `ExecutableSpec` variant must not compile silently into the
    // SEARCHING branch, which is the unsafe default.
    match cmd.executable_spec() {
        Some(ExecutableSpec::Exact(p)) => {
            Ok(crate::child::spawn::windows_raw::resolve::absolutise_exact(p)?.into_os_string())
        }
        Some(ExecutableSpec::Search(_)) | None => Ok(token),
    }
}

/// The joined `lpParameters` line, NUL-checked per element BEFORE the join: `lpParameters` is one
/// string, so a refusal built from it could only say that SOME element carried a NUL.
fn elevated_params(argv: &[OsString]) -> Result<OsString, Error> {
    let mut tail_wide: Vec<Vec<u16>> = Vec::with_capacity(argv.len() - 1);
    for (i, a) in argv.iter().enumerate().skip(1) {
        ensure_no_nul_wide(&format!("argument {i}"), a)?;
        tail_wide.push(a.encode_wide().collect());
    }
    let tail_refs: Vec<&[u16]> = tail_wide.iter().map(|v| v.as_slice()).collect();
    Ok(OsString::from_wide(&crate::quote::windows::join_wide(&tail_refs)))
}

/// The default value of `hive\Software\Microsoft\Windows\CurrentVersion\App Paths\<subkey>`,
/// unexpanded, as `shell_file::reject_app_path` judges it. A missing key or default value is
/// [`AppPath::Absent`]; any other failure, or a value that is not a string, is
/// [`AppPath::Unreadable`]. Read through the process's own registry view, which is the one
/// in-process shell32 reads.
fn app_path(hive: HKEY, subkey: &OsStr) -> AppPath {
    let key: Vec<u16> = OsStr::new(r"Software\Microsoft\Windows\CurrentVersion\App Paths\")
        .encode_wide()
        .chain(subkey.encode_wide())
        .chain([0])
        .collect();
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    let mut data: Vec<u16> = Vec::new();
    loop {
        let mut bytes = u32::try_from(data.len() * 2).expect("a registry value fits in u32 bytes");
        let buffer = (!data.is_empty()).then(|| data.as_mut_ptr().cast());
        // SAFETY: `key` is NUL-terminated and outlives the call; `buffer`, when given, points at
        // `bytes` writable bytes of `data`.
        let rc = unsafe {
            RegGetValueW(
                hive,
                PCWSTR(key.as_ptr()),
                PCWSTR::null(),
                flags,
                None,
                buffer,
                Some(&mut bytes),
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return AppPath::Absent;
        }
        match (rc, buffer) {
            (ERROR_SUCCESS, Some(_)) => {
                data.truncate(bytes as usize / 2);
                while data.last() == Some(&0) {
                    data.pop();
                }
                return AppPath::Target(OsString::from_wide(&data));
            }
            // Sized, or grown since it was sized: size to what it reports and read again.
            (ERROR_SUCCESS | ERROR_MORE_DATA, _) => data = vec![0; (bytes as usize).div_ceil(2).max(1)],
            _ => return AppPath::Unreadable,
        }
    }
}

// Both the sync (`spawn_elevated`) and async spawn arms route an elevated `Command` here.
pub(crate) fn launch_runas(cmd: &Command) -> Result<RunasOutcome, Error> {
    launch_runas_with_host(cmd, &Host::detect())
}

/// The validated `SHELLEXECUTEINFOW` payload: every string field, NUL-terminated, plus the show
/// command. Built only when a consent prompt is actually warranted.
pub(crate) struct RunasLaunch {
    file_w: Vec<u16>,
    params_w: Vec<u16>,
    dir_w: Option<Vec<u16>>,
    verb_w: Vec<u16>,
    show: windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD,
}

/// What the launch will do, decided with no effect whatsoever.
pub(crate) enum RunasStep {
    AlreadyElevated,
    Launch(Box<RunasLaunch>),
}

/// PURE given `host` (the Windows gate seam): every config gate, every input check, and the
/// planner decision — and NOTHING that touches the system.
///
/// Split out from the launch so the unit tests can drive it. They probe what happens when a check
/// is removed, and a test that drove `launch_runas_with_host` instead would, on the unelevated
/// leg of that hypothetical, fall through the planner and issue a REAL `ShellExecuteExW` with
/// verb `runas` — raising a UAC prompt and elevating the probe program on the developer's own
/// machine. Returning the decision instead makes that outcome unreachable from a test.
pub(crate) fn plan_runas(cmd: &Command, host: &Host) -> Result<RunasStep, Error> {
    let req = cmd.elevation_request();
    let (backend, auth) = (req.backend, req.auth.clone());
    // Structural config gate FIRST — privilege-independent (before the short-circuit), so
    // an already-elevated caller gets the same verdict for piped/env/contain/commandline.
    reject_unsupported_config(cmd)?;
    let argv = elevated_argv(cmd)?; // validates commandline()/empty argv too
    let program = elevated_program(cmd, argv)?;

    // Input validation stays with `reject_unsupported_config`, ABOVE the short-circuit, so every
    // verdict here is a property of the REQUEST rather than of the caller's ambient privilege.
    // Putting it below would make the same `Command` refused when unelevated and accepted when
    // already elevated — the exact "depends which path ran" divergence these checks exist to
    // remove.

    // Ahead of EVERY other field's check, including the per-element argv loop, because this is the
    // field that decides which image runs ELEVATED: `C:\tools\setup` + NUL + `.bat` launches
    // `C:\tools\setup`, a program the caller never named, and a request poisoning the program and
    // an argument together would otherwise come back naming only `argument 1`. `reject_batch_path`
    // below refuses an interior NUL too, but it runs after those fields, so this ordering is the
    // elevated path's own.
    let file_w = wide_nul("program path", program.as_os_str())?;

    // Then EVERY remaining field, and only then the batch gate: a truncating argument or working
    // directory is a defect the caller can fix, and "batch escaping is not implemented" would hide
    // it — a clean `.bat` next to a poisoned `current_dir()` would never mention that `lpDirectory`
    // truncates too. `params` is checked per element, by index, inside `elevated_params`.
    let params = elevated_params(argv)?;
    let dir = cmd
        .cwd()
        .map(|d| wide_nul("working directory", d.as_os_str()))
        .transpose()?;
    let params_w = wide_nul("argument line", params.as_os_str())?;
    let verb_w = wide_nul("verb", OsStr::new("runas"))?;

    // Refuse a `.bat`/`.cmd` spelled in the program `elevated_program` returned — the caller's
    // TOKEN, except on the `Exact` arm, where it is that token completed to an absolute path.
    // (Completion only prefixes a directory and applies Win32's own normalisation, so it can add a
    // `.bat` reading but never remove one; over-rejection is the safe direction here.) Why, in
    // `crate::child::spawn::batch_refusal`; here the `runas` `batfile` association substitutes
    // `lpParameters` into `%*` unescaped, so the injected command runs ELEVATED.
    //
    // The batch gate reads the caller's STRING, so a token `ShellExecuteEx` REWRITES before opening
    // is refused first: quoted, a URL (`file:` is percent-decoded), a `shell:`/`::{CLSID}` name,
    // one starting with `www` (relaunched as `http://www…`), or one holding a `%` — and so is a `current_dir()` holding a `%` or `"`, which it expands before
    // searching a relative token there. See `shell_file`. On what is left, the gate judges the name
    // Win32 resolves the token to — trailing dots and spaces, `..` collapse, drive and UNC and
    // device roots, and data-stream pieces.
    //
    // Then what `ShellExecuteEx` finds by LOOKUP. A token must end in `.exe` or `.com`, so no
    // extension is completed (`PathResolveW`/`PathFileExistsDefExtW` try `.bat` and `.cmd`) and no
    // other association runs; and every App Paths registration shell32 would consult for it, in
    // either hive, must name an `.exe` or `.com` too.
    //
    // What stays open: an App Paths key written between this check and the launch, which can still
    // redirect to a batch file (HKCU is writable by the user); and WHICH image a relative token
    // loads — the search in `lpDirectory` and on the path, and ReactOS's substitution of the drive
    // root or Windows directory for a missing `lpDirectory` — which is always an `.exe` or `.com`,
    // though not necessarily the one meant, until the image is resolved before the launch (#139).
    let program_path = std::path::Path::new(&program);
    shell_file::reject_shell_rewrite(program_path)?;
    if let Some(dir) = cmd.cwd() {
        shell_file::reject_directory_rewrite(dir)?;
    }
    crate::child::spawn::reject_batch_path(program_path)?;
    crate::child::spawn::reject_normalised_batch_path(program_path)?;
    shell_file::reject_non_image(program_path)?;
    let registered: Vec<AppPath> = [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER]
        .into_iter()
        .flat_map(|hive| shell_file::app_paths_subkeys(&program).map(|subkey| app_path(hive, &subkey)))
        .collect();
    shell_file::reject_app_path(program_path, &registered)?;

    match host.plan(Privilege::Elevated, backend, auth) {
        Transition::RunAsIs => return Ok(RunasStep::AlreadyElevated),
        Transition::Reject { error } => return Err(error),
        Transition::ElevatePosix { .. } => unreachable!("planner never yields ElevatePosix on a windows host"),
        Transition::ElevateMacosGui { .. } => {
            unreachable!("planner never yields ElevateMacosGui on a windows host")
        }
        Transition::ElevateWindows { .. } => {}
    }

    // Every arm, since `ShellExecuteEx` applies PATHEXT to any `lpFile`. Below the short-circuit:
    // an already-elevated caller re-spawns through `CreateProcessW`, which assumes no default
    // extension, so an extensionless image is not plantable there.
    crate::resolve::reject_unloadable_image(std::path::Path::new(&program), true)?;

    Ok(RunasStep::Launch(Box::new(RunasLaunch {
        file_w,
        params_w,
        dir_w: dir,
        verb_w,
        show: runas_show_command(cmd.flags_request()),
    })))
}

/// The effect: `ShellExecuteEx(runas)` on an already-validated payload, plus the identity read of
/// the child it launched. Everything that could refuse the request happened in [`plan_runas`].
pub(crate) fn launch_runas_with_host(cmd: &Command, host: &Host) -> Result<RunasOutcome, Error> {
    let launch = match plan_runas(cmd, host)? {
        RunasStep::AlreadyElevated => return Ok(RunasOutcome::AlreadyElevated),
        RunasStep::Launch(launch) => launch,
    };
    let RunasLaunch {
        file_w,
        params_w,
        dir_w,
        verb_w,
        show,
    } = *launch;

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
            lpDirectory: dir_w.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
            nShow: show.0,
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
    match launch_runas(&*cmd)? {
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
