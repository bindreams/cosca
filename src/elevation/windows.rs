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
    }
}

use crate::command::Command;
use crate::error::Error;
use crate::stdio::ResolvedStdio;

/// Enforce the honest capability matrix for Windows elevation. ShellExecuteEx(runas)
/// passes NO handles and no environment, and a Job Object cannot span the integrity
/// boundary — so every non-inherit slot, every fd >= 3, any explicit env, and
/// `.contain()` is a loud `Unsupported`, never a silent lie.
// Not yet called by production code: Task 14's `launch_runas` calls this gate before
// the UAC prompt.
#[allow(dead_code)]
pub(crate) fn reject_unsupported_config(cmd: &Command) -> Result<(), Error> {
    let unsupported = |op: &str, detail: &str| {
        Err(Error::Unsupported { op: op.into(), platform: "windows", detail: detail.into() })
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
    Ok(())
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
