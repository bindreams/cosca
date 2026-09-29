//! Windows `(pid, ppid)` snapshot via the ToolHelp process snapshot — the same
//! API the Job-Object backend uses for its thread walk. Only
//! `th32ProcessID` / `th32ParentProcessID` are read; the high-res start token
//! comes from `ProcessId::of` later.

use std::mem::size_of;

use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_FILES};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use crate::error::Error;
use crate::identity::RawPid;

/// A failed or interrupted snapshot is [`Error::Unassessable`] naming the Win32 call and its
/// code: a partial list would read as "no descendants" to the tree walk.
pub(crate) fn process_parents() -> Result<Vec<(RawPid, RawPid)>, Error> {
    let mut out = Vec::new();

    // Process32FirstW/NextW signal end-of-enumeration with ERROR_NO_MORE_FILES.
    let end_of_walk = windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0);

    // SAFETY: snapshot/iterate with an owned handle, closed before every return.
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(snap) => snap,
            Err(e) => return Err(snapshot_failed("CreateToolhelp32Snapshot", e)),
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut step = Process32FirstW(snap, &mut entry);
        let fault = loop {
            match step {
                Ok(()) => out.push((entry.th32ProcessID, entry.th32ParentProcessID)),
                Err(e) if e.code() == end_of_walk => break None,
                Err(e) => break Some(snapshot_failed("Process32FirstW/Process32NextW", e)),
            }
            step = Process32NextW(snap, &mut entry);
        };
        _ = CloseHandle(snap);
        if let Some(fault) = fault {
            return Err(fault);
        }
    }

    Ok(out)
}

fn snapshot_failed(call: &str, e: windows::core::Error) -> Error {
    log::warn!("enumerate::process_parents: {call} failed ({e}); no process snapshot");
    Error::Unassessable {
        detail: format!("the process snapshot could not be taken: {call} failed ({e})"),
        source: Some(std::io::Error::from(e)),
    }
}
