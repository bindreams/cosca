//! Windows `(pid, ppid)` snapshot via the ToolHelp process snapshot — the same
//! API the Job-Object backend uses for its thread walk. We read only
//! `th32ProcessID` / `th32ParentProcessID`; the high-res start token comes from
//! `ProcessId::of` later.

use std::mem::size_of;

use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_FILES};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use crate::identity::RawPid;

pub(crate) fn process_parents() -> Vec<(RawPid, RawPid)> {
    let mut out = Vec::new();

    // Process32FirstW/NextW signal end-of-enumeration with ERROR_NO_MORE_FILES.
    let end_of_walk = windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0);

    // SAFETY: snapshot/iterate with an owned handle, closed before every return.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut step = Process32FirstW(snap, &mut entry);
        loop {
            match step {
                Ok(()) => out.push((entry.th32ProcessID, entry.th32ParentProcessID)),
                Err(e) if e.code() == end_of_walk => break,
                Err(_) => break, // snapshot fault: return what we have (best-effort)
            }
            step = Process32NextW(snap, &mut entry);
        }
        let _ = CloseHandle(snap);
    }

    out
}
