//! macOS `(pid, ppid)` snapshot: `proc_listallpids` for the pid set, then
//! `proc_pidinfo(PROC_PIDTBSDINFO).pbi_ppid` per pid (the same call `identity`
//! uses for its start token).

use crate::identity::RawPid;

/// Read the parent pid of `pid` via `proc_bsdinfo`, or `None` if not resolvable.
fn ppid_of(pid: libc::c_int) -> Option<RawPid> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: proc_pidinfo writes up to `size` bytes into `info`; pointer/size match.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    (n == size).then_some(info.pbi_ppid)
}

pub(crate) fn process_parents() -> Vec<(RawPid, RawPid)> {
    // First call (null buffer, size 0) returns the buffer size needed in bytes.
    // SAFETY: the sizing form of proc_listallpids takes a null buffer.
    let needed = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return Vec::new();
    }

    // Capacity in pids, with headroom: the set can grow between the two calls.
    let cap = needed as usize / std::mem::size_of::<libc::c_int>() + 16;
    let mut pids: Vec<libc::c_int> = vec![0; cap];
    let buf_bytes = (pids.len() * std::mem::size_of::<libc::c_int>()) as libc::c_int;
    // SAFETY: `pids` owns `buf_bytes` writable bytes; proc_listallpids writes pids.
    let written = unsafe { libc::proc_listallpids(pids.as_mut_ptr() as *mut libc::c_void, buf_bytes) };
    if written <= 0 {
        return Vec::new();
    }
    let count = (written as usize).min(pids.len());

    let mut out = Vec::with_capacity(count);
    for &pid in &pids[..count] {
        if pid <= 0 {
            continue; // pid 0 (kernel) / padding slots
        }
        if let Some(ppid) = ppid_of(pid) {
            out.push((pid as RawPid, ppid));
        }
    }
    out
}
