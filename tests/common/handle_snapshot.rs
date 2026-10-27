//! One kernel snapshot of the handles this process holds, for the tests and the testbin, which
//! includes this file with `#[path]`.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::GetCurrentProcess;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    /// `process` is a process handle; `info` is `len` bytes for `class`, and `ret_len` receives the
    /// size the class needs.
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        info: *mut std::ffi::c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
}

/// `class` 51 of `NtQueryInformationProcess`, `ProcessHandleInformation`: a
/// [`HandleSnapshotHeader`] followed by that many [`HandleTableEntry`].
const PROCESS_HANDLE_INFORMATION: u32 = 51;

/// `STATUS_INFO_LENGTH_MISMATCH`: the buffer is too small; the call reports the size it needs.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

/// `OBJ_INHERIT`: the kernel's bit for `HANDLE_FLAG_INHERIT` in a handle table entry.
pub const OBJ_INHERIT: u32 = 0x2;

/// `PROCESS_HANDLE_SNAPSHOT_INFORMATION`, without its trailing array.
#[repr(C)]
struct HandleSnapshotHeader {
    number_of_handles: usize,
    reserved: usize,
}

/// `PROCESS_HANDLE_TABLE_ENTRY_INFO`.
#[repr(C)]
struct HandleTableEntry {
    handle_value: usize,
    handle_count: usize,
    pointer_count: usize,
    granted_access: u32,
    object_type_index: u32,
    handle_attributes: u32,
    reserved: u32,
}

/// Calls `visit` with every handle this process holds and its `OBJ_*` attributes, from one
/// snapshot the kernel takes in a single call. Other threads may close a handle in the snapshot, or
/// reuse its value, before `visit` runs, so a caller that queries the handle must say why that
/// cannot change its answer. The attributes are the snapshot's own and need no query.
pub fn walk_handles(mut visit: impl FnMut(HANDLE, u32)) {
    // `u64` words keep the buffer aligned for both structs.
    let mut words = vec![0u64; (size_of::<HandleSnapshotHeader>() + 64 * size_of::<HandleTableEntry>()) / 8];
    loop {
        let mut needed = 0u32;
        // SAFETY: the pseudo-handle is always valid; the buffer and `needed` are live and of the
        // sizes passed.
        let status = unsafe {
            NtQueryInformationProcess(
                GetCurrentProcess(),
                PROCESS_HANDLE_INFORMATION,
                words.as_mut_ptr().cast(),
                (words.len() * 8) as u32,
                &mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            // The process may have opened more handles since: ask again at the size it reported.
            let len = (needed as usize).div_ceil(8).max(words.len() * 2);
            words.resize(len, 0);
            continue;
        }
        assert!(
            status >= 0,
            "NtQueryInformationProcess(ProcessHandleInformation): {status:#x}"
        );
        break;
    }
    let base = words.as_ptr().cast::<u8>();
    // SAFETY: a successful call filled the buffer with a header and `number_of_handles` entries.
    let count = unsafe { (*base.cast::<HandleSnapshotHeader>()).number_of_handles };
    debug_assert!(
        size_of::<HandleSnapshotHeader>() + count * size_of::<HandleTableEntry>() <= words.len() * 8,
        "the snapshot's entries fit the buffer"
    );
    // SAFETY: as above; the entries follow the header, whose size is a multiple of their alignment.
    let entries = unsafe {
        std::slice::from_raw_parts(
            base.add(size_of::<HandleSnapshotHeader>()).cast::<HandleTableEntry>(),
            count,
        )
    };
    for entry in entries {
        visit(HANDLE(entry.handle_value as *mut _), entry.handle_attributes);
    }
}
