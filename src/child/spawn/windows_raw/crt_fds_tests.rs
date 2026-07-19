use super::*;
use crate::stdio::Fd;
use std::collections::BTreeMap;
const FOPEN: u8 = 0x01;
const FPIPE: u8 = 0x08;
const HSZ: usize = std::mem::size_of::<*mut core::ffi::c_void>();
fn h(v: isize) -> windows::Win32::Foundation::HANDLE {
    windows::Win32::Foundation::HANDLE(v as _)
}

#[test]
fn encodes_count_flags_and_handles_for_fd3() {
    let mut m = BTreeMap::new();
    for (n, v) in [(0i32, 10isize), (1, 11), (2, 12)] {
        m.insert(Fd::from_raw(n), (h(v), FdKind::CharDev));
    }
    m.insert(Fd::from_raw(3), (h(99), FdKind::Pipe));
    let t = encode(&m);
    assert_eq!(&t.bytes[0..4], &4i32.to_le_bytes());
    assert_eq!(t.bytes[4 + 3] & (FOPEN | FPIPE), FOPEN | FPIPE);
    assert_eq!(t.bytes.len(), 4 + 4 + 4 * HSZ);
    assert_eq!(t.bytes.len(), encoded_len(3));
    assert_eq!(t.handles.len(), 4);
}
#[test]
fn interior_gap_is_invalid_handle_and_zero_flag() {
    let mut m = BTreeMap::new();
    m.insert(Fd::from_raw(3), (h(30), FdKind::Pipe));
    m.insert(Fd::from_raw(5), (h(50), FdKind::File));
    let t = encode(&m);
    assert_eq!(&t.bytes[0..4], &6i32.to_le_bytes());
    assert_eq!(t.bytes[4 + 4], 0);
    let off = 4 + 6 + 4 * HSZ;
    assert_eq!(&t.bytes[off..off + HSZ], &(-1isize as usize).to_ne_bytes()[..]);
    assert_eq!(t.handles.len(), 2);
}
#[test]
fn cap_computed_len_boundary_and_overflow_safe() {
    assert!(table_fits(encoded_len(10)));
    // exact boundary: the largest maxfd whose encoded_len <= u16::MAX fits; the next does not.
    let hsz = std::mem::size_of::<*mut core::ffi::c_void>();
    let max_n = (u16::MAX as usize - 4) / (1 + hsz); // N slots fit
    assert!(table_fits(encoded_len((max_n - 1) as i32)));
    assert!(!table_fits(encoded_len((max_n + 8) as i32)));
    // overflow-safe: i32::MAX must saturate, not panic/wrap, and cleanly reject.
    assert_eq!(encoded_len(i32::MAX), usize::MAX);
    assert!(!table_fits(encoded_len(i32::MAX)));
}
#[test]
fn classify_invalid_handle_is_error() {
    // An invalid handle drives GetFileType -> FILE_TYPE_UNKNOWN with a nonzero GetLastError.
    assert!(classify(windows::Win32::Foundation::INVALID_HANDLE_VALUE).is_err());
}
