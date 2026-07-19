//! MSVCRT `lpReserved2` fd-table encoder + a `GetFileType` device classifier.
//!
//! The child CRT recovers inherited descriptors n>=3 from
//! `STARTUPINFO.lpReserved2`: a little-endian `i32` slot count, then `count`
//! per-slot flag bytes, then `count` pointer-sized native-endian OS handles. A
//! present slot carries `FOPEN` OR-ed with a device-kind bit; an interior gap
//! carries a zero flag and `INVALID_HANDLE_VALUE`. See the CRT `ioinfo`/`osfile`
//! layout that `__acrt_get_std_handle`/`_pipe` and friends read back.

use std::collections::BTreeMap;

use windows::Win32::Foundation::{GetLastError, SetLastError, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR};
use windows::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE};

use crate::error::Error;
use crate::stdio::Fd;

// MSVCRT per-slot flag bits (the CRT `ioinfo` `osfile` byte).
const FOPEN: u8 = 0x01; // slot is in use
const FPIPE: u8 = 0x08; // anonymous/named pipe
const FDEV: u8 = 0x40; // character device (console/tty)

// Byte width of a serialized handle in the blob: a native pointer.
const HANDLE_SIZE: usize = size_of::<HANDLE>();

/// Device class of an inherited handle, driving its CRT flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FdKind {
    Pipe,
    File,
    CharDev,
}

/// An encoded `lpReserved2` blob plus the present handles it references. The
/// spawn path marks `handles` inheritable (and passes `bytes` as `lpReserved2`)
/// before calling `CreateProcessW`.
pub(crate) struct FdTable {
    pub bytes: Vec<u8>,
    pub handles: Vec<HANDLE>,
}

/// Classify `h` into the CRT device kind via `GetFileType`.
///
/// `GetFileType` returns `FILE_TYPE_UNKNOWN` both for a genuinely unknown (but
/// valid) handle and on failure; the two are told apart by `GetLastError`. It
/// does not reset last-error on the success path, so we clear it first — the
/// canonical MSDN idiom — otherwise a stale nonzero code from an earlier call
/// would masquerade as a classify failure.
pub(crate) fn classify(h: HANDLE) -> Result<FdKind, Error> {
    // SAFETY: `SetLastError` only writes the calling thread's last-error slot.
    unsafe { SetLastError(NO_ERROR) };
    // SAFETY: `GetFileType` reads only the handle's type; any handle value is a
    // valid argument (an invalid one yields `FILE_TYPE_UNKNOWN` + a set error).
    let file_type = unsafe { GetFileType(h) };
    if file_type == FILE_TYPE_PIPE {
        Ok(FdKind::Pipe)
    } else if file_type == FILE_TYPE_CHAR {
        Ok(FdKind::CharDev)
    } else if file_type == FILE_TYPE_DISK {
        Ok(FdKind::File)
    } else {
        // `FILE_TYPE_UNKNOWN` (or any other value): a set last-error means the
        // call failed; `NO_ERROR` means the type is genuinely unknown (treat as
        // a regular file for CRT flag purposes).
        // SAFETY: reads the calling thread's last-error slot; no preconditions.
        let err = unsafe { GetLastError() };
        if err == NO_ERROR {
            Ok(FdKind::File)
        } else {
            Err(Error::Io(std::io::Error::from_raw_os_error(err.0 as i32)))
        }
    }
}

/// The `osfile` flag byte for a present slot of the given kind.
fn present_flag(kind: FdKind) -> u8 {
    let kind_bits = match kind {
        FdKind::Pipe => FPIPE,
        FdKind::CharDev => FDEV,
        FdKind::File => 0,
    };
    FOPEN | kind_bits
}

/// Byte length of the `lpReserved2` blob for a dense `0..=maxfd` table.
///
/// The exact length is computed with checked arithmetic. Any length that cannot
/// fit the `WORD`-sized `cbReserved2` field can never reach `CreateProcessW`, so
/// it is reported as `usize::MAX` — a saturating "does not fit" sentinel that
/// [`table_fits`] rejects. This is overflow-safe on every target width (a
/// negative fd, a narrow-`usize` multiply, or an `i32::MAX` fd all saturate to
/// `usize::MAX`), so a wrapped-small value can never slip past the cap and admit
/// a giant [`encode`] allocation.
pub(crate) fn encoded_len(maxfd: i32) -> usize {
    match usize::try_from(maxfd)
        .ok()
        .and_then(|m| m.checked_add(1))
        .and_then(|n| n.checked_mul(1 + HANDLE_SIZE))
        .and_then(|x| x.checked_add(4))
    {
        Some(len) if table_fits(len) => len,
        _ => usize::MAX,
    }
}

/// Whether an encoded blob fits the `WORD`-sized `cbReserved2` field.
pub(crate) fn table_fits(byte_len: usize) -> bool {
    byte_len <= u16::MAX as usize
}

/// Encode `entries` into a dense `0..=maxfd` `lpReserved2` blob (`maxfd` is the
/// largest key; an empty map yields a zero-count blob). Interior gaps get a zero
/// flag and `INVALID_HANDLE_VALUE`; present slots get `FOPEN | kind` and push
/// their handle to `handles` (gap handles are NOT pushed).
///
/// Precondition: the caller has checked `table_fits(encoded_len(maxfd))` — this
/// pre-sizes and fills the blob without re-checking the cap.
pub(crate) fn encode(entries: &BTreeMap<Fd, (HANDLE, FdKind)>) -> FdTable {
    let maxfd: i32 = entries.keys().next_back().map_or(-1, |fd| fd.raw());
    debug_assert!(
        entries.is_empty() || table_fits(encoded_len(maxfd)),
        "encode called past the size cap; gate on table_fits(encoded_len(maxfd)) first"
    );
    // Slot count N = maxfd + 1 (0 for an empty map). `maxfd` is a real, in-range
    // descriptor, so `+ 1` cannot overflow `i32`.
    let n: usize = usize::try_from(maxfd).map_or(0, |m| m + 1);

    let mut bytes = Vec::with_capacity((1 + HANDLE_SIZE).saturating_mul(n).saturating_add(4));
    bytes.extend_from_slice(&(n as i32).to_le_bytes());

    let mut handles: Vec<HANDLE> = Vec::new();
    // Flags section: one byte per slot.
    for i in 0..n {
        match entries.get(&Fd::from_raw(i as i32)) {
            Some((_, kind)) => bytes.push(present_flag(*kind)),
            None => bytes.push(0),
        }
    }
    // Handles section: one pointer-sized native-endian handle per slot.
    for i in 0..n {
        match entries.get(&Fd::from_raw(i as i32)) {
            Some((h, _)) => {
                bytes.extend_from_slice(&(h.0 as usize).to_ne_bytes());
                handles.push(*h);
            }
            None => bytes.extend_from_slice(&(INVALID_HANDLE_VALUE.0 as usize).to_ne_bytes()),
        }
    }

    FdTable { bytes, handles }
}

#[cfg(test)]
#[path = "crt_fds_tests.rs"]
mod crt_fds_tests;
