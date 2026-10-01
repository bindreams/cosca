//! A UTF-16 environment block for a raw `CreateProcessW` call, keyed the way Windows and std key
//! environment names.
#![cfg(windows)]

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;

use windows::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN};

/// A name ordered by `CompareStringOrdinal(.., bIgnoreCase = TRUE)`, as std's `EnvKey` is: each
/// UTF-16 code unit is uppercased to one code unit by Windows' own table, then compared by value.
/// So `ß` never equals `SS`, and a malformed name (an unpaired surrogate) equals only itself.
/// Rust's `to_uppercase` is not that rule: it expands `ß` and turns every malformed name into
/// U+FFFD, merging variables Windows keeps apart.
struct EnvKey(Vec<u16>);

impl Ord for EnvKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // SAFETY: both slices are valid UTF-16 buffers that outlive the call; the API only reads
        // them.
        match unsafe { CompareStringOrdinal(&self.0, &other.0, true) } {
            CSTR_EQUAL => Ordering::Equal,
            CSTR_LESS_THAN => Ordering::Less,
            CSTR_GREATER_THAN => Ordering::Greater,
            // Fails only on invalid parameters, which the slices rule out.
            _ => panic!(
                "comparing environment names failed: {}",
                std::io::Error::last_os_error()
            ),
        }
    }
}

impl PartialOrd for EnvKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for EnvKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for EnvKey {}

/// The block for `vars`, in order of precedence (a later entry replaces an earlier one with the
/// same name and keeps its own spelling). Sorted as `CreateProcessW` requires, each entry
/// `NAME=value` NUL-terminated, and the block ends with an extra NUL.
pub fn env_block(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Vec<u16> {
    let mut by_name_old: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
    for (key, value) in vars {
        by_name_old.insert(key.to_string_lossy().to_uppercase(), (key, value));
    }
    let by_name: Vec<(OsString, OsString)> = by_name_old.into_values().collect();
    let by_name: BTreeMap<u8, (OsString, OsString)> = by_name.into_iter().enumerate().map(|(i, v)| (i as u8, v)).collect();
    let mut block: Vec<u16> = Vec::new();
    for (key, value) in by_name.values() {
        block.extend(key.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}
