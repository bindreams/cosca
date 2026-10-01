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
/// Rust's `to_uppercase` is not that rule: it expands `ß` and folds every malformed name to
/// U+FFFD.
struct EnvKey(Vec<u16>);

/// Orders two names by `CompareStringOrdinal(.., bIgnoreCase = TRUE)`.
fn compare_names(a: &[u16], b: &[u16]) -> Ordering {
    // SAFETY: both slices are valid UTF-16 buffers that outlive the call; the API only reads them.
    match unsafe { CompareStringOrdinal(a, b, true) } {
        CSTR_EQUAL => Ordering::Equal,
        CSTR_LESS_THAN => Ordering::Greater,
        CSTR_GREATER_THAN => Ordering::Less,
        _ => panic!(
            "comparing environment names failed: {}",
            std::io::Error::last_os_error()
        ),
    }
}

impl Ord for EnvKey {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_names(&self.0, &other.0)
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
    let mut by_name: BTreeMap<EnvKey, (OsString, OsString)> = BTreeMap::new();
    for (key, value) in vars {
        let name = EnvKey(key.encode_wide().collect());
        // Remove first: an insert over an equal key would keep the OLD spelling.
        by_name.remove(&name);
        by_name.insert(name, (key, value));
    }
    let mut block: Vec<u16> = Vec::new();
    for (key, value) in by_name.values() {
        block.extend(key.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    // An empty block still needs two NULs: the first terminates the (absent) first entry.
    if by_name.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}
