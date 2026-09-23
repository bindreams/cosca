//! Environment-variable key identity, compared the way Windows and std's own `EnvKey` compare it.

use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;

use windows::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN};

/// An environment key ordered by `CompareStringOrdinal(.., bIgnoreCase = TRUE)`, as std orders its
/// `EnvKey`: each UTF-16 code unit is uppercased to exactly one code unit by Windows' own table,
/// then compared by value. So `ß` never equals `SS`, surrogates (paired or not) match only
/// themselves, and the order is the case-insensitive ordinal sort `CreateProcessW` expects of an
/// environment block. The table is the OS's, so it is asked rather than modelled.
///
/// This equals std for keys under 2^31 UTF-16 units. std passes longer lengths to
/// `CompareStringOrdinal` with `as _`, which truncates them; this compares such keys in pieces and
/// stays correct, deliberately.
///
/// The key keeps the name it was created with. A map insert of an equal key keeps the existing
/// key, so a map keeps the first name it saw for each variable, as std's does.
#[derive(Clone, Debug)]
pub(super) struct EnvKey {
    name: OsString,
    wide: Vec<u16>,
}

impl EnvKey {
    pub(super) fn new(key: &OsStr) -> Self {
        Self {
            name: key.to_os_string(),
            wide: key.encode_wide().collect(),
        }
    }

    pub(super) fn name(&self) -> &OsStr {
        &self.name
    }
}

impl Ord for EnvKey {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_ignore_case(&self.wide, &other.wide, MAX_CHUNK)
    }
}

impl PartialOrd for EnvKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for EnvKey {
    fn eq(&self, other: &Self) -> bool {
        // One unit folds to one unit, so keys of different lengths are never equal.
        self.wide.len() == other.wide.len() && self.cmp(other) == Ordering::Equal
    }
}

impl Eq for EnvKey {}

/// The longest slice `CompareStringOrdinal` accepts: its lengths are `i32`.
const MAX_CHUNK: usize = i32::MAX as usize;

/// Compare `a` and `b` in `chunk`-unit pieces. The fold is per code unit, so comparing piecewise
/// and then by length is exactly the whole-string comparison.
fn cmp_ignore_case(a: &[u16], b: &[u16], chunk: usize) -> Ordering {
    debug_assert!(
        (1..=MAX_CHUNK).contains(&chunk),
        "chunk {chunk} out of CompareStringOrdinal's range"
    );
    for (a, b) in a.chunks(chunk).zip(b.chunks(chunk)) {
        // SAFETY: both slices are valid for their lengths, which `chunk` keeps within `i32`.
        let result = unsafe { CompareStringOrdinal(a, b, true) };
        match result {
            CSTR_EQUAL => {}
            CSTR_LESS_THAN => return Ordering::Less,
            CSTR_GREATER_THAN => return Ordering::Greater,
            // Fails only on invalid parameters, which the slices rule out.
            _ => panic!("comparing environment keys failed: {}", std::io::Error::last_os_error()),
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
#[path = "env_key_tests.rs"]
mod env_key_tests;
