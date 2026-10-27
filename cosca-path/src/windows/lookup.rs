//! What [`FakeFilesystem`](crate::fs::FakeFilesystem) needs to know about a Windows path.

use super::{
    drive_len, fold_separator, next_separator, plain_spelling, respell_verbatim, unc_rest, Path, PathBuf, DEVICE,
    VERBATIM,
};
use crate::fs::sealed::Lookup;
use crate::{Component, PurePath};

/// The plain spelling of the `\\.\` path whose name and rest are `rest`, if the name is a drive
/// (`C:\x`) or `UNC` followed by something (`UNC\s\h`): Win32 reads those as the path they name.
/// The raw volume `\\.\C:` is a device and has none, nor has a UNC server `?`.
fn device_plain_spelling(rest: &[u8]) -> Option<Vec<u8>> {
    let is_drive = rest.first() != Some(&b'\\') && drive_len(rest).is_some_and(|len| rest.get(len) == Some(&b'\\'));
    if is_drive {
        return Some(rest.to_vec());
    }
    unc_rest(rest)
        .filter(|unc| !unc.is_empty() && unc[..next_separator(unc, 0)] != *b"?")
        .map(|unc| [br"\\", unc].concat())
}

impl Path {
    /// Whether the path, a `?` device path, reads as the verbatim `\\?\UNC\` path of the server
    /// `.` or `?`, which [`PathBuf::parse`] refuses with [`ParseError::UnspellableUncServer`].
    fn names_unspellable_unc_server(&self) -> bool {
        let folded: Vec<u8> = self.lexically_normal().bytes().iter().map(fold_separator).collect();
        folded
            .strip_prefix(VERBATIM)
            .and_then(unc_rest)
            .is_some_and(|unc| matches!(&unc[..next_separator(unc, 0)], b"." | b"?"))
    }

    /// A UNC share with nothing below it, with or without the separator after it.
    fn is_share_root(&self) -> bool {
        self.as_unc().is_some() && self.is_fully_qualified() && self.components().next().is_none()
    }
}

impl Lookup for Path {
    fn lookup_spelling(&self) -> PathBuf {
        let normal = self.lexically_normal();
        let mut bytes = normal.bytes().to_vec();
        // `x\.` and `x\..` name an entry, not a directory spelled with a separator.
        let ends_in_dot = matches!(
            self.components().next_back(),
            Some(Component::CurDir | Component::ParentDir)
        );
        if ends_in_dot && normal.components().next_back() == Some(Component::Empty) {
            bytes.pop();
        }
        for b in &mut bytes {
            if *b == b'/' {
                *b = b'\\';
            }
        }
        // A device path spelled `?` reads as the verbatim path it names: `//?/C:/x` is `C:\x`. A UNC
        // server `?` has no plain spelling, and leaves a verbatim one: it is respelled, and no
        // stated path matches it.
        if let Some(rest) = bytes.strip_prefix(VERBATIM) {
            bytes = plain_spelling(rest);
            respell_verbatim(&mut bytes);
        } else if let Some(plain) = bytes.strip_prefix(DEVICE).and_then(device_plain_spelling) {
            // A `.` device path named for a drive or `UNC` is the same object as that path.
            bytes = plain;
        }
        let spelled = PathBuf::from_wtf8(bytes.clone());
        // A share root is one entry with or without its separator; spell it with.
        if spelled.is_share_root() && bytes.last() != Some(&b'\\') {
            bytes.push(b'\\');
            return PathBuf::from_wtf8(bytes);
        }
        spelled
    }

    fn canonical_spelling(&self) -> PathBuf {
        match self.bytes().strip_suffix(b"\\") {
            Some(root) if self.is_share_root() => PathBuf::from_wtf8(root.to_vec()),
            _ => self.to_path_buf(),
        }
    }

    fn refusal(&self) -> Option<&'static str> {
        if self.bytes().contains(&0) {
            Some("the path holds a NUL")
        } else if self.bytes().is_empty() {
            Some("the path is empty")
        } else if self.names_unspellable_unc_server() {
            Some("the path is a verbatim UNC path whose server `.` or `?` has no plain spelling")
        } else {
            None
        }
    }
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod lookup_tests;
