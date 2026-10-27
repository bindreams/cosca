//! What [`FakeFilesystem`](crate::fs::FakeFilesystem) needs to know about a POSIX path.

use super::{Path, PathBuf};
use crate::fs::sealed::Lookup;
use crate::{Component, PurePath};

impl Lookup for Path {
    fn lookup_spelling(&self) -> PathBuf {
        let mut bytes = Vec::new();
        if self.has_root() {
            bytes.push(b'/');
        }
        let mut named = false;
        let mut trailing = false;
        let mut dotted = false;
        for c in self.components() {
            let name: &[u8] = match c {
                // `.` names nothing, but after a name it demands a directory (`tool/.`).
                Component::Empty | Component::CurDir => {
                    dotted |= c == Component::CurDir;
                    trailing = named;
                    continue;
                }
                Component::ParentDir => b"..",
                Component::Normal(name) => name.as_bytes(),
            };
            if named {
                bytes.push(b'/');
            }
            bytes.extend_from_slice(name);
            named = true;
            trailing = false;
        }
        if trailing {
            bytes.push(b'/');
        }
        // Only `.` was written: the current directory, which is not the empty path.
        if !named && dotted && !self.has_root() {
            bytes.push(b'.');
        }
        PathBuf::from(bytes)
    }

    fn canonical_spelling(&self) -> PathBuf {
        self.to_path_buf()
    }

    fn refusal(&self) -> Option<&'static str> {
        self.as_bytes().contains(&0).then_some("the path holds a NUL")
    }
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod lookup_tests;
