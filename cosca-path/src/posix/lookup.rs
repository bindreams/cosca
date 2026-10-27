//! What [`FakeFilesystem`](crate::fs::FakeFilesystem) needs to know about a POSIX path.

use std::io;

use super::{Path, PathBuf};
use crate::fs::sealed::{Cwd, Implicit, Lookup, Spelling};
use crate::{Component, PurePath};

/// The path of the resolved names `names`: `/` and the names, or the names (`.` for none).
fn spell(rooted: bool, names: &[&[u8]]) -> PathBuf {
    let mut bytes = Vec::new();
    if rooted {
        bytes.push(b'/');
    }
    bytes.extend_from_slice(&names.join(&b'/'));
    if bytes.is_empty() {
        bytes.push(b'.');
    }
    PathBuf::from(bytes)
}

impl Lookup for Path {
    /// `.` and `..` resolve against the names before them, as the kernel does where no link is
    /// involved: `a/./b` is `a/b`, `a/b/..` is `a`, and `..` at the root stays there. Each is a
    /// lookup inside the directory before it (`a/..` needs `a` to be a searchable directory), which is
    /// in [`inside`](Spelling::inside) unless the path passes through it anyway. A final `.` after a
    /// name demands a directory, as a trailing separator does. A relative path that resolves to no
    /// name is the current directory `.`; one that starts with `..` keeps it, since the fake does not
    /// know where it leads.
    fn lookup(&self) -> Spelling<PathBuf> {
        let rooted = self.has_root();
        let mut names: Vec<&[u8]> = Vec::new();
        let mut inside = Vec::new();
        let mut dir_only = false;
        let mut named = false;
        let mut dotted = false;
        for component in self.components() {
            let name = match component {
                Component::Empty => {
                    dir_only = named;
                    continue;
                }
                Component::CurDir | Component::ParentDir => {
                    // The current directory of a relative path, and the ancestors of it, are no entry
                    // of the fake's.
                    if rooted || names.iter().any(|n| *n != b"..") {
                        inside.push((spell(rooted, &names), component == Component::ParentDir));
                    }
                    if component == Component::CurDir {
                        dotted = true;
                        dir_only = named;
                        continue;
                    }
                    match names.last() {
                        Some(last) if *last != b".." => {
                            names.pop();
                        }
                        None if rooted => {}
                        _ => names.push(b".."),
                    }
                    named = true;
                    dir_only = false;
                    continue;
                }
                Component::Normal(name) => name.as_bytes(),
            };
            names.push(name);
            named = true;
            dir_only = false;
        }
        let nothing_written = !rooted && !named && !dotted;
        let key = if nothing_written {
            PathBuf::default()
        } else {
            spell(rooted, &names)
        };
        let mut spelling = Spelling::new(key);
        spelling.dir_only = dir_only || spelling.key.file_name().is_none();
        spelling.inside = inside;
        if !rooted {
            if !nothing_written && names.iter().all(|n| *n == b"..") {
                spelling.implicit = Some(Implicit::Always);
            }
            spelling.cwd = Cwd::Relative {
                tag: Vec::new(),
                dotdot: names.first() == Some(&&b".."[..]),
            };
        }
        if self.as_bytes().contains(&0) {
            spelling.refusal = Some((io::ErrorKind::InvalidInput, "the path holds a NUL".to_owned()));
        }
        spelling
    }

    fn canonical_spelling(&self) -> PathBuf {
        self.to_path_buf()
    }
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod lookup_tests;
