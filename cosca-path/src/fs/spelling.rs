//! What a path type tells [`FakeFilesystem`](super::FakeFilesystem) about how the host reads a path.

pub(crate) mod sealed {
    use std::io;

    use crate::PurePath;

    /// What [`FakePath`](super::super::FakePath) requires, kept out of the public API.
    pub trait Lookup: PurePath {
        /// How the OS reads the path: the entry it names, and what the lookup of it needs on the way.
        fn lookup(&self) -> Spelling<Self::Buf>;

        /// A [`Spelling::key`] as `canonical` returns it: the host's spelling, which has no
        /// separator after a UNC share root.
        fn canonical_spelling(&self) -> Self::Buf;
    }

    /// How the host reads a path, as far as the fake models it.
    pub struct Spelling<B> {
        /// The entry the path names, so that two spellings of one entry have one key. Separators
        /// collapse, and so do `.` and (where the host resolves it as text) `..`; a name's
        /// trailing separator is in [`dir_only`](Self::dir_only), not here.
        pub key: B,
        /// Only a directory answers to this path: it ends in a separator, or in a `.` after a name
        /// (POSIX), or names a directory index, or has no file name (a root, `.`, a final `..`).
        pub dir_only: bool,
        /// The directories a `.` or `..` is looked up inside, in order, and whether it is a `..`.
        /// POSIX only: Win32 resolves both as text.
        pub inside: Vec<(B, bool)>,
        /// The path reads the default data stream of its name (`f::$DATA`): a file's own data, and
        /// an error for a directory.
        pub data_stream: bool,
        /// The path is the device of the volume whose root is this key (`\\.\C:`), which the host
        /// refuses where the volume exists.
        pub volume: Option<B>,
        /// The path names nothing, whatever is stated (a stream of a name that is not the last).
        pub nothing: bool,
        /// A directory every host has though nothing states it: the current directory and its
        /// ancestors.
        pub implicit: Option<Implicit<B>>,
        /// What the path depends on besides what is stated.
        pub cwd: Cwd,
        /// The host's answer to every question about the path, whatever is stated, if the host does
        /// not look it up.
        pub refusal: Option<(io::ErrorKind, String)>,
    }

    impl<B> Spelling<B> {
        /// A fully qualified path named `key`, with nothing special about it.
        pub fn new(key: B) -> Spelling<B> {
            Spelling {
                key,
                dir_only: false,
                inside: Vec::new(),
                data_stream: false,
                volume: None,
                nothing: false,
                implicit: None,
                cwd: Cwd::Absolute,
                refusal: None,
            }
        }
    }

    /// When a directory that nothing states is there anyway.
    pub enum Implicit<B> {
        Always,
        /// While this entry is (a drive's current directory exists where the drive does).
        IfExists(B),
    }

    /// What a path's meaning depends on.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Cwd {
        /// Nothing: it names one object on every host.
        Absolute,
        /// The current directory, the current drive, or a drive's current directory (`tag` says which:
        /// two paths with one tag depend on the same thing). With `dotdot`, the path starts with a `..`,
        /// so it may name an object beside, or above, anything else.
        Relative { tag: Vec<u8>, dotdot: bool },
    }
}
