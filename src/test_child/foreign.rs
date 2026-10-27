//! Std-owned children for tests of the foreign `Process` surface. The test holds the std handle,
//! so it reads the child's own exit status, and the piped stdin it takes out of that handle is the
//! one thing a fixture blocks on.

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::send_log::Capture;

/// A `cat` blocked on its piped stdin: it ends by `SIGTERM`'s default disposition, or with 0 once
/// the stdin it holds is dropped.
pub(crate) fn blocker() -> Child {
    crate::test_spawn::spawn(Command::new("cat").stdin(Stdio::piped())).expect("spawn the blocker")
}

/// A root (see [`blocked_tree_root`](super::blocked_tree_root), which defines what it reports) with
/// a `cat` grandchild blocked on the stdin held in `grandchild_stdin`.
pub(crate) struct BlockedTree {
    pub(crate) root: Child,
    pub(crate) grandchild: u32,
    grandchild_stdin: ChildStdin,
    stdout: ChildStdout,
}

/// Spawn a [`BlockedTree`], with the grandchild's pid already read.
///
/// The root shares its stdout with the grandchild, so that reaches EOF only when the whole tree is
/// gone. The grandchild's stdin is kept out of `root.stdin`, so `Child::wait` does not release it.
pub(crate) fn blocked_tree() -> BlockedTree {
    let mut root = crate::test_spawn::spawn(
        crate::test_reexec::command(std::env::current_exe().expect("current_exe"))
            .args(super::blocked_tree_root::argv())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    )
    .expect("spawn the tree");
    let grandchild_stdin = root.stdin.take().expect("piped stdin");
    let mut stdout = root.stdout.take().expect("piped stdout");
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stdout.read_exact(&mut byte).expect("the grandchild's pid");
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    let grandchild = String::from_utf8(line)
        .expect("utf-8")
        .parse()
        .expect("the grandchild's pid");
    BlockedTree {
        root,
        grandchild,
        grandchild_stdin,
        stdout,
    }
}

/// The identity-checked `SIGTERM`s of the tree walk over `root` and its `grandchild`: exactly the
/// root, then the grandchild.
pub(crate) fn assert_tree_sigtermed(sends: &Capture, root: u32, grandchild: u32) {
    assert_eq!(
        sends.by_identity(),
        [(root, libc::SIGTERM), (grandchild, libc::SIGTERM)],
        "the walk must SIGTERM the root {root}, then its grandchild {grandchild}"
    );
}

impl BlockedTree {
    /// Release the grandchild's stdin and assert both members ended of `SIGTERM`: the root by its
    /// own status, the grandchild by the one the root read. A member the walk did not signal
    /// leaves with 0 once released, which fails here.
    pub(crate) fn assert_died_of_sigterm(self) {
        let Self {
            mut root,
            grandchild_stdin,
            mut stdout,
            ..
        } = self;
        drop(grandchild_stdin);
        let status = root.wait().expect("reap the root");
        assert_eq!(status.signal(), Some(libc::SIGTERM), "root: got {status:?}");
        let mut reported = String::new();
        stdout
            .read_to_string(&mut reported)
            .expect("read to the end of the tree's stdout");
        assert_eq!(
            reported.trim(),
            (128 + libc::SIGTERM).to_string(),
            "the grandchild's reported status: 128 + the signal it died of"
        );
    }
}
