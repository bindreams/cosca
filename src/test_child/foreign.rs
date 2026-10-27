//! Std-owned children for tests of the foreign `Process` surface. The test holds the std handle,
//! so it reads the child's own exit status, and the piped stdin it takes out of that handle is the
//! one thing a fixture blocks on.

use std::io::Read;
use std::process::{Child, ChildStdout, Command, Stdio};

/// A `cat` blocked on its piped stdin: it ends by `SIGTERM`'s default disposition, or with 0 once
/// the stdin it holds is dropped.
pub(crate) fn blocker() -> Child {
    crate::test_spawn::spawn(Command::new("cat").stdin(Stdio::piped())).expect("spawn the blocker")
}

/// A root `sh` with a `cat` grandchild, both blocked on one piped stdin; the root's stdout is
/// shared with the grandchild, so it reaches EOF only when the whole tree is gone. The grandchild
/// is forked before the readiness byte, which is read before this returns.
pub(crate) fn blocked_tree() -> (Child, ChildStdout) {
    let mut child = crate::test_spawn::spawn(
        Command::new("sh")
            // `dash` points an async command's stdin at /dev/null before its own redirections run,
            // so the pipe is dup'd to fd 3 first and the grandchild reads that.
            .args(["-c", "exec 3<&0; cat <&3 & echo r; wait"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    )
    .expect("spawn the tree");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut ready = [0u8; 1];
    stdout.read_exact(&mut ready).expect("readiness byte");
    (child, stdout)
}

/// Read `stdout` to EOF: the tree behind [`blocked_tree`] is gone. Call it after the root was
/// waited for, which drops its stdin, so a member that survived the shutdown leaves by itself.
pub(crate) fn assert_tree_gone(mut stdout: ChildStdout) {
    let mut rest = Vec::new();
    stdout
        .read_to_end(&mut rest)
        .expect("read to the end of the tree's stdout");
}
