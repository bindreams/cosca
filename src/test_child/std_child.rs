//! A std child a test owns, killed and reaped when it is dropped.

use std::io::Write;
use std::process::{Child, ChildStdin, Command};

/// A std child of this test, killed and reaped when dropped, also while the test panics.
///
/// The guard is the only reaper. A test that reaps the child behind std (a `waitid`, a pidfd) takes
/// it out with [`into_inner`](Self::into_inner) first.
pub(crate) struct StdChild(Option<Child>);

impl StdChild {
    /// Spawn `cmd`, which the test built itself, under the spawn lock (`CREATE_NO_WINDOW` on
    /// Windows), and guard the child.
    #[track_caller]
    pub(crate) fn spawn(cmd: &mut Command) -> Self {
        Self(Some(crate::test_spawn::spawn(cmd).expect("spawn the std child")))
    }

    /// [`spawn`](Self::spawn) with `flags` as the creation word, plus `CREATE_NO_WINDOW` unless
    /// `console` is `Asked`.
    #[cfg(windows)]
    #[track_caller]
    pub(crate) fn spawn_with(cmd: &mut Command, flags: u32, console: super::Console) -> Self {
        Self(Some(
            crate::test_spawn::spawn_with(cmd, flags, console).expect("spawn the std child"),
        ))
    }

    /// The child without its guard; the caller kills and reaps it.
    #[must_use = "the child is no longer killed or reaped when dropped"]
    pub(crate) fn into_inner(mut self) -> Child {
        self.0.take().expect("the child is present until into_inner")
    }

    /// The child without its guard, and the write end of its piped stdin, for a test that hands
    /// both on: the caller kills and reaps the child.
    #[must_use = "the child is no longer killed or reaped when dropped"]
    pub(crate) fn into_parts(self) -> (Child, ChildStdin) {
        let mut child = self.into_inner();
        let stdin = child.stdin.take().expect("piped stdin");
        (child, stdin)
    }
}

impl std::ops::Deref for StdChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        self.0.as_ref().expect("the child is present until into_inner")
    }
}

impl std::ops::DerefMut for StdChild {
    fn deref_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("the child is present until into_inner")
    }
}

impl Drop for StdChild {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        // `writeln!`, not `eprintln!`, which panics on a closed stderr (an abort mid-unwind). After
        // a failed kill, don't wait: the child may still be alive.
        let panicking = std::thread::panicking();
        if let Err(e) = child.kill() {
            _ = writeln!(std::io::stderr(), "StdChild: kill: {e}");
            debug_assert!(panicking, "kill the std child: {e}");
            return;
        }
        if let Err(e) = child.wait() {
            _ = writeln!(std::io::stderr(), "StdChild: wait: {e}");
            debug_assert!(panicking, "reap the std child: {e}");
        }
    }
}

/// A [`BLOCKER_ARGV`](super::BLOCKER_ARGV) child.
pub(crate) fn blocker() -> StdChild {
    blocker_with(|_| {})
}

/// A blocker whose command `configure` sets up first. Stdout defaults to null: an inherited one
/// would stay open in a child that outlives its test. Stdin stays piped; a test that builds its
/// own command uses [`StdChild::spawn`].
pub(crate) fn blocker_with(configure: impl FnOnce(&mut Command)) -> StdChild {
    let mut cmd = blocker_command();
    configure(&mut cmd);
    StdChild::spawn(&mut cmd)
}

/// [`blocker_with`] for a test that sets the creation word: `flags`, plus `CREATE_NO_WINDOW`
/// unless `console` is `Asked`.
#[cfg(windows)]
pub(crate) fn blocker_with_flags(
    flags: u32,
    console: super::Console,
    configure: impl FnOnce(&mut Command),
) -> StdChild {
    let mut cmd = blocker_command();
    configure(&mut cmd);
    StdChild::spawn_with(&mut cmd, flags, console)
}

/// The `BLOCKER_ARGV` command every blocker constructor starts from: piped stdin, stdout null.
fn blocker_command() -> Command {
    let mut cmd = Command::new(super::BLOCKER_ARGV[0]);
    cmd.args(&super::BLOCKER_ARGV[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null());
    cmd
}
