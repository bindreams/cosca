//! A std child a test owns, killed and reaped when it is dropped.

use std::io::Write;
use std::process::{Child, Command};

/// A std child of this test, killed and reaped when dropped, also while the test panics.
/// Dereferences to its [`Child`].
///
/// The guard is the only reaper. A test that reaps the child behind std (a `waitid`, a pidfd) takes
/// it out with [`into_inner`](Self::into_inner) first.
#[cfg_attr(windows, allow(dead_code, reason = "its held-child callers are not converted yet"))]
pub(crate) struct StdChild(Option<Child>);

impl StdChild {
    /// The child, which no longer has a guard: the caller kills and reaps it.
    #[allow(dead_code, reason = "its held-child callers are not converted yet")]
    #[must_use = "the child is no longer killed or reaped when dropped"]
    pub(crate) fn into_inner(mut self) -> Child {
        self.0.take().expect("the child is present until into_inner")
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

/// A [`BLOCKER_ARGV`](super::BLOCKER_ARGV) child with stdout inherited.
#[cfg_attr(windows, allow(dead_code, reason = "its held-child callers are not converted yet"))]
pub(crate) fn blocker() -> StdChild {
    blocker_with(|_| {})
}

/// A [`BLOCKER_ARGV`](super::BLOCKER_ARGV) child whose command `configure` has set up first: its
/// stdout, stderr, credentials, `pre_exec`. The stdin stays piped.
#[cfg_attr(windows, allow(dead_code, reason = "its held-child callers are not converted yet"))]
pub(crate) fn blocker_with(configure: impl FnOnce(&mut Command)) -> StdChild {
    let mut cmd = super::held_std_blocker(std::process::Stdio::inherit());
    configure(&mut cmd);
    StdChild(Some(crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker")))
}
