use std::io::Write;

use crate::identity::ProcessId;
use crate::Process;

/// A test's hold on a real child that the product lets go (a `detach`, `kill_on_drop(false)`, a
/// let-go `Unreaped`, a teardown that leaves it): the child's `release` (the write end of its stdin,
/// `None` where something else ends it) and a [`Process`] opened while the test still held the child.
///
/// Dropping the guard drops the release, then waits, with no cap, until the child has exited. A test
/// that returned earlier would leave the child running past its own process, holding the runner's
/// captured stdout and stderr open: nextest marks the test LEAK.
///
/// Only for a child that ends once its release drops, or that is already dead. A child that is
/// frozen or stopped never ends, and its guard would hang the test.
///
/// It waits through [`Process::wait`], so it is one type on every platform and holds for a child
/// that something reaps meanwhile. A test that needs the unreaped zombie or its exit record uses
/// `wait_until_zombie` (Unix); a frozen child, which no guard may take, is `crate::test_frozen::Remote`'s
/// (Windows). That wait takes this thread's wait seams like any wait of the crate's: a test that arms
/// `wait::fault` or reads `wait::block_probe` drops its guard after it has read them.
///
/// The release is a sync pipe writer, closed when it drops. An async test gives its child a stdin
/// from [`held_writer_stdin`](super::held_writer_stdin), not a tokio `ChildStdin`. On Windows that
/// one's pipe closes only when the reactor next runs, and this wait blocks the thread that would
/// run it.
pub(crate) struct ExitGuard {
    release: Option<crate::PipeWriter>,
    process: Process,
}

impl ExitGuard {
    /// Holds `release` and the child `id`, opened at once: while the test holds the child its pid
    /// cannot have been reused.
    #[track_caller]
    pub(crate) fn new(release: Option<crate::PipeWriter>, id: ProcessId) -> Self {
        let process = Process::open(id)
            .expect("open the child the test lets go")
            .expect("the child the test lets go is running");
        Self { release, process }
    }
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        drop(self.release.take());
        // `writeln!`, not `eprintln!`, which panics on a closed stderr (an abort mid-unwind).
        if let Err(e) = self.process.wait() {
            _ = writeln!(std::io::stderr(), "ExitGuard: wait: {e}");
            if !std::thread::panicking() {
                panic!("wait for the child to exit: {e}");
            }
        }
    }
}
