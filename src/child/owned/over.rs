//! Tests only: put stated answers in front of a spawned child's real [`OsChild`].

use super::OwnedChild;
use crate::os_process::fake::FakeProcess;

impl OwnedChild {
    /// Answer from the tables `script` gives a [`FakeProcess`] put over this child's own
    /// [`OsChild`](crate::os_process::child::OsChild): a call a table has an answer for gets it, and
    /// every other call, `os_handle` included, is the real one. The test keeps the returned fake to
    /// read what the child asked of it.
    pub(crate) fn script_over(&mut self, script: impl FnOnce(FakeProcess) -> FakeProcess) -> FakeProcess {
        let real = std::mem::replace(&mut self.os, Box::new(FakeProcess::new([])));
        let fake = script(FakeProcess::over(real));
        self.os = Box::new(fake.clone());
        fake
    }
}
