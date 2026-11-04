//! A stated-facts [`OsProcess`]: what `exited()` answers, in order, and nothing the OS would do. It
//! models no signal. It never blocks; a `Running` look hands out a [`WaitFor`] that the test fires with
//! [`FakeProcess::wake`], and the driver's own blocking call is what a test counts.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::time::Instant;

use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::signal::{Sent, Sig};

/// One scripted answer of [`OsProcess::exited`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum Answer {
    Exited,
    Running,
    /// The look fails with an `Error::Io` of this kind.
    Err(std::io::ErrorKind),
}

pub(crate) struct FakeProcess {
    id: ProcessId,
    script: Mutex<Script>,
    source: Source,
}

/// What looks consume and record, behind one lock so a `&FakeProcess` is `Sync`.
struct Script {
    exits: VecDeque<Answer>,
    looks: usize,
    look_times: Vec<Instant>,
    on_look: Option<Box<dyn FnMut(usize) + Send>>,
}

impl FakeProcess {
    /// A process that answers `exits` to successive looks. A look past the script panics.
    pub(crate) fn new(id: ProcessId, exits: impl IntoIterator<Item = Answer>) -> Self {
        Self {
            id,
            script: Mutex::new(Script {
                exits: exits.into_iter().collect(),
                looks: 0,
                look_times: Vec::new(),
                on_look: None,
            }),
            source: Source::new(),
        }
    }

    /// Fire the [`WaitFor`] that `Running` looks hand out; it stays fired.
    pub(crate) fn wake(&self) {
        self.source.fire();
    }

    /// How many times `exited` was called.
    pub(crate) fn looks(&self) -> usize {
        self.script().looks
    }

    /// The `wait::now()` of each look, taken after its `on_look` hook ran.
    pub(crate) fn look_times(&self) -> Vec<Instant> {
        self.script().look_times.clone()
    }

    /// Run `hook` with the index of each look, at the start of the look.
    pub(crate) fn on_look(&self, hook: impl FnMut(usize) + Send + 'static) {
        self.script().on_look = Some(Box::new(hook));
    }

    fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.script.lock().expect("FakeProcess: a look or hook panicked")
    }
}

impl fmt::Debug for FakeProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.script();
        f.debug_struct("FakeProcess")
            .field("id", &self.id)
            .field("exits", &script.exits)
            .field("looks", &script.looks)
            .finish_non_exhaustive()
    }
}

impl OsProcess for FakeProcess {
    fn signal(&self, _sig: Sig) -> Result<Sent, Error> {
        unimplemented!("FakeProcess models no signal: it states what looks answer")
    }

    fn exited(&self) -> Result<Exit<'_>, Error> {
        let mut script = self.script();
        let index = script.looks;
        script.looks += 1;
        if let Some(hook) = script.on_look.as_mut() {
            hook(index);
        }
        script.look_times.push(crate::wait::now());
        match script
            .exits
            .pop_front()
            .expect("FakeProcess: a look was made past the scripted answers")
        {
            Answer::Exited => Ok(Exit::Exited),
            Answer::Running => Ok(Exit::Running(self.source.wait_for())),
            Answer::Err(kind) => Err(Error::Io(kind.into())),
        }
    }
}

/// What a `Running` look hands out, and the way a test fires it.
#[cfg(unix)]
struct Source {
    rx: std::io::PipeReader,
    tx: std::io::PipeWriter,
}

#[cfg(unix)]
impl Source {
    fn new() -> Self {
        let (rx, tx) = std::io::pipe().expect("FakeProcess: pipe");
        Self { rx, tx }
    }

    fn fire(&self) {
        use std::io::Write;
        (&self.tx).write_all(&[1]).expect("FakeProcess: fire the pipe");
    }

    fn wait_for(&self) -> WaitFor<'_> {
        use std::os::fd::AsFd;
        WaitFor::Readable(self.rx.as_fd())
    }
}

#[cfg(windows)]
struct Source(std::os::windows::io::OwnedHandle);

#[cfg(windows)]
impl Source {
    fn new() -> Self {
        Self(crate::os_process::windows::cancel::new_cancel_event().expect("FakeProcess: create the event"))
    }

    fn fire(&self) {
        crate::os_process::windows::cancel::signal_cancel(&self.0);
    }

    fn wait_for(&self) -> WaitFor<'_> {
        use std::os::windows::io::AsHandle;
        WaitFor::Signalled(self.0.as_handle())
    }
}
