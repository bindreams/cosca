//! A stated-facts [`OsProcess`]: what `exited()` and `signal()` answer, in order, and nothing the
//! OS would do. It never blocks; a `Running` look hands out a [`WaitFor`] that the test fires with
//! [`FakeProcess::wake`], and the driver's own blocking call is what a test counts.

use std::collections::VecDeque;
use std::fmt;
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
}

pub(crate) struct FakeProcess {
    id: ProcessId,
    exits: VecDeque<Answer>,
    signals: VecDeque<Result<Sent, Error>>,
    looks: usize,
    look_times: Vec<Instant>,
    on_look: Option<Box<dyn FnMut(usize) + Send>>,
    source: Source,
}

impl FakeProcess {
    /// A process that answers `exits` to successive looks and `signals` to successive sends. A
    /// look or send past the script panics.
    pub(crate) fn new(
        id: ProcessId,
        exits: impl IntoIterator<Item = Answer>,
        signals: impl IntoIterator<Item = Result<Sent, Error>>,
    ) -> Self {
        Self {
            id,
            exits: exits.into_iter().collect(),
            signals: signals.into_iter().collect(),
            looks: 0,
            look_times: Vec::new(),
            on_look: None,
            source: Source::new(),
        }
    }

    /// Fire the [`WaitFor`] that `Running` looks hand out; it stays fired.
    pub(crate) fn wake(&self) {
        self.source.fire();
    }

    /// How many times `exited` was called.
    pub(crate) fn looks(&self) -> usize {
        self.looks
    }

    /// The `wait::now()` of each look, taken after its `on_look` hook ran.
    pub(crate) fn look_times(&self) -> &[Instant] {
        &self.look_times
    }

    /// Run `hook` with the index of each look, at the start of the look.
    pub(crate) fn on_look(&mut self, hook: impl FnMut(usize) + Send + 'static) {
        self.on_look = Some(Box::new(hook));
    }
}

impl fmt::Debug for FakeProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeProcess")
            .field("id", &self.id)
            .field("exits", &self.exits)
            .field("looks", &self.looks)
            .finish_non_exhaustive()
    }
}

impl OsProcess for FakeProcess {
    fn signal(&mut self, _sig: Sig) -> Result<Sent, Error> {
        self.signals
            .pop_front()
            .expect("FakeProcess: a signal was sent past the scripted answers")
    }

    fn exited(&mut self) -> Result<Exit<'_>, Error> {
        let index = self.looks;
        self.looks += 1;
        if let Some(hook) = self.on_look.as_mut() {
            hook(index);
        }
        self.look_times.push(crate::wait::now());
        match self
            .exits
            .pop_front()
            .expect("FakeProcess: a look was made past the scripted answers")
        {
            Answer::Exited => Ok(Exit::Exited),
            Answer::Running => Ok(Exit::Running(self.source.wait_for())),
        }
    }
}

/// What a `Running` look hands out, and the way a test fires it.
#[cfg(unix)]
struct Source {
    /// Kept open: on macOS only the kqueue refers to it.
    #[cfg_attr(
        target_os = "macos",
        allow(dead_code, reason = "only keeps the pipe open for the kqueue")
    )]
    rx: std::io::PipeReader,
    tx: std::io::PipeWriter,
    #[cfg(target_os = "macos")]
    watch: super::macos::ExitWatch,
}

#[cfg(unix)]
impl Source {
    fn new() -> Self {
        let (rx, tx) = std::io::pipe().expect("FakeProcess: pipe");
        #[cfg(target_os = "macos")]
        let watch = {
            use std::os::fd::AsFd;
            super::macos::ExitWatch::readable(rx.as_fd()).expect("FakeProcess: arm the pipe's kqueue")
        };
        Self {
            rx,
            tx,
            #[cfg(target_os = "macos")]
            watch,
        }
    }

    fn fire(&self) {
        use std::io::Write;
        (&self.tx).write_all(&[1]).expect("FakeProcess: fire the pipe");
    }

    fn wait_for(&self) -> WaitFor<'_> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            WaitFor::Readable(self.rx.as_fd())
        }
        #[cfg(target_os = "macos")]
        WaitFor::Kqueue(&self.watch)
    }
}

#[cfg(windows)]
struct Source(std::os::windows::io::OwnedHandle);

#[cfg(windows)]
impl Source {
    fn new() -> Self {
        Self(crate::wait::backend::new_cancel_event().expect("FakeProcess: create the event"))
    }

    fn fire(&self) {
        crate::wait::backend::signal_cancel(&self.0);
    }

    fn wait_for(&self) -> WaitFor<'_> {
        use std::os::windows::io::AsHandle;
        WaitFor::Signalled(self.0.as_handle())
    }
}
