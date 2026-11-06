//! A stated-facts [`OsChild`]: what each call answers, in order, and nothing the OS would do. A call
//! past its table panics. It never blocks; a `Running` answer hands out a [`WaitFor`] that the test
//! fires with [`FakeProcess::wake`], and the driver's own blocking call is what a test counts.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use super::child::{ExitRecord, Foreign, OsChild, PeekOutcome, TryReapOutcome};
use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
use crate::signal::{Sent, Sig};

/// One scripted answer of [`OsProcess::exited`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum Answer {
    Exited,
    Running,
    /// The look fails with an `Error::Io` of this kind.
    Err(std::io::ErrorKind),
}

/// One scripted answer of [`OsChild::try_reap`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum ReapAnswer {
    Reaped(ExitRecord),
    Running,
    Recheck,
    Foreign(Foreign),
    /// The reap fails with an `Error::Io` of this kind.
    Err(std::io::ErrorKind),
}

/// One scripted answer of [`OsChild::peek`].
pub(crate) type PeekAnswer = Result<PeekOutcome, std::io::ErrorKind>;

/// One scripted answer of [`OsProcess::signal`].
pub(crate) type SignalAnswer = Result<Sent, std::io::ErrorKind>;

/// Cloning gives another handle on the same tables and the same wake source: the test keeps one,
/// the code under test owns the other.
#[derive(Clone)]
pub(crate) struct FakeProcess(Arc<Shared>);

struct Shared {
    script: Mutex<Script>,
    source: Source,
}

/// What calls consume and record, behind one lock so a `&FakeProcess` is `Sync`.
struct Script {
    exits: VecDeque<Answer>,
    peeks: VecDeque<PeekAnswer>,
    reaps: VecDeque<ReapAnswer>,
    signals: VecDeque<SignalAnswer>,
    /// `exited` and `try_reap` calls: the looks.
    looks: usize,
    look_times: Vec<Instant>,
    signal_calls: Vec<Sig>,
    on_look: Option<Box<dyn FnMut(usize) + Send>>,
}

impl FakeProcess {
    /// A process that answers `exits` to successive `exited` looks. Every table starts empty, and a
    /// call past its table panics.
    pub(crate) fn new(exits: impl IntoIterator<Item = Answer>) -> Self {
        Self(Arc::new(Shared {
            script: Mutex::new(Script {
                exits: exits.into_iter().collect(),
                peeks: VecDeque::new(),
                reaps: VecDeque::new(),
                signals: VecDeque::new(),
                looks: 0,
                look_times: Vec::new(),
                signal_calls: Vec::new(),
                on_look: None,
            }),
            source: Source::new(),
        }))
    }

    /// Answer `peeks` to successive [`OsChild::peek`] calls.
    pub(crate) fn peeks(self, peeks: impl IntoIterator<Item = PeekAnswer>) -> Self {
        self.script().peeks = peeks.into_iter().collect();
        self
    }

    /// Answer `reaps` to successive [`OsChild::try_reap`] calls.
    pub(crate) fn reaps(self, reaps: impl IntoIterator<Item = ReapAnswer>) -> Self {
        self.script().reaps = reaps.into_iter().collect();
        self
    }

    /// Answer `signals` to successive [`OsProcess::signal`] calls.
    pub(crate) fn signals(self, signals: impl IntoIterator<Item = SignalAnswer>) -> Self {
        self.script().signals = signals.into_iter().collect();
        self
    }

    /// Fire the [`WaitFor`] that `Running` answers hand out; it stays fired, except that each
    /// `Running` answer of [`OsChild::try_reap`] hands out an unfired one.
    pub(crate) fn wake(&self) {
        self.0.source.fire();
    }

    /// How many looks were made: calls of `exited` and of `try_reap`.
    pub(crate) fn looks(&self) -> usize {
        self.script().looks
    }

    /// The `wait::now()` of each look, taken after its `on_look` hook ran.
    pub(crate) fn look_times(&self) -> Vec<Instant> {
        self.script().look_times.clone()
    }

    /// Each signal sent, in order.
    pub(crate) fn signal_calls(&self) -> Vec<Sig> {
        self.script().signal_calls.clone()
    }

    /// Run `hook` with the index of each look, at the start of the look. It runs with no lock held,
    /// so it may park, and other calls are answered meanwhile.
    pub(crate) fn on_look(&self, hook: impl FnMut(usize) + Send + 'static) {
        self.script().on_look = Some(Box::new(hook));
    }

    /// The lock, whether or not a hook panicked under it.
    fn script(&self) -> MutexGuard<'_, Script> {
        self.0.script.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count a look and run its hook.
    fn begin_look(&self) {
        let (index, hook) = {
            let mut script = self.script();
            let index = script.looks;
            script.looks += 1;
            (index, script.on_look.take())
        };
        if let Some(mut hook) = hook {
            hook(index);
            let mut script = self.script();
            if script.on_look.is_none() {
                script.on_look = Some(hook);
            }
        }
        self.script().look_times.push(crate::wait::now());
    }
}

impl fmt::Debug for FakeProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.script();
        f.debug_struct("FakeProcess")
            .field("exits", &script.exits)
            .field("looks", &script.looks)
            .finish_non_exhaustive()
    }
}

impl OsProcess for FakeProcess {
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        let mut script = self.script();
        script.signal_calls.push(sig);
        match script
            .signals
            .pop_front()
            .expect("FakeProcess: a signal was sent past the scripted answers")
        {
            Ok(sent) => Ok(sent),
            Err(kind) => Err(Error::Io(kind.into())),
        }
    }

    fn exited(&self) -> Result<Exit<'_>, Error> {
        self.begin_look();
        match self
            .script()
            .exits
            .pop_front()
            .expect("FakeProcess: a look was made past the scripted answers")
        {
            Answer::Exited => Ok(Exit::Exited),
            Answer::Running => Ok(Exit::Running(self.0.source.wait_for())),
            Answer::Err(kind) => Err(Error::Io(kind.into())),
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    fn os_handle(&self) -> super::child::OsHandle<'_> {
        self.0.source.os_handle()
    }
}

impl OsChild for FakeProcess {
    fn peek(&self) -> Result<PeekOutcome, Error> {
        match self
            .script()
            .peeks
            .pop_front()
            .expect("FakeProcess: a peek was made past the scripted answers")
        {
            Ok(outcome) => Ok(outcome),
            Err(kind) => Err(Error::Io(kind.into())),
        }
    }

    fn try_reap(&self) -> Result<TryReapOutcome<'_>, Error> {
        self.begin_look();
        match self
            .script()
            .reaps
            .pop_front()
            .expect("FakeProcess: a reap was made past the scripted answers")
        {
            ReapAnswer::Reaped(record) => Ok(TryReapOutcome::Reaped(record)),
            ReapAnswer::Running => {
                // Each reap that runs is a new wait: one holder's wake is not the next one's.
                self.0.source.reset();
                Ok(TryReapOutcome::Running(self.0.source.wait_for()))
            }
            ReapAnswer::Recheck => Ok(TryReapOutcome::Recheck),
            ReapAnswer::Foreign(foreign) => Ok(TryReapOutcome::Foreign(foreign)),
            ReapAnswer::Err(kind) => Err(Error::Io(kind.into())),
        }
    }
}

/// What a `Running` answer hands out, and the way a test fires it.
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

    /// Unfire it: read what `fire` wrote.
    fn reset(&self) {
        use std::io::Read;
        use std::os::fd::AsFd;
        while crate::os_process::poll::is_readable(self.rx.as_fd()).expect("FakeProcess: poll the pipe") {
            (&self.rx).read_exact(&mut [0]).expect("FakeProcess: unfire the pipe");
        }
    }

    fn wait_for(&self) -> WaitFor<'_> {
        use std::os::fd::AsFd;
        WaitFor::Readable(self.rx.as_fd())
    }

    #[cfg(target_os = "linux")]
    fn os_handle(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.rx.as_fd()
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

    /// Unfire it.
    fn reset(&self) {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: the event is alive for the call.
        unsafe {
            windows::Win32::System::Threading::ResetEvent(windows::Win32::Foundation::HANDLE(self.0.as_raw_handle()))
        }
        .expect("FakeProcess: reset the event");
    }

    fn wait_for(&self) -> WaitFor<'_> {
        WaitFor::Signalled(self.os_handle())
    }

    fn os_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        use std::os::windows::io::AsHandle;
        self.0.as_handle()
    }
}
