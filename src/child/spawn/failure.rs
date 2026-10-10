//! A failed spawn's answer to whether the program could have started.
//!
//! Every spawn, sync and tokio, fails with a [`SpawnFailure`], which the public entry points turn
//! into an [`Error`]: [`Error::MayHaveStarted`] around the cause, or the cause alone.
//!
//! There is deliberately no `From<Error>` (nor `From<io::Error>`) for [`SpawnFailure`], so a `?`
//! on a plain error does not compile in a function that returns one. Every failure point in a
//! spawn names its answer: [`Classify::not_started`] or [`SpawnFailure::started`].

use crate::error::{ChildFate, Error};

/// A failed spawn's error, and whether the program could have started.
#[derive(Debug)]
pub(crate) enum SpawnFailure {
    /// The program did not start, and cosca has proved it.
    NotStarted(Error),
    /// The program may have started: the child reached `exec` (on Windows, `CreateProcess` or
    /// `ShellExecuteEx` succeeded), or cosca cannot prove it did not.
    MayHaveStarted {
        /// What failed. Never itself an [`Error::MayHaveStarted`].
        cause: Error,
        /// What the failed spawn did with the child.
        fate: ChildFate,
        /// Whether the child is an elevation backend (see [`Error::MayHaveStarted`]).
        wrapper_elevated: bool,
    },
}

impl SpawnFailure {
    /// A failure after which the program may have started, of a child that is not an elevation
    /// backend.
    pub(crate) fn started(cause: Error, fate: ChildFate) -> SpawnFailure {
        SpawnFailure::MayHaveStarted {
            cause,
            fate,
            wrapper_elevated: false,
        }
    }

    /// Applies `f` to the error, keeping the answer.
    #[cfg(any(test, unix))]
    pub(crate) fn map(self, f: impl FnOnce(Error) -> Error) -> SpawnFailure {
        match self {
            SpawnFailure::NotStarted(e) => SpawnFailure::NotStarted(f(e)),
            SpawnFailure::MayHaveStarted {
                cause,
                fate,
                wrapper_elevated,
            } => SpawnFailure::MayHaveStarted {
                cause: f(cause),
                fate,
                wrapper_elevated,
            },
        }
    }

    /// This failure, if it says the program may have started, marked as that of an elevation
    /// backend, whose elevated program may outlive its fate (see [`Error::MayHaveStarted`]).
    pub(crate) fn behind_wrapper(self) -> SpawnFailure {
        match self {
            SpawnFailure::MayHaveStarted { cause, fate, .. } => SpawnFailure::MayHaveStarted {
                cause,
                fate,
                wrapper_elevated: true,
            },
            not_started => not_started,
        }
    }

    /// This failure, if it says the program may have started, with the error and fate `f` makes of
    /// its cause: for an answer that comes after the failure, from a leaf's abandonment.
    #[cfg(all(feature = "tokio", target_os = "linux"))]
    pub(crate) fn answered_by(self, f: impl FnOnce(Error) -> (Error, ChildFate)) -> SpawnFailure {
        match self {
            SpawnFailure::MayHaveStarted {
                cause,
                wrapper_elevated,
                ..
            } => {
                let (cause, fate) = f(cause);
                SpawnFailure::MayHaveStarted {
                    cause,
                    fate,
                    wrapper_elevated,
                }
            }
            not_started => not_started,
        }
    }

    /// The error itself, whatever the answer.
    #[cfg(all(feature = "tokio", target_os = "linux"))]
    pub(crate) fn error(&self) -> &Error {
        match self {
            SpawnFailure::NotStarted(e) | SpawnFailure::MayHaveStarted { cause: e, .. } => e,
        }
    }
}

/// The error of a run-to-completion helper (`output`, `status`, `read`) that failed after its spawn
/// succeeded: the program may have started, and `fate` says what became of its child.
/// `behind_wrapper` is whether the child is an elevation backend.
pub(crate) fn after_the_spawn(cause: Error, fate: ChildFate, behind_wrapper: bool) -> Error {
    let failure = SpawnFailure::started(cause, fate);
    Error::from(if behind_wrapper {
        failure.behind_wrapper()
    } else {
        failure
    })
}

// Only the Unix tests take a `SpawnFailure` apart; the rest read the public `Error`.
#[cfg(all(test, unix))]
impl SpawnFailure {
    /// The error and fate of a failure that answered that the program may have started; panics
    /// otherwise.
    #[track_caller]
    pub(crate) fn expect_may_have_started_with(self) -> (Error, ChildFate) {
        match self {
            SpawnFailure::MayHaveStarted { cause, fate, .. } => (cause, fate),
            SpawnFailure::NotStarted(e) => panic!("expected `may have started`, got `not started`: {e:?}"),
        }
    }

    /// The error of a failure that answered that the program did not start; panics otherwise.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "only the Linux handshake's tests take a not-started failure apart"
        )
    )]
    #[track_caller]
    pub(crate) fn expect_not_started(self) -> Error {
        match self {
            SpawnFailure::NotStarted(e) => e,
            SpawnFailure::MayHaveStarted { cause, fate, .. } => {
                panic!("expected `not started`, got `may have started` ({fate:?}): {cause:?}")
            }
        }
    }
}

/// The cause and fate inside an error a public spawn returned, which must say the program may have
/// started.
#[cfg(test)]
#[track_caller]
pub(crate) fn expect_may_have_started_with(error: Error) -> (Error, ChildFate) {
    match error {
        Error::MayHaveStarted { fate, source, .. } => (*source, fate),
        other => panic!("expected Error::MayHaveStarted, got {other:?}"),
    }
}

/// Whether `error` is an `Unsupported` refusal.
#[cfg(all(test, windows))]
pub(crate) fn unsupported(error: &Error) -> bool {
    matches!(error, Error::Unsupported { .. })
}

/// Whether `error` is an `Io(InvalidInput)` refusal.
#[cfg(all(test, windows))]
pub(crate) fn invalid_input(error: &Error) -> bool {
    matches!(error, Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput)
}

/// An error a public spawn returned, which must say the program did not start.
#[cfg(test)]
#[track_caller]
pub(crate) fn expect_not_started(error: Error) -> Error {
    assert!(
        !matches!(error, Error::MayHaveStarted { .. }),
        "expected an error that says the program did not start, got {error:?}"
    );
    error
}

impl From<SpawnFailure> for Error {
    fn from(failure: SpawnFailure) -> Error {
        match failure {
            SpawnFailure::NotStarted(error) => {
                debug_assert!(
                    !matches!(error, Error::MayHaveStarted { .. }),
                    "a spawn answered both `not started` and `may have started`: {error}"
                );
                error
            }
            SpawnFailure::MayHaveStarted {
                cause,
                fate,
                wrapper_elevated,
            } => {
                debug_assert!(
                    !matches!(cause, Error::MayHaveStarted { .. }),
                    "a `may have started` failure's cause is itself `may have started`: {cause}"
                );
                Error::MayHaveStarted {
                    fate,
                    wrapper_elevated,
                    source: Box::new(cause),
                }
            }
        }
    }
}

/// The plain errors a spawn's failure points produce. Sealed: a [`SpawnFailure`] is not one, so an
/// answered failure cannot be answered again.
pub(crate) trait PlainError: Into<Error> + sealed::Sealed {}
impl PlainError for Error {}
impl PlainError for std::io::Error {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::error::Error {}
    impl Sealed for std::io::Error {}
}

/// Answers, for a failure point in a spawn, that its error leaves the program not started. A failure
/// that may have started is built with [`SpawnFailure::started`], which takes the fate of the child.
pub(crate) trait Classify<T> {
    /// This failure happens before the program can start.
    fn not_started(self) -> Result<T, SpawnFailure>;
}

impl<T, E: PlainError> Classify<T> for Result<T, E> {
    fn not_started(self) -> Result<T, SpawnFailure> {
        self.map_err(|e| SpawnFailure::NotStarted(e.into()))
    }
}

/// Test seams that fail a run-to-completion helper (`output`, `status`, `read`) after its spawn
/// succeeded, or make its child look like an elevation backend. Thread-local; the guard clears them.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::Cell;
    use std::thread::LocalKey;

    use crate::error::Error;

    thread_local! {
        static WAIT: Cell<bool> = const { Cell::new(false) };
        static PUMP: Cell<bool> = const { Cell::new(false) };
        static WRAPPER: Cell<bool> = const { Cell::new(false) };
    }

    /// The message of the error the seams fail with.
    pub(crate) const FAILURE: &str = "forced failure after the spawn (test seam)";

    #[must_use = "the seam is cleared as soon as the guard is dropped"]
    pub(crate) struct Armed(&'static LocalKey<Cell<bool>>);

    impl Drop for Armed {
        fn drop(&mut self) {
            self.0.with(|f| f.set(false));
        }
    }

    fn arm(flag: &'static LocalKey<Cell<bool>>) -> Armed {
        flag.with(|f| f.set(true));
        Armed(flag)
    }

    /// The next `Child::wait` on this thread fails, before it waits.
    pub(crate) fn fail_the_next_wait() -> Armed {
        arm(&WAIT)
    }

    /// The next `Child::communicate` on this thread fails, before it pumps.
    pub(crate) fn fail_the_next_pump() -> Armed {
        arm(&PUMP)
    }

    /// Every child on this thread looks like an elevation backend while the guard lives.
    pub(crate) fn pretend_wrapper() -> Armed {
        arm(&WRAPPER)
    }

    fn take(flag: &'static LocalKey<Cell<bool>>) -> Option<Error> {
        flag.with(|f| f.replace(false))
            .then(|| Error::Io(std::io::Error::other(FAILURE)))
    }

    pub(crate) fn take_wait_failure() -> Option<Error> {
        take(&WAIT)
    }

    pub(crate) fn take_pump_failure() -> Option<Error> {
        take(&PUMP)
    }

    pub(crate) fn wrapper() -> bool {
        WRAPPER.with(Cell::get)
    }
}

#[cfg(test)]
#[path = "failure_tests.rs"]
mod failure_tests;
