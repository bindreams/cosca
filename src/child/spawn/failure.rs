//! A failed spawn's answer to whether the program could have started.
//!
//! Every spawn, sync and tokio, fails with a [`SpawnFailure`], which the public entry points turn
//! into an [`Error`]: [`Error::MayHaveStarted`] around the cause, or the cause alone.
//!
//! There is deliberately no `From<Error>` (nor `From<io::Error>`) for [`SpawnFailure`], so a `?`
//! on a plain error does not compile in a function that returns one. Every failure point in a
//! spawn names its answer: [`Classify::not_started`] or [`SpawnFailure::started`].

use crate::error::{ChildFate, Error};
use crate::Unreaped;

/// A failed spawn's error, and whether the program could have started.
#[derive(Debug)]
pub(crate) enum SpawnFailure {
    /// The program did not start, and cosca has proved it.
    NotStarted(Error),
    /// As [`NotStarted`](Self::NotStarted), after the spawn forked a child it held and dealt with:
    /// `fate` is what became of it.
    #[cfg(target_os = "linux")]
    NotStartedWithChild {
        /// What failed.
        cause: Error,
        /// What the failed spawn did with the child it held.
        fate: ChildFate,
    },
    /// The program may have started: the child reached `exec` (on Windows, `CreateProcess` or
    /// `ShellExecuteEx` succeeded), or cosca cannot prove it did not.
    MayHaveStarted {
        /// What failed. Never itself an [`Error::MayHaveStarted`].
        cause: Error,
        /// What the failed spawn did with the child.
        fate: ChildFate,
        /// Whether the child is an elevation backend (see [`Error::MayHaveStarted`]).
        wrapper_elevated: bool,
        /// The child, when the spawn hands it to the caller (see [`Error::MayHaveStarted`]).
        unreaped: Option<Box<Unreaped>>,
    },
}

impl SpawnFailure {
    /// A failure after which the program may have started, of a child that is not an elevation
    /// backend. `unreaped` is the child the spawn hands back, if it does; then `fate` is `Running`
    /// with its identity, or `Unknown` (the look at it failed), or `Killed` (the wait for it failed).
    pub(crate) fn started(cause: Error, fate: ChildFate, unreaped: Option<Unreaped>) -> SpawnFailure {
        SpawnFailure::MayHaveStarted {
            cause,
            fate,
            wrapper_elevated: false,
            unreaped: unreaped.map(Box::new),
        }
    }

    /// Applies `f` to the error, keeping the answer.
    #[cfg(any(test, unix))]
    pub(crate) fn map(self, f: impl FnOnce(Error) -> Error) -> SpawnFailure {
        match self {
            SpawnFailure::NotStarted(e) => SpawnFailure::NotStarted(f(e)),
            #[cfg(target_os = "linux")]
            SpawnFailure::NotStartedWithChild { cause, fate } => {
                SpawnFailure::NotStartedWithChild { cause: f(cause), fate }
            }
            SpawnFailure::MayHaveStarted {
                cause,
                fate,
                wrapper_elevated,
                unreaped,
            } => SpawnFailure::MayHaveStarted {
                cause: f(cause),
                fate,
                wrapper_elevated,
                unreaped,
            },
        }
    }

    /// This failure, if it says the program may have started, marked as that of an elevation
    /// backend, whose elevated program may outlive its fate (see [`Error::MayHaveStarted`]).
    pub(crate) fn behind_wrapper(self) -> SpawnFailure {
        match self {
            SpawnFailure::MayHaveStarted {
                cause, fate, unreaped, ..
            } => SpawnFailure::MayHaveStarted {
                cause,
                fate,
                wrapper_elevated: true,
                unreaped,
            },
            not_started => not_started,
        }
    }
}

/// The error of a run-to-completion helper (`output`, `status`, `read`) that failed after its spawn
/// succeeded: the program may have started, and `fate` says what became of its child.
/// `unreaped` is the child its teardown could not end, handed back. `behind_wrapper` is whether the
/// child is an elevation backend.
pub(crate) fn after_the_spawn(
    cause: Error,
    fate: ChildFate,
    unreaped: Option<Unreaped>,
    behind_wrapper: bool,
) -> Error {
    Error::from(failed_after_the_spawn(cause, fate, unreaped, behind_wrapper))
}

/// [`after_the_spawn`], as the [`SpawnFailure`] a spawn returns.
pub(crate) fn failed_after_the_spawn(
    cause: Error,
    fate: ChildFate,
    unreaped: Option<Unreaped>,
    behind_wrapper: bool,
) -> SpawnFailure {
    let failure = SpawnFailure::started(cause, fate, unreaped);
    if behind_wrapper {
        failure.behind_wrapper()
    } else {
        failure
    }
}

// Only the Unix tests take a `SpawnFailure` apart; the rest read the public `Error`.
#[cfg(all(test, unix))]
impl SpawnFailure {
    /// The error and fate of a failure that answered that the program may have started; panics
    /// otherwise.
    #[track_caller]
    pub(crate) fn expect_may_have_started_with(self) -> (Error, ChildFate) {
        let (cause, fate, unreaped) = self.parts();
        // Dropping a handed-back child would wait for it; a test that gets one takes it apart with
        // `test_child::SpawnFailure::expect_may_have_started_parts`.
        if let Some(unreaped) = unreaped {
            unreaped.leak();
            panic!("the spawn handed a child back ({fate:?}): {cause:?}");
        }
        (cause, fate)
    }

    /// The error, fate and handed-back child (if any) of a failure that answered that the program
    /// may have started; panics otherwise. For `test_child`, which wraps the child in its
    /// `HandedBack`.
    #[track_caller]
    pub(crate) fn parts(self) -> (Error, ChildFate, Option<Unreaped>) {
        match self {
            SpawnFailure::MayHaveStarted {
                cause, fate, unreaped, ..
            } => (cause, fate, unreaped.map(|unreaped| *unreaped)),
            SpawnFailure::NotStarted(e) => panic!("expected `may have started`, got `not started`: {e:?}"),
            #[cfg(target_os = "linux")]
            SpawnFailure::NotStartedWithChild { cause, .. } => {
                panic!("expected `may have started`, got `not started`: {cause:?}")
            }
        }
    }

    /// The error and fate of a failure that answered that the program did not start and that the
    /// spawn dealt with a child it held; panics otherwise.
    #[cfg(target_os = "linux")]
    #[track_caller]
    pub(crate) fn expect_not_started_with_child(self) -> (Error, ChildFate) {
        match self {
            SpawnFailure::NotStartedWithChild { cause, fate } => (cause, fate),
            other => panic!("expected `not started` with a child's fate, got {other:?}"),
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
            #[cfg(target_os = "linux")]
            SpawnFailure::NotStartedWithChild { cause, .. } => cause,
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
    let (cause, fate, unreaped) = error_parts(error);
    if let Some(unreaped) = unreaped {
        unreaped.leak();
        panic!("the spawn handed a child back ({fate:?}): {cause:?}");
    }
    (cause, fate)
}

/// The cause, fate and handed-back child (if any) inside an error a public spawn returned, which
/// must say the program may have started. For `test_child`, which wraps the child in its
/// `HandedBack`.
#[cfg(test)]
#[track_caller]
pub(crate) fn error_parts(error: Error) -> (Error, ChildFate, Option<Unreaped>) {
    match error {
        Error::MayHaveStarted {
            fate, source, unreaped, ..
        } => (*source, fate, unreaped.map(|unreaped| *unreaped)),
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
            #[cfg(target_os = "linux")]
            SpawnFailure::NotStartedWithChild { cause: error, .. } => {
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
                unreaped,
            } => {
                debug_assert!(
                    !matches!(cause, Error::MayHaveStarted { .. }),
                    "a `may have started` failure's cause is itself `may have started`: {cause}"
                );
                debug_assert!(
                    unreaped.as_ref().is_none_or(|child| match fate {
                        ChildFate::Running { id } => id == child.id(),
                        ChildFate::Unknown | ChildFate::Killed => true,
                        _ => false,
                    }),
                    "a child handed back is `Running` with its identity, `Unknown` or `Killed`, got {fate:?}"
                );
                Error::MayHaveStarted {
                    fate,
                    wrapper_elevated,
                    source: Box::new(cause),
                    unreaped,
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
/// succeeded. Thread-local; the guard clears them.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::Cell;
    use std::thread::LocalKey;

    use crate::error::Error;

    thread_local! {
        static WAIT: Cell<bool> = const { Cell::new(false) };
        static PUMP: Cell<bool> = const { Cell::new(false) };
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
}

#[cfg(test)]
#[path = "failure_tests.rs"]
mod failure_tests;
