//! What a graceful shutdown does once its cooperative stop has been sent: the answers of the grace
//! wait, the sweep and the reap, written once for every call (the stop itself is
//! [`stop`](crate::stop)'s).

use crate::error::Error;

/// The answer of a graceful shutdown that failed more than one way: `first`, the failure that is the
/// call's answer (a kill's, a sweep's or a reap's), with the others of the same call (`peers`: the
/// cooperative signal's refusal, the grace wait's failure) below it in order. What failed decides the
/// variant: see [`Error::with_peers_or_warn`] for a leaf `first`, which is the answer as it is and
/// logs its peers. `call` names the call and its process (`graceful_shutdown_tree(123)`), as the
/// warn does.
pub(crate) fn joined(call: &str, first: Error, peers: impl IntoIterator<Item = Error>) -> Error {
    first.with_peers_or_warn(call, peers)
}

/// What a graceful shutdown does once its grace wait has returned, for a lone process. `watch` is
/// the wait's result: `Ok(true)` means the process exited in time and `kill` is not called.
/// Otherwise (the grace ran out, or the wait itself failed, so the grace was unobservable)
/// `kill` runs. A kill error is the answer, with a watch error below it as its peer; with the kill
/// done, a watch error is handed back for the caller to surface once it has finished (`Ok(Some)`).
/// `call` names the call as for [`joined`], built only for a kill error.
pub(crate) fn after_grace(
    call: impl FnOnce() -> String,
    watch: Result<bool, Error>,
    kill: impl FnOnce() -> Result<(), Error>,
) -> Result<Option<Error>, Error> {
    if matches!(watch, Ok(true)) {
        return Ok(None);
    }
    let watch = watch.err();
    match kill() {
        Ok(()) => Ok(watch),
        Err(e) => Err(joined(&call(), e, watch)),
    }
}

/// The tree twin of [`after_grace`]: `sweep` always runs, because a root that exited in grace
/// does not mean its descendants drained. A sweep error is the answer, with a watch error below it
/// as its peer; a watch error alone surfaces after the sweep succeeded.
///
/// The async twin runs the two halves itself, with its sweep awaited between them, and calls
/// [`after_sweep`] with its answer.
pub(crate) fn after_tree_grace(
    call: &str,
    watch: Result<bool, Error>,
    sweep: impl FnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
    after_sweep(call, sweep(), watch)
}

/// What [`after_tree_grace`] does with the sweep's answer: a failed sweep is the answer, with a
/// failed watch below it; with the sweep done, the watch failure is.
pub(crate) fn after_sweep(call: &str, sweep: Result<(), Error>, watch: Result<bool, Error>) -> Result<(), Error> {
    match sweep {
        Ok(()) => watch.map(|_| ()),
        Err(e) => Err(joined(call, e, watch.err())),
    }
}

/// What an owned child's graceful shutdown answers once the root is reaped: the reap's failure, with
/// the refusal of the cooperative signal (`refusal`) and the grace wait's failure (`watch`) below it,
/// else the watch failure alone, else the status. A reap that succeeded follows a sweep that proved the
/// tree clear, which supersedes the refusal.
pub(crate) fn after_reap(
    call: impl FnOnce() -> String,
    waited: Result<std::process::ExitStatus, Error>,
    refusal: Option<Error>,
    watch: Option<Error>,
) -> Result<std::process::ExitStatus, Error> {
    match waited {
        Ok(status) => watch.map_or(Ok(status), Err),
        Err(e) => Err(joined(&call(), e, refusal.into_iter().chain(watch))),
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
