//! The crate's one policy for a repeating condition: report it at `warn` the first time this
//! process meets it, and at `debug` after. The ten-thousandth report of a standing host property
//! tells an embedder nothing new, and a log an embedder learns to filter out is worse than none.

use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

/// The level to report `condition` at: `Warn` the first time `seen` meets it, `Debug` after.
///
/// Generic over the condition so every once-per-condition report in the crate shares this one
/// policy while keying on its own conditions.
#[cfg_attr(
    not(any(target_os = "linux", feature = "tokio")),
    allow(
        dead_code,
        reason = "callers are the linux cgroup degrade path and the tokio spawn errno path; dead without either"
    )
)]
pub(crate) fn report_level<C: Ord>(seen: &Mutex<BTreeSet<C>>, condition: C) -> log::Level {
    // A panic elsewhere while holding the lock cannot leave a set half-inserted; recover it
    // rather than turn a log call into a second panic.
    if seen.lock().unwrap_or_else(PoisonError::into_inner).insert(condition) {
        log::Level::Warn
    } else {
        log::Level::Debug
    }
}

#[cfg(test)]
#[path = "warn_once_tests.rs"]
mod warn_once_tests;
