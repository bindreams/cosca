//! Whether another pass of the fd-marker sweep runs.
//!
//! The decision reads the counts of the passes alone, never the OS, so it is the same on every
//! platform and tested on all of them.

/// What follows a pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// Another pass runs.
    Another,
    /// The pass found nothing: the sweep ends.
    Converged,
    /// The passes kept finding new identities and their count did not fall.
    StillForking,
}

/// What follows pass number `pass` (from 1), which found `found` identities no earlier pass had
/// seen, when the pass before it found `previous`.
///
/// Pass 1 counts the tree as it stood; every later pass counts the identities no earlier pass had
/// seen (mostly forks made during the pass before it), so the two are not comparable. Pass 3
/// therefore always runs when pass 2 found something. From then on another pass runs only when the
/// pass found fewer new identities than the pass before it.
///
/// A fork is alive and can fork again before the next pass reaches it, and a member the sweep
/// leaves running (an EPERM-unkillable one, say) keeps forking for as long as it lives. "Found
/// something new" alone can therefore stay true forever, and a numeric cap is forbidden, so the
/// count must fall. A count that must fall cannot do so forever, but it cannot tell a long finite
/// fork chain from an endless one either: some finite trees stop early. The passes can number about
/// what pass 2 found, each a whole-host scan.
pub(crate) fn after_pass(pass: usize, previous: usize, found: usize) -> Next {
    if found == 0 {
        Next::Converged
    } else if pass <= 2 || found < previous {
        Next::Another
    } else {
        Next::StillForking
    }
}

/// Runs `pass` (given its number, from 1) until [`after_pass`] stops the sweep, and says whether it
/// stopped on a count that did not fall ([`Next::StillForking`]). `pass` returns how many
/// identities it found that no earlier pass had seen.
pub(crate) fn run_passes(mut pass: impl FnMut(usize) -> usize) -> bool {
    let mut number = 1;
    let mut previous = 0;
    loop {
        let found = pass(number);
        match after_pass(number, previous, found) {
            Next::Another => {
                previous = found;
                number += 1;
            }
            Next::Converged => return false,
            Next::StillForking => return true,
        }
    }
}

#[cfg(test)]
#[path = "sweep_passes_tests.rs"]
mod sweep_passes_tests;
