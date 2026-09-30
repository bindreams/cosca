//! Test seam: alias a process's start token, and count start-token reads.

use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::identity::StartToken;

thread_local! {
    static ALIASES: RefCell<BTreeMap<u32, StartToken>> = const { RefCell::new(BTreeMap::new()) };
    static READS: RefCell<BTreeMap<u32, usize>> = const { RefCell::new(BTreeMap::new()) };
}

/// While the guard lives, a start-token read for `pid` that found a `stat` answers `token`.
///
/// A read that found no process still answers `Gone`: the seam aliases an identity and never
/// invents a process. Arm it after the process it aliases over exists.
pub(crate) fn alias_token(pid: u32, token: StartToken) -> AliasGuard {
    ALIASES.with(|a| {
        let previous = a.borrow_mut().insert(pid, token);
        assert!(previous.is_none(), "an alias for pid {pid} is already armed");
    });
    AliasGuard { pid }
}

#[must_use = "the alias ends when the guard drops"]
pub(crate) struct AliasGuard {
    pid: u32,
}

impl Drop for AliasGuard {
    fn drop(&mut self) {
        ALIASES.with(|a| a.borrow_mut().remove(&self.pid));
    }
}

pub(crate) mod alias_token {
    /// How many start-token reads for `pid` this thread has made, armed or not.
    pub(crate) fn reads(pid: u32) -> usize {
        super::READS.with(|r| r.borrow().get(&pid).copied().unwrap_or(0))
    }
}

/// Counts one read of `pid`, and answers its alias.
pub(super) fn on_read(pid: u32, found: bool) -> Option<StartToken> {
    READS.with(|r| *r.borrow_mut().entry(pid).or_insert(0) += 1);
    if !found {
        return None;
    }
    ALIASES.with(|a| a.borrow().get(&pid).copied())
}
