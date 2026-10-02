//! Test seam: alias a process's start token.

use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::identity::StartToken;

thread_local! {
    static ALIASES: RefCell<BTreeMap<u32, StartToken>> = const { RefCell::new(BTreeMap::new()) };
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

/// Answers `pid`'s alias for a read that found a `stat`.
pub(super) fn on_read(pid: u32, found: bool) -> Option<StartToken> {
    if !found {
        return None;
    }
    ALIASES.with(|a| a.borrow().get(&pid).copied())
}
