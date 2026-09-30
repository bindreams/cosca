//! The holder's guard: whoever writes `W { token }` arms exactly one, in the same critical
//! section, and every exit of the holder goes through it.

use super::{Guard, SharedChild, State};

/// Arms the holder. Its `Drop`, which runs only if [`finish`](HolderGuard::finish) never did,
/// restores `N` and wakes the waiters, **only if the state is still its own `W`**: another
/// holder's `W` is left alone. It covers an `Err`, a `?` and a panic, before or after the
/// re-lock.
///
/// It owns the re-taken lock too: [`relock`](HolderGuard::relock) stores the `MutexGuard` back,
/// and `Drop` uses it when there is one and locks only when there is none, so a panic after the
/// re-lock cannot self-deadlock.
pub(super) struct HolderGuard<'a> {
    sc: &'a SharedChild,
    token: u64,
    lock: Option<Guard<'a>>,
    done: bool,
}

impl<'a> HolderGuard<'a> {
    /// Write `W { token }` with a fresh token and arm the guard with `lock`, in one critical
    /// section.
    pub(super) fn arm(sc: &'a SharedChild, mut lock: Guard<'a>) -> Self {
        let token = lock.next_token;
        lock.next_token += 1;
        lock.set(State::W { token });
        sc.notify(&mut lock);
        HolderGuard {
            sc,
            token,
            lock: Some(lock),
            done: false,
        }
    }

    /// Drop the lock, for the unlocked wait.
    pub(super) fn unlock(&mut self) {
        self.lock = None;
    }

    /// Take the lock again after the unlocked wait, and check that the state is still this
    /// holder's `W`: nothing else writes `State` while `W` is held.
    pub(super) fn relock(&mut self) {
        if self.lock.is_none() {
            self.lock = Some(self.sc.lock());
        }
        #[cfg(test)]
        super::seams::panic_after_relock_if_armed();
        self.assert_own();
    }

    fn assert_own(&self) {
        let state = self.lock.as_ref().map(|lock| lock.state);
        debug_assert!(
            matches!(state, Some(State::W { token }) if token == self.token),
            "the holder found the state {state:?}, not its own W {{ token: {} }}",
            self.token
        );
    }

    /// Sleep on the handle's `Condvar` for at most `dur`, releasing the lock atomically and
    /// taking it back. A `notify_all` wakes the sleep at once.
    #[cfg(target_os = "linux")]
    pub(super) fn sleep(&mut self, dur: std::time::Duration) {
        let lock = self.lock.take().unwrap_or_else(|| self.sc.lock());
        #[cfg(test)]
        super::seams::before_condvar_block(Some(dur));
        self.lock = Some(self.sc.cv_wait_timeout(lock, dur));
        self.assert_own();
    }

    /// Write `state`, wake the waiters, and hand back the lock with no guard left, in one
    /// critical section. Consuming the guard makes it impossible for a normal return to restore
    /// `N` under a newer holder.
    pub(super) fn finish(mut self, state: State) -> Guard<'a> {
        let mut lock = self.lock.take().unwrap_or_else(|| self.sc.lock());
        debug_assert!(
            matches!(lock.state, State::W { token } if token == self.token),
            "the holder finished over the state {:?}, not its own W",
            lock.state
        );
        lock.set(state);
        self.sc.notify(&mut lock);
        self.done = true;
        lock
    }
}

impl Drop for HolderGuard<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut lock = self.lock.take().unwrap_or_else(|| self.sc.lock());
        if matches!(lock.state, State::W { token } if token == self.token) {
            lock.set(State::N);
            self.sc.notify(&mut lock);
        }
    }
}
