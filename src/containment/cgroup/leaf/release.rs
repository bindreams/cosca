//! Giving up a leaf on an async `Drop`: bounded work only.

use super::*;

impl CgroupLeaf {
    /// Give up the leaf without waiting: what an async `Drop` does where [`Drop`] would block on
    /// the drain. At most two `rmdir`s and, with the drop's own tree kill, two `cgroup.kill`
    /// writes; a leaf that has not drained is left behind.
    ///
    /// A leaf this handle killed or was armed to kill is left with a `warn` naming its path and
    /// pointing at [`wait_tree`](crate::tokio::Child::wait_tree). A leaf nothing killed keeps
    /// the levels of `Drop`: `debug`, or `warn` only if a kill attempt failed. A drain that could
    /// not be read is reported as that, at the same level.
    ///
    /// Never calls [`abandon`](Self::abandon_before_verdict), `disarm` or `block_until_drained`:
    /// the first two would clear the kill record this reads, and the last is the wait.
    pub(crate) fn release_without_waiting(mut self) {
        debug_assert!(self.report.is_none(), "a released leaf has taken its placement verdict");
        // The leaf's own `Drop` must do nothing but stop the pump after this: it blocks in
        // `drain_and_remove`.
        self.abandoned = true;

        let armed = self.armed.load(Ordering::Relaxed);
        let killed = self.killed.load(Ordering::Relaxed);
        let first = match self.rmdir_leaf() {
            Ok(()) => return,
            Err(e) if removed_after_drain(&e) => return,
            Err(e) => e,
        };
        if !self.child_entered() {
            warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed ({first}); cgroup.kill not written: nothing of the child's is in it"),
            );
            return;
        }
        if armed || killed {
            if let Err(e) = self.hard_kill() {
                warn_leaf_left_behind(
                    &self.leaf_path,
                    format_args!("rmdir failed ({first}) on release; cgroup.kill failed ({e})"),
                );
                return;
            }
        }
        let unread = match self.drain_now() {
            Ok(crate::containment::TreeDrain::AllMembersExited) => {
                self.sweep_and_retry_rmdir("on release, after the tree drained");
                return;
            }
            Ok(_) => None,
            Err(e) => Some(e),
        };
        // A failed read says nothing about the drain: it is reported as what it is.
        let cause = match &unread {
            Some(e) => format!("its drain could not be read ({e})"),
            None => "the tree it killed has not drained".to_owned(),
        };
        if armed || killed {
            warn_leaf_left_behind(
                &self.leaf_path,
                format_args!(
                    "rmdir failed ({first}) on release, and {cause}; nothing waited for it: call \
                     wait_tree().await before dropping to have the leaf removed"
                ),
            );
        } else if self.kill_attempt_failed.load(Ordering::Relaxed) {
            warn_leaf_left_behind(
                &self.leaf_path,
                format_args!(
                    "rmdir failed ({first}); its cgroup.kill failed, so the tree that opted out of \
                     Drop's own teardown is still running{}",
                    unread.as_ref().map_or(String::new(), |_| format!("; {cause}"))
                ),
            );
        } else {
            log::debug!(
                "cgroup leaf {} is left behind for a tree that opted out of teardown ({first}){}",
                self.leaf_path.display(),
                unread.as_ref().map_or(String::new(), |_| format!("; {cause}"))
            );
        }
    }
}

#[cfg(test)]
#[path = "release_tests.rs"]
mod release_tests;
