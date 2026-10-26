//! The root of a tree that a teardown reaches through the root's pid: a process group, and a macOS
//! fd marker's group.

/// The root of a tree whose group is named by the root's pid, as each send to that group needs it.
/// Built from the root's own handle for one call and never stored, so no checked pid outlives the
/// send it was checked for.
#[derive(Clone, Copy)]
pub(crate) struct GroupRoot<'a> {
    /// Linux: the root's pidfd. A send through it with `PIDFD_SIGNAL_PROCESS_GROUP` names the group
    /// exactly: the kernel resolves it from the pidfd's process, never from a number.
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::BorrowedFd<'a>>,
    /// Whether the root's pid still names its group, read now. `None`: no root was given, for a
    /// caller whose mechanism names no group.
    check: Option<&'a dyn Fn() -> Result<(), String>>,
}

impl<'a> GroupRoot<'a> {
    /// The root that `pidfd` names (Linux; `None` elsewhere, or for a root that has none), checked by
    /// `check`: `Ok` while the root's pid still names its group, else why not.
    #[cfg(unix)]
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables, reason = "only Linux has a pidfd"))]
    pub(crate) fn new(
        pidfd: Option<std::os::fd::BorrowedFd<'a>>,
        check: &'a dyn Fn() -> Result<(), String>,
    ) -> GroupRoot<'a> {
        GroupRoot {
            #[cfg(target_os = "linux")]
            pidfd,
            check: Some(check),
        }
    }

    /// No root, for a caller whose mechanism names no group (a cgroup, a Job Object, a tree walk).
    /// A send by number with it is refused.
    #[cfg(any(not(unix), all(test, target_os = "linux")))]
    pub(crate) fn none() -> GroupRoot<'static> {
        GroupRoot {
            #[cfg(target_os = "linux")]
            pidfd: None,
            check: None,
        }
    }

    /// A root with no pidfd whose check always passes, for a test that sends to a group it owns.
    #[cfg(all(test, unix))]
    pub(crate) fn trusted_for_test() -> GroupRoot<'static> {
        fn trusted() -> Result<(), String> {
            Ok(())
        }
        GroupRoot {
            #[cfg(target_os = "linux")]
            pidfd: None,
            check: Some(&trusted),
        }
    }

    /// The root's pidfd, if it has one.
    #[cfg(target_os = "linux")]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'a>> {
        self.pidfd
    }

    /// Linux 6.9+: whether the root's group still has a member, zombies included, asked through the
    /// root's pidfd, which names the group exactly whoever reaped the root. `None` without a pidfd,
    /// or where the kernel cannot say ([`pidfd_group_has_member`](crate::containment::unix::pidfd_group_has_member)).
    #[cfg(target_os = "linux")]
    pub(crate) fn has_member(&self) -> Option<bool> {
        self.pidfd.and_then(crate::containment::unix::pidfd_group_has_member)
    }

    /// Whether the root's pid still names its group, read now. Called right before each send by
    /// that number, and its answer serves that send alone: where a pid check cannot be made atomic
    /// with its send, the two are back to back.
    ///
    /// On Linux 6.9+ the root's pidfd answers (`has_member`): while the group
    /// has a member its number is its own, whoever reaped the root, and once it has none it is
    /// [`NotItsGroup::Empty`]. Elsewhere the caller's check answers from the root's state.
    #[cfg_attr(not(unix), allow(dead_code, reason = "only Unix sends to a group by number"))]
    pub(crate) fn check(&self) -> Result<(), NotItsGroup> {
        #[cfg(all(test, unix))]
        crate::send_log::record_group(crate::send_log::GroupStep::Check);
        #[cfg(target_os = "linux")]
        match self.has_member() {
            Some(true) => return Ok(()),
            Some(false) => return Err(NotItsGroup::Empty),
            None => {}
        }
        match self.check {
            Some(check) => check().map_err(NotItsGroup::Unproven),
            None => {
                debug_assert!(false, "a send by the root's number was given no root to check");
                Err(NotItsGroup::Unproven("no root was given to check".to_owned()))
            }
        }
    }
}

/// Why [`GroupRoot::check`] refused a send by the group's number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotItsGroup {
    /// Linux 6.9+: the root's pidfd shows the group has no member left, so it can gain none: a
    /// process listed by its number is in another group that took the number.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "only Linux has a pidfd"))]
    Empty,
    /// Nothing shows the number is still the group's, for this reason.
    Unproven(String),
}

impl std::fmt::Display for NotItsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotItsGroup::Empty => f.write_str("the root's process group has no member left"),
            NotItsGroup::Unproven(why) => f.write_str(why),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "group_root_tests.rs"]
mod group_root_tests;
