//! The root of a tree that a teardown reaches through the root's pid: a process group, and a macOS
//! fd marker's group.

/// The root of a tree whose group is named by the root's pid, as each send to that group needs it.
/// Built from the root's own handle for one call and never stored, so no checked pid outlives the
/// send it was checked for.
#[derive(Clone, Copy)]
pub(crate) struct GroupRoot<'a> {
    /// Linux: the root's pidfd. A send through it with `PIDFD_SIGNAL_PROCESS_GROUP` names the group
    /// exactly: the kernel resolves it from the pidfd's process, never from a number.
    #[cfg(unix)]
    pidfd: Option<std::os::fd::BorrowedFd<'a>>,
    /// Whether the root's pid still names its group, read now. `None`: no root was given, for a
    /// caller whose mechanism names no group.
    check: Option<&'a dyn Fn() -> Result<(), String>>,
}

impl<'a> GroupRoot<'a> {
    /// The root that `pidfd` names (Linux; `None` elsewhere, or for a root that has none), checked by
    /// `check`: `Ok` while the root's pid still names its group, else why not.
    #[cfg(unix)]
    pub(crate) fn new(
        pidfd: Option<std::os::fd::BorrowedFd<'a>>,
        check: &'a dyn Fn() -> Result<(), String>,
    ) -> GroupRoot<'a> {
        GroupRoot {
            pidfd,
            check: Some(check),
        }
    }

    /// No root, for a caller whose mechanism names no group (a cgroup, a Job Object, a tree walk).
    /// A send by number with it is refused.
    #[cfg_attr(
        target_os = "linux",
        allow(dead_code, reason = "Linux names no group outside a process group")
    )]
    pub(crate) fn none() -> GroupRoot<'static> {
        GroupRoot {
            #[cfg(unix)]
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
            pidfd: None,
            check: Some(&trusted),
        }
    }

    /// The root's pidfd, if it has one (Linux).
    #[cfg(unix)]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'a>> {
        self.pidfd
    }

    /// Whether the root's pid still names its group, read now. Called right before each send by
    /// that number, and its answer serves that send alone: where a pid check cannot be made atomic
    /// with its send, the two are back to back.
    #[cfg_attr(not(unix), allow(dead_code, reason = "only Unix sends to a group by number"))]
    pub(crate) fn check(&self) -> Result<(), String> {
        #[cfg(all(test, unix))]
        crate::send_log::record_group(crate::send_log::GroupStep::Check);
        match self.check {
            Some(check) => check(),
            None => {
                debug_assert!(false, "a send by the root's number was given no root to check");
                Err("no root was given to check".to_owned())
            }
        }
    }
}
