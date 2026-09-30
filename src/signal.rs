//! The signals cosca sends to a process it owns.

/// A signal cosca sends to an owned process. Windows has only `Kill`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "`Term` and `Stop` are sent from the lone `terminate` on")]
pub(crate) enum Sig {
    Kill,
    Term,
    Stop,
}

#[cfg(target_os = "linux")]
impl Sig {
    pub(crate) fn as_rustix(self) -> rustix::process::Signal {
        match self {
            Sig::Kill => rustix::process::Signal::KILL,
            Sig::Term => rustix::process::Signal::TERM,
            Sig::Stop => rustix::process::Signal::STOP,
        }
    }
}

#[cfg(target_os = "macos")]
impl Sig {
    pub(crate) fn as_libc(self) -> libc::c_int {
        match self {
            Sig::Kill => libc::SIGKILL,
            Sig::Term => libc::SIGTERM,
            Sig::Stop => libc::SIGSTOP,
        }
    }
}
