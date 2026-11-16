//! [`Signal`]: a signal a caller may choose for a cooperative stop.

/// A signal sent to ask a process, or a tree of them, to stop.
///
/// Every signal [`nix::sys::signal::Signal`] names on the platform except `SIGKILL` and `SIGSTOP`,
/// which a process cannot handle (a forced end is a kill); a signal only one platform has exists only
/// there. Real-time signals are not included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(dead_code, reason = "crate-private until the public stop functions take it")]
pub(crate) enum Signal {
    Hup,
    Int,
    Quit,
    Ill,
    Trap,
    Abrt,
    Bus,
    Fpe,
    Usr1,
    Segv,
    Usr2,
    Pipe,
    Alrm,
    Term,
    #[cfg(target_os = "linux")]
    Stkflt,
    Chld,
    Cont,
    Tstp,
    Ttin,
    Ttou,
    Urg,
    Xcpu,
    Xfsz,
    Vtalrm,
    Prof,
    Winch,
    Io,
    #[cfg(target_os = "linux")]
    Pwr,
    Sys,
    #[cfg(target_os = "macos")]
    Emt,
    #[cfg(target_os = "macos")]
    Info,
}

impl Signal {
    /// The signal's name as the platform spells it, `"SIGTERM"` for [`Term`](Self::Term).
    pub(crate) fn name(self) -> &'static str {
        self.as_nix().as_str()
    }

    pub(crate) fn as_nix(self) -> nix::sys::signal::Signal {
        use nix::sys::signal::Signal as Nix;
        match self {
            Signal::Hup => Nix::SIGHUP,
            Signal::Int => Nix::SIGINT,
            Signal::Quit => Nix::SIGQUIT,
            Signal::Ill => Nix::SIGILL,
            Signal::Trap => Nix::SIGTRAP,
            Signal::Abrt => Nix::SIGABRT,
            Signal::Bus => Nix::SIGBUS,
            Signal::Fpe => Nix::SIGFPE,
            Signal::Usr1 => Nix::SIGUSR1,
            Signal::Segv => Nix::SIGSEGV,
            Signal::Usr2 => Nix::SIGUSR2,
            Signal::Pipe => Nix::SIGPIPE,
            Signal::Alrm => Nix::SIGALRM,
            Signal::Term => Nix::SIGTERM,
            #[cfg(target_os = "linux")]
            Signal::Stkflt => Nix::SIGSTKFLT,
            Signal::Chld => Nix::SIGCHLD,
            Signal::Cont => Nix::SIGCONT,
            Signal::Tstp => Nix::SIGTSTP,
            Signal::Ttin => Nix::SIGTTIN,
            Signal::Ttou => Nix::SIGTTOU,
            Signal::Urg => Nix::SIGURG,
            Signal::Xcpu => Nix::SIGXCPU,
            Signal::Xfsz => Nix::SIGXFSZ,
            Signal::Vtalrm => Nix::SIGVTALRM,
            Signal::Prof => Nix::SIGPROF,
            Signal::Winch => Nix::SIGWINCH,
            Signal::Io => Nix::SIGIO,
            #[cfg(target_os = "linux")]
            Signal::Pwr => Nix::SIGPWR,
            Signal::Sys => Nix::SIGSYS,
            #[cfg(target_os = "macos")]
            Signal::Emt => Nix::SIGEMT,
            #[cfg(target_os = "macos")]
            Signal::Info => Nix::SIGINFO,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn as_rustix(self) -> rustix::process::Signal {
        rustix::process::Signal::from_named_raw(self.as_nix() as i32)
            .expect("rustix names every signal nix names on Linux")
    }
}

#[cfg(test)]
#[path = "public_tests.rs"]
mod public_tests;
