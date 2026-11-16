use super::Signal;

/// Every variant on the platform. A variant missing here is missing from the checks below.
const ALL: &[Signal] = &[
    Signal::Hup,
    Signal::Int,
    Signal::Quit,
    Signal::Ill,
    Signal::Trap,
    Signal::Abrt,
    Signal::Bus,
    Signal::Fpe,
    Signal::Usr1,
    Signal::Segv,
    Signal::Usr2,
    Signal::Pipe,
    Signal::Alrm,
    Signal::Term,
    #[cfg(target_os = "linux")]
    Signal::Stkflt,
    Signal::Chld,
    Signal::Cont,
    Signal::Tstp,
    Signal::Ttin,
    Signal::Ttou,
    Signal::Urg,
    Signal::Xcpu,
    Signal::Xfsz,
    Signal::Vtalrm,
    Signal::Prof,
    Signal::Winch,
    Signal::Io,
    #[cfg(target_os = "linux")]
    Signal::Pwr,
    Signal::Sys,
    #[cfg(target_os = "macos")]
    Signal::Emt,
    #[cfg(target_os = "macos")]
    Signal::Info,
];

/// A signal is named as the platform names it, and no two variants are one signal.
///
/// Mutant: a variant converts to another variant's signal.
#[skuld::test]
fn each_signal_has_its_own_number_and_name() {
    assert_eq!(Signal::Term.name(), "SIGTERM");
    assert_eq!(Signal::Usr1.name(), "SIGUSR1");
    let mut numbers: Vec<i32> = ALL.iter().map(|s| s.as_nix() as i32).collect();
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), ALL.len(), "two variants are one signal");
}

/// The variants are the signals `nix` names, less `SIGKILL` and `SIGSTOP`, in both directions.
///
/// Mutant: a signal `nix` names has no variant; a variant is `SIGKILL`, `SIGSTOP` or not a `nix` signal.
#[skuld::test]
fn the_variants_are_the_nix_signals_a_process_can_handle() {
    use nix::sys::signal::Signal as Nix;
    let handled = |n: &Nix| !matches!(n, Nix::SIGKILL | Nix::SIGSTOP);
    for nix in Nix::iterator().filter(handled) {
        assert!(ALL.iter().any(|s| s.as_nix() == nix), "{nix} has no variant");
    }
    for signal in ALL {
        let nix = signal.as_nix();
        assert!(handled(&nix), "{signal:?} is {nix}, which a process cannot handle");
        assert!(Nix::iterator().any(|n| n == nix), "{signal:?} is no signal nix names");
    }
}

/// The two crates' types for a signal carry the same number.
///
/// Mutant: the `rustix` conversion of a variant is another signal.
#[cfg(target_os = "linux")]
#[skuld::test]
fn the_rustix_signal_is_the_nix_signal() {
    for signal in ALL {
        assert_eq!(signal.as_rustix().as_raw(), signal.as_nix() as i32, "{signal:?}");
    }
}
