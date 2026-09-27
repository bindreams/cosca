//! Test-only: drop whatever lets this process bypass DAC (discretionary access control), so a
//! fixture that needs an `EACCES` precondition can rely on it holding for every caller — not just
//! non-root ones.

/// Makes DAC apply to this process for the rest of its life: drops root (if root) to an
/// unprivileged uid/gid, and — on Linux, regardless of uid — strips `CAP_DAC_OVERRIDE` and
/// `CAP_DAC_READ_SEARCH` from the effective, permitted and ambient capability sets. Neither
/// traditional root nor a non-root caller carrying either capability ambient (independently of
/// uid — see below) can bypass a permission check afterwards.
///
/// A plain `setuid()` away from root already clears every capability set as a side effect
/// (`capabilities(7)`, "Effect of User ID Changes on Capabilities", rule 1: a transition that
/// leaves NONE of the real/effective/saved uid at 0, where at least one of them previously was,
/// clears the permitted, effective AND ambient sets). That rule never fires for a caller that was
/// never uid 0 to begin with: an ambient capability carried by an ALREADY non-root caller
/// survives a bare `setuid()` untouched, because the ambient set is copied back into the
/// permitted and effective sets at every `execve` — including this process's own re-exec into the
/// fixture that calls this function. The explicit capability drop below is what closes that gap;
/// it needs no elevated privilege of its own, since a process may always shed capabilities from
/// its own sets.
///
/// Call this ONLY at the very start of a freshly re-exec'd, single-test fixture process (see
/// [`crate::test_child::run_fixture`]): it changes this process's uid, gid, and (on Linux)
/// capability sets permanently, which would corrupt every other concurrently running test if it
/// ran inside the shared multi-test suite process instead.
pub(crate) fn drop_dac_bypass() {
    drop_root_uid();
    #[cfg(target_os = "linux")]
    drop_dac_capabilities();
}

/// The uid and gid a root fixture drops to: `nobody` on Linux, and the conventional unallocated
/// id elsewhere.
const UNPRIVILEGED: libc::uid_t = 65534;

/// The traditional half of [`drop_dac_bypass`]: root reaches an unsearchable directory anyway
/// (`CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH` are both implicitly held), so a root fixture becomes
/// [`UNPRIVILEGED`] first. A no-op for a caller that was never root.
fn drop_root_uid() {
    // SAFETY: plain credential calls with valid arguments. libtest runs this on a thread of its
    // own, not the main one, which is fine: glibc and musl broadcast a set*id to every thread
    // (setxid), and Darwin's credentials are per-process, so the whole fixture process drops
    // together — and the check that must run restricted happens on this same thread anyway.
    unsafe {
        if libc::geteuid() != 0 {
            return;
        }
        assert_eq!(
            libc::setgroups(0, std::ptr::null()),
            0,
            "setgroups: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::setgid(UNPRIVILEGED),
            0,
            "setgid({UNPRIVILEGED}): {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::setuid(UNPRIVILEGED),
            0,
            "setuid({UNPRIVILEGED}): {}",
            std::io::Error::last_os_error()
        );
    }
}

/// The Linux-only half of [`drop_dac_bypass`]: strips the two DAC-bypass capabilities from every
/// set a non-root caller could carry them in, closing the ambient-capability gap a bare
/// [`drop_root_uid`] leaves open.
#[cfg(target_os = "linux")]
fn drop_dac_capabilities() {
    use caps::{CapSet, Capability};
    for cap in [Capability::CAP_DAC_OVERRIDE, Capability::CAP_DAC_READ_SEARCH] {
        for set in [CapSet::Effective, CapSet::Permitted, CapSet::Ambient] {
            // A capability already absent from `set` is not an error: `caps::drop` reads first
            // and only writes back if the capability was actually present.
            if let Err(e) = caps::drop(None, set, cap) {
                panic!("dropping {cap:?} from {set:?}: {e}");
            }
        }
    }
}
