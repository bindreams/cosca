//! Test-only: drop whatever lets this process bypass DAC (discretionary access control), so a
//! fixture that needs an `EACCES` precondition can rely on it holding for every caller — not just
//! non-root ones.

/// Makes DAC apply to the calling thread, and the threads and children it creates afterwards, for
/// the rest of its life. On Linux this strips `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` from
/// the effective, permitted, inheritable and ambient capability sets, and — when this thread
/// holds `CAP_SETPCAP` — the bounding set too, so a uid-0 caller cannot regain either capability
/// at a later `execve` either. Elsewhere it drops root (if root) to an unprivileged uid/gid, the
/// only DAC bypass a non-Linux caller can hold.
///
/// **Linux does not change uid.** Root's own `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` are
/// themselves droppable capabilities, distinct from `CAP_SETUID`/`CAP_SETGID` — measured: root
/// started with `--cap-drop SETUID,SETGID` (or `--cap-drop ALL`, or inside a fresh user namespace
/// made with `unshare -r`) has neither of the latter two, so `setuid()` itself fails there. A
/// fixture that called `setuid()` unconditionally and asserted its success — an earlier version
/// of this function did — panics in exactly the lanes `main` (which asserts nothing) passes.
/// Dropping only the two DAC capabilities, without touching uid at all, is both sufficient (a
/// uid-0 caller stripped of both is already indistinguishable from unprivileged for DAC purposes)
/// and — unlike a `setuid()` this thread may not be able to perform — always available: shedding
/// a capability from a thread's own sets needs no privilege beyond already holding it.
///
/// A plain `setuid()` away from root, where available, clears the permitted, effective and
/// ambient capability sets as a side effect (`capabilities(7)`, "Effect of User ID Changes on
/// Capabilities", rule 1: a transition that leaves NONE of the real/effective/saved uid at 0,
/// where at least one of them previously was, clears those three sets — the inheritable and
/// bounding sets are untouched by any uid change). That rule never fires for a caller that was
/// never uid 0 to begin with: an ambient capability carried by an ALREADY non-root caller
/// survives a bare `setuid()` untouched, because the ambient set is copied back into the
/// permitted and effective sets at every `execve` — including this process's own re-exec into the
/// fixture that calls this function. On Linux, the explicit capability drop closes that gap
/// directly, whether or not a uid change ever happens.
///
/// Call this ONLY at the very start of a freshly re-exec'd, single-test fixture process (see
/// [`crate::test_child::run_fixture`]): it changes this thread's credentials permanently, which
/// would corrupt every other concurrently running test if it ran inside the shared multi-test
/// suite process instead.
pub(crate) fn drop_dac_bypass() -> std::io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    drop_root_uid()?;
    #[cfg(target_os = "linux")]
    drop_dac_capabilities()?;
    Ok(())
}

/// The uid and gid a root fixture drops to: `nobody` on Linux, and the conventional unallocated
/// id elsewhere. Unused on Linux, which never changes uid — see [`drop_dac_bypass`].
#[cfg(not(target_os = "linux"))]
const UNPRIVILEGED: libc::uid_t = 65534;

/// The non-Linux half of [`drop_dac_bypass`]: root reaches an unsearchable directory anyway (it
/// is the platform's only DAC bypass, with no separate capability system to strip), so a root
/// fixture becomes [`UNPRIVILEGED`] first. A no-op for a caller that was never root.
#[cfg(not(target_os = "linux"))]
fn drop_root_uid() -> std::io::Result<()> {
    // SAFETY: plain credential calls with valid arguments. libtest runs this on a thread of its
    // own, not the main one, which is fine: glibc and musl broadcast a set*id to every thread
    // (setxid), and Darwin's credentials are per-process, so the whole fixture process drops
    // together — and the check that must run restricted happens on this same thread anyway.
    unsafe {
        if libc::geteuid() != 0 {
            return Ok(());
        }
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(UNPRIVILEGED) != 0
            || libc::setuid(UNPRIVILEGED) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The Linux-only half of [`drop_dac_bypass`]: strips `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`
/// from every capability set the calling thread could carry them in, via `rustix::thread` (a
/// safe wrapper this crate already depends on for Linux — no reason to add a second capability
/// crate for a test-only helper).
#[cfg(target_os = "linux")]
fn drop_dac_capabilities() -> std::io::Result<()> {
    use rustix::thread::CapabilitySet;
    let dac = CapabilitySet::DAC_OVERRIDE | CapabilitySet::DAC_READ_SEARCH;

    // Effective, permitted, inheritable: one call reads, one writes back all three at once. A
    // thread may always shed its own capabilities from these three sets — no privilege needed,
    // so dropping bits this thread never held (the common, non-root case) is a harmless no-op.
    let mut sets = rustix::thread::capabilities(None)?;
    sets.effective.remove(dac);
    sets.permitted.remove(dac);
    sets.inheritable.remove(dac);
    rustix::thread::set_capabilities(None, sets)?;

    // Ambient: not part of the struct above, cleared per-capability via `prctl`. Issued
    // unconditionally for both capabilities regardless of whether either is actually ambient —
    // lowering an absent ambient capability is a harmless no-op (`PR_CAP_AMBIENT_LOWER` on a bit
    // that was never set still returns success), so no `capability_is_in_ambient_set` check first.
    rustix::thread::configure_capability_in_ambient_set(CapabilitySet::DAC_OVERRIDE, false)?;
    rustix::thread::configure_capability_in_ambient_set(CapabilitySet::DAC_READ_SEARCH, false)?;

    // Bounding: prevents a uid-0 caller from regaining either capability at a LATER `execve`
    // (bounding only ever shrinks over a process's life). Needs `CAP_SETPCAP`, which this thread
    // may not have — that is not a precondition failure, since bounding membership was never what
    // let a `stat` through; only the effective set was. Best-effort, silently skipped otherwise.
    if rustix::thread::capabilities(None)?
        .effective
        .contains(CapabilitySet::SETPCAP)
    {
        rustix::thread::remove_capability_from_bounding_set(CapabilitySet::DAC_OVERRIDE)?;
        rustix::thread::remove_capability_from_bounding_set(CapabilitySet::DAC_READ_SEARCH)?;
    }

    // The precondition every caller of this function relies on, checked here rather than trusted:
    // a caller three functions away that hits an unexpected `Ok(stat)` should not have to work out
    // for itself whether this dropped anything.
    let effective = rustix::thread::capabilities(None)?.effective;
    if effective.intersects(dac) {
        return Err(std::io::Error::other(format!(
            "still holds {:?} in the effective set after dropping it",
            effective & dac
        )));
    }
    Ok(())
}
