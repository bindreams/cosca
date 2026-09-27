//! Test-only: drop whatever lets this process bypass DAC (discretionary access control), so a
//! fixture that needs an `EACCES` precondition can rely on it holding for every caller — not just
//! non-root ones.

/// Makes DAC apply to the calling thread, and the threads and children it creates afterwards, for
/// the rest of its life. On Linux this strips `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` from
/// the effective, permitted and inheritable capability sets (the ambient set follows for free —
/// see below), sets `no_new_privs` so a uid-0 caller's later `execve` cannot regain either
/// capability from the bounding set (see below for why that is otherwise live), and — when this
/// thread holds `CAP_SETPCAP` — drops both from the bounding set too, so even a caller that does
/// not set `no_new_privs` on its own children loses them for good. Elsewhere it drops root (if
/// root) to an unprivileged uid/gid, the only DAC bypass a non-Linux caller can hold.
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
/// suite process instead. Asserted in debug via
/// [`crate::test_child::parent_pid_matches`] — the same real-parent-pid check `run_fixture`'s own
/// callers gate on, so a caller that reaches this function without having gone through that gate
/// panics here instead of corrupting the shared process silently.
pub(crate) fn drop_dac_bypass() -> std::io::Result<()> {
    debug_assert!(
        crate::test_child::parent_pid_matches(),
        "drop_dac_bypass must only run in a freshly re-exec'd, single-test fixture process — \
         this process's real parent does not match the pid run_fixture recorded"
    );
    if let Ok(msg) = std::env::var(INJECT_FAILURE_ENV) {
        return Err(std::io::Error::other(msg));
    }
    #[cfg(not(target_os = "linux"))]
    drop_root_uid()?;
    #[cfg(target_os = "linux")]
    drop_dac_capabilities()?;
    Ok(())
}

/// Test-only: when set, [`drop_dac_bypass`] returns `Err` immediately with this value as the
/// message, skipping the real drop entirely. This is the seam each of `drop_dac_bypass`'s two
/// call sites drives on its OWN — a mutant at either site (discarding the `Result`, or otherwise
/// not propagating the `Err`) is only caught by a driver that goes through that SAME site, not by
/// one that calls its downstream handler directly (measured: an earlier version of
/// `exact_posix_tests.rs::reports_and_exits_on_an_injected_dac_bypass_failure` called
/// `report_and_exit_on_dac_bypass_failure` directly, and a mutant that dropped the call to
/// `drop_dac_bypass` at the real call site entirely went undetected). Driven from
/// `exact_posix_tests.rs::reports_and_exits_on_an_injected_dac_bypass_failure` (its
/// `report_and_exit_on_dac_bypass_failure(drop_dac_bypass())` call site) and from
/// `resolve_base_tests.rs::a_denied_candidate_fails_a_loadable_only_search_closed_reports_an_injected_dac_bypass_failure`
/// (one of its three `.expect()` sites — the other two share the identical one-line pattern, so
/// are not separately driven). A real failure IS forceable without this seam —
/// `strace -f -e trace=capset -e inject=capset:error=EPERM`, measured — just not portably enough
/// to run as an ordinary `cargo test`.
pub(crate) const INJECT_FAILURE_ENV: &str = "COSCA_FIXTURE_INJECT_DAC_BYPASS_FAILURE";

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
    // own, not the main one, which is fine: Darwin's credentials are per-process, so the whole
    // fixture process drops together — and the check that must run restricted happens on this
    // same thread anyway.
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
    //
    // No separate ambient step: the kernel enforces "a capability is never ambient unless it is
    // also permitted AND inheritable" as an invariant of capset itself, so dropping a bit from
    // either of those two here already clears it from ambient too (measured: `CapAmb` reads `0`
    // afterwards with no `prctl(PR_CAP_AMBIENT, …)` call at all). An earlier version of this
    // function called `PR_CAP_AMBIENT_LOWER` explicitly, redundantly — and on a kernel without
    // ambient support (Linux < 4.3), or under a seccomp filter that refuses `PR_CAP_AMBIENT`
    // specifically (the bounding-set and `no_new_privs` calls below are `prctl` too, and stay
    // unaffected by such a filter), that call was the only step that failed: `main`, which never
    // touches ambient, passes there; this function, for no reason once capset's own invariant
    // already does the job, did not.
    let mut sets = rustix::thread::capabilities(None)?;
    sets.effective.remove(dac);
    sets.permitted.remove(dac);
    sets.inheritable.remove(dac);
    rustix::thread::set_capabilities(None, sets)?;

    // Bounding: prevents a uid-0 caller from regaining either capability at a LATER `execve` via
    // the ordinary route — bounding only ever shrinks over a process's life. Needs `CAP_SETPCAP`,
    // which this thread may not have — that is not a precondition failure, since bounding
    // membership was never what let a `stat` through; only the effective set was. Best-effort,
    // silently skipped otherwise (`no_new_privs` below is what covers that case instead).
    if rustix::thread::capabilities(None)?
        .effective
        .contains(CapabilitySet::SETPCAP)
    {
        rustix::thread::remove_capability_from_bounding_set(CapabilitySet::DAC_OVERRIDE)?;
        rustix::thread::remove_capability_from_bounding_set(CapabilitySet::DAC_READ_SEARCH)?;
    }

    // Without CAP_SETPCAP, the bounding set above is untouched, and a uid-0 thread's `execve` of
    // an ordinary binary still regains everything in it: measured, a child this thread execs
    // afterward has `CapEff` restored to the FULL bounding set, via the kernel's legacy
    // set-user-ID-root compatibility grant (`capabilities(7)`) — "if the caller is uid 0, the
    // exec'd program's permitted set becomes the bounding set" — which applies regardless of
    // what this thread's OWN effective/permitted sets were reduced to. `no_new_privs` disables
    // exactly that grant (same reference, "Effect of no_new_privs"), so the exec'd child inherits
    // this thread's ALREADY-reduced set instead of the raw bounding set. It needs no privilege of
    // its own and cannot be unset once set, which is exactly the "for the rest of its life"
    // guarantee this function promises.
    rustix::thread::set_no_new_privs(true)?;

    // The precondition every caller of this function relies on, checked here rather than trusted:
    // a caller three functions away that hits an unexpected `Ok(stat)` should not have to work out
    // for itself whether this dropped anything. Checks permitted and inheritable too, not just
    // effective: a `capset` that dropped effective but left a bit in permitted would still pass an
    // effective-only check on THIS thread, yet a uid-0 `execve` recomputes the CHILD's permitted
    // set from the parent's permitted (intersected with bounding) — measured, exactly that gap —
    // so an effective-only postcondition would miss it even though the exec-time regain it exists
    // to catch is real.
    let sets = rustix::thread::capabilities(None)?;
    if sets.effective.intersects(dac) || sets.permitted.intersects(dac) || sets.inheritable.intersects(dac) {
        return Err(std::io::Error::other(format!(
            "still holds {:?} somewhere in effective {:?}, permitted {:?} or inheritable {:?}",
            dac, sets.effective, sets.permitted, sets.inheritable
        )));
    }
    if !rustix::thread::no_new_privs()? {
        return Err(std::io::Error::other("no_new_privs did not take"));
    }
    Ok(())
}
