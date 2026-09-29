//! Test-only: start a fixture without the privilege that bypasses DAC (discretionary access
//! control), so a fixture that needs an `EACCES` precondition can rely on it for every caller,
//! root included.

/// Whether the tests that only mean something with a DAC bypass run: the `COSCA_TEST_ROOT` group of
/// `docs/principles.md`'s "Tests fail loudly and never silently skip" and "System-affecting tests
/// run in a sandbox" sections. On unless `COSCA_TEST_ROOT=0`. An enabled group fails, rather than
/// skips, when the caller has no DAC bypass (see [`holds_dac_bypass`]) or has not given
/// `COSCA_TEST_ROOT_CONSENT=1`. CI's ordinary jobs opt out; the root jobs (#218) do not.
pub(crate) fn root_tests_enabled() -> bool {
    if std::env::var("COSCA_TEST_ROOT").is_ok_and(|v| v == "0") {
        return false;
    }
    assert!(
        holds_dac_bypass(),
        "the root tests need a DAC bypass (CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH effective on Linux, uid 0 elsewhere): \
         run the suite as root or with that capability in a sandbox, or set COSCA_TEST_ROOT=0 to opt out"
    );
    assert!(
        std::env::var("COSCA_TEST_ROOT_CONSENT").is_ok_and(|v| v == "1"),
        "the root tests run as root: set COSCA_TEST_ROOT_CONSENT=1 (in a sandbox) or COSCA_TEST_ROOT=0"
    );
    true
}

/// Whether this thread can bypass DAC: an effective DAC capability on Linux, so a non-root caller
/// holding one (ambient, say) qualifies and a root caller without one does not; uid 0 elsewhere.
fn holds_dac_bypass() -> bool {
    #[cfg(target_os = "linux")]
    {
        rustix::thread::capabilities(None).is_ok_and(|sets| bypasses_dac(sets.effective))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
}

#[cfg(target_os = "linux")]
fn bypasses_dac(effective: rustix::thread::CapabilitySet) -> bool {
    use rustix::thread::CapabilitySet;
    effective.intersects(CapabilitySet::DAC_OVERRIDE | CapabilitySet::DAC_READ_SEARCH)
}

/// Makes `cmd`'s child give up DAC bypass in its own `pre_exec`, after `fork` and before `exec`.
///
/// Credentials and capability sets belong to a thread on Linux. Only the single thread of a
/// just-forked child speaks for the whole process, and everything it later `exec`s or spawns
/// inherits the result. A fixture that dropped from inside a libtest worker thread would leave the
/// thread-group leader, which `/proc/<pid>/...` permission checks consult, unreduced.
///
/// On Linux the child sheds `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` and sets `no_new_privs`,
/// which stops a uid-0 `execve` from regaining them. Elsewhere a root child becomes
/// [`UNPRIVILEGED`], the only DAC bypass there.
///
/// A failure fails `cmd.spawn()`. The hook runs in a forked child of a multithreaded process, so it
/// makes only raw syscalls; its `debug_assert!`s carry literal messages for the same reason.
pub(crate) fn drop_dac_bypass_before_exec(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: the hook makes only async-signal-safe syscalls and allocates nothing on the success
    // path.
    unsafe {
        cmd.pre_exec(drop_dac_bypass);
    }
}

#[cfg(target_os = "linux")]
fn drop_dac_bypass() -> std::io::Result<()> {
    use rustix::thread::CapabilitySet;
    let dac = CapabilitySet::DAC_OVERRIDE | CapabilitySet::DAC_READ_SEARCH;

    // A thread may always shed its own capabilities, so bits it never held make this a no-op.
    // Ambient needs no step of its own: the kernel keeps ambient a subset of permitted and
    // inheritable.
    let mut sets = rustix::thread::capabilities(None)?;
    sets.effective.remove(dac);
    sets.permitted.remove(dac);
    sets.inheritable.remove(dac);
    rustix::thread::set_capabilities(None, sets)?;

    // The bounding set is left alone: `no_new_privs` alone disables the set-user-ID-root grant
    // (`capabilities(7)`, "Effect of no_new_privs") that would give a uid-0 `execve` the bits back.
    rustix::thread::set_no_new_privs(true)?;

    let sets = rustix::thread::capabilities(None)?;
    debug_assert!(
        !sets.effective.intersects(dac) && !sets.permitted.intersects(dac) && !sets.inheritable.intersects(dac),
        "a DAC capability survived the drop"
    );
    debug_assert!(rustix::thread::no_new_privs()?, "no_new_privs did not take");
    Ok(())
}

/// The uid and gid a root fixture drops to where there is no capability system to shed instead.
#[cfg(not(target_os = "linux"))]
pub(crate) const UNPRIVILEGED: libc::uid_t = 65534;

#[cfg(not(target_os = "linux"))]
fn drop_dac_bypass() -> std::io::Result<()> {
    // SAFETY: plain credential syscalls with valid arguments, in a single-threaded child.
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

#[cfg(test)]
#[path = "test_privilege_tests.rs"]
mod test_privilege_tests;
