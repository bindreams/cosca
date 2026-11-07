//! Test-only: start a fixture without the privilege that bypasses DAC (discretionary access
//! control), so a fixture that needs an `EACCES` precondition can rely on it for every caller,
//! root included.

pub(crate) mod setuid;

#[cfg(test)]
#[path = "test_privilege/setuid_helper_tests.rs"]
mod setuid_helper_tests;
#[cfg(test)]
#[path = "test_privilege/setuid_lane_check_tests.rs"]
mod setuid_lane_check_tests;
#[cfg(test)]
#[path = "test_privilege/setuid_protocol_tests.rs"]
mod setuid_protocol_tests;

/// The command for the setuid helper as a `setuid-stdin-block root` child, with no stdio set. The
/// child writes its `+` ready byte to stdout once it is root, and exits with success when its stdin
/// reaches EOF.
///
/// # Panics
/// As [`setuid::setuid_helper`] does.
pub(crate) fn setuid_blocker_command() -> crate::Command {
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    // `args` is the whole argv, program name included.
    cmd.executable(setuid::setuid_helper())
        .args(["cosca_testbin", "setuid-stdin-block", "root"]);
    cmd
}

/// [`setuid_blocker_command`] for a spawn that fails after its fork, which closes the parent ends of
/// its pipes. Returns the command; the write end of the child's stdin, which the caller holds so
/// that the child runs on; and `until_root`, which blocks until the child has written its ready
/// byte and so is root, and which the caller runs once the spawn has returned (a refused kill is
/// refused only from then on).
///
/// # Panics
/// As [`setuid::setuid_helper`] does, and (in `until_root`) when the ready byte does not come.
#[cfg(target_os = "linux")]
pub(crate) fn setuid_blocker_for_a_failing_spawn() -> (crate::Command, crate::PipeWriter, impl FnOnce() + 'static) {
    use std::io::Read as _;
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let (mut ready, ready_end) = std::io::pipe().expect("pipe");
    let mut cmd = setuid_blocker_command();
    cmd.stdin(stdin).expect("set stdin");
    cmd.stdout(crate::Stdio::from_file(std::fs::File::from(
        std::os::fd::OwnedFd::from(ready_end),
    )))
    .expect("set stdout");
    cmd.stderr(crate::Stdio::null()).expect("null stderr");
    let until_root = move || {
        let mut byte = [0u8; 1];
        ready.read_exact(&mut byte).expect("the helper reports ready");
        assert_eq!(byte, *b"+");
    };
    (cmd, writer, until_root)
}

/// Spawns the setuid helper as a `setuid-stdin-block root` child through [`crate::Command`] and
/// waits for its `+` ready byte, so the child is root and blocked on its stdin. Returns the child
/// and the write end of its stdin; closing that makes the helper exit with success.
///
/// Lives here, not in [`setuid`]: integration tests include that file with `#[path]` and have no
/// `crate::Command`.
///
/// # Panics
/// As [`setuid::setuid_helper`] does, and when the spawn or the ready byte fails.
pub(crate) fn spawn_setuid_blocker() -> (crate::Child, crate::PipeWriter) {
    use std::io::Read as _;
    let mut cmd = setuid_blocker_command();
    cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::null()).expect("stderr null");
    let mut child = cmd.spawn().expect("spawn the setuid helper");
    let stdin = child.stdin().expect("piped stdin");
    let mut ready = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut ready)
        .expect("the helper reports ready");
    assert_eq!(ready, *b"+");
    (child, stdin)
}

/// A plain root `sh` over `count` setuid-root helpers, each blocked on the stdin the test holds
/// (the returned write end) and past its ready byte. A helper refuses the kill of its caller.
/// `configure` sets the root's command up further (its containment, say).
#[cfg(unix)]
pub(crate) fn root_over_setuid_blockers(
    count: usize,
    configure: impl FnOnce(&mut crate::Command),
) -> (crate::Child, crate::PipeWriter) {
    use std::io::Read as _;
    // A background job's own stdin is `/dev/null`, so each helper reads fd 3.
    let job = r#""$0" setuid-stdin-block root <&3 3<&- &"#;
    let script = format!("exec 3<&0; {} wait", vec![job; count].join(" "));
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args(["sh", "-c", &script]).arg(setuid::setuid_helper());
    cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::null()).expect("stderr null");
    configure(&mut cmd);
    let mut child = cmd.spawn().expect("spawn the root");
    let stdin = child.stdin().expect("piped stdin");
    let mut ready = vec![0u8; count];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut ready)
        .expect("every helper reports ready");
    assert!(ready.iter().all(|byte| *byte == b'+'), "{ready:?}");
    (child, stdin)
}

/// Fails unless the caller holds a DAC bypass (see [`holds_dac_bypass`]). Off-switch and consent belong
/// to the `ROOT` group (`test_groups.rs`).
pub(crate) fn assert_holds_dac_bypass() {
    assert!(
        holds_dac_bypass(),
        "the root tests need a DAC bypass (CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH effective on Linux, uid 0 elsewhere): \
         run the suite as root or with that capability in a sandbox, or set COSCA_TEST_ROOT=0 to opt out"
    );
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
