//! Fixtures for a contained root reaped behind its handle's back, and the record its tree ops log
//! for it.

/// Every record of the tree ops' skip for a root reaped elsewhere contains this.
pub(crate) const REAPED_ELSEWHERE: &str = "was reaped elsewhere";

/// Asserts the one record since `mark` on this thread says the root was reaped elsewhere, is a
/// `warn`, and names the group it left unsignalled.
#[track_caller]
pub(crate) fn assert_one_reaped_elsewhere_warn(mark: usize, pgid: u32) {
    let warns = crate::log_capture::records_since_on_current_thread(mark, REAPED_ELSEWHERE);
    assert_eq!(warns.len(), 1, "exactly one record, got {warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn, "{warns:?}");
    assert!(
        warns[0].1.contains(&format!("pgid {pgid}")),
        "it names the group: {warns:?}"
    );
}

/// Every record of the tree ops' skip for a root's number they cannot trust contains this.
pub(crate) const UNTRUSTED_NUMBER: &str = "may name another process";

/// Asserts the one record since `mark` on this thread says the root's number may name another
/// process, is a `warn`, and names the group it left unsignalled.
#[track_caller]
pub(crate) fn assert_one_untrusted_number_warn(mark: usize, pgid: u32) {
    let warns = crate::log_capture::records_since_on_current_thread(mark, UNTRUSTED_NUMBER);
    assert_eq!(warns.len(), 1, "exactly one record, got {warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn, "{warns:?}");
    assert!(
        warns[0].1.contains(&format!("pgid {pgid}")),
        "it names the group: {warns:?}"
    );
}

/// A `sleep` in its own session: `Attached::ProcessGroup`, or on macOS an fd marker with a group.
pub(crate) fn session_sleep() -> crate::Command {
    let mut cmd = crate::Command::new();
    cmd.args(["sleep", "300"]);
    cmd.contain_with(crate::ContainMode::Session);
    cmd
}

/// Reaps `pid`, this process's child that has been told to die, behind its handle's back, as an
/// application with its own reaper does.
pub(crate) fn reap_behind(pid: u32) {
    super::wait_until_zombie(pid);
    let mut status = 0;
    // SAFETY: `pid` is this test's own zombie child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
}

/// A [`session_sleep`] child, killed and reaped behind its back, and its group's id.
pub(crate) fn foreign_reaped_group_root() -> (crate::Child, u32) {
    let child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    child.kill().expect("kill the root");
    reap_behind(pid);
    (child, pid)
}
