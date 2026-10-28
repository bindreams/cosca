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

/// Asserts the one record since `mark` on this thread says the root was reaped elsewhere, is a
/// `warn`, and names the walk from the root's pid it skipped.
#[cfg(target_os = "macos")]
#[track_caller]
pub(crate) fn assert_one_reaped_elsewhere_walk_warn(mark: usize, pid: u32) {
    let warns = crate::log_capture::records_since_on_current_thread(mark, REAPED_ELSEWHERE);
    assert_eq!(warns.len(), 1, "exactly one record, got {warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn, "{warns:?}");
    assert!(
        warns[0]
            .1
            .contains(&format!("walk the process table from the root's pid (root pid {pid})")),
        "it names the walk: {warns:?}"
    );
}

/// Every record of the tree ops' skip for a root's number they cannot trust contains this.
pub(crate) const UNTRUSTED_NUMBER: &str = "may name another process";

/// Every record of a skip that killed the root through its pidfd instead contains this.
#[cfg(target_os = "linux")]
pub(crate) const ROOT_KILLED_BY_PIDFD: &str = "killed the root through its pidfd";

/// Every record of a skip that sent the root a `SIGTERM` through its pidfd instead contains this.
#[cfg(target_os = "linux")]
pub(crate) const ROOT_TERMED_BY_PIDFD: &str = "SIGTERM to the root through its pidfd";

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

/// A `cat` in its own session, reading a stdin pipe it gets from the child's handle. A test that
/// must see a signal end it holds that stdin and drops it only after the signal's send: a send that
/// went nowhere then shows in the exit status (`0`, which no signal gives) instead of leaving a
/// wait to block on a root that never ends.
#[cfg(target_os = "linux")]
pub(crate) fn session_cat() -> crate::Command {
    let mut cmd = crate::Command::new();
    cmd.args(["cat"]);
    cmd.contain_with(crate::ContainMode::Session);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd
}

/// [`session_cat`] that ignores `SIGTERM` (an ignored signal stays ignored across `exec`), so only
/// a kill ends it before its stdin closes. It prints a line to its piped stdout once it ignores the
/// signal.
#[cfg(target_os = "linux")]
pub(crate) fn term_ignoring_session_cat() -> crate::Command {
    let mut cmd = crate::Command::new();
    cmd.args(["sh", "-c", r#"trap "" TERM; echo ready; exec cat"#]);
    cmd.contain_with(crate::ContainMode::Session);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
    cmd
}

/// Ends `pid`, this test's own unreaped child, with a `SIGKILL` the test sends itself. For setup
/// that needs a dead root: it goes by none of the routes a test checks, so a mutant that makes one
/// of them send nothing cannot leave the root alive for the wait that follows to block on.
///
/// Debug builds assert `pid` is still a child of this process: a reaped one would leave the number
/// free for another process.
pub(crate) fn kill_own_child(pid: u32) {
    #[cfg(debug_assertions)]
    {
        // Only a number that is no child of ours answers `ECHILD`.
        // SAFETY: an all-zero `siginfo_t` is valid and `waitid` writes only into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        #[cfg(target_os = "linux")]
        let all_kinds = libc::__WALL;
        #[cfg(not(target_os = "linux"))]
        let all_kinds = 0;
        // SAFETY: `info` is a valid out-pointer.
        let peeked = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | all_kinds,
            )
        };
        assert_eq!(
            peeked,
            0,
            "pid {pid} is no unreaped child of this process: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: `pid` is this test's own child and nothing has reaped it, so its number names it.
    let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    assert_eq!(sent, 0, "{}", std::io::Error::last_os_error());
}

/// Reaps `pid`, this process's child that has been told to die, behind its handle's back, as an
/// application with its own reaper does.
pub(crate) fn reap_behind(pid: u32) {
    reap_behind_status(pid);
}

/// [`reap_behind`], answering how `pid` ended.
pub(crate) fn reap_behind_status(pid: u32) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;

    super::wait_until_zombie(pid);
    let mut status = 0;
    // SAFETY: `pid` is this test's own zombie child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
    std::process::ExitStatus::from_raw(status)
}

/// A [`session_sleep`] child, killed and reaped behind its back, and its group's id.
pub(crate) fn foreign_reaped_group_root() -> (crate::Child, u32) {
    let child = session_sleep().spawn().expect("spawn");
    let pid = child.id().pid();
    kill_own_child(pid);
    reap_behind(pid);
    (child, pid)
}

/// Every record of the tree ops' skip for a root whose handle was forgotten unproven contains this.
#[cfg(feature = "tokio")]
pub(crate) const MAY_STILL_RUN: &str = "may still be running";

/// The text of every `warn` since `mark` on this thread.
pub(crate) fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level == log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// A root `sh` that leaves a marker holder outside its process group, then sleeps. The holder is a
/// `cat` that called `setsid` (through `perl`, as macOS has no `setsid` command) and reads the
/// root's stdin through fd 3, as `sh` points a background job's stdin at `/dev/null` otherwise. It
/// prints its pid once it has left the group. It holds the stderr pipe's write end: once the root is
/// gone, stderr reaches EOF exactly when the holder is. With `ignore_term`, the holder ignores
/// `SIGTERM` (an ignored signal stays ignored across `exec`), so only a kill ends it.
#[cfg(target_os = "macos")]
pub(crate) fn escaped_holder_script(ignore_term: bool) -> String {
    let ignore = if ignore_term { r#"$SIG{TERM} = "IGNORE"; "# } else { "" };
    format!(
        r#"exec 3<&0
perl -MPOSIX -e '{ignore}POSIX::setsid() > 0 or die "setsid: $!"; $| = 1; print "$$\n"; open(STDOUT, ">", "/dev/null") or die; exec("cat") or die' <&3 3<&- &
exec 3<&-
exec sleep 300"#
    )
}

/// Asserts that `holder` leads its own process group, so a `killpg` of the root's group misses it.
#[cfg(target_os = "macos")]
#[track_caller]
pub(crate) fn assert_left_the_group(holder: u32, root: u32) {
    // SAFETY: `getpgid` reads a process's group and has no memory-safety preconditions.
    let pgid = unsafe { libc::getpgid(holder as libc::pid_t) };
    assert_eq!(
        pgid,
        holder as libc::pid_t,
        "the holder must lead its own group, not the root's ({root}): {}",
        std::io::Error::last_os_error()
    );
}

/// A spawned [`escaped_holder_script`] tree.
#[cfg(target_os = "macos")]
pub(crate) struct EscapedHolder {
    pub(crate) pid: u32,
    /// Held so the holder's `cat` ends only when killed.
    _stdin: std::io::PipeWriter,
    stderr: std::io::PipeReader,
}

#[cfg(target_os = "macos")]
impl EscapedHolder {
    /// Blocks until the holder is gone: its stderr reaches EOF. Call only once the test has shown
    /// the holder was signalled, so a missed kill fails an assertion rather than hanging here.
    pub(crate) fn assert_dies(mut self) {
        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut self.stderr, &mut rest).expect("the holder's stderr reaches EOF");
        assert!(rest.is_empty(), "unexpected stderr from the holder: {rest:?}");
    }
}

/// Spawns [`escaped_holder_script`] behind an fd marker, with a group unless `mode` is `TreeWalk`,
/// and waits for its holder to leave the root's group.
#[cfg(target_os = "macos")]
pub(crate) fn escaped_holder_tree(mode: crate::ContainMode, ignore_term: bool) -> (crate::Child, EscapedHolder) {
    use std::io::BufRead as _;
    let mut cmd = crate::Command::new();
    cmd.args(["sh", "-c", &escaped_holder_script(ignore_term)]);
    cmd.contain_with(mode);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::pipe_out()).expect("stderr pipe");
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), crate::Containment::FdMarker);
    let mut line = String::new();
    std::io::BufReader::new(child.stdout().expect("stdout pipe"))
        .read_line(&mut line)
        .expect("read the holder's pid");
    let pid: u32 = line.trim().parse().expect("the holder's pid");
    assert_left_the_group(pid, child.id().pid());
    let holder = EscapedHolder {
        pid,
        _stdin: child.stdin().expect("stdin pipe"),
        stderr: child.stderr().expect("stderr pipe"),
    };
    (child, holder)
}
