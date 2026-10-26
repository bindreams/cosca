//! Linux: a tree call on a process group whose root is reaped. On 6.9+ the root's pidfd names the
//! group exactly, whoever reaped the root; below 6.9 the root's own handle decides what goes out by
//! the group's number.

use std::io::Read as _;

use crate::send_log::{Capture, GroupStep, Route};
use crate::test_child::reaped_elsewhere::{foreign_reaped_group_root, reap_behind};
use crate::test_groups::{pidfd_group_signal, Group};

/// A session root `sh` that leaves a member in its group, says `started`, and sleeps holding neither
/// the member's stdin nor stderr. The member reads stdin through fd 3 (`sh` points a background
/// job's stdin at `/dev/null` otherwise) and, at its end of file, says `survived` on stderr.
pub(crate) const ROOT_WITH_A_MEMBER: [&str; 3] = [
    "sh",
    "-c",
    "exec 3<&0; (cat <&3 3<&- >/dev/null; echo survived >&2) & echo started; exec sleep 300 <&- 3<&- 2>/dev/null",
];

/// A test's ends of the pipes of [`ROOT_WITH_A_MEMBER`]'s member.
pub(crate) struct Member {
    stdin: std::io::PipeWriter,
    stderr: std::io::PipeReader,
}

impl Member {
    /// The pipes of a [`ROOT_WITH_A_MEMBER`] spawn, to give its stdin, stdout and stderr, and the
    /// read end of its stdout.
    pub(crate) fn pipes() -> (MemberStdio, std::io::PipeReader, Member) {
        let (stdin_read, stdin) = std::io::pipe().expect("stdin pipe");
        let (started, stdout_write) = std::io::pipe().expect("stdout pipe");
        let (stderr, stderr_write) = std::io::pipe().expect("stderr pipe");
        let stdio = |end: std::os::fd::OwnedFd| crate::Stdio::from_file(std::fs::File::from(end));
        let child_ends = MemberStdio {
            stdin: stdio(stdin_read.into()),
            stdout: stdio(stdout_write.into()),
            stderr: stdio(stderr_write.into()),
        };
        (child_ends, started, Member { stdin, stderr })
    }

    /// Closes the member's stdin and reads its stderr to the end. A member still running ends at that
    /// end of file and says `survived`; one already sent a fatal signal never runs again, and says
    /// nothing. Neither waits on a signal's delivery.
    pub(crate) fn end(self) -> String {
        let Member { stdin, mut stderr } = self;
        drop(stdin);
        let mut said = String::new();
        stderr
            .read_to_string(&mut said)
            .expect("read the member's stderr to its end");
        said
    }

    /// Asserts the member was sent a fatal signal before this call.
    #[track_caller]
    pub(crate) fn assert_killed(self) {
        let said = self.end();
        assert!(
            !said.contains("survived"),
            "the group's member was not killed: {said:?}"
        );
    }

    /// Asserts the member was sent no fatal signal.
    #[track_caller]
    pub(crate) fn assert_survived(self) {
        let said = self.end();
        assert!(said.contains("survived"), "the group's member was killed: {said:?}");
    }
}

/// The child's ends of [`Member::pipes`].
pub(crate) struct MemberStdio {
    pub(crate) stdin: crate::Stdio,
    pub(crate) stdout: crate::Stdio,
    pub(crate) stderr: crate::Stdio,
}

/// Reads [`ROOT_WITH_A_MEMBER`]'s `started` from `stdout`, once its member exists.
pub(crate) fn await_started(mut stdout: std::io::PipeReader) {
    let mut started = [0u8; 8];
    stdout.read_exact(&mut started).expect("read `started`");
    assert_eq!(&started, b"started\n");
}

/// A [`ROOT_WITH_A_MEMBER`] spawn, once its member exists.
pub(crate) fn root_with_a_member() -> (crate::Child, Member) {
    let (stdio, started, member) = Member::pipes();
    let child = {
        let mut cmd = crate::Command::new();
        cmd.args(ROOT_WITH_A_MEMBER);
        cmd.contain_with(crate::ContainMode::Session);
        cmd.stdin(stdio.stdin).expect("set stdin");
        cmd.stdout(stdio.stdout).expect("set stdout");
        cmd.stderr(stdio.stderr).expect("set stderr");
        cmd.spawn().expect("spawn")
    };
    await_started(started);
    (child, member)
}

/// Ends `member` when a graceful shutdown on this thread reaches the end of its `SIGTERM`, before
/// any sweep, and keeps what it said.
pub(crate) struct EndedAtTheSigterm {
    said: std::rc::Rc<std::cell::RefCell<Option<String>>>,
    hook: crate::oneshot_hook::Armed,
}

impl EndedAtTheSigterm {
    pub(crate) fn new(member: Member) -> EndedAtTheSigterm {
        let said = std::rc::Rc::new(std::cell::RefCell::new(None));
        let hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterTerminate, {
            let said = said.clone();
            move || *said.borrow_mut() = Some(member.end())
        });
        EndedAtTheSigterm { said, hook }
    }

    /// Asserts the `SIGTERM` killed the member: a sweep after it cannot. Without the hook's run, the
    /// member is ended here and the assertion fails.
    #[track_caller]
    pub(crate) fn assert_killed_by_the_sigterm(self) {
        let EndedAtTheSigterm { said, hook } = self;
        drop(hook);
        let said = said.take().expect("the shutdown reached the end of its SIGTERM");
        assert!(
            !said.contains("survived"),
            "the group's member outlived the SIGTERM: {said:?}"
        );
    }
}

/// 6.9+: a root reaped by another reaper still names its group through its pidfd, so `kill_tree`
/// kills the members left. Mutant: "a root reaped elsewhere is never signalled".
#[skuld::test]
fn kill_tree_kills_the_group_of_a_root_reaped_elsewhere(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (child, member) = root_with_a_member();
    let pid = child.id().pid();
    child.kill().expect("kill the root alone");
    reap_behind(pid);
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    result.expect("the group is killed through the root's pidfd");
    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGKILL)),
        "{steps:?}"
    );
    member.assert_killed();
}

/// 6.9+: a root reaped by another reaper whose group has no member left has no tree to kill:
/// `kill_tree` sends nothing and succeeds. Mutants: "a group with no member left is still
/// unassessable", "it is signalled through the pidfd regardless".
#[skuld::test]
fn kill_tree_of_a_root_reaped_elsewhere_with_no_member_left_sends_nothing(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (child, _pgid) = foreign_reaped_group_root();
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    result.expect("an empty group is killed already");
    assert_eq!(steps, [], "nothing was sent");
}

/// Below 6.9, after this handle's own reap, a root pid that names no process is still the id of the
/// root's group while a member is left: the group is killed by that number, right after its check.
/// Mutant: "after this handle's own reap, a pid that names nothing fails the check".
#[skuld::test]
fn kill_tree_below_6_9_kills_the_group_by_number_after_this_handles_own_reap() {
    let (child, member) = root_with_a_member();
    child.kill().expect("kill the root alone");
    child.wait().expect("this handle reaps the root");
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    drop(old_kernel);
    result.expect("the group is killed by its number");
    assert_eq!(
        steps.get(..3),
        Some(
            &[
                GroupStep::Group(Route::Pidfd, libc::SIGKILL),
                GroupStep::Check,
                GroupStep::Group(Route::Number, libc::SIGKILL)
            ][..]
        ),
        "{steps:?}"
    );
    member.assert_killed();
}

/// 6.9+: a root whose handle cannot say whether it was reaped still names its group exactly through
/// its pidfd, so `kill_tree` kills the group as usual. Mutant: "only a reaped root's group is
/// decided by the pidfd".
#[skuld::test]
fn kill_tree_of_a_root_its_handle_cannot_read_kills_its_group_through_the_pidfd(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    let (child, member) = root_with_a_member();
    let capture = Capture::start();
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    let result = child.kill_tree();
    assert_peeks_exhausted();
    drop(forced);
    let steps = capture.group_steps();
    result.expect("the group is killed through the root's pidfd");
    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGKILL)),
        "{steps:?}"
    );
    member.assert_killed();
}

/// A session root reaped elsewhere whose group keeps one member, and a process of this test that
/// leads a group of its own. Armed, the group's own send is refused, the member then leaves the
/// group, which leaves it empty, and the other group stands in for one that took its number before
/// `converge` lists it.
pub(crate) struct EmptiedGroup {
    root: crate::Child,
    stdin: std::io::PipeWriter,
    stdout: std::io::PipeReader,
    stderr: std::io::PipeReader,
    other: std::process::Child,
}

impl EmptiedGroup {
    pub(crate) fn new() -> EmptiedGroup {
        use crate::test_child::{await_member_ready, member_command};
        // The member waits for a line on stdin, then leaves the group by `setsid`, says so, and holds
        // stderr's write end until stdin's EOF.
        let mut cmd = crate::Command::new();
        cmd.args([
            "sh",
            "-c",
            r#"exec 3<&0; sh -c 'read _ <&3; exec setsid sh -c "echo left; exec cat <&3 3<&- >/dev/null"' & echo started; exec sleep 300 <&- 2>/dev/null"#,
        ]);
        cmd.contain_with(crate::ContainMode::Session);
        cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
        cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
        cmd.stderr(crate::Stdio::pipe_out()).expect("stderr pipe");
        let mut root = cmd.spawn().expect("spawn the root");
        let mut stdout = root.stdout().expect("stdout pipe");
        let mut started = [0u8; 8];
        stdout.read_exact(&mut started).expect("read `started`");
        assert_eq!(&started, b"started\n");
        let (stdin, stderr) = (root.stdin().expect("stdin pipe"), root.stderr().expect("stderr pipe"));
        let pid = root.id().pid();
        root.kill().expect("kill the root alone");
        reap_behind(pid);
        let mut other = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn the other group's leader");
        await_member_ready(&mut other);
        EmptiedGroup {
            root,
            stdin,
            stdout,
            stderr,
            other,
        }
    }

    /// Arms the refusal, the listing of the other group, and the member's leaving right after the
    /// listing. Returns the root, and what ends the test ([`Armed::finish`]).
    pub(crate) fn arm(self) -> (crate::Child, Armed) {
        use std::io::Write as _;
        let EmptiedGroup {
            root,
            stdin,
            mut stdout,
            stderr,
            other,
        } = self;
        let refused = crate::containment::unix::fault::refuse_group_sends();
        let listed = crate::containment::unix::fault::list_instead(other.id() as i32);
        let mut tell = stdin.try_clone().expect("clone stdin");
        let left = crate::containment::unix::fault::set_after_listing(move || {
            tell.write_all(b"\n").expect("tell the member to leave");
            let mut left = [0u8; 5];
            stdout.read_exact(&mut left).expect("read `left`");
            assert_eq!(&left, b"left\n");
        });
        let armed = Armed {
            guard: Box::new((refused, listed, left)),
            stdin,
            stderr,
            other,
        };
        (root, armed)
    }
}

/// An armed [`EmptiedGroup`] without its root.
pub(crate) struct Armed {
    guard: Box<dyn std::any::Any>,
    stdin: std::io::PipeWriter,
    stderr: std::io::PipeReader,
    other: std::process::Child,
}

impl Armed {
    /// Disarms, asserts the other group's leader was sent nothing and ends it, and ends the member
    /// that left the group.
    pub(crate) fn finish(self) {
        use std::os::unix::process::ExitStatusExt as _;
        let Armed {
            guard,
            stdin,
            mut stderr,
            mut other,
        } = self;
        drop(guard);
        let running = other.try_wait().expect("look at the other group's leader");
        other.kill().expect("kill the other group's leader");
        let status = other.wait().expect("reap the other group's leader");
        drop(stdin);
        let mut rest = Vec::new();
        stderr.read_to_end(&mut rest).expect("read stderr to the member's end");
        assert_eq!(running, None, "the other group's leader was signalled");
        assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
    }
}

/// 6.9+: a process listed by the number of a group the root's pidfd shows has no member left is in
/// another group that took the number: it is sent nothing, and `kill_tree` succeeds. Mutant: "a
/// group with no member left leaves the listed process unassessable".
#[skuld::test]
fn kill_tree_leaves_alone_a_group_that_took_the_number_of_its_emptied_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (child, armed) = EmptiedGroup::new().arm();
    let capture = Capture::start();
    let result = child.kill_tree();
    let steps = capture.group_steps();
    armed.finish();
    result.expect("the tree is gone");
    assert!(
        !steps.iter().any(|step| matches!(step, GroupStep::Member(..))),
        "nothing was resent: {steps:?}"
    );
}

/// 6.9+: a process listed by the number of a group the root's pidfd shows has no member left is in
/// another group that took the number: one that refuses `terminate_tree`'s probe does not fail the
/// call. Mutant: "the probe asks no root check".
#[skuld::test]
fn terminate_tree_leaves_alone_a_group_that_took_the_number_of_its_emptied_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (child, armed) = EmptiedGroup::new().arm();
    let refusing = crate::containment::unix::fault::refuse_probes();
    let result = child.terminate_tree();
    drop(refusing);
    armed.finish();
    result.expect("the tree is gone");
}

/// What `graceful_shutdown_tree` returns once the tree of a root reaped elsewhere is down.
pub(crate) const STATUS_REAPED_ELSEWHERE: &str = "exit status cannot be collected: the root was reaped elsewhere";

/// Asserts `result` is the answer of a shutdown that brought the tree down but could not collect the
/// root's status, and that it warned of nothing left behind but, for an async handle, tokio's own
/// handle of the root reaped elsewhere.
#[track_caller]
pub(crate) fn assert_down_without_status(result: Result<std::process::ExitStatus, crate::error::Error>, mark: usize) {
    match result {
        Err(crate::error::Error::Unassessable { detail, source: None }) => {
            assert!(detail.contains(STATUS_REAPED_ELSEWHERE), "{detail}");
        }
        other => panic!("expected the tree down without the root's status, got {other:?}"),
    }
    let mut warns = crate::test_child::reaped_elsewhere::warns_since(mark);
    warns.retain(|warn| !warn.contains("forgetting tokio's handle for it leaks"));
    assert_eq!(warns, Vec::<String>::new(), "nothing was left behind");
}

/// 6.9+: `terminate_tree` of a root reaped elsewhere still signals its group through the root's
/// pidfd. Mutants: "the pidfd decides only `kill_tree`", "the send through the pidfd carries signal
/// 0", "it is recorded and not made".
#[skuld::test]
fn terminate_tree_signals_the_group_of_a_root_reaped_elsewhere(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (child, member) = root_with_a_member();
    let pid = child.id().pid();
    child.kill().expect("kill the root alone");
    reap_behind(pid);
    let capture = Capture::start();
    let result = child.terminate_tree();
    let steps = capture.group_steps();
    result.expect("the group is signalled through the root's pidfd");
    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGTERM)),
        "{steps:?}"
    );
    member.assert_killed();
}

/// 6.9+: `terminate_tree` of a root reaped elsewhere whose group has no member left sends nothing
/// and succeeds. Mutants: "a group with no member left is still unassessable", "it is signalled
/// through the pidfd regardless".
#[skuld::test]
fn terminate_tree_of_a_root_reaped_elsewhere_with_no_member_left_sends_nothing(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (child, _pgid) = foreign_reaped_group_root();
    let capture = Capture::start();
    let result = child.terminate_tree();
    let steps = capture.group_steps();
    result.expect("an empty group has nothing to signal");
    assert_eq!(steps, [], "nothing was sent");
}

/// 6.9+: `graceful_shutdown_tree` of a root reaped elsewhere shuts its group down through the root's
/// pidfd, then answers that the root's status went to the other reaper. Mutants: "only the root is
/// shut down through its pidfd", "the shutdown ends on the root's lost status", "graceful sends no
/// `SIGTERM`".
#[skuld::test]
fn graceful_shutdown_tree_shuts_down_the_group_of_a_root_reaped_elsewhere(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    crate::log_capture::install();
    let (child, member) = root_with_a_member();
    let pid = child.id().pid();
    child.kill().expect("kill the root alone");
    reap_behind(pid);
    let mark = crate::log_capture::mark();
    let ended = EndedAtTheSigterm::new(member);
    let capture = Capture::start();
    let result = child.graceful_shutdown_tree(std::time::Duration::from_secs(1));
    let steps = capture.group_steps();
    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGTERM)),
        "{steps:?}"
    );
    ended.assert_killed_by_the_sigterm();
    assert_down_without_status(result, mark);
}

/// 6.9+: `graceful_shutdown_tree` of a root reaped elsewhere whose group has no member left sends
/// nothing, and answers that the root's status went to the other reaper. Mutants: "a group with no
/// member left ends the call unassessable", "it is signalled through the pidfd regardless".
#[skuld::test]
fn graceful_shutdown_tree_of_a_root_reaped_elsewhere_with_no_member_left_sends_nothing(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    crate::log_capture::install();
    let (child, _pgid) = foreign_reaped_group_root();
    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    let result = child.graceful_shutdown_tree(std::time::Duration::from_secs(1));
    let steps = capture.group_steps();
    assert_eq!(steps, [], "nothing was sent");
    assert_down_without_status(result, mark);
}
