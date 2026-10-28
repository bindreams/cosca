//! A shell root with a background member, each held by a pipe of the test's own: the member ends at
//! its stdin's end of file and says `survived` unless a fatal signal reached it first. A test ends
//! the member's stdin or the root's release pipe itself, so a kill that sent nothing fails an
//! assertion instead of leaving a wait unbounded.

use std::io::Read as _;

/// A session root `sh` that leaves a member in its group, says `started`, and blocks holding neither
/// the member's stdin nor stderr. The member reads stdin through fd 3 (`sh` points a background
/// job's stdin at `/dev/null` otherwise) and, at its end of file, says `survived` on stderr. The
/// root reads fd 4 ([`Member::pipes`]'s release pipe) and exits at its end of file, so a test can end
/// it without a signal.
#[cfg(target_os = "linux")]
pub(crate) const ROOT_WITH_A_MEMBER: [&str; 3] = [
    "sh",
    "-c",
    "exec 3<&0; (cat <&3 3<&- 4<&- >/dev/null && echo survived >&2) & echo started; exec cat <&4 3<&- 4<&- >/dev/null 2>/dev/null",
];

/// The descriptor the root of [`ROOT_WITH_A_MEMBER`] reads its release from.
#[cfg(target_os = "linux")]
pub(crate) const RELEASE_FD: i32 = 4;

/// A test's ends of the pipes of [`ROOT_WITH_A_MEMBER`]'s member and root.
pub(crate) struct Member {
    /// The write end of the member's stdin. Dropped, the member ends at its end of file.
    stdin: std::rc::Rc<std::cell::Cell<Option<std::io::PipeWriter>>>,
    stderr: std::io::PipeReader,
    /// The write end of the root's release pipe. Dropped, the root exits by itself.
    root_release: std::rc::Rc<std::cell::Cell<Option<std::io::PipeWriter>>>,
}

impl Member {
    /// The pipes of a [`ROOT_WITH_A_MEMBER`] spawn, to give its stdin, stdout, stderr and
    /// [`RELEASE_FD`], and the read end of its stdout.
    pub(crate) fn pipes() -> (MemberStdio, std::io::PipeReader, Member) {
        let (stdin_read, stdin) = std::io::pipe().expect("stdin pipe");
        let (started, stdout_write) = std::io::pipe().expect("stdout pipe");
        let (stderr, stderr_write) = std::io::pipe().expect("stderr pipe");
        let (release_read, root_release) = std::io::pipe().expect("release pipe");
        let stdio = |end: std::os::fd::OwnedFd| crate::Stdio::from_file(std::fs::File::from(end));
        let child_ends = MemberStdio {
            stdin: stdio(stdin_read.into()),
            stdout: stdio(stdout_write.into()),
            stderr: stdio(stderr_write.into()),
            release: stdio(release_read.into()),
        };
        let member = Member {
            stdin: std::rc::Rc::new(std::cell::Cell::new(Some(stdin))),
            stderr,
            root_release: std::rc::Rc::new(std::cell::Cell::new(Some(root_release))),
        };
        (child_ends, started, member)
    }

    /// Releases the root once a teardown's kill returned
    /// ([`release_when_a_teardown_waits`](crate::child::spawn::fault::release_when_a_teardown_waits)),
    /// so a kill that sent nothing fails the member assertion instead of hanging the wait. Keep the
    /// guard through the teardown; it never releases the member.
    #[cfg(target_os = "linux")]
    pub(crate) fn release_root_when_a_teardown_waits(&self) -> Box<dyn std::any::Any> {
        crate::child::spawn::fault::release_when_a_teardown_waits(&self.root_release)
    }

    /// Releases the member once a cgroup leaf's drain is about to block, so a leaf whose kill sent
    /// nothing drains with the member saying `survived`, and the member assertion fails instead of
    /// the drain hanging. A kill that reached the member is already pending, so it always beats
    /// the release. A kill's delivery is not awaited, so the seam must not fail on its own: the
    /// drain of a leaf the kill just emptied can reach it too. Keep the guard through the teardown.
    #[cfg(all(target_os = "linux", feature = "tokio"))]
    pub(crate) fn release_when_the_drain_blocks(&self) -> crate::oneshot_hook::Armed {
        let stdin = std::rc::Rc::clone(&self.stdin);
        crate::containment::cgroup::fault::set_before_drain_block(move || drop(stdin.take()))
    }

    /// Closes the member's stdin and reads its stderr to the end. A member still running ends at that
    /// end of file and says `survived`; one already sent a fatal signal never runs again, and says
    /// nothing. Neither waits on a signal's delivery. The root's writer is released too, whatever
    /// guards of [`Member::release_root_when_a_teardown_waits`] still hold the cell, so a failed
    /// assertion on what this returns unwinds without a drop that waits on a root nothing ended.
    pub(crate) fn end(self) -> String {
        let Member {
            stdin,
            mut stderr,
            root_release,
        } = self;
        drop((stdin.take(), root_release.take()));
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
    #[cfg(target_os = "linux")]
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
    pub(crate) release: crate::Stdio,
}

/// Reads [`ROOT_WITH_A_MEMBER`]'s `started` from `stdout`, once its member exists.
pub(crate) fn await_started(mut stdout: std::io::PipeReader) {
    let mut started = [0u8; 8];
    stdout.read_exact(&mut started).expect("read `started`");
    assert_eq!(&started, b"started\n");
}

/// The sync `ROOT_WITH_A_MEMBER`, its root blocked on fd 4 instead of sleeping: it exits `0` once the
/// writer of that pipe is dropped, which the member's stdin does not share.
#[cfg(feature = "tokio")]
const RELEASABLE_ROOT_WITH_A_MEMBER: [&str; 3] = [
    "sh",
    "-c",
    "exec 3<&0; (cat <&3 3<&- >/dev/null && echo survived >&2) & echo started; exec cat <&4 4<&- 3<&- >/dev/null 2>/dev/null",
];

/// The sync `root_with_a_member`'s twin with the containment `contain` sets, and the writer whose drop
/// ends its root with status `0`; drop it right after the kill.
#[cfg(feature = "tokio")]
pub(crate) fn releasable_root_with_a_member_contained(
    contain: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, Member, std::io::PipeWriter) {
    let (stdio, started, member) = Member::pipes();
    let child = {
        let mut cmd = crate::tokio::Command::new();
        cmd.args(RELEASABLE_ROOT_WITH_A_MEMBER);
        cmd.fd(4, stdio.release).expect("set the root's release pipe");
        contain(&mut cmd);
        cmd.stdin(stdio.stdin).expect("set stdin");
        cmd.stdout(stdio.stdout).expect("set stdout");
        cmd.stderr(stdio.stderr).expect("set stderr");
        cmd.spawn().expect("spawn")
    };
    await_started(started);
    let release = member
        .root_release
        .take()
        .expect("the root's release writer is still held");
    (child, member, release)
}
