use std::io::{BufRead, BufReader, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};

use super::InChild;
use crate::child::spawn::fd_map::{self, FdMapping};

/// One line from `pipe`, without its newline. A pipe whose every write end is closed gives `""`.
fn line_from(pipe: impl Read) -> String {
    let mut line = String::new();
    BufReader::new(pipe).read_line(&mut line).expect("read a line");
    line.trim_end_matches('\n').to_owned()
}

/// Every step the hook carries takes effect in the one child it registers on. One child carries
/// every step, so a hook that drops any of them fails its row here. Rows: the directory the child
/// enters, its own session, its cgroup placement (Linux; a pipe stands in for `cgroup.procs`), the
/// marker descriptor it keeps open across `exec` (macOS), and its fd mapping.
#[skuld::test]
fn every_in_child_step_takes_effect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut steps = InChild::default();
    steps.enter(std::ffi::CString::new(dir.path().as_os_str().as_bytes()).expect("no NUL"));
    steps.session();

    #[cfg(target_os = "linux")]
    let (mut channel, mut procs_read, procs_write) = {
        let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
        let (procs_read, procs_write) = std::io::pipe().expect("pipe");
        // SAFETY: `procs_write` stays open until the spawn returns, and the channel until its wait.
        unsafe { steps.place(procs_write.as_raw_fd(), channel.slot()) };
        (channel, procs_read, procs_write)
    };

    #[cfg(target_os = "macos")]
    let (marker_read, marker_fd) = {
        let (read, write) = std::io::pipe().expect("pipe");
        let fd = write.as_raw_fd();
        steps.preserve(OwnedFd::from(write));
        (read, fd)
    };

    const MAPPED: i32 = 5;
    let (mapped_read, mapped_write) = std::io::pipe().expect("pipe");
    let mapping = FdMapping {
        parent_fd: OwnedFd::from(mapped_write),
        child_fd: MAPPED,
    };
    fd_map::install(&mut steps, vec![mapping]).expect("install the mapping");

    #[cfg(target_os = "macos")]
    let marker_line = format!("echo marker > /dev/fd/{marker_fd}; ");
    #[cfg(not(target_os = "macos"))]
    let marker_line = String::new();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!(
            "pwd -P; echo mapped > /dev/fd/{MAPPED}; {marker_line}read _ || true"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    steps.register(&mut cmd);
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn");
    // The parent's copies: each pipe reads EOF once the child is done with its own.
    drop(cmd);
    #[cfg(target_os = "linux")]
    drop(procs_write);

    #[cfg(target_os = "linux")]
    {
        let mut written = String::new();
        procs_read.read_to_string(&mut written).expect("read the placement");
        assert_eq!(written, "0", "the placement step writes \"0\" to its cgroup.procs fd");
        let pidfd = crate::containment::cgroup::test_support::pidfd_of(child.id());
        assert_eq!(
            channel.wait(std::os::fd::AsFd::as_fd(&pidfd)),
            crate::containment::cgroup::PlacementReport::Placed,
            "the placement step reports its write"
        );
    }

    let stdout = child.stdout.take().expect("stdout");
    let mut stdout = BufReader::new(stdout);
    let mut cwd = String::new();
    stdout.read_line(&mut cwd).expect("read the cwd");
    assert_eq!(
        std::path::Path::new(cwd.trim_end_matches('\n')),
        dir.path().canonicalize().expect("canonicalize"),
        "the child runs in the directory the enter step chose"
    );
    assert_eq!(
        line_from(mapped_read),
        "mapped",
        "the fd map lands the pipe on fd {MAPPED}"
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        line_from(marker_read),
        "marker",
        "the marker survives exec at its own number"
    );

    // The child is blocked on stdin, unreaped, so its pid is still its own.
    let pid = child.id() as libc::pid_t;
    // SAFETY: `getsid` reads only its argument.
    assert_eq!(
        unsafe { libc::getsid(pid) },
        pid,
        "the session step makes the child a session leader"
    );

    drop(child.stdin.take());
    assert!(child.wait().expect("wait").success());
}

/// A command with no step gets no hook, so std keeps its `posix_spawn` route. glibc's
/// `posix_spawn` refuses a file with no `#!` (`ENOEXEC`), where the fork route's `execvp` runs it
/// with `/bin/sh`. macOS runs it with `sh` on both routes, so this has no observable there.
#[cfg(target_os = "linux")]
#[skuld::test]
fn no_step_registers_no_hook() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let script = dir.path().join("no-shebang");
    std::fs::write(&script, "exit 0\n").expect("write the script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let mut cmd = Command::new(&script);
    InChild::default().register(&mut cmd);
    match crate::test_spawn::spawn(&mut cmd) {
        Err(e) => assert_eq!(e.raw_os_error(), Some(libc::ENOEXEC), "{e}"),
        Ok(mut child) => {
            let status = child.wait().expect("wait");
            panic!("the fork route ran the file through sh ({status}): a hook was registered");
        }
    }
}
