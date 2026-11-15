use std::io::Read;
#[cfg(not(target_os = "linux"))]
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
#[cfg(not(target_os = "linux"))]
use std::process::{Command, Stdio};

use super::InChild;
use crate::child::spawn::fd_map::{self, FdMapping};

/// One line from `pipe`, without its newline. A pipe whose every write end is closed gives `""`.
#[cfg(not(target_os = "linux"))]
fn line_from(pipe: impl Read) -> String {
    let mut line = String::new();
    BufReader::new(pipe).read_line(&mut line).expect("read a line");
    line.trim_end_matches('\n').to_owned()
}

/// Every step the hook carries takes effect in the one child it registers on. The steps are added
/// in the reverse of the order they run in, so a hook that runs them in the order they were added
/// fails too. Rows: the directory the child enters, its own session, the marker descriptor it keeps
/// open across `exec`, and its fd mapping.
///
/// The other pairs of steps are not observable from outside the child, so no row pins them: the
/// session leaves the directory alone, and a map that ran before `preserve` would leave the same
/// descriptors behind, since `dup2` clears `FD_CLOEXEC` itself.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn every_in_child_step_takes_effect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut steps = InChild::default();

    #[cfg(target_os = "macos")]
    let (marker_read, marker_write) = std::io::pipe().expect("pipe");
    #[cfg(target_os = "macos")]
    let marker_fd = marker_write.as_raw_fd();

    let (mapped_read, mapped_write) = std::io::pipe().expect("pipe");
    // A number above every descriptor open here (std's own pipes for this spawn take the next few), so
    // the map cannot replace the marker, whose number the pipe's allocation decides.
    let mapped_fd = {
        let highest = mapped_read.as_raw_fd();
        #[cfg(target_os = "macos")]
        let highest = highest.max(marker_fd);
        highest + 8
    };
    let mapping = FdMapping {
        parent_fd: OwnedFd::from(mapped_write),
        child_fd: mapped_fd,
    };

    fd_map::install(&mut steps, vec![mapping]).expect("install the mapping");
    #[cfg(target_os = "macos")]
    steps.preserve(OwnedFd::from(marker_write));
    steps.session();
    steps.enter(std::ffi::CString::new(dir.path().as_os_str().as_bytes()).expect("no NUL"));

    #[cfg(target_os = "macos")]
    let marker_line = format!("echo marker > /dev/fd/{marker_fd}; ");
    #[cfg(not(target_os = "macos"))]
    let marker_line = String::new();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!(
            "pwd -P; echo mapped > /dev/fd/{mapped_fd}; {marker_line}read _ || true"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    steps.register(&mut cmd);
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn");
    // The parent's copies: each pipe reads EOF once the child is done with its own.
    drop(cmd);

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
        "the fd map lands the pipe on fd {mapped_fd}"
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

/// Every step the spawn's child carries takes effect, through the ordinary spawn's entry. The steps are
/// added in the reverse of the order they run in, so a child that ran them in the order they were
/// added fails too: the fd map targets the descriptor the placement step writes to, and a map that ran
/// first would take the "0" and leave `cgroup.procs` empty. Rows: the directory the child enters, its
/// own session, its cgroup placement (a pipe stands in for `cgroup.procs`), its stdout, and its fd
/// mapping.
///
/// The other pairs of steps are not observable from outside the child, so no row pins them: the
/// session leaves the directory and the placement write alone.
#[cfg(target_os = "linux")]
#[skuld::test]
fn every_in_child_step_takes_effect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut steps = InChild::default();
    let mut channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let (mut procs_read, procs_write) = std::io::pipe().expect("pipe");
    let (mut mapped_read, mapped_write) = std::io::pipe().expect("pipe");
    let (mut stdout_read, stdout_write) = std::io::pipe().expect("pipe");
    // The map targets the descriptor the placement step writes to.
    let mapped_fd = procs_write.as_raw_fd();

    steps.map_stdio(fd_map::Plan::stdio(vec![FdMapping {
        parent_fd: OwnedFd::from(stdout_write),
        child_fd: 1,
    }]));
    fd_map::install(
        &mut steps,
        vec![FdMapping {
            parent_fd: OwnedFd::from(mapped_write),
            child_fd: mapped_fd,
        }],
    )
    .expect("install the mapping");
    // SAFETY: `procs_write` stays open, and the channel too, until the spawn has returned.
    unsafe { steps.place(procs_write.as_raw_fd(), channel.slot()) };
    steps.session();
    steps.enter(std::ffi::CString::new(dir.path().as_os_str().as_bytes()).expect("no NUL"));

    let started = super::spawn_sh(&format!("pwd -P; echo mapped > /dev/fd/{mapped_fd}"), &mut steps).expect("spawn");
    // The parent's copies: each pipe reads EOF once the child is done with its own.
    drop(steps);
    drop(procs_write);

    let mut written = String::new();
    procs_read.read_to_string(&mut written).expect("read the placement");
    assert_eq!(written, "0", "the placement step writes \"0\" to its cgroup.procs fd");
    assert_eq!(
        channel.wait(started.owned.pidfd().expect("a pidfd box")),
        crate::containment::cgroup::PlacementReport::Placed,
        "the placement step reports its write"
    );

    let mut stdout = String::new();
    stdout_read.read_to_string(&mut stdout).expect("read the stdout");
    assert_eq!(
        std::path::Path::new(stdout.trim_end_matches('\n')),
        dir.path().canonicalize().expect("canonicalize"),
        "the child runs in the directory the enter step chose, and its stdout is the pipe's"
    );
    let mut mapped = String::new();
    mapped_read.read_to_string(&mut mapped).expect("read the mapped pipe");
    assert_eq!(mapped, "mapped\n", "the fd map lands the pipe on fd {mapped_fd}");

    // The child has not been waited for, so its pid is still its own.
    let pid = started.pid as libc::pid_t;
    // SAFETY: `getsid` reads only its argument.
    assert_eq!(
        unsafe { libc::getsid(pid) },
        pid,
        "the session step makes the child a session leader"
    );
    assert_eq!(super::exit_code(&started), Some(0));
}

/// A failing `enter` stops the child before the placement step (a pipe stands in for `cgroup.procs`), so
/// a spawn that fails there leaves the child's placement unwritten. The pipe reads empty; a child that
/// ran the placement before `enter` would leave a "0" in it.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failing_enter_step_stops_the_child_before_placement() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing");

    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let (mut procs_read, procs_write) = std::io::pipe().expect("pipe");
    let mut steps = InChild::default();
    // SAFETY: `procs_write` stays open, and the channel too, until the spawn has returned.
    unsafe { steps.place(procs_write.as_raw_fd(), channel.slot()) };
    steps.enter(std::ffi::CString::new(missing.as_os_str().as_bytes()).expect("no NUL"));

    let err = match super::spawn_sh("true", &mut steps) {
        Err(err) => err,
        Ok(started) => panic!("the child entered a missing directory (pid {})", started.pid),
    };
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "{err}");

    // The parent's copies: the pipe reads EOF once the failed child's own is closed.
    drop(steps);
    drop(procs_write);
    let mut written = String::new();
    procs_read.read_to_string(&mut written).expect("read the placement");
    assert_eq!(written, "", "the placement step ran although the enter step failed");
}

/// `register` adds no hook for a command with no step, so each step must count in `is_empty`: a
/// step it forgets is dropped from a command that has nothing else.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn is_empty_counts_every_step() {
    assert!(InChild::default().is_empty(), "no step");

    let mut steps = InChild::default();
    steps.enter(std::ffi::CString::new("/").expect("no NUL"));
    assert!(!steps.is_empty(), "is_empty ignores the enter step");

    let mut steps = InChild::default();
    steps.session();
    assert!(!steps.is_empty(), "is_empty ignores the session step");

    #[cfg(target_os = "macos")]
    {
        let (_read, write) = std::io::pipe().expect("pipe");
        let mut steps = InChild::default();
        steps.preserve(OwnedFd::from(write));
        assert!(!steps.is_empty(), "is_empty ignores the preserve step");
    }

    let (_read, write) = std::io::pipe().expect("pipe");
    let mut steps = InChild::default();
    let mapping = FdMapping {
        parent_fd: OwnedFd::from(write),
        child_fd: 9,
    };
    fd_map::install(&mut steps, vec![mapping]).expect("install the mapping");
    assert!(!steps.is_empty(), "is_empty ignores the fd map step");
}
