use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use rustix::io::Errno;

use super::super::log::Log;
use super::{readable_now, replace_stdio, wait_readable};

fn pipe() -> (OwnedFd, OwnedFd) {
    let (reader, writer) = std::io::pipe().unwrap();
    (reader.into(), writer.into())
}

#[skuld::test]
fn readiness_is_reported_per_descriptor_and_a_hang_up_counts() {
    let (quiet_reader, _quiet_writer) = pipe();
    let (reader, writer) = pipe();
    assert_eq!(
        readable_now([quiet_reader.as_fd(), reader.as_fd()]).unwrap(),
        [false, false]
    );
    rustix::io::write(&writer, b"x").unwrap();
    assert_eq!(
        readable_now([quiet_reader.as_fd(), reader.as_fd()]).unwrap(),
        [false, true]
    );
    drop(writer);
    assert_eq!(wait_readable([Some(reader.as_fd()), None]).unwrap(), [true, false]);
}

#[skuld::test]
fn a_failed_poll_is_an_error_and_never_silence() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_failed_poll_is_an_error_and_never_silence),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let (reader, _writer) = pipe();
    // `poll` of more descriptors than `RLIMIT_NOFILE` allows is `EINVAL`.
    let limit = rustix::process::Rlimit {
        current: Some(0),
        maximum: rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum,
    };
    rustix::process::setrlimit(rustix::process::Resource::Nofile, limit).unwrap();
    assert_eq!(readable_now([reader.as_fd()]), Err(Errno::INVAL));
    assert_eq!(wait_readable([Some(reader.as_fd())]), Err(Errno::INVAL));
}

fn target_of(fd: i32) -> std::path::PathBuf {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap()
}

#[skuld::test]
fn the_standard_descriptors_become_dev_null() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(the_standard_descriptors_become_dev_null),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    // Each descriptor starts as the same pipe, so that none is `/dev/null` by chance. The originals
    // come back before anything is asserted, or a failure would be reported to `/dev/null`.
    let originals = [
        rustix::io::dup(rustix::stdio::stdin()).unwrap(),
        rustix::io::dup(rustix::stdio::stdout()).unwrap(),
        rustix::io::dup(rustix::stdio::stderr()).unwrap(),
    ];
    let (_reader, writer) = pipe();
    rustix::stdio::dup2_stdin(&writer).unwrap();
    rustix::stdio::dup2_stdout(&writer).unwrap();
    rustix::stdio::dup2_stderr(&writer).unwrap();
    replace_stdio(&Log::new(None));
    let targets: Vec<_> = (0..3).map(target_of).collect();
    rustix::stdio::dup2_stdin(&originals[0]).unwrap();
    rustix::stdio::dup2_stdout(&originals[1]).unwrap();
    rustix::stdio::dup2_stderr(&originals[2]).unwrap();
    for (fd, target) in targets.iter().enumerate() {
        assert_eq!(target, std::path::Path::new("/dev/null"), "fd {fd}");
    }
}

#[skuld::test]
fn a_dev_null_that_cannot_be_opened_is_logged_and_the_descriptors_stay() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_dev_null_that_cannot_be_opened_is_logged_and_the_descriptors_stay),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let (lines, log_fd) = pipe();
    let log = Log::new(Some(log_fd.as_raw_fd()));
    let before: Vec<_> = (0..3).map(target_of).collect();
    // No descriptor can be made: the soft limit is the lowest free number.
    let spare = rustix::io::dup(rustix::stdio::stdin()).unwrap();
    let limit = rustix::process::Rlimit {
        current: Some(spare.as_raw_fd() as u64),
        maximum: rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum,
    };
    drop(spare);
    rustix::process::setrlimit(rustix::process::Resource::Nofile, limit).unwrap();
    replace_stdio(&log);
    let mut text = [0u8; 512];
    let flags = rustix::fs::fcntl_getfl(&lines).unwrap();
    rustix::fs::fcntl_setfl(&lines, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
    let n = rustix::io::read(&lines, &mut text).unwrap();
    let text = String::from_utf8_lossy(&text[..n]);
    assert!(text.contains("cannot open /dev/null"), "{text:?}");
    assert_eq!((0..3).map(target_of).collect::<Vec<_>>(), before);
}
