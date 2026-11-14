//! `pid_file::read` decides a failed read from the call that failed and its errno alone: a scan
//! covers all of `/proc`, and a `kill(pid, 0)` probe of a foreign uid's process fails under `hidepid`.

use super::{read, ReadOutcome};
use crate::identity::{FakeKernel, HostKernel, Kernel};

/// The call a row's errno answers for.
#[derive(Debug, Clone, Copy)]
enum Call {
    Open,
    Read,
}

/// What the `self/stat` re-check of an `EPERM` finds. No re-check row means none is asked: a
/// `FakeKernel` with no row for `self/stat` panics on the read.
#[derive(Debug, Clone, Copy)]
enum Recheck {
    Answers,
    Fails(Call, i32),
}

#[derive(Debug)]
enum Want {
    Skipped,
    /// A refusal whose refusing errno is this.
    Refused(i32),
    /// An `Unreadable` whose words contain this.
    Unreadable(&'static str),
}

/// What a failed read of `4242/stat` is, by (call that failed, errno, re-check).
///
/// Mutant: a `read(2)` errno is read as the `openat2`'s (`EPERM` asks the re-check, `ENOSYS` is a
/// refusal, `EXDEV` is beyond a mount); `read(2)`'s `ESRCH` is no skip; a failed re-check is a skip or
/// a refusal; a refusal is an `Unreadable`.
#[skuld::test]
fn a_failed_read_is_what_its_call_and_errno_say() {
    use Call::{Open, Read};
    use Recheck::{Answers, Fails};

    let dir = HostKernel.open_proc().expect("/proc opens");
    let rows = [
        // The pid is not there for us.
        (Open, libc::ENOENT, None, Want::Skipped),
        (Open, libc::ESRCH, None, Want::Skipped),
        (Open, libc::EACCES, None, Want::Skipped),
        (Open, libc::EPERM, Some(Answers), Want::Skipped),
        // A task that exits between the open and the read.
        (Read, libc::ESRCH, None, Want::Skipped),
        // An `openat2` refusal, by the pid's own errno or by the directory's.
        (Open, libc::ENOSYS, None, Want::Refused(libc::ENOSYS)),
        (Open, libc::ENODEV, None, Want::Refused(libc::ENODEV)),
        (
            Open,
            libc::EPERM,
            Some(Fails(Open, libc::EPERM)),
            Want::Refused(libc::EPERM),
        ),
        (
            Open,
            libc::EPERM,
            Some(Fails(Open, libc::ENOSYS)),
            Want::Refused(libc::ENOSYS),
        ),
        (
            Open,
            libc::EPERM,
            Some(Fails(Open, libc::ENODEV)),
            Want::Refused(libc::ENODEV),
        ),
        // The checked directory would not cross a mount.
        (Open, libc::EXDEV, None, Want::Unreadable("lies beyond a mount")),
        (Open, libc::ELOOP, None, Want::Unreadable("lies beyond a mount")),
        // Nothing is known about the pid.
        (Open, libc::EIO, None, Want::Unreadable("could not be read")),
        (Open, libc::EMFILE, None, Want::Unreadable("could not be read")),
        // A failed re-check is no evidence of `hidepid`, and a `read(2)` failure is no refusal.
        (
            Open,
            libc::EPERM,
            Some(Fails(Open, libc::EMFILE)),
            Want::Unreadable("re-check of self/stat failed"),
        ),
        (
            Open,
            libc::EPERM,
            Some(Fails(Read, libc::ENOSYS)),
            Want::Unreadable("re-check of self/stat failed"),
        ),
        (Read, libc::EPERM, None, Want::Unreadable("could not be read")),
        (Read, libc::ENOSYS, None, Want::Unreadable("could not be read")),
        (Read, libc::ENOENT, None, Want::Unreadable("could not be read")),
        (Read, libc::EXDEV, None, Want::Unreadable("could not be read")),
        (Read, libc::EIO, None, Want::Unreadable("could not be read")),
    ];
    for (call, errno, recheck, want) in rows {
        fn row<'a>(kernel: FakeKernel<'a>, path: &str, call: Call, errno: i32) -> FakeKernel<'a> {
            match call {
                Open => kernel.on_read(path, Err(errno)),
                Read => kernel.on_read_failing_after_open(path, errno),
            }
        }
        let mut kernel = row(FakeKernel::new(), "4242/stat", call, errno);
        kernel = match recheck {
            None => kernel,
            Some(Answers) => kernel.on_read("self/stat", Ok(b"")),
            Some(Fails(call, errno)) => row(kernel, "self/stat", call, errno),
        };
        let name = format!("{call:?} {errno}, re-check {recheck:?}");
        match (read(&kernel, &dir, 4242, "stat"), want) {
            (Ok(ReadOutcome::Skipped(_)), Want::Skipped) => {}
            (Ok(ReadOutcome::Refused(refusal)), Want::Refused(refusing)) => {
                assert_eq!(crate::error::first_os_code(&refusal.cause()), Some(refusing), "{name}");
                assert!(refusal.requirement().contains("requires openat2"), "{name}");
            }
            (Err(unreadable), Want::Unreadable(words)) => {
                assert!(unreadable.to_string().contains(words), "{name}: {unreadable}");
            }
            (got, want) => panic!("{name}: expected {want:?}, got {got:?}"),
        }
    }
}

/// A file that is not `stat` is read the same way, and named in the failure.
#[skuld::test]
fn a_pids_cgroup_file_is_read_like_its_stat_and_named_in_the_failure() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let kernel = FakeKernel::new()
        .on_read("4242/cgroup", Ok(b"0::/\n"))
        .on_read("4243/cgroup", Err(libc::EIO));

    assert!(matches!(
        read(&kernel, &dir, 4242, "cgroup"),
        Ok(ReadOutcome::Read(bytes)) if bytes == b"0::/\n"
    ));
    let Err(unreadable) = read(&kernel, &dir, 4243, "cgroup") else {
        panic!("EIO is no skip");
    };
    assert!(unreadable.to_string().contains("4243/cgroup"), "{unreadable}");
}

/// The `stat` read's own error is the unreadable pid's `source()`.
#[skuld::test]
fn an_unreadable_pid_has_the_reads_error_as_its_source() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let kernel = FakeKernel::new().on_read("4242/stat", Err(libc::EIO));
    let Err(unreadable) = read(&kernel, &dir, 4242, "stat") else {
        panic!("EIO is no skip");
    };
    let source = std::error::Error::source(&unreadable).expect("an unreadable pid has a source");
    assert_eq!(
        source
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error),
        Some(libc::EIO)
    );
}

/// An unreadable pid says which `stat` failed and not the OS error, which is its `source()`.
#[skuld::test]
fn an_unreadable_pid_says_what_failed_and_not_the_os_error() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let os_error = std::io::Error::from_raw_os_error(libc::EIO).to_string();
    let kernel = FakeKernel::new().on_read("4242/stat", Err(libc::EIO));
    let Err(unreadable) = read(&kernel, &dir, 4242, "stat") else {
        panic!("EIO is no skip");
    };
    assert!(!unreadable.to_string().contains(&os_error), "{unreadable}");
    assert!(unreadable.to_string().contains("4242/stat"), "{unreadable}");

    let beyond = FakeKernel::new().on_read("4242/stat", Err(libc::EXDEV));
    let Err(unreadable) = read(&beyond, &dir, 4242, "stat") else {
        panic!("EXDEV is no skip");
    };
    let os_error = std::io::Error::from_raw_os_error(libc::EXDEV).to_string();
    assert!(!unreadable.to_string().contains(&os_error), "{unreadable}");
}

/// The pid's own failure is kept beside a refusal the checked directory made: the refusal's second
/// cause, naming the pid, with the pid's `EPERM` below it. A lone refusal has no second cause.
///
/// Mutant: the second failure is named in the words only, or dropped.
#[skuld::test]
fn the_other_failure_of_a_refused_pid_is_kept_beside_the_refusal() {
    use crate::error::Error;

    let dir = HostKernel.open_proc().expect("/proc opens");
    for recheck in [libc::EPERM, libc::ENOSYS, libc::ENODEV] {
        let kernel = FakeKernel::new()
            .on_read("4242/stat", Err(libc::EPERM))
            .on_read("self/stat", Err(recheck));
        let Ok(ReadOutcome::Refused(refusal)) = read(&kernel, &dir, 4242, "stat") else {
            panic!("{recheck}: a refusing directory is a refusal");
        };

        let cause = refusal.cause();

        let Error::Several(causes) = &cause else {
            panic!("{recheck}: expected Several, got {cause:?}");
        };
        let codes: Vec<_> = causes.iter().map(|c| crate::error::first_os_code(&**c)).collect();
        assert_eq!(codes, [Some(recheck), Some(libc::EPERM)], "{recheck}");
        let second = &**causes.iter().nth(1).expect("a second cause");
        let words = crate::error::Report(second).to_string();
        assert!(
            words.contains("4242/stat was refused, and the checked /proc refused self/stat too"),
            "{recheck}: {words}"
        );
        assert_eq!(
            crate::error::first_os_code(second),
            Some(libc::EPERM),
            "{recheck}: {words}"
        );
    }
    let kernel = FakeKernel::new().on_read("4242/stat", Err(libc::ENOSYS));
    let Ok(ReadOutcome::Refused(refusal)) = read(&kernel, &dir, 4242, "stat") else {
        panic!("ENOSYS is a refusal");
    };
    assert!(
        matches!(refusal.cause(), Error::Io(_)),
        "a lone refusal has no second cause"
    );
}

/// The pid's `EPERM` is kept beside a re-check that failed without refusing: it is the peer the
/// scan's error holds as a second cause, and the re-check's error is the source.
///
/// Mutant: the second failure is named in the words only, or dropped.
#[skuld::test]
fn the_pids_eperm_is_kept_as_the_peer_of_a_failed_recheck() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let kernel = FakeKernel::new()
        .on_read("4242/stat", Err(libc::EPERM))
        .on_read("self/stat", Err(libc::EMFILE));
    let Err(mut unreadable) = read(&kernel, &dir, 4242, "stat") else {
        panic!("a failed directory is no skip");
    };

    let kept = unreadable.take_peer().and_then(|e| e.raw_os_error());

    assert_eq!(kept, Some(libc::EPERM));
    assert_eq!(crate::error::first_os_code(&unreadable), Some(libc::EMFILE));
    assert_eq!(
        unreadable.take_peer().and_then(|e| e.raw_os_error()),
        None,
        "taken once"
    );
    let beyond = FakeKernel::new().on_read("4242/stat", Err(libc::EIO));
    let Err(mut unreadable) = read(&beyond, &dir, 4242, "stat") else {
        panic!("EIO is no skip");
    };
    assert!(unreadable.take_peer().is_none(), "a plain failure has no peer");
}

/// A `self/stat` re-check that fails for another reason (`EMFILE`, `ENOMEM`, `EIO`) is no refusal:
/// the text says the pid's `stat` was refused and the re-check failed, and the `source()` is the
/// re-check's own error, the operative cause.
///
/// Mutant: a failed re-check is a `Refused`, so the result is not an `Err(Unreadable)`.
#[skuld::test]
fn a_recheck_that_fails_without_refusing_is_its_own_error_and_the_source() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    for recheck in [libc::EMFILE, libc::ENOMEM, libc::EIO] {
        let kernel = FakeKernel::new()
            .on_read("4242/stat", Err(libc::EPERM))
            .on_read("self/stat", Err(recheck));
        let unreadable = match read(&kernel, &dir, 4242, "stat") {
            Err(unreadable) => unreadable,
            other => panic!("{recheck}: a failed re-check is neither a skip nor a refusal: {other:?}"),
        };

        let text = unreadable.to_string();

        assert!(text.starts_with("4242/stat was refused"), "{recheck}: {text}");
        assert!(text.contains("re-check of self/stat failed"), "{recheck}: {text}");
        let os_text = std::io::Error::from_raw_os_error(recheck).to_string();
        assert!(
            !text.contains(&os_text),
            "the cause is the source, not in the words: {text}"
        );
        assert_eq!(
            crate::error::first_os_code(&unreadable),
            Some(recheck),
            "{recheck}: {text}"
        );
    }
}
