//! `read_in_scan` decides a failed read from the read's errno alone: a scan covers all of `/proc`,
//! and a `kill(pid, 0)` probe of a foreign uid's process fails under `hidepid`.

use super::{read_in_scan, PidStat};
use crate::identity::{FakeKernel, HostKernel, Kernel};

/// The `stat` read's own error is the unreadable pid's `source()`.
#[skuld::test]
fn an_unreadable_pid_has_the_reads_error_as_its_source() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let kernel = FakeKernel::new().on_read("4242/stat", Err(libc::EIO));
    let Err(unreadable) = read_in_scan(&kernel, &dir, 4242) else {
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
    let Err(unreadable) = read_in_scan(&kernel, &dir, 4242) else {
        panic!("EIO is no skip");
    };
    assert!(!unreadable.to_string().contains(&os_error), "{unreadable}");
    assert!(unreadable.to_string().contains("4242/stat"), "{unreadable}");

    let beyond = FakeKernel::new().on_read("4242/stat", Err(libc::EXDEV));
    let Err(unreadable) = read_in_scan(&beyond, &dir, 4242) else {
        panic!("EXDEV is no skip");
    };
    let os_error = std::io::Error::from_raw_os_error(libc::EXDEV).to_string();
    assert!(!unreadable.to_string().contains(&os_error), "{unreadable}");
}

/// An `openat2` refusal (`EPERM`, `ENOSYS`, `ENODEV`) is [`PidStat::Refused`] carrying the refusing
/// errno: the checked directory refusing `self/stat` beside a pid's `EPERM` (the refusal is the
/// directory's, not the pid's `EPERM`), or the pid's own `stat` answering `ENOSYS`/`ENODEV`.
///
/// Mutant: the pid's `EPERM` is the refusal's errno; a refusal is an `Unreadable`.
#[skuld::test]
fn a_refused_openat2_is_a_refusal_carrying_the_refusing_errno() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    for (stat, recheck, refusing) in [
        (libc::EPERM, Some(libc::EPERM), libc::EPERM),
        (libc::EPERM, Some(libc::ENOSYS), libc::ENOSYS),
        (libc::EPERM, Some(libc::ENODEV), libc::ENODEV),
        (libc::ENOSYS, None, libc::ENOSYS),
        (libc::ENODEV, None, libc::ENODEV),
    ] {
        let mut kernel = FakeKernel::new().on_read("4242/stat", Err(stat));
        if let Some(recheck) = recheck {
            kernel = kernel.on_read("self/stat", Err(recheck));
        }
        match read_in_scan(&kernel, &dir, 4242) {
            Ok(PidStat::Refused(call)) => {
                assert_eq!(call.errno().raw_os_error(), refusing, "{stat}/{recheck:?}");
                assert!(call.requirement().is_some(), "{stat}/{recheck:?}");
            }
            other => panic!("{stat}/{recheck:?}: expected Refused, got {other:?}"),
        }
    }
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
    let Err(mut unreadable) = read_in_scan(&kernel, &dir, 4242) else {
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
    let Err(mut unreadable) = read_in_scan(&beyond, &dir, 4242) else {
        panic!("EIO is no skip");
    };
    assert!(unreadable.take_peer().is_none(), "a plain failure has no peer");
}

/// A `self/stat` re-check that fails for another reason (`EMFILE`, `ENOMEM`, `EIO`) is no refusal:
/// the text says the pid's `stat` was refused and the re-check failed, and the `source()` is the
/// re-check's own error, the operative cause.
///
/// Mutant: any re-check failure is "refused self/stat too", with the pid's `EPERM` as the source.
#[skuld::test]
fn a_recheck_that_fails_without_refusing_is_its_own_error_and_the_source() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    for recheck in [libc::EMFILE, libc::ENOMEM, libc::EIO] {
        let kernel = FakeKernel::new()
            .on_read("4242/stat", Err(libc::EPERM))
            .on_read("self/stat", Err(recheck));
        let Err(unreadable) = read_in_scan(&kernel, &dir, 4242) else {
            panic!("{recheck}: a failed re-check is no skip");
        };

        let text = unreadable.to_string();

        assert!(text.starts_with("4242/stat was refused"), "{recheck}: {text}");
        assert!(text.contains("re-check of self/stat failed"), "{recheck}: {text}");
        assert!(!text.contains("refused self/stat too"), "{recheck}: {text}");
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

/// Mutant: "`read_in_scan` asks `kill(pid, 0)` to tell a hidden pid from a gone one". A
/// `FakeKernel` with no `signal_probe` row panics on any probe.
#[skuld::test]
fn a_scan_skips_a_pid_it_cannot_read_without_asking_kill() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let cases = [
        ("ENOENT", FakeKernel::new().on_read("4242/stat", Err(libc::ENOENT))),
        ("EACCES", FakeKernel::new().on_read("4242/stat", Err(libc::EACCES))),
        (
            "EPERM, then self/stat reads",
            FakeKernel::new()
                .on_read("4242/stat", Err(libc::EPERM))
                .on_read("self/stat", Ok(b"")),
        ),
    ];
    for (name, kernel) in cases {
        match read_in_scan(&kernel, &dir, 4242) {
            Ok(PidStat::Skipped(_)) => {}
            other => panic!("{name}: expected Skipped, got {other:?}"),
        }
    }
}
