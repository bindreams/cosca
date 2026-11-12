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

/// A `stat` refused while the checked directory refuses `self/stat` too (`EPERM`, `ENOSYS`,
/// `ENODEV`: the refusal set of an `openat2`): the text says both refusals, and the `source()` is
/// the pid's own `stat` error, with its code.
///
/// Mutant: the `source()` is the directory's error, or the directory's error is put in the text.
#[skuld::test]
fn a_pid_refused_beside_a_refusing_directory_keeps_its_own_stat_error_as_its_source() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    for recheck in [libc::EPERM, libc::ENOSYS, libc::ENODEV] {
        let kernel = FakeKernel::new()
            .on_read("4242/stat", Err(libc::EPERM))
            .on_read("self/stat", Err(recheck));
        let Err(unreadable) = read_in_scan(&kernel, &dir, 4242) else {
            panic!("{recheck}: a refusing directory is no skip");
        };

        let text = unreadable.to_string();

        assert!(text.starts_with("4242/stat was refused"), "{recheck}: {text}");
        assert!(text.contains("refused self/stat too"), "{recheck}: {text}");
        assert!(
            !text.contains(&std::io::Error::from_raw_os_error(recheck).to_string()),
            "{recheck}: {text}"
        );
        assert_eq!(
            crate::error::first_os_code(&unreadable),
            Some(libc::EPERM),
            "{recheck}: {text}"
        );
    }
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
