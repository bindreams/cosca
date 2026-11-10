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
