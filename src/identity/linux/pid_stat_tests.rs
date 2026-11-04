//! `read_in_scan` decides a failed read from the read's errno alone: a scan covers all of `/proc`,
//! and a `kill(pid, 0)` probe of a foreign uid's process fails under `hidepid`.

use super::{read_in_scan, PidStat};
use crate::identity::{FakeKernel, HostKernel, Kernel};

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
