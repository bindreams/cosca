use rustix::io::Errno;
use rustix::process::{getpid, Pid};

use super::fake::FakeKernel;
use super::{HostKernel, Kernel};

#[skuld::test]
fn host_kernel_reads_a_file_under_the_proc_it_opens() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let stat = HostKernel.read(&dir, "self/stat").expect("self/stat reads");
    let text = String::from_utf8(stat).expect("stat is UTF-8");
    assert!(
        text.starts_with(&format!("{} ", std::process::id())),
        "self/stat names this process: {text:?}"
    );
}

#[skuld::test]
fn host_pids_lists_this_process() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let pids = HostKernel.pids(&dir).expect("/proc lists");
    assert!(pids.contains(&std::process::id()), "{pids:?}");
}

#[skuld::test]
fn fake_pids_row_answers_without_the_host() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let listed = FakeKernel::new().on_pids(Ok(&[7]));
    assert_eq!(listed.pids(&dir).expect("the row lists"), vec![7]);
    let refused = FakeKernel::new().on_pids(Err(libc::EIO));
    assert_eq!(
        refused.pids(&dir).expect_err("the row refuses").raw_os_error(),
        Some(libc::EIO)
    );
}

#[skuld::test]
fn host_signal_probe_is_ok_for_this_process_and_esrch_for_i32_max() {
    assert_eq!(HostKernel.signal_probe(getpid()), Ok(()));
    assert_eq!(
        HostKernel.signal_probe(Pid::from_raw(i32::MAX).expect("a positive number")),
        Err(Errno::SRCH)
    );
}

#[skuld::test]
fn host_pidfd_open_opens_this_process_and_says_esrch_for_i32_max() {
    assert!(HostKernel.pidfd_open(getpid()).is_ok());
    assert_eq!(
        HostKernel
            .pidfd_open(Pid::from_raw(i32::MAX).expect("a positive number"))
            .map(drop),
        Err(Errno::SRCH)
    );
}
