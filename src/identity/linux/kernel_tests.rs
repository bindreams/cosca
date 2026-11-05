use rustix::io::Errno;
use rustix::process::{getpid, Pid, PidfdFlags};

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
fn host_signal_probe_is_ok_for_this_process_and_esrch_for_i32_max() {
    assert_eq!(HostKernel.signal_probe(getpid()), Ok(()));
    assert_eq!(
        HostKernel.signal_probe(Pid::from_raw(i32::MAX).expect("a positive number")),
        Err(Errno::SRCH)
    );
}

#[skuld::test]
fn host_pidfd_open_opens_this_process_and_says_esrch_for_i32_max() {
    assert!(HostKernel.pidfd_open(getpid(), PidfdFlags::empty()).is_ok());
    assert_eq!(
        HostKernel
            .pidfd_open(Pid::from_raw(i32::MAX).expect("a positive number"), PidfdFlags::empty())
            .map(drop),
        Err(Errno::SRCH)
    );
}
